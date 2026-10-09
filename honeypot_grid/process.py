"""Bounded Linux subprocess execution; no shell, inherited env or silent cleanup."""

import ctypes
import os
import resource
import selectors
import signal
import subprocess
import time

from .policy import Rejected, integer

_LIBC = ctypes.CDLL(None, use_errno=True)


def bounded_run(argv, *, timeout=10, output_limit=65536, pass_fds=(), vm_limits=False):
    integer(timeout, 1, 60)
    integer(output_limit, 1, 1_048_576)
    parent = os.getpid()

    def child_policy():
        # CLI is single-threaded. Set death signal before exec and close fork race.
        if _LIBC.prctl(1, signal.SIGKILL, 0, 0, 0) or os.getppid() != parent:
            os._exit(125)
        if _LIBC.prctl(38, 1, 0, 0, 0):  # PR_SET_NO_NEW_PRIVS
            os._exit(125)
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        if vm_limits:
            resource.setrlimit(resource.RLIMIT_CPU, (timeout, timeout))
            resource.setrlimit(resource.RLIMIT_AS, (1536 * 1024**2, 1536 * 1024**2))
            resource.setrlimit(resource.RLIMIT_FSIZE, (0, 0))

    process = None
    output = bytearray()
    try:
        process = subprocess.Popen(
            argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            env={"PATH": "/usr/bin:/bin", "HOME": "/nonexistent"},
            close_fds=True,
            pass_fds=pass_fds,
            start_new_session=True,
            preexec_fn=child_policy,
        )
        deadline = time.monotonic() + timeout
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise Rejected("subprocess deadline exceeded")
                for key, _ in selector.select(min(remaining, 0.1)):
                    block = os.read(key.fd, min(65536, output_limit + 1 - len(output)))
                    if not block:
                        selector.unregister(key.fileobj)
                    else:
                        output.extend(block)
                        if len(output) > output_limit:
                            raise Rejected("subprocess output limit exceeded")
            remaining = deadline - time.monotonic()
            if remaining <= 0 or process.wait(timeout=remaining) != 0:
                raise Rejected("subprocess failed")
        return bytes(output)
    except (OSError, subprocess.SubprocessError) as exc:
        raise Rejected("subprocess unavailable") from exc
    finally:
        if process is not None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait(timeout=5)
            process.stdout.close()
