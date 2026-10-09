"""Local dedicated-VM Docker adapter, no-network only, fixed argv and no shell."""

import json
import os
import re
import stat
import subprocess

from .policy import Config, Rejected, fields, identifier

RUN_HASH = re.compile(r"[a-f0-9]{64}\Z")


def run_command(argv):
    try:
        result = subprocess.run(
            argv,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
            env={"PATH": "/usr/bin:/bin", "HOME": "/nonexistent"},
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise Rejected("runtime unavailable") from exc
    if result.returncode or len(result.stdout) > 65536:
        raise Rejected("runtime command rejected")
    return result.stdout


class DockerRuntime:
    name = "docker-none"

    def __init__(self, attestation: dict, runner=None):
        fields(
            attestation,
            {
                "dedicated_lab_vm",
                "no_production_routes",
                "no_host_credentials",
                "operator",
                "authorization_ref",
            },
        )
        for name in ("dedicated_lab_vm", "no_production_routes", "no_host_credentials"):
            if attestation[name] is not True:
                raise Rejected("dedicated VM attestation required")
        self.attestation = attestation
        identifier(attestation["operator"])
        identifier(attestation["authorization_ref"])
        self.runner = runner or run_command
        if runner is None:
            info = os.stat("/usr/bin/docker", follow_symlinks=False)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
                raise Rejected("trusted system Docker executable required")

    def _run(self, *args):
        return self.runner(["/usr/bin/docker", "--host", "unix:///var/run/docker.sock", *args])

    def _json(self, *args):
        try:
            return json.loads(self._run(*args))
        except (ValueError, TypeError) as exc:
            raise Rejected("invalid runtime metadata") from exc

    def _name(self, digest):
        if type(digest) is not str or not RUN_HASH.fullmatch(digest):
            raise Rejected("invalid runtime plan hash")
        return "hpg-" + digest

    def preflight(self, config: Config):
        if (
            self.attestation["operator"] != config.owner
            or self.attestation["authorization_ref"] != config.authorization_ref
        ):
            raise Rejected("VM attestation outside scope")
        info = self._json("info", "--format", "{{json .}}")
        security = info.get("SecurityOptions", [])
        if (
            info.get("OSType") != "linux"
            or info.get("CgroupVersion") != "2"
            or info.get("CgroupDriver") not in ("systemd", "cgroupfs")
            or not any("seccomp" in s for s in security)
            or not any("apparmor" in s or "selinux" in s for s in security)
        ):
            raise Rejected("runtime lacks required enforcement")
        image = self._json("image", "inspect", config.image_digest)
        if (
            type(image) is not list
            or len(image) != 1
            or image[0].get("Id") != config.image_digest
            or image[0].get("Config", {}).get("Volumes")
            or image[0].get("Config", {}).get("Labels", {}).get("org.honeypot-grid.synthetic")
            != "true"
        ):
            raise Rejected("unapproved local synthetic image")

    def _inspect(self, digest):
        name = self._name(digest)
        output = self._json("container", "inspect", name)
        if type(output) is not list or len(output) != 1 or type(output[0]) is not dict:
            raise Rejected("invalid container metadata")
        value = output[0]
        labels = value.get("Config", {}).get("Labels", {})
        if (
            labels.get("org.honeypot-grid.plan") != digest
            or labels.get("org.honeypot-grid.owner") != self.attestation["operator"]
            or labels.get("org.honeypot-grid.authorization")
            != self.attestation["authorization_ref"]
        ):
            raise Rejected("container ownership mismatch")
        return value

    def verify(self, digest, config: Config):
        value = self._inspect(digest)
        host = value.get("HostConfig", {})
        command = value.get("Config", {})
        if (
            value.get("Image") != config.image_digest
            or host.get("NetworkMode") != "none"
            or host.get("Privileged") is not False
            or host.get("ReadonlyRootfs") is not True
            or host.get("Binds")
            or value.get("Mounts")
            or host.get("PortBindings")
            or host.get("PidMode") not in ("", "private")
            or host.get("IpcMode") != "private"
            or command.get("User") != "65532:65532"
            or "ALL" not in host.get("CapDrop", [])
            or host.get("CapAdd")
            or host.get("Devices")
            or host.get("DeviceRequests")
            or "no-new-privileges" not in host.get("SecurityOpt", [])
            or any("unconfined" in s for s in host.get("SecurityOpt", []))
            or host.get("PidsLimit") != 32
            or host.get("Memory") != config.memory_mib * 1024 * 1024
            or host.get("MemorySwap") != host.get("Memory")
            or host.get("NanoCpus") != config.cpu_millicores * 1000000
            or host.get("RestartPolicy", {}).get("Name") != "no"
        ):
            raise Rejected("container enforcement mismatch")
        return value.get("State", {}).get("Running") is True

    def exists(self, digest):
        name = self._name(digest)
        lines = self._run(
            "container", "ls", "--all", "--filter", f"name=^/{name}$", "--format", "{{.Names}}"
        ).splitlines()
        if lines not in ([], [name]):
            raise Rejected("ambiguous runtime inventory")
        return bool(lines)

    def start(self, digest, config: Config):
        self.preflight(config)
        name = self._name(digest)
        if not self.exists(digest):
            self._run(
                "container",
                "create",
                "--name",
                name,
                "--pull",
                "never",
                "--label",
                f"org.honeypot-grid.plan={digest}",
                "--network",
                "none",
                "--label",
                f"org.honeypot-grid.owner={config.owner}",
                "--label",
                f"org.honeypot-grid.authorization={config.authorization_ref}",
                "--ipc",
                "private",
                "--read-only",
                "--user",
                "65532:65532",
                "--cap-drop",
                "ALL",
                "--security-opt",
                "no-new-privileges",
                "--pids-limit",
                "32",
                "--memory",
                f"{config.memory_mib}m",
                "--memory-swap",
                f"{config.memory_mib}m",
                "--cpus",
                str(config.cpu_millicores / 1000),
                "--restart",
                "no",
                "--log-driver",
                "local",
                "--log-opt",
                "max-size=1m",
                "--log-opt",
                "max-file=1",
                "--no-healthcheck",
                "--entrypoint",
                "python",
                config.image_digest,
                "-m",
                "honeypot_grid.sensor",
                "--service",
                config.service,
                "--sensor-id",
                config.lab_id,
                "--seconds",
                str(config.ttl_seconds),
            )
        try:
            if not self.verify(digest, config):
                self._run("container", "start", name)
            if not self.verify(digest, config):
                raise Rejected("sensor did not start")
        except Rejected, OSError, KeyError, TypeError:
            self.stop(digest)
            raise

    def stop(self, digest):
        if self.exists(digest):
            self._inspect(digest)  # Never delete a resource with mismatched ownership.
            self._run("container", "rm", "--force", "--volumes", self._name(digest))
        if self.exists(digest):
            raise Rejected("runtime cleanup unconfirmed")

    def inventory(self):
        names = self._run(
            "container",
            "ls",
            "--all",
            "--filter",
            f"label=org.honeypot-grid.owner={self.attestation['operator']}",
            "--filter",
            f"label=org.honeypot-grid.authorization={self.attestation['authorization_ref']}",
            "--format",
            "{{.Names}}",
        ).splitlines()
        if len(names) > 1000 or any(
            not n.startswith("hpg-") or not RUN_HASH.fullmatch(n[4:]) for n in names
        ):
            raise Rejected("invalid managed inventory")
        return [n[4:] for n in names]
