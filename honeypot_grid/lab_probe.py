"""Fixed harmless Docker guest probe; documentation-range targets only.

The host never executes PROBE. ENETUNREACH proves a kernel routing denial for
these attempts, not an independent review of the host/provider boundary.
"""

PROBE = r"""
import errno, json, os, socket
assert set(os.listdir('/sys/class/net')) == {'lo'}
status = dict(line.split(':', 1) for line in open('/proc/self/status') if ':' in line)
assert int(status['CapEff'].strip(), 16) == 0
assert int(status['CapBnd'].strip(), 16) == 0
assert status['NoNewPrivs'].strip() == '1'
assert os.getuid() == 65532
assert os.statvfs('/').f_flag & os.ST_RDONLY
blocked = 0
for family, targets in ((socket.AF_INET, ['192.0.2.' + str(i) for i in range(1, 6)]),
                        (socket.AF_INET6, ['2001:db8::' + str(i) for i in range(1, 6)])):
    for target in targets:
        for kind, port in ((socket.SOCK_STREAM, 443), (socket.SOCK_DGRAM, 53),
                           (socket.SOCK_DGRAM, 80)):
            sock = None
            try:
                sock = socket.socket(family, kind)
                sock.settimeout(0.5)
                result = sock.connect_ex((target, port))
                assert result == errno.ENETUNREACH
            except OSError as exc:
                assert family == socket.AF_INET6 and exc.errno == errno.EAFNOSUPPORT
            finally:
                if sock is not None: sock.close()
            blocked += 1
assert blocked == 30
print(json.dumps({'version': 1, 'only_loopback': True, 'blocked_attempts': blocked,
                  'unprivileged': True}))
"""


def validate_probe(result):
    from .policy import Rejected, fields

    fields(result, {"version", "only_loopback", "blocked_attempts", "unprivileged"})
    expected = {"version": 1, "only_loopback": True, "blocked_attempts": 30, "unprivileged": True}
    if any(type(result[k]) is not type(v) or result[k] != v for k, v in expected.items()):
        raise Rejected("laboratory probe did not establish expected denial")
    return expected
