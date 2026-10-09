from concurrent.futures import ThreadPoolExecutor

import pytest

from honeypot_grid.manager import Manager
from honeypot_grid.policy import ISOLATION, Rejected


def test_simultaneous_apply_consumes_once(tmp_path):
    database = tmp_path / "concurrent.sqlite3"
    digest = "sha256:" + "0" * 64
    scope = {
        "lab_id": "lab-demo",
        "owner": "lab-operator",
        "authorization_ref": "demo-only",
        "services": ["http-mock"],
        "image_digests": [digest],
    }
    config = {k: scope[k] for k in ("lab_id", "owner", "authorization_ref")} | {
        "service": "http-mock",
        "image_digest": digest,
        "ttl_seconds": 600,
        "memory_mib": 128,
        "cpu_millicores": 250,
        "isolation": dict(ISOLATION),
    }
    manager = Manager(database, lambda: 1000)
    result = manager.prepare(config, scope)
    manager.approve(result["plan_hash"], "lab-operator")

    def apply(_):
        worker = Manager(database, lambda: 1000)
        try:
            return worker.apply(result["plan"], scope, "lab-operator")["changed"]
        finally:
            worker.close()

    try:
        with ThreadPoolExecutor(max_workers=2) as workers:
            assert sorted(workers.map(apply, range(2))) == [False, True]
        with pytest.raises(Rejected):
            manager.approve(result["plan_hash"], "lab-operator")
        assert manager.db.execute(
            "SELECT count(*) FROM audit WHERE action='mock-provisioned'"
        ).fetchone() == (1,)
    finally:
        manager.close()
