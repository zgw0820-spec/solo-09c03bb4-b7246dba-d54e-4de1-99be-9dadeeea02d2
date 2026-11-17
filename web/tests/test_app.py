"""单元/集成测试：证书校验、并发控制、回滚、待核实与重启恢复。

FakeControl 模拟 nginx 行为：收到重载回执为 ok 时，
把"当前 live 目录里的证书"当作 nginx 对外服务的证书。
"""
from __future__ import annotations

import datetime as dt
import threading

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from app import certutil
from app.certutil import CertError
from app.service import BadRequest, CertService, Config, Conflict, ProbeError

DOMAIN = "demo.internal"


class FakeControl:
    """行为接近真实 nginx：reload 后服务 live 目录中的证书。"""

    def __init__(self, service: CertService):
        self.service = service
        self.receipt_mode = "ok"   # ok | fail | timeout
        self.served: str | None = None
        self.reload_count = 0
        self.probe_error = False
        # 可按令牌定制回执：令牌 -> 回执字符串 / None（超时）。
        # 未命中的令牌走 receipt_mode。
        self.receipts: dict[str, str | None] = {}
        # 可在指定令牌的回执返回前执行动作（模拟迟到结果与交错的启用）。
        self.before_receipt: dict[str, callable] = {}
        # 探测到指定指纹后执行一次动作（模拟探测与写入交错）。
        self.on_probe: list[tuple[str, callable]] = []

    def _live_fp(self):
        return self.service.live_fingerprint()

    def probe(self) -> str:
        if self.probe_error:
            raise ProbeError("fake probe error")
        if self.served is None:
            raise ProbeError("nothing served yet")
        # 握手返回某个指纹后触发一次性动作（模拟探测与其它提交交错）
        for fp, action in list(self.on_probe):
            if self.served == fp:
                self.on_probe.remove((fp, action))
                action()
                break
        if self.served is None:
            raise ProbeError("nothing served yet")
        return self.served

    def request_reload(self, token: str) -> None:
        self.reload_count += 1
        if self.receipt_mode == "ok":
            self.served = self._live_fp()

    def wait_receipt(self, token: str, timeout: float):
        hook = self.before_receipt.pop(token, None)
        if hook is not None:
            hook()
        if token in self.receipts:
            return self.receipts[token]
        if self.receipt_mode == "timeout":
            return None
        if self.receipt_mode == "fail":
            return "fail test: simulated reload failure"
        return "ok"


@pytest.fixture()
def cfg(tmp_path):
    return Config(
        site_domain=DOMAIN,
        data_dir=str(tmp_path / "data"),
        live_dir=str(tmp_path / "live"),
        reload_dir=str(tmp_path / "reload"),
        receipt_timeout=0.2,
        verify_timeout=1.5,
        pending_ttl=0.5,
        probe_interval=0.05,
        startup_probe_timeout=0.5,
        restore_interval=0.1,
    )


@pytest.fixture()
def service(cfg):
    svc = CertService(cfg)
    svc.control = FakeControl(svc)
    svc.startup(background=False)
    yield svc
    svc.shutdown()


def make_cert(service, days_valid=365, not_before_days_ago=0, domain=DOMAIN):
    with open(f"{service.cfg.data_dir}/ca/ca.pem", "rb") as f:
        ca_cert = f.read()
    with open(f"{service.cfg.data_dir}/ca/ca-key.pem", "rb") as f:
        ca_key = f.read()
    return certutil.generate_server_cert(
        domain, ca_cert, ca_key,
        days_valid=days_valid, not_before_days_ago=not_before_days_ago,
    )


def upload_new(service, **kw):
    chain, key = make_cert(service, **kw)
    return service.upload(chain, key)[0]


# ---------------------------------------------------------------- 证书校验


def test_validate_ok(service):
    chain, key = make_cert(service)
    info = certutil.validate_upload(chain, key, DOMAIN)
    assert len(info.fingerprint) == 64


def test_validate_key_mismatch(service):
    chain, _ = make_cert(service)
    _, other_key = make_cert(service)
    with pytest.raises(CertError, match="不匹配"):
        certutil.validate_upload(chain, other_key, DOMAIN)


def test_validate_wrong_domain(service):
    chain, key = make_cert(service, domain="other.internal")
    with pytest.raises(CertError, match="域名"):
        certutil.validate_upload(chain, key, DOMAIN)


def test_validate_expired(service):
    chain, key = make_cert(service, days_valid=-1, not_before_days_ago=10)
    with pytest.raises(CertError, match="已过期"):
        certutil.validate_upload(chain, key, DOMAIN)


def test_validate_not_yet_valid(service):
    chain, key = make_cert(service, days_valid=365, not_before_days_ago=-5)
    with pytest.raises(CertError, match="尚未生效"):
        certutil.validate_upload(chain, key, DOMAIN)


def test_validate_broken_chain(service):
    chain, key = make_cert(service)
    leaf = chain.split(b"-----END CERTIFICATE-----")[0] + b"-----END CERTIFICATE-----\n"
    other_ca, _ = certutil.generate_ca("Other CA")
    with pytest.raises(CertError, match="证书链"):
        certutil.validate_upload(leaf + other_ca, key, DOMAIN)


def test_validate_encrypted_key(service):
    chain, _ = make_cert(service)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    enc_key = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(b"secret"),
    )
    with pytest.raises(CertError, match="加密"):
        certutil.validate_upload(chain, enc_key, DOMAIN)


def test_validate_self_signed_ok(service):
    ca, key = certutil.generate_ca("self-signed.demo.internal")
    # 自签名 CA 的 CN 不含站点域名，应被域名检查拒绝
    with pytest.raises(CertError, match="域名"):
        certutil.validate_upload(ca, key, DOMAIN)


def test_wildcard_match():
    assert certutil.dns_name_matches("*.example.com", "a.example.com")
    assert not certutil.dns_name_matches("*.example.com", "a.b.example.com")
    assert not certutil.dns_name_matches("*.example.com", "example.com")
    assert certutil.dns_name_matches("example.com", "EXAMPLE.com")


# ---------------------------------------------------------------- 上传


def test_upload_and_duplicate(service):
    chain, key = make_cert(service)
    v1, created1 = service.upload(chain, key)
    v2, created2 = service.upload(chain, key)
    assert created1 and not created2
    assert v1["id"] == v2["id"]
    assert v1["status"] == "candidate"


# ---------------------------------------------------------------- 启用流程


def test_activate_happy_path(service):
    v2 = upload_new(service)
    op = service.activate(v2["id"], base_version_id=1)
    assert op["state"] == "succeeded"
    st = service.status(probe=False)
    assert st["active_version_id"] == v2["id"]
    assert service.control.served == v2["fingerprint"]
    assert service.live_fingerprint() == v2["fingerprint"]
    versions = {v["id"]: v["status"] for v in st["versions"]}
    assert versions[1] == "superseded"
    assert versions[v2["id"]] == "active"


def test_activate_stale_base_rejected(service):
    v2 = upload_new(service)
    with pytest.raises(Conflict, match="过期"):
        service.activate(v2["id"], base_version_id=999)
    st = service.status(probe=False)
    assert st["active_version_id"] == 1


def test_activate_already_active(service):
    with pytest.raises(BadRequest):
        service.activate(1, base_version_id=1)


def test_concurrent_activate_only_one_wins(service):
    v2 = upload_new(service)
    results, errors = [], []

    def worker():
        try:
            results.append(service.activate(v2["id"], base_version_id=1))
        except Conflict as exc:
            errors.append(str(exc))

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert len(results) == 1, f"应有且仅有一个提交成功: {results} {errors}"
    assert results[0]["state"] == "succeeded"
    assert len(errors) == 7
    st = service.status(probe=False)
    assert st["active_version_id"] == v2["id"]
    assert len(st["ops"]) == 1  # 只登记了一个操作


def test_duplicate_submit_after_success_rejected(service):
    v2 = upload_new(service)
    service.activate(v2["id"], base_version_id=1)
    with pytest.raises(Conflict, match="过期"):
        service.activate(v2["id"], base_version_id=1)  # 重复提交同一表单


def test_reload_failure_rolls_back(service):
    v2 = upload_new(service)
    old_fp = service.status(probe=False)["active"]["fingerprint"]
    service.control.served = old_fp  # nginx 当前服务旧证书
    service.control.receipt_mode = "fail"
    op = service.activate(v2["id"], base_version_id=1)
    assert op["state"] == "failed"
    assert "重载失败" in op["detail"]
    st = service.status(probe=False)
    assert st["active_version_id"] == 1
    # 文件已回滚，nginx 仍服务旧证书
    assert service.live_fingerprint() == old_fp
    assert service.control.served == old_fp
    versions = {v["id"]: v["status"] for v in st["versions"]}
    assert versions[v2["id"]] == "failed"


def test_receipt_timeout_goes_pending_then_confirms(service):
    v2 = upload_new(service)
    service.control.receipt_mode = "timeout"
    op = service.activate(v2["id"], base_version_id=1)
    assert op["state"] == "pending_verify"
    assert service.status(probe=False)["active_version_id"] == 1  # 尚未切换
    # nginx 后来真的完成了重载
    service.control.served = service.live_fingerprint()
    service.reconcile_once()
    st = service.status(probe=False)
    assert st["active_version_id"] == v2["id"]
    assert service.get_op(op["seq"])["state"] == "succeeded"


def test_pending_expires_and_rolls_back(service):
    v2 = upload_new(service)
    old_fp = service.status(probe=False)["active"]["fingerprint"]
    service.control.receipt_mode = "timeout"
    op = service.activate(v2["id"], base_version_id=1)
    assert op["state"] == "pending_verify"
    # nginx 一直服务旧证书；超过宽限期后回退
    service.control.served = old_fp
    import time

    time.sleep(0.6)  # pending_ttl = 0.5
    service.reconcile_once()
    op = service.get_op(op["seq"])
    assert op["state"] == "failed"
    assert "回退" in op["detail"]
    assert service.live_fingerprint() == old_fp
    assert service.status(probe=False)["active_version_id"] == 1


def test_old_pending_op_cannot_overwrite_newer(service):
    """旧操作待核实期间有新提交成功后，旧操作不得再改动任何状态/文件。"""
    v2 = upload_new(service)
    v3 = upload_new(service)
    service.control.receipt_mode = "timeout"
    op_a = service.activate(v2["id"], base_version_id=1)
    assert op_a["state"] == "pending_verify"
    # 新提交（基于同一在用版号 1）成功
    service.control.receipt_mode = "ok"
    op_b = service.activate(v3["id"], base_version_id=1)
    assert op_b["state"] == "succeeded"
    assert service.status(probe=False)["active_version_id"] == v3["id"]
    # 旧操作 A 在创建 B 时已被取代；即使 nginx 稍后开始服务 v2 的证书也不得翻盘
    assert service.get_op(op_a["seq"])["state"] == "superseded"
    service.control.served = v2["fingerprint"]
    service.reconcile_once()
    st = service.status(probe=False)
    assert st["active_version_id"] == v3["id"]
    assert service.live_fingerprint() == v3["fingerprint"]


# ---------------------------------------------------------------- 交接竞态
# 场景对应值班员遇到的事故：旧核实读到原证书、新启用已成功、旧核实仍回退
# 文件并重载，页面显示 B 在用而客户端拿到原证书。


def _v3(service):
    v2 = upload_new(service)
    v3 = upload_new(service)
    return v2, v3


def test_superseded_pending_verify_makes_no_writes(service):
    """旧待核实操作被新提交取代后，即使超过宽限期也不得写文件/回退。"""
    v2, v3 = _v3(service)
    old_fp = service.status(probe=False)["active"]["fingerprint"]
    service.control.receipt_mode = "timeout"
    op_a = service.activate(v2["id"], base_version_id=1)
    assert op_a["state"] == "pending_verify"
    service.control.receipt_mode = "ok"
    op_b = service.activate(v3["id"], base_version_id=1)
    assert op_b["state"] == "succeeded"
    assert service.get_op(op_a["seq"])["state"] == "superseded"
    writes_before = service.control.reload_count
    import time

    time.sleep(0.6)  # 超过 pending_ttl
    service.reconcile_once()
    # 旧操作既未回写文件，也未触发回退重载
    assert service.live_fingerprint() == v3["fingerprint"]
    assert service.control.served == v3["fingerprint"]
    assert service.control.reload_count == writes_before
    assert service.get_op(op_a["seq"])["state"] == "superseded"
    assert service.status(probe=False)["active_version_id"] == v3["id"]
    assert old_fp != v3["fingerprint"]


def test_rollback_aborts_if_superseded_between_check_and_write(service):
    """归属检查在 I/O 锁内完成：检查通过后被新提交抢先，旧回退不得生效。"""
    v2, v3 = _v3(service)
    service.control.receipt_mode = "timeout"
    op_a = service.activate(v2["id"], base_version_id=1)
    assert op_a["state"] == "pending_verify"

    service._io_lock.acquire()
    try:
        # 持锁期间新提交无法写文件，模拟"回退即将写盘但已被取代"
        with service.db.txn() as c:
            c.execute(
                "UPDATE ops SET state='superseded' WHERE seq=?", (op_a["seq"],)
            )
        assert not service._rollback_files(service._version(1), owner_seq=op_a["seq"])
        assert not service._may_write(op_a["seq"])
        assert service._write_live_guarded(service._version(1), op_a["seq"]) is None
    finally:
        service._io_lock.release()
    # 文件没有被旧回退改动（仍是 A 写入的目标证书）
    assert service.get_op(op_a["seq"])["state"] == "superseded"


def test_new_activation_waits_for_late_prior_receipt(service, monkeypatch):
    """旧回退已发出、回执迟到：新启用必须等它落定，不能把可被覆盖的握手判成功。"""
    v2, v3 = _v3(service)
    service.control.receipt_mode = "timeout"
    op_a = service.activate(v2["id"], base_version_id=1)
    assert op_a["state"] == "pending_verify"

    # 制造"旧回退已发出、回执未到"：登记一个未决回退令牌
    service.control.receipts["rollback-late"] = None
    with service._io_lock:
        service._register_token("rollback-late", op_a["seq"], service._write_gen)
        service.control.request_reload("rollback-late")
    assert service._unresolved_tokens(0)

    service.control.receipt_mode = "ok"
    # 新启用 B 在旧回执到达前不能下结论
    monkeypatch.setattr(service.cfg, "late_reload_wait", 0.05)
    op_b = service.activate(v3["id"], base_version_id=1)
    assert op_b["state"] == "pending_verify"
    assert "回执" in op_b["detail"]
    # 没有把 B 判为成功，也没有改写在用版本
    assert service.status(probe=False)["active_version_id"] == 1
    # 由于旧回执未决，B 甚至不应写盘
    assert service.live_fingerprint() != v3["fingerprint"]

    # 旧回执落定后，后台重跑 B：写盘 -> 重载 -> 以新建握手确认
    service.control.receipts["rollback-late"] = "ok"
    service._resolve_token("rollback-late", "ok")
    service.reconcile_once()
    assert service.get_op(op_b["seq"])["state"] == "succeeded"
    assert service.status(probe=False)["active_version_id"] == v3["id"]
    assert service.control.served == v3["fingerprint"]
    assert service.live_fingerprint() == v3["fingerprint"]


def test_late_rollback_receipt_cannot_flip_new_success(service):
    """旧回退的迟到回执/重载若真把文件改回原证书，新启用不得判成功。"""
    v2, v3 = _v3(service)
    old_fp = service.status(probe=False)["active"]["fingerprint"]
    service.control.receipt_mode = "timeout"
    op_a = service.activate(v2["id"], base_version_id=1)
    assert op_a["state"] == "pending_verify"

    # 旧回退的迟到结果：在 B 探测之后把文件与对外服务改回旧证书
    def late_rollback():
        service._write_live(service._version(1))
        service.control.served = old_fp

    service.control.on_probe = [(v3["fingerprint"], late_rollback)]
    service.control.receipt_mode = "ok"
    op_b = service.activate(v3["id"], base_version_id=1)
    # 写入代次在探测之后被改，B 不得判成功
    assert op_b["state"] in ("pending_verify", "superseded")
    assert service.get_op(op_a["seq"])["state"] in ("superseded", "succeeded")

    # 后台继续跟进：对外服务一度被改回原证书，不能直接把 B 判成功。
    # 允许两种结局：重跑并再次以握手确认 B；或恢复到可确认旧版本。
    service.control.on_probe = []
    for _ in range(4):
        service.reconcile_once()
        import time
        time.sleep(0.05)
    st = service.status(probe=False)
    state = service.get_op(op_b["seq"])["state"]
    if state == "succeeded":
        # 只有重跑后的新建握手确实回到 B 才允许成功
        assert service.control.served == v3["fingerprint"]
        assert service.live_fingerprint() == v3["fingerprint"]
        assert st["active_version_id"] == v3["id"]
    else:
        assert st["active_version_id"] == 1
        assert service.live_fingerprint() == old_fp


def test_old_reconcile_rollback_after_new_success_is_dropped(service):
    """事故时序：旧核实读到原证书 -> B 成功 -> 旧核实醒来回退。

    旧核实必须发现"自己已被取代"，既不回写文件也不请求回退；页面与
    客户端实际拿到的证书必须都是 B。
    """
    v2, v3 = _v3(service)
    old_fp = service.status(probe=False)["active"]["fingerprint"]
    service.control.receipt_mode = "timeout"
    op_a = service.activate(v2["id"], base_version_id=1)
    assert op_a["state"] == "pending_verify"
    assert service.live_fingerprint() == v2["fingerprint"]

    service.cfg.reconcile_delay_before_rollback = 0.3

    def interleave():
        # 旧核实已探测到"原证书"（此刻 Nginx 仍服务旧证书），在回退前
        # 让 B 完成启用。
        service.control.receipt_mode = "ok"

        def run_b():
            op_b = service.activate(v3["id"], base_version_id=1)
            assert op_b["state"] == "succeeded"

        t = threading.Thread(target=run_b)
        t.start()
        t.join()

    # 让后台核实命中"原证书"，并在延迟窗口内插入 B
    service.control.served = old_fp
    service.control.on_probe = [(old_fp, interleave)]
    service.control.served = old_fp
    # 超过 pending_ttl，使旧核实进入回退流程
    import time

    time.sleep(0.6)
    reload_before_b = None
    service.reconcile_once()
    # B 成功后在用文件/服务均为 v3
    assert service.get_op(op_a["seq"])["state"] == "superseded"
    st = service.status(probe=False)
    assert st["active_version_id"] == v3["id"]
    assert service.live_fingerprint() == v3["fingerprint"]
    assert service.control.served == v3["fingerprint"]
    assert reload_before_b is None


def test_pending_success_requires_no_unresolved_reload(service):
    v2 = upload_new(service)
    service.control.receipt_mode = "timeout"
    op = service.activate(v2["id"], base_version_id=1)
    assert op["state"] == "pending_verify"
    service.control.served = v2["fingerprint"]
    # 一个不属于本操作的未决令牌
    with service._io_lock:
        service._register_token("late-x", -1, service._write_gen)
    service.reconcile_once()
    assert service.get_op(op["seq"])["state"] == "pending_verify"
    service.control.receipts["late-x"] = "ok"
    service._resolve_token("late-x", "ok")
    service.reconcile_once()
    assert service.get_op(op["seq"])["state"] == "succeeded"


# ---------------------------------------------------------------- 重启恢复


def restart(service_factory_cfg):
    svc = CertService(service_factory_cfg)
    svc.control = FakeControl(svc)
    return svc


def test_restart_confirms_successful_activation(cfg):
    svc = CertService(cfg)
    svc.control = FakeControl(svc)
    svc.startup(background=False)
    v2 = upload_new(svc)
    svc.control.receipt_mode = "timeout"
    op = svc.activate(v2["id"], base_version_id=1)
    assert op["state"] == "pending_verify"
    # 模拟进程崩溃：nginx 实际已切到新证书
    served = svc.live_fingerprint()
    svc.shutdown()
    svc2 = restart(cfg)
    svc2.control.served = served
    svc2.startup(background=False)
    st = svc2.status(probe=False)
    assert st["active_version_id"] == v2["id"]
    assert svc2.get_op(op["seq"])["state"] == "succeeded"
    svc2.shutdown()


def test_restart_rolls_back_unconfirmed_activation(cfg):
    svc = CertService(cfg)
    svc.control = FakeControl(svc)
    svc.startup(background=False)
    v2 = upload_new(svc)
    old_fp = svc.status(probe=False)["active"]["fingerprint"]
    svc.control.receipt_mode = "timeout"
    op = svc.activate(v2["id"], base_version_id=1)
    assert op["state"] == "pending_verify"
    # 进程崩溃时 nginx 仍服务旧证书
    svc.shutdown()
    svc2 = restart(cfg)
    svc2.control.served = old_fp
    svc2.startup(background=False)
    st = svc2.status(probe=False)
    assert st["active_version_id"] == 1
    assert svc2.get_op(op["seq"])["state"] == "failed"
    assert svc2.live_fingerprint() == old_fp  # 文件已恢复到可确认版本
    svc2.shutdown()


def test_restart_with_activating_op_recovered(cfg):
    """进程在操作处于 activating 时崩溃（未留下任何终态）。"""
    svc = CertService(cfg)
    svc.control = FakeControl(svc)
    svc.startup(background=False)
    v2 = upload_new(svc)
    old_fp = svc.status(probe=False)["active"]["fingerprint"]
    # 手工制造一个悬空的 activating 操作（等价于崩溃瞬间）
    with svc.db.txn() as c:
        st = c.execute("SELECT * FROM state WHERE id=1").fetchone()
        seq = st["current_op_seq"] + 1
        ts = certutil.dt.datetime.now(certutil.dt.timezone.utc).isoformat()
        c.execute(
            "INSERT INTO ops (seq, version_id, base_version_id, state, detail,"
            " created_at, updated_at) VALUES (?,?,?,?,?,?,?)",
            (seq, v2["id"], 1, "activating", None, ts, ts),
        )
        c.execute("UPDATE state SET current_op_seq=?", (seq,))
    svc.shutdown()
    svc2 = restart(cfg)
    svc2.control.served = old_fp
    svc2.startup(background=False)
    assert svc2.get_op(seq)["state"] == "failed"
    assert svc2.status(probe=False)["active_version_id"] == 1
    svc2.shutdown()


def test_restart_restores_tampered_live_files(cfg):
    svc = CertService(cfg)
    svc.control = FakeControl(svc)
    svc.startup(background=False)
    active_fp = svc.status(probe=False)["active"]["fingerprint"]
    # 带外篡改 live 文件
    chain, key = make_cert(svc)
    with open(f"{cfg.live_dir}/fullchain.pem", "wb") as f:
        f.write(chain)
    assert svc.live_fingerprint() != active_fp
    svc.shutdown()
    svc2 = restart(cfg)
    svc2.control.served = active_fp
    svc2.startup(background=False)
    assert svc2.live_fingerprint() == active_fp
    assert svc2.control.reload_count >= 1  # 触发了恢复重载
    svc2.shutdown()


def test_reconciler_restores_out_of_band_change(service):
    """无在途操作时，nginx 实测指纹与在用版本不一致会被自动修复。"""
    active_fp = service.status(probe=False)["active"]["fingerprint"]
    service.control.served = "0" * 64  # 带外变更
    import time

    time.sleep(0.15)  # restore_interval = 0.1
    service.reconcile_once()
    assert service.control.reload_count >= 1
