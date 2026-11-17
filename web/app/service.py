"""证书启用核心逻辑。

设计要点：
- 启用请求带"页面所见版号"(base_version_id)，在 BEGIN IMMEDIATE 事务内
  比较-交换，过期提交与并发重复提交直接拒绝，不会覆盖在用证书。
- 启用成功以"Nginx 新建 TLS 连接返回新证书指纹"为唯一判据；
  重载回执失败 -> 回滚文件并保持旧版本在用；
  回执不明/无法探测 -> 置"待核实"，由后台核实循环继续处理。
- 任何落库/写文件动作前都检查"自己是否仍是最新操作"，
  旧操作不得覆盖后来提交。
- 进程重启时按 Nginx 实际服务的指纹对账，恢复到可确认的在用版本。
"""
from __future__ import annotations

import datetime as dt
import hashlib
import logging
import os
import socket
import ssl
import threading
import time
import uuid
from dataclasses import dataclass

from . import certutil
from .db import DB

log = logging.getLogger("certops")

UTC = dt.timezone.utc


def now_iso() -> str:
    return dt.datetime.now(UTC).isoformat(timespec="seconds")


class Conflict(Exception):
    """409：版号过期或已有操作在进行。"""


class BadRequest(Exception):
    """400：请求内容不合法。"""


class NotFound(Exception):
    """404：目标不存在。"""


class ProbeError(Exception):
    """无法与 Nginx 建立 TLS 连接。"""


@dataclass
class Config:
    site_domain: str = "demo.internal"
    data_dir: str = "/data"
    live_dir: str = "/certs/live"
    reload_dir: str = "/reload"
    probe_host: str = "nginx"
    probe_port: int = 443
    receipt_timeout: float = 6.0      # 等待重载回执的秒数
    verify_timeout: float = 10.0      # 启用后探测新证书的秒数
    pending_ttl: float = 45.0         # 待核实操作的宽限秒数，超时回退
    probe_interval: float = 0.5
    startup_probe_timeout: float = 15.0
    restore_interval: float = 30.0    # 无在途操作时一致性修复的最小间隔
    reconcile_interval: float = 2.0   # 后台核实循环扫描间隔
    late_reload_wait: float = 3.0     # 等待先前重载回执落定的上限
    stale_reload_age: float = 15.0    # 超过该时长仍无回执的令牌视为已失效
    reconcile_delay_before_rollback: float = 0.0  # 测试钩子：探测后延迟再回退
    activate_delay_after_write: float = 0.0  # 测试钩子：写完文件后人为延迟

    @property
    def db_path(self) -> str:
        return os.path.join(self.data_dir, "certops.db")

    @classmethod
    def from_env(cls) -> "Config":
        e = os.environ
        return cls(
            site_domain=e.get("SITE_DOMAIN", "demo.internal"),
            data_dir=e.get("DATA_DIR", "/data"),
            live_dir=e.get("LIVE_DIR", "/certs/live"),
            reload_dir=e.get("RELOAD_DIR", "/reload"),
            probe_host=e.get("NGINX_PROBE_HOST", "nginx"),
            probe_port=int(e.get("NGINX_PROBE_PORT", "443")),
            receipt_timeout=float(e.get("RECEIPT_TIMEOUT", "6")),
            verify_timeout=float(e.get("VERIFY_TIMEOUT", "10")),
            pending_ttl=float(e.get("PENDING_TTL", "45")),
            startup_probe_timeout=float(e.get("STARTUP_PROBE_TIMEOUT", "15")),
            late_reload_wait=float(e.get("LATE_RELOAD_WAIT", "3")),
            stale_reload_age=float(e.get("STALE_RELOAD_AGE", "15")),
            reconcile_interval=float(e.get("RECONCILE_INTERVAL", "2")),
            reconcile_delay_before_rollback=float(
                e.get("RECONCILE_DELAY_BEFORE_ROLLBACK", "0")
            ),
            activate_delay_after_write=float(e.get("ACTIVATE_DELAY_AFTER_WRITE", "0")),
        )


def tls_fingerprint(host: str, port: int, server_name: str, timeout: float = 3.0) -> str:
    """新建一条 TLS 连接，返回对端叶子证书的 SHA-256 指纹。"""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            with ctx.wrap_socket(sock, server_hostname=server_name) as ssock:
                der = ssock.getpeercert(binary_form=True)
    except OSError as exc:
        raise ProbeError(str(exc)) from exc
    return hashlib.sha256(der).hexdigest()


class FileReloadChannel:
    """经共享目录与 nginx 侧 watcher 通信：REQUEST 追加令牌，RESULT 回收回执。"""

    def __init__(self, reload_dir: str):
        self.req_path = os.path.join(reload_dir, "REQUEST")
        self.res_path = os.path.join(reload_dir, "RESULT")

    def request(self, token: str) -> None:
        with open(self.req_path, "a", encoding="utf-8") as f:
            f.write(f"{token} {now_iso()}\n")
            f.flush()
            os.fsync(f.fileno())

    def wait(self, token: str, timeout: float) -> str | None:
        """等到 'ok' / 'fail ...'；超时返回 None（回执不明）。"""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                with open(self.res_path, "r", encoding="utf-8") as f:
                    for line in f:
                        parts = line.strip().split(" ", 1)
                        if len(parts) == 2 and parts[0] == token:
                            return parts[1]
            except FileNotFoundError:
                pass
            time.sleep(0.2)
        return None

    def unresolved(self) -> list[tuple[str, float]]:
        """列出已请求但尚未收到回执的令牌及其请求时长（秒）。

        用于进程重启后接管上一进程发出、nginx 侧可能仍在处理的重载请求：
        这些请求随时可能把文件/对外服务改回去，不能忽略。
        """
        requested: dict[str, str] = {}
        try:
            with open(self.req_path, "r", encoding="utf-8") as f:
                for line in f:
                    parts = line.strip().split(" ", 1)
                    if parts and parts[0]:
                        requested[parts[0]] = parts[1] if len(parts) > 1 else ""
        except FileNotFoundError:
            pass
        answered: set[str] = set()
        try:
            with open(self.res_path, "r", encoding="utf-8") as f:
                for line in f:
                    parts = line.strip().split(" ", 1)
                    if parts and parts[0]:
                        answered.add(parts[0])
        except FileNotFoundError:
            pass
        now = dt.datetime.now(UTC)
        result = []
        for token, ts in requested.items():
            if token in answered:
                continue
            age = 0.0
            try:
                age = max(0.0, (now - dt.datetime.fromisoformat(ts)).total_seconds())
            except (TypeError, ValueError):
                pass
            result.append((token, age))
        return result


class RealControl:
    """生产用 Nginx 控制面：文件通道触发平滑重载 + 真实 TLS 探测。"""

    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.channel = FileReloadChannel(cfg.reload_dir)

    def probe(self) -> str:
        return tls_fingerprint(
            self.cfg.probe_host, self.cfg.probe_port, self.cfg.site_domain
        )

    def request_reload(self, token: str) -> None:
        self.channel.request(token)

    def wait_receipt(self, token: str, timeout: float) -> str | None:
        return self.channel.wait(token, timeout)

    def unresolved_requests(self) -> list[tuple[str, float]]:
        return self.channel.unresolved()


class CertService:
    def __init__(self, cfg: Config, control=None):
        self.cfg = cfg
        for d in (cfg.data_dir, cfg.live_dir, cfg.reload_dir):
            os.makedirs(d, exist_ok=True)
        self.db = DB(cfg.db_path)
        self.control = control or RealControl(cfg)
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._probe_cache: tuple[float, str | None] = (0.0, None)
        self._last_restore = 0.0
        # 串行化"写 live 文件 + 请求重载 + 等回执"整段，避免旧回退与新启用
        # 的写文件/重载互相穿插，导致 nginx 最终加载了错误的文件。
        self._io_lock = threading.RLock()
        # 写入 live 文件时递增；重载回执返回后据此判断文件是否已被别人改写。
        self._write_gen = 0
        self._gen_lock = threading.Lock()
        # 正在等回执的重载令牌（跨线程，用于识别"迟到的旧回退"）。
        self._pending_tokens: dict[str, dict] = {}
        self._token_lock = threading.Lock()
        # 因旧回执未决而没有写盘的启用：旧回执落定后需要在后台重跑。
        self._drain_retry: set[int] = set()
        # 握手已是目标证书但文件被迟到的旧回退改回：需要恢复后再核实（按操作记录）。
        self._recovery_needed: set[int] = set()
        # 后台核实循环的扫描间隔。
        self._reconcile_poll = cfg.reconcile_interval

    # ------------------------------------------------------------ 生命周期

    def startup(self, background: bool = True) -> None:
        self.db.init_schema()
        with self.db.txn() as c:
            empty = c.execute("SELECT COUNT(*) n FROM versions").fetchone()["n"] == 0
        if empty:
            self._seed()
        # 上次进程退出时遗留的"启用中"操作一律转为待核实
        with self.db.txn() as c:
            c.execute(
                "UPDATE ops SET state='pending_verify',"
                " detail='进程重启，启用结果待核实', updated_at=?"
                " WHERE state='activating'",
                (now_iso(),),
            )
        self._adopt_orphan_reloads()
        # 先让上一进程遗留的重载请求落定（旧回退若迟到，其握手结果会覆盖
        # 重启后的判定，不能据此宣布启用成功）。
        self._drain_prior_reloads(None)
        served = self._probe_with_grace(self.cfg.startup_probe_timeout)
        with self.db.txn() as c:
            op = self._latest_inflight(c)
        if op:
            target = self._version(op["version_id"])
            if served is not None and served == target["fingerprint"]:
                if (
                    self.live_fingerprint() != target["fingerprint"]
                    or self._unresolved_tokens(op["seq"])
                ):
                    # 握手已是新证书，但文件/在途回退仍可能把它改回去。
                    log.warning(
                        "startup: 握手是新证书但文件或在途回退未落定，操作 #%s 保持待核实",
                        op["seq"],
                    )
                else:
                    self._finalize_success(op["seq"], note="重启后核实：新证书已生效")
            elif served is not None:
                # 实际服务的不是目标证书：恢复到可确认的在用版本，并再以
                # 新建 TLS 握手确认恢复结果；确认不了就保持待核实。
                recovered = self._recover_to_confirmable(served)
                confirmed = self._probe_with_grace(
                    min(self.cfg.startup_probe_timeout, self.cfg.verify_timeout)
                )
                if (
                    recovered is not None
                    and confirmed == recovered["fingerprint"]
                    and self._still_owner(op["seq"])
                ):
                    self._finalize_fail(
                        op["seq"], "进程重启，启用结果未确认，已恢复到可确认的在用版本"
                    )
                else:
                    log.warning(
                        "startup: 恢复后仍无法确认实际在用版本，操作 #%s 保持待核实",
                        op["seq"],
                    )
            else:
                log.warning("startup: 无法探测 Nginx，操作 #%s 保持待核实", op["seq"])
        else:
            self._ensure_live_matches_active(served)
        if background:
            self._thread = threading.Thread(
                target=self._reconcile_loop, name="reconciler", daemon=True
            )
            self._thread.start()

    def _adopt_orphan_reloads(self) -> None:
        """接管上一进程已发出、回执未到的重载请求。

        这些请求（尤其是旧回退）随时可能改写文件/对外服务；重启后的核实
        必须先等它们落定，或至少知道它们未决，不能直接判定成功。
        """
        pending_fn = getattr(self.control, "unresolved_requests", None)
        if pending_fn is None:
            return
        try:
            pending = pending_fn()
        except Exception:
            log.exception("读取未决重载请求失败")
            return
        for token, age in pending:
            if age > self.cfg.stale_reload_age:
                log.warning("重启后发现长期未回执的重载请求，忽略：%s (%.0fs)", token, age)
                continue
            # 只有回退类重载的迟到结果可能把证书改回旧版本；恢复类与普通
            # 重载执行时读取的是当时的 live 文件，不会回带旧内容。
            kind = "rollback" if token.startswith("rollback-") else "reload"
            log.warning("重启后接管未回执的重载请求：%s (%.1fs)", token, age)
            with self._token_lock:
                self._pending_tokens[token] = {
                    "owner": -1,
                    "gen": self._write_gen,
                    "kind": kind,
                    # 让等待截止时间仍按原始请求时刻计算
                    "requested_at": time.monotonic() - age,
                    "resolved": False,
                    "receipt": None,
                }

    def shutdown(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=3)
        self.db.close()

    def _seed(self) -> None:
        """首次启动：生成演示 CA 与"旧证书"，作为版本 1 在用。"""
        ca_cert, ca_key = certutil.generate_ca()
        chain, key = certutil.generate_server_cert(
            self.cfg.site_domain, ca_cert, ca_key,
            days_valid=330, not_before_days_ago=300,
        )
        info = certutil.validate_upload(chain, key, self.cfg.site_domain)
        ca_dir = os.path.join(self.cfg.data_dir, "ca")
        os.makedirs(ca_dir, exist_ok=True)
        with open(os.path.join(ca_dir, "ca.pem"), "wb") as f:
            f.write(ca_cert)
        with open(os.path.join(ca_dir, "ca-key.pem"), "wb") as f:
            f.write(ca_key)
        with self.db.txn() as c:
            cur = c.execute(
                "INSERT INTO versions (fingerprint, domain, subject, san, not_before,"
                " not_after, cert_pem, key_pem, status, created_at)"
                " VALUES (?,?,?,?,?,?,?,?,?,?)",
                (
                    info.fingerprint, self.cfg.site_domain, info.subject,
                    ",".join(info.san), info.not_before.isoformat(),
                    info.not_after.isoformat(), chain.decode(), key.decode(),
                    "active", now_iso(),
                ),
            )
            vid = cur.lastrowid
            c.execute("UPDATE state SET active_version_id=?", (vid,))
        self._write_live(self._version(vid))
        log.info("seeded demo cert version #%s fp=%s", vid, info.fingerprint[:16])

    # ------------------------------------------------------------ 上传

    def upload(self, chain_pem: bytes, key_pem: bytes):
        info = certutil.validate_upload(chain_pem, key_pem, self.cfg.site_domain)
        with self.db.txn() as c:
            row = c.execute(
                "SELECT * FROM versions WHERE fingerprint=?", (info.fingerprint,)
            ).fetchone()
            if row:
                return dict(row), False
            cur = c.execute(
                "INSERT INTO versions (fingerprint, domain, subject, san, not_before,"
                " not_after, cert_pem, key_pem, status, created_at)"
                " VALUES (?,?,?,?,?,?,?,?,?,?)",
                (
                    info.fingerprint, self.cfg.site_domain, info.subject,
                    ",".join(info.san), info.not_before.isoformat(),
                    info.not_after.isoformat(), chain_pem.decode(), key_pem.decode(),
                    "candidate", now_iso(),
                ),
            )
            vid = cur.lastrowid
            row = c.execute("SELECT * FROM versions WHERE id=?", (vid,)).fetchone()
            return dict(row), True

    # ------------------------------------------------------------ 启用

    def activate(self, version_id: int, base_version_id: int) -> dict:
        """提交启用。比较-交换通过后在请求线程内同步执行，结果有界。"""
        with self.db.txn() as c:
            st = c.execute("SELECT * FROM state WHERE id=1").fetchone()
            if st["active_version_id"] != base_version_id:
                raise Conflict(
                    f"页面版号已过期（当前在用版本 #{st['active_version_id']}），"
                    "请刷新后重试"
                )
            inflight = c.execute(
                "SELECT seq FROM ops WHERE state='activating'"
            ).fetchone()
            if inflight:
                raise Conflict(f"另一启用操作 (#{inflight['seq']}) 正在进行，请稍后")
            v = c.execute("SELECT * FROM versions WHERE id=?", (version_id,)).fetchone()
            if not v:
                raise NotFound(f"版本 #{version_id} 不存在")
            if v["id"] == st["active_version_id"]:
                raise BadRequest(f"版本 #{version_id} 当前已在用")
            if v["status"] not in ("candidate", "failed", "superseded"):
                raise BadRequest(f"版本 #{version_id} 状态为 {v['status']}，不可启用")
            # 新操作取代所有仍待核实的旧操作
            c.execute(
                "UPDATE ops SET state='superseded',"
                " detail=COALESCE(detail,'') || ' 被更新的操作取代', updated_at=?"
                " WHERE state='pending_verify'",
                (now_iso(),),
            )
            # 被取代的旧操作不再需要"等旧回执后重跑"
            with self._token_lock:
                self._drain_retry.clear()
            # 旧操作的"恢复后再核实"标记同样作废：新操作会自行写目标证书
            with self._token_lock:
                self._recovery_needed.clear()
            seq = st["current_op_seq"] + 1
            ts = now_iso()
            c.execute(
                "INSERT INTO ops (seq, version_id, base_version_id, state, detail,"
                " created_at, updated_at) VALUES (?,?,?,?,?,?,?)",
                (seq, version_id, base_version_id, "activating", None, ts, ts),
            )
            c.execute("UPDATE state SET current_op_seq=?", (seq,))
        try:
            self._execute(seq)
        except Exception as exc:  # 任何未预期异常都不得让操作悬空
            log.exception("activate op #%s failed unexpectedly", seq)
            self._mark_pending(seq, f"内部错误（{exc!r}），待核实")
        return self.get_op(seq)

    def _execute(self, seq: int) -> None:
        op = self.get_op(seq)
        target = self._version(op["version_id"])
        base = self._version(op["base_version_id"])
        # 0. 先处理"迟到的旧回退"：等待启动前已发出、尚未回收的重载回执。
        #    旧回退可能改写文件后重载；未等它落定就探测，得到的握手结果
        #    随时可能被覆盖，不能据此判定成功。
        if not self._drain_prior_reloads(seq):
            # 旧回退仍可能在稍后改写文件：本次不写盘、不判成功，保持待核实。
            # 记录待重试，等旧回执落定后由后台重跑本次启用。
            with self._token_lock:
                self._drain_retry.add(seq)
            self._mark_pending(
                seq, "先前操作的重载回执未决，无法确定新连接不会被旧回退覆盖，待核实"
            )
            return
        # 1. 落盘新证书文件（原子替换；写前确认自己仍是最新操作）
        gen = self._write_live_guarded(target, owner_seq=seq)
        if gen is None:
            self._mark_superseded(seq)
            return
        if self.cfg.activate_delay_after_write:  # 测试钩子：制造崩溃窗口
            time.sleep(self.cfg.activate_delay_after_write)
        # 2. 请求 Nginx 平滑重载并等回执（写入代次与令牌绑定）
        token, token_gen = self._request_reload_tracked(
            f"{seq}-{uuid.uuid4().hex[:8]}", owner_seq=seq, kind="reload"
        )
        if token is None:
            self._mark_superseded(seq)
            return
        receipt = self.control.wait_receipt(token, self.cfg.receipt_timeout)
        self._resolve_token(token, receipt)
        # 3. 以新建 TLS 连接的实际握手结果为准
        served = None
        deadline = time.monotonic() + self.cfg.verify_timeout
        while time.monotonic() < deadline:
            try:
                served = self.control.probe()
            except ProbeError:
                served = None
            if served == target["fingerprint"]:
                break
            if receipt is not None and receipt.startswith("fail"):
                break
            time.sleep(self.cfg.probe_interval)
        # 4. 判定前在 I/O 锁内确认：仍是最新操作、live 文件仍是本次写入、
        #    且回执之后没有别的操作改写文件。否则任何结论都可能被覆盖。
        with self._io_lock:
            if not self._still_owner(seq):
                self._mark_superseded(seq)
                return
            if self._write_gen != token_gen:
                with self._token_lock:
                    self._recovery_needed.add(seq)
                self._mark_pending(
                    seq, "重载期间证书文件被其他操作改写，本次握手结果不可用，待核实"
                )
                return
            live_fp = self.live_fingerprint()
            if served == target["fingerprint"] and live_fp != target["fingerprint"]:
                # 握手拿到新证书，但落盘文件已不是它：下次重载就会改回去。
                with self._token_lock:
                    self._recovery_needed.add(seq)
                self._mark_pending(
                    seq, "握手返回新证书但证书文件已被改写，恢复正在用版本后需再核实"
                )
                return
            if served == target["fingerprint"] and not self._unresolved_tokens(seq):
                self._finalize_success(seq, note="新 TLS 连接已返回新证书")
                return
            if served == target["fingerprint"]:
                # 仍有未落定的旧回退：其迟到结果可能覆盖本次握手，保持待核实，
                # 待回执落定后由后台再以新建握手确认。
                self._mark_pending(
                    seq, "握手返回新证书但存在未落定的先前重载，结果可能被覆盖，待核实"
                )
                return
        if receipt is not None and receipt.startswith("fail"):
            if self._rollback_files(base, owner_seq=seq):
                self._finalize_fail(seq, f"Nginx 重载失败（{receipt}），已沿用旧证书")
            else:
                self._mark_superseded(seq)
            return
        if receipt == "ok" and served is not None:
            if self._rollback_files(base, owner_seq=seq):
                self._finalize_fail(
                    seq, "重载后新连接仍返回旧证书，已回退并保持旧证书在用"
                )
            else:
                self._mark_superseded(seq)
            return
        # 回执不明或无法探测 -> 待核实
        reason = "重载回执超时" if receipt is None else "无法建立新连接核实"
        self._mark_pending(seq, f"{reason}，待核实")

    # ------------------------------------------------------------ 终态落库

    def _invalidate_probe(self) -> None:
        self._probe_cache = (0.0, None)

    def _next_write_gen(self) -> int:
        with self._gen_lock:
            self._write_gen += 1
            return self._write_gen

    def _register_token(
        self, token: str, owner_seq: int, gen: int, kind: str = "rollback"
    ) -> None:
        """登记已发出的重载请求。

        kind="rollback" 表示可能把证书改回旧版本的回退/恢复类重载：这类
        回执未落定前，新的启用结论可能被其迟到结果覆盖，必须等待。
        kind="reload" 为普通启用重载，其迟到执行读取的是当时的 live 文件，
        不会把证书改回旧内容（真实 nginx 语义），不作为阻塞项。
        """
        with self._token_lock:
            self._pending_tokens[token] = {
                "owner": owner_seq,
                "gen": gen,
                "kind": kind,
                "requested_at": time.monotonic(),
                "resolved": False,
                "receipt": None,
            }

    def _resolve_token(self, token: str, receipt: str | None = None) -> None:
        """记录回执。

        回退类重载若回执超时（None），不能当作"已落定"：watcher 可能稍后
        才真正执行，其迟到结果仍会覆盖新启用。这类令牌保持未决，直到收到
        回执或超过 stale_reload_age。
        """
        with self._token_lock:
            entry = self._pending_tokens.get(token)
            if entry is None:
                return
            if receipt is None and entry.get("kind", "rollback") == "rollback":
                return
            entry["resolved"] = True
            entry["receipt"] = receipt

    def _unresolved_tokens(self, owner_seq: int | None) -> list[str]:
        """列出未落定、可能把证书改回旧版本的重载令牌（不属于 owner_seq）。

        只统计"回退/恢复"类重载：它们读取的不是当时的 live 文件，而是明确
        的旧版本内容，迟到结果会覆盖新启用的判定。超过 stale_reload_age
        仍无回执的令牌视为 watcher 已失效，不再等待并记录告警。
        """
        now = time.monotonic()
        stale: list[str] = []
        result: list[str] = []
        with self._token_lock:
            for tok, e in list(self._pending_tokens.items()):
                if e["resolved"]:
                    if now - e["requested_at"] > 300:
                        self._pending_tokens.pop(tok, None)
                    continue
                if e.get("kind", "rollback") != "rollback":
                    continue
                if now - e["requested_at"] > self.cfg.stale_reload_age:
                    stale.append(tok)
                    self._pending_tokens.pop(tok, None)
                    continue
                if e["owner"] != owner_seq:
                    result.append(tok)
        if stale:
            log.warning("重载回执长期未到，视为失效：%s", stale)
        return result

    def _drain_prior_reloads(self, owner_seq: int) -> bool:
        """等待更早操作已发出的重载回执落定。

        旧回退的握手/重载可能在本操作写文件之后才完成，其迟到结果会覆盖
        本操作的判定。只有确认这些回执都已返回，后续握手结果才可信。
        返回 False 表示仍无法确定，调用方必须保持"待核实"。
        """
        deadline = time.monotonic() + self.cfg.late_reload_wait
        while True:
            pending = self._unresolved_tokens(owner_seq)
            if not pending:
                return True
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                log.warning("仍有未落定的旧重载回执：%s", pending)
                return False
            token = pending[0]
            receipt = self.control.wait_receipt(token, min(remaining, 0.5))
            if receipt is not None:
                self._resolve_token(token, receipt)

    def _may_write(self, owner_seq: int | None) -> bool:
        """在 I/O 锁内调用：判断当前是否仍可改写 live 文件。

        owner_seq 为 None 表示后台一致性修复：仅在没有启用中操作时允许。
        """
        with self.db.txn() as c:
            if owner_seq is None:
                inflight = c.execute(
                    "SELECT seq FROM ops WHERE state='activating'"
                ).fetchone()
                return inflight is None
        return self._still_owner(owner_seq)

    def _still_owner(self, seq: int) -> bool:
        with self.db.txn() as c:
            st = c.execute("SELECT * FROM state WHERE id=1").fetchone()
            op = self._op(c, seq)
            return bool(
                op
                and op["state"] in ("activating", "pending_verify")
                and st["current_op_seq"] == seq
            )

    def _mark_superseded(self, seq: int) -> None:
        with self._token_lock:
            self._drain_retry.discard(seq)
        with self.db.txn() as c:
            op = self._op(c, seq)
            if not op or op["state"] not in ("activating", "pending_verify"):
                return
            c.execute(
                "UPDATE ops SET state='superseded', detail=?, updated_at=? WHERE seq=?",
                ("已被更新的操作取代，本操作不再回写文件或触发回退", now_iso(), seq),
            )
        self._invalidate_probe()

    def _finalize_success(self, seq: int, note: str = "") -> None:
        with self.db.txn() as c:
            op = self._op(c, seq)
            if not op or op["state"] not in ("activating", "pending_verify"):
                return
            st = c.execute("SELECT * FROM state WHERE id=1").fetchone()
            if st["current_op_seq"] != seq:
                c.execute(
                    "UPDATE ops SET state='superseded', detail=?, updated_at=?"
                    " WHERE seq=?",
                    ("已有更新的操作，本操作结果作废", now_iso(), seq),
                )
                return
            c.execute("UPDATE versions SET status='superseded' WHERE status='active'")
            c.execute(
                "UPDATE versions SET status='active' WHERE id=?", (op["version_id"],)
            )
            c.execute(
                "UPDATE state SET active_version_id=?", (op["version_id"],)
            )
            c.execute(
                "UPDATE ops SET state='succeeded', detail=?, updated_at=? WHERE seq=?",
                (note or "启用成功", now_iso(), seq),
            )
        self._invalidate_probe()

    def _finalize_fail(self, seq: int, reason: str) -> None:
        with self.db.txn() as c:
            op = self._op(c, seq)
            if not op or op["state"] not in ("activating", "pending_verify"):
                return
            st = c.execute("SELECT * FROM state WHERE id=1").fetchone()
            if st["current_op_seq"] != seq:
                c.execute(
                    "UPDATE ops SET state='superseded', detail=?, updated_at=?"
                    " WHERE seq=?",
                    ("已有更新的操作，本操作结果作废", now_iso(), seq),
                )
                return
            c.execute(
                "UPDATE ops SET state='failed', detail=?, updated_at=? WHERE seq=?",
                (reason, now_iso(), seq),
            )
            c.execute(
                "UPDATE versions SET status='failed' WHERE id=? AND status!='active'",
                (op["version_id"],),
            )
        self._invalidate_probe()

    def _mark_pending(self, seq: int, detail: str) -> None:
        with self.db.txn() as c:
            op = self._op(c, seq)
            if not op or op["state"] != "activating":
                return
            st = c.execute("SELECT * FROM state WHERE id=1").fetchone()
            if st["current_op_seq"] != seq:
                c.execute(
                    "UPDATE ops SET state='superseded', detail=?, updated_at=?"
                    " WHERE seq=?",
                    ("已有更新的操作，本操作结果作废", now_iso(), seq),
                )
                return
            c.execute(
                "UPDATE ops SET state='pending_verify', detail=?, updated_at=?"
                " WHERE seq=?",
                (detail, now_iso(), seq),
            )

    # ------------------------------------------------------------ 后台核实

    def _reconcile_loop(self) -> None:
        while not self._stop.wait(self._reconcile_poll):
            try:
                self.reconcile_once()
            except Exception:
                log.exception("reconcile tick failed")

    def reconcile_op(self, seq: int) -> None:
        """核实单个待核实操作：确认成功，或在宽限期后回退。

        判定必须以防"旧回退覆盖新启用"为前提：
        - 归属（current_op_seq）在探测前后都要成立；
        - 只要还有未落定的旧重载令牌，握手结果就可能被覆盖，不得判成功；
        - 回退写文件在 I/O 锁内重新校验归属，已取代则什么都不做。
        """
        op = self.get_op(seq)
        if op["state"] != "pending_verify":
            return
        with self._token_lock:
            needs_recovery = seq in self._recovery_needed
            self._recovery_needed.discard(seq)
        if needs_recovery:
            # 迟到旧回退改写了文件/对外服务：旧回退已落定，重跑本次启用
            # （写目标证书 -> 重载 -> 新建握手确认）；若已被取代则只恢复在用版本。
            if self._unresolved_tokens(seq):
                return  # 仍可能有别的旧回退，继续等
            if self._still_owner(seq):
                self._resume_drained_activation(seq)
                return
            try:
                served_now = self.control.probe()
            except ProbeError:
                served_now = None
            if served_now is not None:
                self._ensure_live_matches_active(served_now)
            return
        with self._token_lock:
            retry = seq in self._drain_retry
        if retry and self._unresolved_tokens(seq):
            # 旧回退回执仍未落定：保持待核实，且绝不能凭此刻的握手判成功。
            return
        if retry:
            with self._token_lock:
                self._drain_retry.discard(seq)
            # 仍未写盘：直接重跑启用，而不是拿旧握手结果下结论。
            if self.live_fingerprint() != self._version(op["version_id"])["fingerprint"]:
                self._resume_drained_activation(seq)
                return
        target = self._version(op["version_id"])
        try:
            served = self.control.probe()
        except ProbeError:
            return  # 无法确认，保持待核实
        created = dt.datetime.fromisoformat(op["created_at"])
        age = (dt.datetime.now(UTC) - created).total_seconds()
        if served == target["fingerprint"]:
            if self._unresolved_tokens(seq):
                return  # 迟到的旧回退仍可能覆盖，继续待核实
            if self.live_fingerprint() != target["fingerprint"]:
                # 握手是新证书，但落盘文件已被旧回退改回：下次重载会改回去，
                # 不能判成功。先恢复正在用版本，再重新核实。
                with self._token_lock:
                    self._recovery_needed.add(seq)
                return
            self._finalize_success(seq, note="核实：新 TLS 连接已返回新证书")
            return
        if age <= self.cfg.pending_ttl:
            return
        if self.cfg.reconcile_delay_before_rollback:
            # 测试钩子：模拟"核实已读到原证书、但回退动作被拖到新启用之后"。
            time.sleep(self.cfg.reconcile_delay_before_rollback)
        with self.db.txn() as c:
            st = c.execute("SELECT * FROM state WHERE id=1").fetchone()
            active_id = st["active_version_id"]
        active = self._version(active_id)
        if not self._rollback_files(active, owner_seq=seq):
            self._mark_superseded(seq)
            return
        self._finalize_fail(seq, "超过待核实时限仍未生效，已回退到可确认的在用版本")
        # 回退本身可能迟到/失败：只有新建握手确实回到可确认版本才结束待核实，
        # 否则重新保持待核实，继续由后台跟进。
        confirmed = self._probe_with_grace(
            min(self.cfg.verify_timeout, 3.0)
        )
        if confirmed != active["fingerprint"]:
            self._keep_pending(seq, "已请求回退，但新建握手仍未回到可确认版本，待核实")

    def _keep_pending(self, seq: int, detail: str) -> None:
        """把本次核实中暂时判失败的操作重新置回待核实。"""
        with self.db.txn() as c:
            op = self._op(c, seq)
            if not op or op["state"] != "failed":
                return
            st = c.execute("SELECT * FROM state WHERE id=1").fetchone()
            if st["current_op_seq"] != seq:
                return
            c.execute(
                "UPDATE ops SET state='pending_verify', detail=?, updated_at=?"
                " WHERE seq=?",
                (detail, now_iso(), seq),
            )

    def _resume_drained_activation(self, seq: int) -> None:
        """旧回执已落定：重跑这次尚未写盘的启用。"""
        gen = self._write_live_guarded(self._version(self.get_op(seq)["version_id"]), seq)
        if gen is None:
            self._mark_superseded(seq)
            return
        target = self._version(self.get_op(seq)["version_id"])
        base = self._version(self.get_op(seq)["base_version_id"])
        token, token_gen = self._request_reload_tracked(
            f"{seq}-{uuid.uuid4().hex[:8]}", owner_seq=seq, kind="reload"
        )
        if token is None:
            self._mark_superseded(seq)
            return
        receipt = self.control.wait_receipt(token, self.cfg.receipt_timeout)
        self._resolve_token(token, receipt)
        served = None
        deadline = time.monotonic() + self.cfg.verify_timeout
        while time.monotonic() < deadline:
            try:
                served = self.control.probe()
            except ProbeError:
                served = None
            if served == target["fingerprint"]:
                break
            if receipt is not None and receipt.startswith("fail"):
                break
            time.sleep(self.cfg.probe_interval)
        with self._io_lock:
            if not self._still_owner(seq):
                self._mark_superseded(seq)
                return
            if (
                served == target["fingerprint"]
                and self._write_gen == token_gen
                and self.live_fingerprint() == target["fingerprint"]
                and not self._unresolved_tokens(seq)
            ):
                self._finalize_success(seq, note="旧回执落定后重试：新 TLS 连接已返回新证书")
                return
        if receipt is not None and receipt.startswith("fail"):
            if self._rollback_files(base, owner_seq=seq):
                self._finalize_fail(seq, f"Nginx 重载失败（{receipt}），已沿用旧证书")
            else:
                self._mark_superseded(seq)
            return
        if receipt == "ok" and served is not None:
            if self._rollback_files(base, owner_seq=seq):
                self._finalize_fail(seq, "重载后新连接仍返回旧证书，已回退并保持旧证书在用")
            else:
                self._mark_superseded(seq)
            return
        self._mark_pending(seq, "重试后回执不明/无法核实，待核实")

    def reconcile_once(self) -> None:
        with self.db.txn() as c:
            activating = c.execute(
                "SELECT COUNT(*) n FROM ops WHERE state='activating'"
            ).fetchone()["n"]
            if activating:
                return  # 前台请求线程 owns 启用中的操作
            op = c.execute(
                "SELECT * FROM ops WHERE state='pending_verify'"
                " ORDER BY seq DESC LIMIT 1"
            ).fetchone()
            st = c.execute("SELECT * FROM state WHERE id=1").fetchone()
        if op:
            if st["current_op_seq"] != op["seq"]:
                self._mark_superseded(op["seq"])
                return
            self.reconcile_op(op["seq"])
            return
        # 无在途操作：保持"文件/实测/在用"三者一致（限流）
        if time.monotonic() - self._last_restore < self.cfg.restore_interval:
            return
        try:
            served = self.control.probe()
        except ProbeError:
            return
        active = self._version(st["active_version_id"])
        if active and served != active["fingerprint"]:
            self._last_restore = time.monotonic()
            self._ensure_live_matches_active(served)

    # ------------------------------------------------------------ 恢复辅助

    def _recover_to_confirmable(self, served: str) -> dict | None:
        """按 Nginx 实际服务的指纹，把在用版本恢复到可确认的版本。

        返回恢复后（或已一致）的在用版本；若因并发操作而未能写入，返回 None。
        """
        with self.db.txn() as c:
            known = c.execute(
                "SELECT * FROM versions WHERE fingerprint=?", (served,)
            ).fetchone()
            if known and known["status"] != "active":
                c.execute(
                    "UPDATE versions SET status='superseded' WHERE status='active'"
                )
                c.execute(
                    "UPDATE versions SET status='active' WHERE id=?", (known["id"],)
                )
                c.execute("UPDATE state SET active_version_id=?", (known["id"],))
            active = c.execute(
                "SELECT v.* FROM state s JOIN versions v"
                " ON v.id=s.active_version_id WHERE s.id=1"
            ).fetchone()
        if active:
            active = dict(active)
            if (
                self._write_live_guarded(active, owner_seq=None) is None
                and self.live_fingerprint() != active["fingerprint"]
            ):
                return None
            self._request_reload_tracked(
                f"recover-{uuid.uuid4().hex[:8]}", owner_seq=None
            )
            self._invalidate_probe()
        return active if active else None

    def _ensure_live_matches_active(self, served: str | None) -> None:
        with self.db.txn() as c:
            active = c.execute(
                "SELECT v.* FROM state s JOIN versions v"
                " ON v.id=s.active_version_id WHERE s.id=1"
            ).fetchone()
        if not active:
            return
        live_fp = self.live_fingerprint()
        if live_fp != active["fingerprint"]:
            log.warning("live 文件与在用版本不一致，恢复为版本 #%s", active["id"])
            if self._write_live_guarded(dict(active), owner_seq=None) is None:
                return
            self._request_reload_tracked(
                f"restore-{uuid.uuid4().hex[:8]}", owner_seq=None
            )
        elif served is not None and served != active["fingerprint"]:
            log.warning("Nginx 服务指纹与在用版本不一致，重新触发重载")
            self._request_reload_tracked(
                f"restore-{uuid.uuid4().hex[:8]}", owner_seq=None
            )

    def _rollback_files(self, version: dict, owner_seq: int) -> bool:
        """把 live 文件回退到指定版本并触发重载。

        返回 False 表示本操作已被取代，未做任何改动（调用方不得再判终态）。
        整个写入+重载在 I/O 锁内完成，避免与新启用穿插后被误读为"新证书"。
        """
        if version is None:
            return False
        with self._io_lock:
            if not self._may_write(owner_seq):
                log.info("op #%s 已被取代，跳过回退写文件/重载", owner_seq)
                return False
            self._write_live(version)
            self._request_reload_tracked(
                f"rollback-{uuid.uuid4().hex[:8]}", owner_seq=owner_seq, wait=True
            )
        self._invalidate_probe()
        return True

    # ------------------------------------------------------------ 查询

    def get_op(self, seq: int) -> dict:
        with self.db.txn() as c:
            row = self._op(c, seq)
            if not row:
                raise NotFound(f"操作 #{seq} 不存在")
            return dict(row)

    def status(self, probe: bool = True) -> dict:
        with self.db.txn() as c:
            st = c.execute("SELECT * FROM state WHERE id=1").fetchone()
            versions = [
                dict(r)
                for r in c.execute(
                    "SELECT id, fingerprint, domain, subject, san, not_before,"
                    " not_after, status, created_at FROM versions ORDER BY id"
                ).fetchall()
            ]
            ops = [
                dict(r)
                for r in c.execute(
                    "SELECT * FROM ops ORDER BY seq DESC LIMIT 10"
                ).fetchall()
            ]
        active = next(
            (v for v in versions if v["id"] == st["active_version_id"]), None
        )
        served = self.probe_cached() if probe else None
        if served is None:
            consistency = "unknown"
        elif active and served == active["fingerprint"]:
            consistency = "match"
        else:
            consistency = "mismatch"
        return {
            "domain": self.cfg.site_domain,
            "served_fingerprint": served,
            "consistency": consistency,
            "active_version_id": st["active_version_id"],
            "current_op_seq": st["current_op_seq"],
            "active": active,
            "versions": versions,
            "ops": ops,
            "latest_op": ops[0] if ops else None,
        }

    def probe_cached(self, ttl: float = 2.0) -> str | None:
        ts, val = self._probe_cache
        if time.monotonic() - ts < ttl:
            return val
        try:
            val = self.control.probe()
        except ProbeError:
            val = None
        self._probe_cache = (time.monotonic(), val)
        return val

    def live_fingerprint(self) -> str | None:
        try:
            with open(os.path.join(self.cfg.live_dir, "fullchain.pem"), "rb") as f:
                return certutil.fingerprint_pem_chain(f.read())
        except (OSError, certutil.CertError):
            return None

    # ------------------------------------------------------------ 内部

    def _version(self, vid: int) -> dict | None:
        if vid is None:
            return None
        with self.db.txn() as c:
            row = c.execute("SELECT * FROM versions WHERE id=?", (vid,)).fetchone()
            return dict(row) if row else None

    @staticmethod
    def _op(c, seq: int):
        return c.execute("SELECT * FROM ops WHERE seq=?", (seq,)).fetchone()

    @staticmethod
    def _latest_inflight(c):
        return c.execute(
            "SELECT * FROM ops WHERE state IN ('activating','pending_verify')"
            " ORDER BY seq DESC LIMIT 1"
        ).fetchone()

    def _write_live(self, version: dict) -> None:
        """原子写入 live 证书文件（先写临时文件再 rename）。

        每次写入都会推进代次：正在核实的操作据此发现"我探测之后文件又被
        别人改写"，从而不会把可能被覆盖的握手结果判为成功。
        """
        for name, content in (
            ("fullchain.pem", version["cert_pem"]),
            ("privkey.pem", version["key_pem"]),
        ):
            tmp = os.path.join(self.cfg.live_dir, f".{name}.tmp")
            dst = os.path.join(self.cfg.live_dir, name)
            with open(tmp, "w", encoding="utf-8") as f:
                f.write(content)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, dst)
        self._next_write_gen()
        self._invalidate_probe()

    def _write_live_guarded(self, version: dict, owner_seq: int | None) -> int | None:
        """在 I/O 锁内确认归属后写文件，返回本次写入代次；被取代则返回 None。

        归属检查与写入必须原子：否则检查通过后、写入前，新操作可能已经
        完成并置为成功，旧操作再写文件就会把在用证书改回去。
        """
        with self._io_lock:
            if not self._may_write(owner_seq):
                return None
            self._write_live(version)
            with self._gen_lock:
                return self._write_gen

    def _request_reload_tracked(
        self,
        token: str,
        owner_seq: int | None,
        wait: bool = False,
        kind: str = "rollback",
    ) -> tuple[str | None, int]:
        """在 I/O 锁内登记并发出重载请求；返回 (令牌, 当前写入代次)。

        令牌在发出前登记，其他线程才能识别"已发出但回执未到"的旧回退。
        kind="reload" 的普通启用重载不阻塞他人；回退/恢复类
        （kind="rollback"）必须等到回执落定或显式接管。
        """
        with self._io_lock:
            if not self._may_write(owner_seq):
                return None, self._write_gen
            with self._gen_lock:
                gen = self._write_gen
            self._register_token(
                token, owner_seq if owner_seq is not None else -1, gen, kind
            )
            try:
                self.control.request_reload(token)
            except Exception:
                self._resolve_token(token)
                raise
        if wait:
            receipt = self.control.wait_receipt(token, 3.0)  # 尽力而为
            self._resolve_token(token, receipt)
        elif owner_seq is None:
            self._resolve_token(token)
        return token, gen

    def _probe_with_grace(self, timeout: float) -> str | None:
        deadline = time.monotonic() + timeout
        while True:
            try:
                return self.control.probe()
            except ProbeError:
                if time.monotonic() >= deadline:
                    return None
                time.sleep(0.5)
