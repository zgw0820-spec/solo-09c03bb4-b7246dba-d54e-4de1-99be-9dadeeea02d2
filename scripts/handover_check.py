#!/usr/bin/env python3
"""交接竞态实测（真实 nginx + watcher + FastAPI）。

复现值班员遇到的事故：
  1. 启用 A 后回执超时 -> 待核实；
  2. 旧核实进行中（已通过新建握手读到"原证书"）；
  3. 另一笔启用 B 成功；
  4. 旧核实继续回退文件并重载 —— 曾导致页面显示 B 在用、客户端拿到原证书。

验证修复后：
  - 已被取代的核实不得回写文件或触发回退（场景 2）；
  - 旧回退若已发出，新启用必须等其迟到结果，不能把可能被覆盖的握手判成功（场景 1）；
  - 回执不明保持待核实，最终以新建 TLS 握手确认实际在用版本。

使用（默认参数即按本脚本需要启动本地栈）：
  PENDING_TTL=3 RECEIPT_TIMEOUT=1 VERIFY_TIMEOUT=2 LATE_RELOAD_WAIT=0.5 \\
  RECONCILE_DELAY_BEFORE_ROLLBACK=6 STALE_RELOAD_AGE=60 \\
  bash scripts/local_stack.sh up
  python3 scripts/handover_check.py
"""
import json
import os
import subprocess
import sys
import threading
import time
import urllib.parse
import urllib.request

WEB = os.environ.get("WEB", "http://127.0.0.1:8080")
TLS_PORT = int(os.environ.get("TLS_PORT", "8443"))
WORK = os.environ.get("LOCAL_WORK", "/tmp/certops-local")
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

passed, failed = [], []


def check(name, cond, extra=""):
    (passed if cond else failed).append(name)
    print(f"{'PASS' if cond else 'FAIL'}  {name} {extra}")


def api(path):
    with urllib.request.urlopen(WEB + path, timeout=15) as r:
        return json.load(r)


def post_form(path, data):
    body = urllib.parse.urlencode(data).encode()
    req = urllib.request.Request(
        WEB + path, data=body,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    try:
        with urllib.request.urlopen(req, timeout=180) as r:
            return r.status, json.load(r)
    except urllib.error.HTTPError as e:
        return e.code, json.load(e)


def upload(cert_dir):
    boundary = "----handover"
    body = b""
    for field, name in (("cert_file", "chain.pem"), ("key_file", "key.pem")):
        with open(os.path.join(cert_dir, name), "rb") as f:
            content = f.read()
        body += (
            f'--{boundary}\r\nContent-Disposition: form-data; name="{field}"; '
            f'filename="{name}"\r\nContent-Type: application/x-pem-file\r\n\r\n'
        ).encode() + content + b"\r\n"
    body += f"--{boundary}--\r\n".encode()
    req = urllib.request.Request(
        WEB + "/upload", data=body,
        headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
    )
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.load(r)["version_id"]


def make_cert(out_dir):
    subprocess.run(
        [sys.executable, os.path.join(ROOT, "scripts", "make_cert.py"),
         "--data-dir", f"{WORK}/data", "--out-dir", out_dir],
        check=True, capture_output=True,
    )
    out = subprocess.run(
        ["openssl", "x509", "-in", f"{out_dir}/chain.pem",
         "-fingerprint", "-sha256", "-noout"],
        capture_output=True, text=True, check=True,
    ).stdout.strip()
    return out.split("=")[1].replace(":", "").lower()


def openssl_fp():
    out = subprocess.run(
        ["openssl", "s_client", "-connect", f"127.0.0.1:{TLS_PORT}",
         "-servername", "demo.internal"],
        input="", capture_output=True, text=True, timeout=15,
    ).stdout
    cert = subprocess.run(
        ["openssl", "x509", "-fingerprint", "-sha256", "-noout"],
        input=out, capture_output=True, text=True,
    ).stdout.strip()
    return cert.split("=")[1].replace(":", "").lower()


def live_fp():
    out = subprocess.run(
        ["openssl", "x509", "-in", f"{WORK}/live/fullchain.pem",
         "-fingerprint", "-sha256", "-noout"],
        capture_output=True, text=True,
    ).stdout.strip()
    return out.split("=")[1].replace(":", "").lower()


def request_tokens():
    try:
        with open(f"{WORK}/reload/REQUEST", "r", encoding="utf-8") as f:
            return [ln.split(" ")[0] for ln in f if ln.strip()]
    except FileNotFoundError:
        return []


def ops_by_seq():
    return {op["seq"]: op for op in api("/api/status")["ops"]}


def watcher_pid():
    with open(f"{WORK}/run/watcher.pid", encoding="utf-8") as f:
        return int(f.read().strip())


def watcher_pause():
    pid = watcher_pid()
    os.kill(pid, 19)  # SIGSTOP：nginx 无法处理重载请求
    return pid


def watcher_resume(pid):
    os.kill(pid, 18)  # SIGCONT


def activate_async(version_id, base_version_id):
    result = {}

    def run():
        result["resp"] = post_form(
            "/activate", {"version_id": version_id, "base_version_id": base_version_id}
        )

    t = threading.Thread(target=run, daemon=True)
    t.start()
    return t, result


def wait_settled(seqs, timeout=90):
    deadline = time.time() + timeout
    while time.time() < deadline:
        ops = ops_by_seq()
        if all(ops.get(s, {}).get("state") not in ("activating", "pending_verify")
               for s in seqs):
            return ops
        time.sleep(0.5)
    return ops_by_seq()


def active_fp(st):
    for v in st["versions"]:
        if v["id"] == st["active_version_id"]:
            return v["fingerprint"]
    return None


def assert_page_matches_client(label):
    st = api("/api/status")
    served = openssl_fp()
    check(f"{label}：页面在用版本 = 客户端实际握手",
          served == active_fp(st),
          f"served={served[:12]} page={str(active_fp(st))[:12]}")
    check(f"{label}：live 文件 = 页面在用版本", live_fp() == active_fp(st))
    return st


def main():
    st = api("/api/status")
    if st["latest_op"] and st["latest_op"]["state"] in ("activating", "pending_verify"):
        print("前置条件：当前无在途操作（请先 down/up 重置本地栈）")
        return 2
    base = st["active_version_id"]

    # ================= 场景 1：旧回退已发出、回执迟到，B 在同期启用 =================
    print("--- 场景 1：旧回退已发出（回执未到），新启用 B ---")
    d_a, d_b = "/tmp/handover-a", "/tmp/handover-b"
    fp_a = make_cert(d_a)
    v_a = upload(d_a)
    fp_b = make_cert(d_b)
    v_b = upload(d_b)

    pid = watcher_pause()
    try:
        t_a, res_a = activate_async(v_a, base)
        t_a.join()
    finally:
        watcher_resume(pid)
    op_a = res_a["resp"][1]["op"]
    check("A 回执超时进入待核实", op_a["state"] == "pending_verify",
          f"state={op_a['state']}")

    # 冻结 watcher，让旧核实的回退请求停留在"已发出、无回执"状态
    pid = watcher_pause()
    before = len(request_tokens())
    rollback_seen = False
    deadline = time.time() + 60
    while time.time() < deadline:
        if any(t.startswith("rollback-") for t in request_tokens()[before:]):
            rollback_seen = True
            break
        if ops_by_seq()[op_a["seq"]]["state"] != "pending_verify":
            break
        time.sleep(0.05)
    check("旧核实已发出回退请求（回执未到）", rollback_seen)
    try:
        if rollback_seen:
            # B 与旧回退交错提交：旧回退可能稍后落定并覆盖握手结果
            st = api("/api/status")
            t_b, res_b = activate_async(v_b, st["active_version_id"])
            t_b.join()
            op_b = res_b["resp"][1]["op"]
            check("B 未凭可被覆盖的握手判成功",
                  op_b["state"] in ("pending_verify", "superseded"),
                  f"state={op_b['state']} detail={op_b.get('detail')}")
    finally:
        watcher_resume(pid)

    if rollback_seen:
        ops = wait_settled([op_b["seq"]])
        op_b_now = ops[op_b["seq"]]
        st = api("/api/status")
        if op_b_now["state"] == "succeeded":
            check("B 最终成功时握手确为 B 证书", openssl_fp() == fp_b)
            check("B 最终成功时 live 文件为 B 证书", live_fp() == fp_b)
            check("B 最终成功时页面在用为 B",
                  st["active_version_id"] == v_b)
        else:
            print(f"INFO  B 最终状态={op_b_now['state']}（{op_b_now.get('detail')}）")
        assert_page_matches_client("场景1")

    # ================= 场景 2：旧核实读到原证书，B 在回退动作前成功 =================
    print("--- 场景 2：旧核实已读到原证书，B 成功，旧核实再尝试回退 ---")
    d_c, d_d = "/tmp/handover-c", "/tmp/handover-d"
    fp_c = make_cert(d_c)
    v_c = upload(d_c)
    fp_d = make_cert(d_d)
    v_d = upload(d_d)

    # 冻结 watcher：C 的重载不被执行，旧核实探测到的仍是原证书；
    # 随后旧核实进入"探测之后、回退之前"的延迟窗口。
    pid = watcher_pause()
    try:
        t_c, res_c = activate_async(v_c, api("/api/status")["active_version_id"])
        t_c.join()
        op_c = res_c["resp"][1].get("op")
        check("C 回执超时进入待核实",
              bool(op_c) and op_c["state"] == "pending_verify",
              f"state={op_c and op_c.get('state')}")
        check("C 的目标证书尚未被 Nginx 服务",
              openssl_fp() != fp_c)
        # PENDING_TTL + 后台轮询后，旧核实已读到原证书并进入延迟窗口
        time.sleep(5)
        check("C 仍待核实（旧核实尚未回退）",
              ops_by_seq()[op_c["seq"]]["state"] == "pending_verify")
        # 恢复 watcher：先执行 C 的重载（对外已是 C 证书），模拟旧核实读到
        # 原证书后环境继续变化；紧接着启用 D。
        watcher_resume(pid)
        pid = None
        st = api("/api/status")
        code, resp = post_form(
            "/activate", {"version_id": v_d, "base_version_id": st["active_version_id"]}
        )
        op_d = resp.get("op", {})
        check("D 在旧核实回退前启用成功",
              code == 200 and op_d.get("state") == "succeeded",
              f"code={code} state={op_d.get('state')} detail={op_d.get('detail')}")
    finally:
        if pid is not None:
            watcher_resume(pid)

    # 等旧核实醒来并尝试回退：它已被取代，不得写文件/回退
    ops = wait_settled([op_c["seq"]], timeout=40)
    check("旧操作 C 已被取代", ops[op_c["seq"]]["state"] == "superseded",
          f"state={ops[op_c['seq']]['state']}")
    st = assert_page_matches_client("场景2")
    check("旧核实未把在用证书改回原证书",
          st["active_version_id"] == v_d and openssl_fp() == fp_d,
          f"active={st['active_version_id']} want={v_d}")
    check("旧核实未改写 live 文件", live_fp() == fp_d)

    # ================= 回归：交接后再次启用仍正常 =================
    print("--- 回归：交接后再次启用 ---")
    d_e = "/tmp/handover-e"
    fp_e = make_cert(d_e)
    v_e = upload(d_e)
    st = api("/api/status")
    code, resp = post_form(
        "/activate", {"version_id": v_e, "base_version_id": st["active_version_id"]}
    )
    op_e = resp.get("op", {})
    check("交接后新启用正常工作",
          code == 200 and op_e.get("state") == "succeeded",
          f"code={code} state={op_e.get('state')} detail={op_e.get('detail')}")
    check("交接后新建握手为证书 E", openssl_fp() == fp_e)

    print(f"\n== handover: {len(passed)} passed, {len(failed)} failed ==")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
