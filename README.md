# 单站点 TLS 证书启用管理

机房运维在网页上为内网站点（演示域名 `demo.internal`）替换 TLS 证书。
启用结果以 **Nginx 新建 TLS 连接实际返回的证书指纹** 为唯一判据。

## 架构

```
┌────────────┐   共享卷 certs/live    ┌──────────────────────────┐
│  web       │ ───────────────────▶ │  nginx（站点 :443）       │
│  FastAPI   │   共享卷 reload       │  + reload-watcher.sh     │
│  + SQLite  │ ◀─────────────────── │  （检测 REQUEST →        │
└────────────┘   REQUEST/RESULT 回执 │   nginx -t && -s reload） │
      │ 新建 TLS 连接探测指纹         └──────────────────────────┘
      └──────────────────────────────────────▶
```

- **web**（`web/`）：FastAPI + SQLite。上传校验、启用编排、并发控制、
  重启对账、后台核实循环。管理页 `:8080`。
- **nginx**（`nginx/`）：提供 TLS 站点；旁挂 watcher 脚本按文件令牌执行
  `nginx -t && nginx -s reload`（平滑重载，旧连接自然完成）并写回执。

## 运行

```bash
docker compose up --build
# 管理页  http://localhost:8080
# 站点    https://localhost:8443  （建议 /etc/hosts 加 127.0.0.1 demo.internal）
```

首次启动自动生成演示 CA 与"旧证书"（版本 #1，在用）。
签发一张演示新证书用于上传：

```bash
# Docker：在容器内签发到共享数据卷（/data 已挂载 webdata 卷）
docker compose run --rm --no-deps --entrypoint python web -c "
from app import certutil; import os
d = os.environ['DATA_DIR']
chain, key = certutil.generate_server_cert('demo.internal',
    open(d + '/ca/ca.pem', 'rb').read(), open(d + '/ca/ca-key.pem', 'rb').read())
open('/tmp/new-chain.pem', 'wb').write(chain)
open('/tmp/new-key.pem', 'wb').write(key)
"
docker compose cp web:/tmp/new-chain.pem /tmp/new-chain.pem
docker compose cp web:/tmp/new-key.pem /tmp/new-key.pem

# 无 Docker 的本地栈
python3 scripts/make_cert.py --data-dir /tmp/certops-local/data --out-dir /tmp/newcert
```

随后在管理页上传证书链与对应私钥。生产环境直接上传真实 CA 签发的证书链
与未加密私钥即可。

无 Docker 时本地验证：`bash scripts/local_stack.sh up`（需 nginx 二进制，
见 `NGINX_BIN` 环境变量）。

## 关键规则实现

| 需求 | 实现 |
| --- | --- |
| 上传校验 | `certutil.validate_upload`：密钥匹配（公钥 DER 对比）、域名（SAN/CN，含单层通配）、有效期、链逐级签发验证 |
| 页面所见版号 | 启用表单携带 `base_version_id`；`BEGIN IMMEDIATE` 事务内比较-交换，不一致即 409「页面版号已过期」 |
| 并发/重复提交 | 同一事务内拒绝已存在 `activating` 操作；重复提交因版号失效被拒；上传按指纹去重 |
| 启用成功判据 | 仅当新建 TLS 连接返回新证书指纹才置 `succeeded` |
| 重载失败 | 回执 `fail` → 文件回滚为旧证书并保持旧版本在用 |
| 回执不明/重启 | 操作置 `pending_verify`（页面显示"待核实"）；后台核实循环以新建 TLS 握手确认或超时回退；进程重启时按 Nginx 实际服务指纹对账，恢复到可确认的在用版本，并对恢复结果再做新建握手确认，确认不了保持待核实 |
| 交接竞态（旧核实 vs 新启用） | 见下节；已被取代的核实不写文件、不触发回退；旧回退已发出时新启用等待其迟到结果，绝不凭可能被覆盖的握手判成功 |
| 旧操作不覆盖新提交 | 任何落库/写文件前检查 `current_op_seq`；新操作创建时把待核实旧操作置 `superseded` |
| 已有连接 | nginx 平滑重载，旧 worker 服务完旧连接再退出 |

## 交接竞态的处理

事故形态：启用 A 回执超时进入待核实；后台核实读到"原证书"；期间启用 B
成功；旧核实随后仍回退文件并重载，页面显示 B 在用而客户端拿到原证书。

实现上的约束（`web/app/service.py`）：

- **I/O 串行化**：写 live 文件、请求重载、登记令牌都在 `_io_lock` 内完成，
  写入代次 `_write_gen` 随之推进；判定成功前在锁内复核"自己仍是最新操作
  (`current_op_seq`)、文件仍是本次写入、live 文件与握手一致"。
- **已取代即无操作**：`_rollback_files` 先校验归属，旧核实被新操作取代后
  直接返回，不写文件、不发回退重载。
- **迟到结果不可忽略**：回退/恢复类重载令牌登记为未决；新启用执行前
  `_drain_prior_reloads` 等待其落定，等不到就保持待核实、不写盘，待回执
  落定后由后台重跑该次启用（`_resume_drained_activation`）。
- **重启后的孤儿请求**：从 `RELOAD/REQUEST` 与 `RESULT` 对账，接管上一进程
  已发出、未回执的重载，同样先等待再核实。
- **以握手为准**：只有新建 TLS 连接返回目标证书、且 live 文件一致、没有
  未决旧回退时才置 `succeeded`；否则保持待核实并继续跟进。回退若未获
  握手确认，操作重新回到待核实而不是结束。

## 验证

```bash
cd web && python3 -m pytest tests/ -q          # 30 项单元/集成测试
bash scripts/local_stack.sh up && python3 scripts/e2e_check.py   # 19 项真实端到端
bash scripts/interrupt_check.sh                # 16 项崩溃/中断恢复实测（含重启时旧回退未落定）
# 交接竞态实测（按脚本头部提示的参数起栈）
PENDING_TTL=3 RECEIPT_TIMEOUT=1 VERIFY_TIMEOUT=2 LATE_RELOAD_WAIT=0.5 \
  RECONCILE_DELAY_BEFORE_ROLLBACK=6 STALE_RELOAD_AGE=60 \
  bash scripts/local_stack.sh up && python3 scripts/handover_check.py  # 19 项
```

## 说明与限制

- 单实例管理进程（SQLite + 进程内锁），不适用于多副本部署。
- 演示用 CA 私钥存于数据目录 `ca/`，仅为签发演示证书；生产应上传外部签发证书。
- nginx 与 web 之间经共享卷文件通信，回执超时（默认 6s）即视为"回执不明"。
- 交接竞态以单实例为前提：进程内的 I/O 锁与令牌表用于串行化写盘/回退。
  多副本部署需改用跨实例的分布式锁与共享操作状态。
