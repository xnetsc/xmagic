# xmagic：单端口多协议代理网关

一句话：**一个公共端口，凭协议首字节自动分发**，同时提供 SSH、SOCKS5、
HTTP 代理（CONNECT）、VLESS-WS、VLESS（裸 TCP）、Trojan-WS、裸 Shadowsocks；
节点自身还能作为下级节点去连多个上级（级联），入站会什么协议、出站就支持
什么协议；选哪个上级既可按用户分组，也可按目标域名/IP 用路由规则指定。

配置有两套功能完全一致的管理界面：**Web 管理后台**（Passkey 登录）和
**命令行**（节点上的 `users.py`、自己机器上的远程 CLI `xmagic.py`），
三者共用同一个身份库引擎，改谁都一样。

## 架构

```
                        公共端口 XRAY_PORT（唯一对外端口）
                                   │
                        sniff.py 首字节分发器（按内容分流）
        ┌──────────┬────────┬──────────┬────────────┬────────────────┐
     "SSH-" 横幅   0x05    CONNECT /    WebSocket     源形式 HTTP     其余字节
        │          │       绝对形式 HTTP   Upgrade      （浏览器）        │
       sshd      SOCKS5 入站   HTTP 入站   Xray fallback 复用器 ──┤   admin 后台
    (公钥认证)   (用户+密码)  (用户+密码)   ├ 路径命中 → VLESS-WS 后端（可多路径）
                                            ├ 路径命中 → Trojan-WS 后端（可多路径）
                                            └ 默认回落 → 裸 Shadowsocks 后端
                                   │
                        出口：直连，或上级池（按用户分组、负载均衡）
```

- 对外只有一个端口（分发器）。所有后端只听 127.0.0.1，admin 后台也不
  例外：它和代理共用这一个公网端口，分发器按内容分流——源形式 HTTP
  （浏览器打开后台）转给它，代理形式的流量转给代理（规则见架构节）。
- 身份只有一个事实源：**SQLite 数据库**（`data/users.db`）。Xray 的
  `config.json`、sshd 的 `authorized_keys` 都是从库里渲染出来的产物。
- 后端回环端口全部可由 env 覆盖（同机跑多个节点做测试时必须错开）。

## 协议与认证（入站 / 上级对称）

| 协议 | 客户端连入（入站） | 本节点连上级（出站） | 认证 |
| --- | --- | --- | --- |
| SSH | sshd，`ssh -D` 得 SOCKS5 | `ssh -N -D` 隧道映射为本地 SOCKS 出站 | 公钥（双向都是） |
| SOCKS5 | Xray socks 入站 | Xray socks 出站 | 用户名+密码（可空） |
| HTTP 代理 | Xray http 入站（CONNECT） | Xray http 出站 | Basic（可空） |
| VLESS-WS | WS 路径分发 → 后端 | 同左 | uuid |
| VLESS（裸 TCP） | 分发器 → 复用器主入站直达 | 同左 | uuid |
| Trojan-WS | WS 路径分发 → 后端 | 同左 | 密码 |
| Shadowsocks | 默认回落 → 后端 | 同左 | 每用户独立密码+method |

每个用户在库里是一套凭证：VLESS uuid、一个共享密码（Trojan / HTTP / SOCKS 共用）、
独立的 SS 密码、可选的 SSH 公钥。连上级时存的也是对方按同一模型签发的凭证——
**两段认证各管一段**：用户连本节点用本节点签发的凭证（在本节点终结）；本节点连
上级用上级签发的凭证（存在本节点的上级记录里）。同组用户在上级侧呈现为同一身份，
这是级联的固有语义；要在上级侧按用户区分，就给用户单独分组、单独配上级记录。

## 管理界面一：Web 后台（Passkey）

- 后台是部署单元的一部分（`admin` 容器），不存在"宿主机上跑脚本"的依赖；
  它与网关共用 `data/` 卷，每次修改自动重新渲染，并通过 Docker socket
  重启 xray / sshd 生效（没挂 socket 时只渲染，界面会如实提示）。
- **只支持一个管理员账号，且只能用 Passkey**：第一个注册的 Passkey 即管理员，
  注册随即永久关闭；不支持密码或其它登录方式。用户验证（UV）强制开启。
- 后台没有自己的公网端口：浏览器打开 `http://<节点>:<XRAY_PORT>/` 就是
  它（分发器按源形式/绝对形式分流，见架构节）。若前面挂了域名 + HTTPS，
  把 `XMAGIC_ADMIN_RPID` / `XMAGIC_ADMIN_ORIGINS` 改成该域名，Passkey 按
  该域名签发。
- Passkey 丢了没有网页找回通道：在节点上跑 `users.py admin-reset` 清掉凭证
  重新注册——能碰宿主机的人本来就拥有这台机器，这是刻意的破窗设计。
  还在登录状态时也可以在后台直接**更换 Passkey**（设置区）：更换完成的那一刻，
  其它所有登录会话立即失效，本页面切到新签发的会话。
- **管理范围是全部业务数据，不只是新建**：网关用户（换密码、换 UUID、改 SSH
  公钥 / 分组 / SS 方法 / 备注、启停、删除）、上级（全部字段可编辑，不必删了
  重加）、目标路由（可编辑）、设置与登录会话——每一项 Web 与两套 CLI 都有，
  功能一一对应。

### 登录会话

- 同一管理员可以同时有多个会话（多浏览器、多台机器的 CLI 登录都算）。
- **会话默认有效期 1 周**，可在后台设置里改（1–2160 小时），Web / CLI 均可改，
  只影响新签发的会话。
- 会话以令牌的 SHA-256 存在库里（原文不落库），后台的「登录会话」页能看到
  每个会话的标识、类型（web/cli）、来源、创建与到期时间，并可**逐个撤销**
  或**撤销其它全部会话**；CLI 同样支持（见下）。

### 设置（含渲染级配置）

后台「设置」里除了会话有效期，还管四项原本只能写在 .env 里的渲染级配置：
VLESS / Trojan 的 WS 路径列表、上级池策略、新用户的默认 SS 方法、是否允许
直连内网地址。存进库里的值优先生效，清空即回退到 .env 的部署默认值；保存
后自动重新渲染生效。端口类配置不在此列——它们绑在分发器 / sshd 进程上，
仍是 .env + compose 的事。

「允许直连内网地址」默认关：经 VLESS / Trojan / Shadowsocks 进来的流量，
直连时不能访问节点本机与内网地址（Xray freedom 出站的默认拦截规则，
防 SSRF）；节点需要访问自家局域网服务时才打开，打开后渲染出的 freedom
出站会带一条放行内网段的 finalRule。

## 管理界面二：命令行（与 Web 功能完全一致）

### 节点上：users.py（引擎自带 CLI）

通过 admin 容器运行，宿主机不需要 Python：

```bash
docker compose run --rm admin python3 users.py add alice --ssh-key-file ~/.ssh/id_ed25519.pub
docker compose run --rm admin python3 users.py upstream-add b1 --addr 1.2.3.4 --port 8080 --proto ss --password ...
docker compose run --rm admin python3 users.py route-add --kind domain --pattern github.com --to intl
docker compose run --rm admin python3 users.py upstream-edit b1 --port 8443   # 上级/路由都可编辑
docker compose run --rm admin python3 users.py route-edit 1 --to direct
docker compose run --rm admin python3 users.py rotate-uuid alice              # 换 UUID / setmethod / setnote / setkey --clear
docker compose run --rm admin python3 users.py settings --vless-ws-paths /a,/b  # 渲染级配置（空串 = 回退 .env）
docker compose run --rm admin python3 users.py apply      # 渲染 + 重启（与网页点保存同一动作）
docker compose run --rm admin python3 users.py status
docker compose run --rm admin python3 users.py sessions   # 会话列表，可 sessions-revoke <id> 撤销
docker compose run --rm admin python3 users.py settings --session-ttl-hours 48
docker compose run --rm admin python3 users.py --json list   # 机器可读输出，方便自动化
```

### 自己机器上：xmagic.py（远程 CLI，批量管节点）

```bash
python3 xmagic.py node add tokyo --url http://<节点地址>:8080   # 后台与代理共用公网端口，直连即可
python3 xmagic.py login            # 自动拉起浏览器走 Passkey，登录态存回本地
python3 xmagic.py users add alice
python3 xmagic.py --node tokyo routes add --kind ip --pattern 1.1.1.1 --to intl
python3 xmagic.py sessions list    # 看这个节点上的全部登录会话
python3 xmagic.py sessions revoke <id>
python3 xmagic.py upstreams edit b1 --port 8443      # 与 Web 编辑同一接口
python3 xmagic.py users rotate-uuid alice
python3 xmagic.py settings set --session-ttl-hours 24
python3 xmagic.py settings set --upstream-strategy random --ss-method chacha20-ietf-poly1305
```

- 节点注册表在 `~/.xmagic/config.json`；目标节点的选择优先级：
  **命令行参数 > 环境变量 > 配置文件**（`--node` / `--url` > `XMAGIC_NODE` /
  `XMAGIC_URL` > 配置里的 current）。全局参数写在子命令前后都行。
- 登录流程：CLI 在本机回环起一个临时监听，把浏览器送到节点的 `/cli-auth`
  页完成 Passkey；页面回交的是一次性代码，CLI 再用它换正式会话令牌——
  令牌不出现在任何 URL 里。
- 会话默认存 `~/.xmagic/sessions/<节点名>.json`（0600）；`login --session-file
  路径` 可存到指定位置，其它命令同名参数（或 `XMAGIC_SESSION_FILE`）选用哪份
  会话——一份会话一个文件，脚本里按节点切换，适合批量管理。
- 退出码约定：0 成功、1 接口错误、2 配置/用法错误、3 未登录或会话过期，
  脚本可据此决定是否重跑 `login`。

## 数据库

业务数据（用户、上级、路由、设置、管理员凭证、登录会话）默认存 SQLite
（`./data/users.db`），也可以跑在 PostgreSQL 或 MySQL 上：

- **多套配置，随时切换**：每个库是一套命名参数（sqlite 是文件路径，
  postgres / mysql 是 DSN），同时只能启用一套，切换立即重新渲染生效。
- **表自动重建**：切到一个还没有表的空库（或对它执行测试）时，
  全部业务表自动按当前结构建好，不需要手工跑迁移脚本。
- **跨库迁移**：任意两套配置之间可以整库复制全部业务表
  （含管理员凭证与登录会话）；目标非空时默认拒绝，显式选覆盖才清表。
- **配置本身存本地**：数据库配置是引导信息，存在节点本地的 SQLite
  文件里（默认 `./data/local.db`，可用 `XMAGIC_LOCAL_DB` 改位置），
  不进任何业务库——这样无论当前启用的是哪个库，节点总能找回全部配置。
- 三个界面操作一致：Web 后台「数据库」区；节点 CLI
  `users.py db-list | db-add | db-edit | db-remove | db-test | db-switch | db-migrate`；
  远程 CLI `xmagic.py db list | add | edit | remove | test | switch | migrate`。
- 列表与输出里的 DSN 密码一律打码。postgres / mysql 驱动
  （psycopg / PyMySQL）已装进 admin 镜像；脱离 Docker 单独跑 users.py 时
  需自行 `pip install "psycopg[binary]" pymysql`，只用 SQLite 不需要。

注意：登录会话也在业务库里。迁移会把会话一并复制过去；只切换、不迁移
到一个没有你会话的库时，Web 与远程 CLI 都需要重新登录。

## WS 多路径

Xray 的 fallback 路径是**精确匹配，不支持通配符/正则**。等效做法：一份路径列表，
每条路径一个回落条目 + 一个后端入站（共用同一用户表），全部同时生效：

```bash
python3 users.py gen-paths 8         # 生成随机路径，如 /assets/x3kf9a
# 路径填进设置即可（Web 后台「设置」或 users.py settings --vless-ws-paths ...，
# 立即渲染生效）；只在部署期定死时才写 .env 的 VLESS_WS_PATHS / TROJAN_WS_PATHS
```

## 级联：多上级、分组、选路策略

```bash
python3 users.py upstream-add b1 --addr 1.2.3.4 --port 8080 --proto ss --password ...
python3 users.py upstream-add b2 --addr node2.example.com --port 8080 --proto vless-ws --uuid ...
python3 users.py upstream-add inet --addr proxy.corp:3128 --proto http --username u --password p
python3 users.py upstream-add b3 --addr node3.example.com --port 22 --proto ssh \
    --username proxy --key-file ./data/ssh_client_keys/b3_key
python3 users.py setgroup alice team-b    # 让 alice 走 team-b 组的池，不设走 default 池
```

- `--proto` 可选 vless-ws / vless / trojan-ws / ss / http / socks / ssh；
  ssh 上级在渲染时被映射为一个本地 SOCKS 端口，并生成 `data/ssh-tunnels.json`
  与 `data/start-tunnels.sh`，由 compose 的 `tunnels` sidecar
  （`--profile cascade`）常驻 `ssh -N -D` 保持隧道。
- 同组多个上级组成一个池，策略由 env `UPSTREAM_STRATEGY` 选：
  `roundRobin`（默认）/ `random` / `leastPing` / `leastLoad`，按**连接**逐个选路。
- 没有任何上级时，出口就是直连（freedom）。

## 按目标选上级（路由规则）

在"按用户分组"之上再加一层：按目标域名/IP 把流量送到指定池、直连或拦截：

```bash
python3 users.py route-add --kind domain --pattern github.com --to intl
python3 users.py route-add --kind ip --pattern 1.1.1.1 --to intl
python3 users.py route-add --kind domain --pattern example.org --to block
python3 users.py route-add --kind full --pattern example.com --to intl --user carol
```

- `--kind`：`domain`（后缀匹配，含子域名）/ `full`（精确域名）/ `keyword` /
  `regexp` / `ip`（单个 IP 或 CIDR）。
- `--to`：上级组名（送进该组池），或 `direct`（不经上级直连），或 `block`（拦截）。
- `--user` 可选：规则只对该用户生效；带用户的规则优先于全局规则。
- 判定顺序：带用户的目标规则 → 全局目标规则 → 按用户分组规则 → 兜底
  （default 池或直连）。目标规则指向的组若没有任何启用的上级，该规则在渲染时
  被跳过并打印 warning，不会让整份配置失效。

## 镜像与 CI

四个镜像由 GitHub Actions 构建并推到 GHCR（amd64 + arm64 双架构）：

| 镜像 | 内容 |
| --- | --- |
| `ghcr.io/xnetsc/xmagic-xray` | 上游 Xray 核心，按 `versions.env` 的钉版号重打标签（不改内容） |
| `ghcr.io/xnetsc/xmagic-dispatcher` | sniff.py 首字节分发器 |
| `ghcr.io/xnetsc/xmagic-sshd` | SSH 入口（公钥-only） |
| `ghcr.io/xnetsc/xmagic-admin` | 管理后台 + users.py 引擎 |

- `build` 工作流：推送到 main 先跑 `tests/` 下的测试套件（后台协议、
  双界面一致性、远程 CLI、分发器分流），全过才构建推送。
- `upstream-check` 工作流：每天查一次 XTLS/Xray-core 的最新 Release，
  有新版就自动改 `versions.env` 的钉版、提交，并触发 `build` 重走构建——
  部署侧的 watchtower 随后自动拉新镜像，整条链无人值守。
- 上游基础镜像（python:3.12-alpine、alpine）不钉版：每次构建自然拉最新。

## 部署

前置说明（不变）：**不要部署在 Railway**——其 AUP 明文禁止运营代理/匿名化服务，
官方对同类自用需求明确回复不允许且有自动检测；同工作区里的其它项目不要连带冒险。
Heroku / Vercel 这类平台也不用考虑：Heroku 只把 HTTP(S) 路由到它分配的端口，
SSH/SOCKS/SS 这些裸 TCP 进不来，文件系统还是临时的；Vercel 是函数式的，
没有常驻监听进程——网关本体在这两家跑不起来，与配置方式无关。

首选 Oracle Cloud Always Free（ARM 2 OCPU / 12 GB 现行额度；注册须本人用真实卡
验证、home region 选定后不可改）。任意允许自用代理的 VPS 也可以。

```bash
git clone https://github.com/xnetsc/xmagic && cd xmagic
cp .env.example .env                 # 至少设 XRAY_PORT、WS 路径
docker compose up -d                 # admin 首次启动会先渲染一份空配置顶住
# 浏览器打开 http://<节点地址>:8080 注册管理员 Passkey → 加用户
# （后台与代理共用这一个端口，每次修改自动渲染 + 重启生效）
# 云控制台防火墙只放行 XRAY_PORT 一个端口
```

自更新：watchtower 每天检查，只自动更新带 label 的 xray 与 dispatcher 镜像；
sshd / admin 随 `docker compose pull` 手动更新（管理面不自己重启自己）。

## 注意事项

- Xray 26.x 已把 WebSocket 传输、Trojan、Shadowsocks 标注为 deprecated（"might be
  removed"）：当前版本可用，将来大版本若移除需迁移（VLESS 侧可转 XHTTP/Reality）。
- **Xray 26 的明文策略**：VLESS / Trojan 本身没有传输加密，Xray 拒绝把
  它们以明文拨向任何公网地址（IP 或域名都拒，配置构建期直接报错）；拨内网/回环
  地址、或经 SSH 隧道/组网时不受此限。公网节点互联请用 ss 或 ssh 上级，或给
  vless / vless-ws / trojan-ws 上级加 `--tls`（SNI 取上级地址，要求上级前面有
  TLS 终结）。同理，本节点的 WS 入口定位是内网/隧道内使用，公网直连请用
  SS / SOCKS / HTTP / SSH。
- `data/users.db` 里是可还原的协议密钥（Xray 需要），文件 600；整机备份时它和
  `data/ssh_client_keys/` 一起按密钥材料对待，不要外发。会话令牌只存哈希，不在此列。
- sshd 容器里 `proxy` 账户已解锁但只允许公钥登录（Dockerfile 里 `passwd -u`）。

## 文件清单

- `admin.py` — Web 管理后台（Passkey、会话管理、配置 API；纯标准库，含 WebAuthn 校验实现）
- `users.py` — 身份库引擎 + 节点侧 CLI（用户/上级/路由/数据库/渲染/apply/设置/会话）
- `xmagic.py` — 远程 CLI（节点注册表、浏览器 Passkey 登录、会话文件、多节点批量管理）
- `sniff.py` — 首字节协议分发器（纯标准库）
- `docker-compose.yml` — xray / dispatcher / sshd / admin / tunnels（可选）/ watchtower
- `Dockerfile.xray`、`Dockerfile.dispatcher`、`Dockerfile.sshd`、`Dockerfile.admin`、`sshd_config`
- `versions.env` — 上游钉版（Xray 版本，upstream-check 工作流自动维护）
- `.github/workflows/` — `build.yml`（测试 + 构建推 GHCR）、`upstream-check.yml`（上游新版自动跟进）
- `tests/` — test_admin.py（后台协议与会话）、test_cli.py（双界面一致性）、test_client.py（远程 CLI 全流程）、test_dispatch.py（分发器分流）、test_databases.py（多数据库：注册表/切换/迁移/方言）
- `.env.example` — 配置模板
