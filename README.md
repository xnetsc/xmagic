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
                        sniff.py 首字节分发器
        ┌──────────────┬───────────┼──────────────┬────────────────┐
     "SSH-" 横幅     0x05       CONNECT /        WebSocket        其余字节
        │            │          绝对形式 HTTP       Upgrade           │
       sshd        SOCKS5 入站   HTTP 入站      Xray fallback 复用器 ──┤
    (公钥认证)    (用户+密码)   (用户+密码)     ├ 路径命中 → VLESS-WS 后端（可多路径）
                                              ├ 路径命中 → Trojan-WS 后端（可多路径）
                                              └ 默认回落 → 裸 Shadowsocks 后端
                                   │
                        出口：直连，或上级池（按用户分组、负载均衡）
```

- 所有后端只听 127.0.0.1，对外只有分发器一个端口。
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
- 默认只绑宿主机 127.0.0.1，经 SSH 隧道访问（`ssh -L 8090:127.0.0.1:8090 节点`，
  浏览器里是 localhost，属 WebAuthn 安全上下文）；要挂域名走 HTTPS 时改
  `XMAGIC_ADMIN_RPID` / `XMAGIC_ADMIN_ORIGINS`。
- Passkey 丢了没有网页找回通道：在节点上跑 `users.py admin-reset` 清掉凭证
  重新注册——能碰宿主机的人本来就拥有这台机器，这是刻意的破窗设计。

### 登录会话

- 同一管理员可以同时有多个会话（多浏览器、多台机器的 CLI 登录都算）。
- **会话默认有效期 1 周**，可在后台设置里改（1–2160 小时），Web / CLI 均可改，
  只影响新签发的会话。
- 会话以令牌的 SHA-256 存在库里（原文不落库），后台的「登录会话」页能看到
  每个会话的标识、类型（web/cli）、来源、创建与到期时间，并可**逐个撤销**
  或**撤销其它全部会话**；CLI 同样支持（见下）。

## 管理界面二：命令行（与 Web 功能完全一致）

### 节点上：users.py（引擎自带 CLI）

通过 admin 容器运行，宿主机不需要 Python：

```bash
docker compose run --rm admin python3 users.py add alice --ssh-key-file ~/.ssh/id_ed25519.pub
docker compose run --rm admin python3 users.py upstream-add b1 --addr 1.2.3.4 --port 8080 --proto ss --password ...
docker compose run --rm admin python3 users.py route-add --kind domain --pattern github.com --to intl
docker compose run --rm admin python3 users.py apply      # 渲染 + 重启（与网页点保存同一动作）
docker compose run --rm admin python3 users.py status
docker compose run --rm admin python3 users.py sessions   # 会话列表，可 sessions-revoke <id> 撤销
docker compose run --rm admin python3 users.py settings --session-ttl-hours 48
docker compose run --rm admin python3 users.py --json list   # 机器可读输出，方便自动化
```

### 自己机器上：xmagic.py（远程 CLI，批量管节点）

```bash
python3 xmagic.py node add tokyo --url http://127.0.0.1:8090   # 先经 SSH 隧道把节点后台映射到本地
python3 xmagic.py login            # 自动拉起浏览器走 Passkey，登录态存回本地
python3 xmagic.py users add alice
python3 xmagic.py --node tokyo routes add --kind ip --pattern 1.1.1.1 --to intl
python3 xmagic.py sessions list    # 看这个节点上的全部登录会话
python3 xmagic.py sessions revoke <id>
python3 xmagic.py settings set --session-ttl-hours 24
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

## WS 多路径（防单路径特征）

Xray 的 fallback 路径是**精确匹配，不支持通配符/正则**。等效做法：一份路径列表，
每条路径一个回落条目 + 一个后端入站（共用同一用户表），全部同时生效：

```bash
python3 users.py gen-paths 8         # 生成随机伪装路径，如 /assets/x3kf9a
# 把输出填进 .env 的 VLESS_WS_PATHS / TROJAN_WS_PATHS（逗号分隔），重渲染重启
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

- `build` 工作流：推送到 main 先跑三套本地实测（后台协议、双界面一致性、
  远程 CLI 全流程），全过才构建推送。
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
# 浏览器打开 http://127.0.0.1:8090（或先 ssh -L 8090:127.0.0.1:8090 过来）
# 注册管理员 Passkey → 在后台加用户（每次修改自动渲染 + 重启生效）
# 云控制台防火墙只放行 XRAY_PORT 一个端口
```

自更新：watchtower 每天检查，只自动更新带 label 的 xray 与 dispatcher 镜像；
sshd / admin 随 `docker compose pull` 手动更新（管理面不自己重启自己）。

## 本地实测记录（2026-11-07，全部在本地真实跑过）

网关本体（沙箱内多节点实测）：

- 单端口全协议（经分发器、经上级出网取 GitHub 200）：SOCKS5+密码 ✓（错密码拒）、
  HTTP CONNECT+Basic ✓（错密码拒）、VLESS-WS ✓、Trojan-WS ✓、裸 SS ✓、
  裸 VLESS-TCP ✓（错 uuid 拒）；SSH 经分发器端口 `ssh -D` ✓、直连 sshd ✓（错公钥拒）。
- WS 双路径别名同时生效 ✓；级联轮询 6/6 均分、随机 10/10、坏池负例全断 ✓；
  按目标选上级六个用例（域名/IP/block/带用户/禁用回落）全过 ✓；
  SSH 上级按渲染出的隧道命令全程打通 ✓；
  Xray 的 http 出站认证经自建 authproxy 逐字节验证（含密码带 `: @ / %`）✓；
  旧格式数据库迁移 ✓。

管理面（软件模拟认证器 + 真实 HTTP 服务/CLI 进程）：

- Passkey 注册/登录全流程 ✓；二次注册被拒 ✓；断言重放被拒 ✓；错密钥被拒 ✓；
  `admin-reset` 后可重新注册 ✓。
- 会话：默认 1 周、改成 24 小时后新签发会话按新值到期 ✓；会话列表带当前标记 ✓；
  按 id 撤销后该令牌立即失效 ✓；撤销其它会话只留当前 ✓；一次性交接代码单用 ✓；
  非回环回调地址被拒 ✓。
- 双界面一致性：CLI 建的用户在 Web 可见、反之亦然 ✓；`--json` 输出可解析 ✓。
- 远程 CLI：双节点注册表、参数覆盖配置、按节点存会话、`--session-file` 选会话、
  未登录退出码 3 ✓。

两个实测中定位到的坑（都不是产品缺陷）：沙箱的上游代理密码会定期轮换，长驻进程
写死旧密码会吃 407（生产环境静态密码不受影响）；多个节点同机测试时回环后端端口
必须错开，否则内核 SO_REUSEPORT 会把连接分流到别的节点后端。

compose 文件本身只做过静态校验；Docker 实际拉起等有 VPS 时验（构建 sshd 镜像、
host 网络、卷挂载路径都是标准用法，风险低）。

## 注意事项

- Xray 26.x 已把 WebSocket 传输、Trojan、Shadowsocks 标注为 deprecated（"might be
  removed"）：当前版本可用，将来大版本若移除需迁移（VLESS 侧可转 XHTTP/Reality）。
- **Xray 26 的明文策略（已实测）**：VLESS / Trojan 本身没有传输加密，Xray 拒绝把
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
- `users.py` — 身份库引擎 + 节点侧 CLI（用户/上级/路由/渲染/apply/设置/会话）
- `xmagic.py` — 远程 CLI（节点注册表、浏览器 Passkey 登录、会话文件、多节点批量管理）
- `sniff.py` — 首字节协议分发器（纯标准库）
- `docker-compose.yml` — xray / dispatcher / sshd / admin / tunnels（可选）/ watchtower
- `Dockerfile.xray`、`Dockerfile.dispatcher`、`Dockerfile.sshd`、`Dockerfile.admin`、`sshd_config`
- `versions.env` — 上游钉版（Xray 版本，upstream-check 工作流自动维护）
- `.github/workflows/` — `build.yml`（测试 + 构建推 GHCR）、`upstream-check.yml`（上游新版自动跟进）
- `tests/` — test_admin.py（后台协议与会话）、test_cli.py（双界面一致性）、test_client.py（远程 CLI 全流程）
- `.env.example` — 配置模板
