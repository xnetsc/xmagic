# xmagic：单端口多协议代理网关

[English](README.md) | **中文**

一句话：**一个公共端口，凭协议首字节自动分发**，同时提供 SSH、
HTTP 代理（CONNECT）、Trojan-WS、Shadowsocks-WS、VLESS+REALITY、裸 Shadowsocks；
自身不带加密的协议默认不开：VLESS-WS、VLESS（裸 TCP）（在设置里
开启）与公网 SOCKS5（`XMAGIC_ENABLE_SOCKS5=1`）；HTTP 留着是因为
它借道外层 HTTPS，Trojan 设计上强制 TLS，Shadowsocks 自带加密。
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
    (公钥认证)   (默认关)  (用户+密码)   ├ 路径命中 → VLESS-WS 后端（可多路径，默认关）
                                            ├ 路径命中 → Trojan-WS 后端（可多路径）
                                            ├ 路径命中 → Shadowsocks-WS 后端（可多路径）
                                            └ 默认回落 → 裸 Shadowsocks 后端
     TLS ClientHello（0x16 0x03）───────────→ VLESS+REALITY 后端（默认开）
                                   │
                        出口：直连，或上级池（按用户分组、负载均衡）
```

- 对外只有一个端口（分发器）。所有后端只听 127.0.0.1，admin 后台也不
  例外：它和代理共用这一个公网端口，分发器按内容分流——源形式 HTTP
  （浏览器打开后台）转给它，代理形式的流量转给代理（规则见架构节）。
- 身份只有一个事实源：**业务数据库**（默认 SQLite，`data/users.db`，
  可换 PostgreSQL / MySQL，见「数据库」节）。Xray 的 `config.json`、
  sshd 的 `authorized_keys` 都是从库里渲染出来的产物。
- 后端回环端口全部可由 env 覆盖（同机跑多个节点做测试时必须错开）。

## 协议与认证（入站 / 上级对称）

| 协议 | 客户端连入（入站） | 本节点连上级（出站） | 认证 |
| --- | --- | --- | --- |
| SSH | sshd，`ssh -D` 得 SOCKS5 | `ssh -N -D` 隧道映射为本地 SOCKS 出站 | 公钥（双向都是） |
| SOCKS5 | Xray socks 入站（公网分支**默认关闭**：明文协议，`XMAGIC_ENABLE_SOCKS5=1` 开启） | Xray socks 出站 | 用户名+密码（可空） |
| HTTP 代理 | Xray http 入站（CONNECT） | Xray http 出站 | Basic（可空） |
| VLESS-WS | WS 路径分发 → 后端（**默认关闭**：VLESS 自身不加密，在设置里开启） | 同左 | uuid |
| VLESS（裸 TCP） | 分发器 → 复用器主入站直达（**默认关闭**） | 同左 | uuid |
| VLESS+REALITY | TLS ClientHello 分发 → REALITY 后端（**默认开启**，与 VLESS 开关无关） | —（仅入站） | uuid |
| Trojan-WS | WS 路径分发 → 后端 | 同左 | 密码 |
| Shadowsocks | 默认回落 → 后端 | 同左 | 每用户独立密码+method |
| Shadowsocks-WS | WS 路径分发 → 后端 | 同左（ss 上级带路径即走 WS 拨号，带 TLS 即 WSS） | 每用户独立密码+method |

每个用户在库里是一套凭证：VLESS uuid（VLESS 入站开启时用，REALITY 入站也用它）、
一个共享密码（Trojan / HTTP / SOCKS 共用）、
独立的 SS 密码、可选的 SSH 公钥。连上级时存的也是对方按同一模型签发的凭证——
**两段认证各管一段**：用户连本节点用本节点签发的凭证（在本节点终结）；本节点连
上级用上级签发的凭证（存在本节点的上级记录里）。同组用户在上级侧呈现为同一身份，
这是级联的固有语义；要在上级侧按用户区分，就给用户单独分组、单独配上级记录。

## 管理界面一：Web 后台（Passkey）

- 后台是部署单元的一部分（`admin` 容器），不存在"宿主机上跑脚本"的依赖；
  它与网关共用 `data/` 卷，每次修改自动重新渲染，并通过 Docker socket
  只重启受影响的容器（xray / sshd / tunnels）生效（没挂 socket 时只渲染，
  界面会如实提示）。渲染产物没变化时不重启任何进程。
- **只支持一个管理员账号，且只能用 Passkey**：第一个注册的 Passkey 即管理员，
  注册随即永久关闭；不支持密码或其它登录方式。用户验证（UV）强制开启。
- 后台没有自己的公网端口：浏览器打开 `http://<节点>:<XRAY_PORT>/` 就是
  它（分发器按源形式/绝对形式分流，见架构节）。若前面挂了域名 + HTTPS，
  把 `XMAGIC_ADMIN_RPID` / `XMAGIC_ADMIN_ORIGINS` 改成该域名，Passkey 按
  该域名签发。
- Passkey 丢了没有网页找回通道：在节点上跑 `users.py admin-reset` 清掉凭证
  重新注册——能碰宿主机的人本来就拥有这台机器，这是刻意的破窗设计。
  还在登录状态时也可以在后台直接**更换 Passkey**（设置区）：更换完成的那一刻，
  其它所有管理员会话立即失效，本页面切到新签发的会话。
- **管理范围是全部业务数据，不只是新建**：代理用户（换密码、换 UUID、改 SSH
  公钥 / 分组 / SS 方法 / 备注、启停、删除）、上级（全部字段可编辑，不必删了
  重加）、目标路由（可编辑）、设置与管理员会话——每一项 Web 与两套 CLI 都有，
  功能一一对应。

### 管理员会话

- 同一管理员可以同时有多个会话（多浏览器、多台机器的 CLI 登录都算）。
- **会话默认有效期 1 周**，可在后台设置里改（1–2160 小时），Web / CLI 均可改，
  只影响新签发的会话。
- 会话是绑钥的，不是持有型令牌：登录时在 Passkey 仪式内做 ECDH 协商
  ——WebAuthn 挑战值本身是「随机数 ‖ 双方临时公钥」的 SHA-256，Passkey
  签名直接覆盖这次密钥协商——之后每个 API 调用都用派生出的会话密钥
  加密传输；会话 id 只是查询键。库里存的是派生密钥（没法存哈希，服务
  端解密要用），所以活着的会话本身就是密钥材料。后台的「管理员会话」页
  能看到每个会话的标识、类型（web/cli）、来源、创建与到期时间，并可
  **逐个撤销**或**撤销其它全部会话**；CLI 同样支持（见下）。

### 设置（含渲染级配置）

后台「设置」里除了会话有效期，还管几项原本只能写在 .env 里的渲染级配置，
以及组内互访的分组退出名单（互访默认开启，见下文「组内互访」）：
VLESS / Trojan / Shadowsocks 的 WS 路径列表、上级池策略、新用户的默认 SS 方法、REALITY
开关与伪装参数（见下一节）、是否允许直连内网地址。存进库里的值优先生效，
清空即回退到 .env 的部署默认值；保存
后自动重新渲染生效。端口类配置不在此列——端口绑在分发器 / sshd 进程上，
仍是 .env + compose 的事。

两个默认不加密的协议不开，除非运维显式选择加入：VLESS 入站
（设置里勾选「启用 VLESS 入站」，或 `VLESS_ENABLED=1`；VLESS 把
加密交给 TLS 层，而本网关不终结 TLS）与 dispatcher 的公网 SOCKS5
分支（环境变量 `XMAGIC_ENABLE_SOCKS5=1`；SOCKS5 是明文，且不是
HTTP、借不了外层 HTTPS 的道）。

「允许直连内网地址」默认关：经 VLESS / Trojan / Shadowsocks 进来的流量，
直连时不能访问节点本机与内网地址（Xray freedom 出站的默认拦截规则，
防 SSRF）；节点需要访问自家局域网服务时才打开，打开后渲染出的 freedom
出站会带一条放行内网段的 finalRule。

### VLESS+REALITY 入站（默认开）

REALITY 让网关多一条外观与真实网站 TLS 1.3 会话无异的入站：握手借用
伪装目标站点的证书与参数，未能通过 REALITY 认证的连接会被直接转发到
该真站——拿探测打这个端口，看到的就是真站本身。与裸 VLESS 不同，
REALITY 自带加密与伪装，因此**默认开启，且与 VLESS 开关相互独立**：
关掉 VLESS 不会关掉 REALITY，反之亦然。客户端用各用户已有的 UUID，
flow 为 `xtls-rprx-vision`。

设置项（Web 后台、`users.py settings`、远程 CLI `settings set` 三面
一致，库里的值胜过 `REALITY_*` 环境变量）：开关、伪装目标 `dest`
（默认 `www.microsoft.com:443`）、客户端可用的 `serverNames`、
`shortIds`。节点的 REALITY 密钥对生成一次后存库；设置里展示**公钥**
（客户端配置要用，私钥永不离开节点），并可轮换——轮换后仍用旧公钥
的客户端配置立即失效。

目标站点怎么选：节点能直达的、支持 **TLS 1.3** 的普通高流量境外
HTTPS 站点即可，默认的 `www.microsoft.com:443` 就可用；`serverNames`
里填的名字必须在其证书覆盖范围内。

客户端配置（Xray）：地址/端口是节点的公网入口，其余参数取自设置页
与用户自己的 UUID：

```json
{
  "protocol": "vless",
  "settings": {"vnext": [{"address": "<节点>", "port": 8080,
    "users": [{"id": "<用户 uuid>", "encryption": "none",
               "flow": "xtls-rprx-vision"}]}]},
  "streamSettings": {"network": "tcp", "security": "reality",
    "realitySettings": {"serverName": "www.microsoft.com",
      "fingerprint": "chrome",
      "publicKey": "<设置里的 reality_public_key>",
      "shortId": "<reality_short_ids 之一>", "spiderX": ""}}
}
```

同样的配置写成分享链接：

```
vless://<用户 uuid>@<节点>:8080?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.microsoft.com&fp=chrome&pbk=<reality_public_key>&sid=<shortId>#xmagic-reality
```

REALITY 是裸 TLS 直达公网口：需要 `XRAY_PORT` 的 **TCP 直达**
（VPS 直连端口，或裸 TCP 转发）。它无法穿过 TLS 终结型边缘——例如
平台的 HTTPS 域名（在边缘终结 TLS 后转发 HTTP）——因为客户端的
TLS 握手必须原封不动地到达 REALITY 入站。

### Shadowsocks over WebSocket 与套 CDN 用法

网关还提供把 Shadowsocks 装进 WebSocket 的入站（简称 SS-WS）：
与裸 SS 同一份每用户密码与 method，走自己的一组 WS 路径（默认
`/ss-ws`，可多路径，在设置里与其它 WS 路径列表同样管理）。SS 自带
加密，这条入站与 SS 家族一致默认开启。承载固有的两个限制：**只
走 TCP**（WS 不承载 UDP，需要 UDP 用裸 SS 入站）；与本节点其它
WS 入站一样，明文 WS 只适合内网/隧道内使用，公网上要在前面套一
层 TLS 终结（下文的 CDN，或任意 TLS 终结器）。

在野的两种客户端方言连的都是这同一个入站：

- **Xray 原生方言**（Xray 本体、v2rayN / v2rayNG / Hiddify）：
  SS 出站带 `streamSettings`、`network: ws`：

```json
{
  "protocol": "shadowsocks",
  "settings": {"servers": [{"address": "<节点>", "port": 8080,
    "method": "aes-256-gcm", "password": "<用户 SS 密码>"}]},
  "streamSettings": {"network": "ws",
    "wsSettings": {"path": "/ss-ws"}}
}
```

  写成分享链接（前面有 TLS 终结时再加 `security=tls`）：

```
ss://<base64(method:password)>@<节点>:8080?type=ws&path=%2Fss-ws#xmagic-ss-ws
```

- **SIP003 插件方言**（mihomo / Clash、sing-box、Shadowrocket）：
  同一个入站同样接 `v2ray-plugin` 客户端的 websocket 模式，插件
  指向同一条 SS 路径即可：

```yaml
proxies:
  - name: xmagic-ss-ws
    type: ss
    server: <节点>
    port: 8080
    cipher: aes-256-gcm
    password: "<用户 SS 密码>"
    plugin: v2ray-plugin
    plugin-opts: {mode: websocket, host: <节点>, path: /ss-ws, mux: false}
```

**套 CDN** 是这条入站在公网上的标准形态：把自有域名接入 CDN
（在 CDN 侧放行 WebSocket），回源指向节点公网口，客户端以
`wss://<你的域名>`＋SS 路径连入——CDN 终结客户端的 TLS 后，把
WebSocket 以明文 HTTP 转发回节点。由于 Shadowsocks 协议自身加密
（目标地址也在加密范围内），CDN 只能看到 SS 密文与连接元数据，
看不到内容、也看不到目标地址；节点的源站地址也藏在 CDN 后面。
剩下的暴露面是域名本身：它的名字出现在 TLS 的 SNI 里，域名一旦
被封这条路就断，需要换新域名。（级联侧同理：`ss` 上级记录带上
路径与 TLS 后拨号就是 SS over WSS，本节点也能经 CDN 去连上级。）

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

安装单文件 CLI（纯 Python 标准库，不用 pip）——从任意一个已部署的节点下载：节点提供的就是它部署时打包的那一份 CLI，装下来必然与服务一致；该节点的 Web 后台里也有同一条命令（已填好节点地址），带一键复制按钮：

```bash
mkdir -p ~/.local/bin && curl -fsSL https://<节点地址>/cli/xmagic.py -o ~/.local/bin/xmagic && chmod +x ~/.local/bin/xmagic
```

`xmagic update` 同理：与所选节点打包的副本按字节对齐，不从任何其它来源取。

```bash
python3 xmagic.py node add tokyo --url http://<节点地址>:8080   # 后台与代理共用公网端口，直连即可
python3 xmagic.py login            # 自动拉起浏览器走 Passkey，登录态存回本地
python3 xmagic.py users add alice
python3 xmagic.py --node tokyo routes add --kind ip --pattern 1.1.1.1 --to intl
python3 xmagic.py passkey replace  # 拉起浏览器：先用当前 Passkey 验证，再注册新 Passkey；保留本 CLI 会话，其余会话全部撤销
python3 xmagic.py sessions list    # 看这个节点上的全部管理员会话
python3 xmagic.py sessions revoke <id>
python3 xmagic.py upstreams edit b1 --port 8443      # 与 Web 编辑同一接口
python3 xmagic.py users rotate-uuid alice
python3 xmagic.py settings set --session-ttl-hours 24
python3 xmagic.py settings set --upstream-strategy random --ss-method chacha20-ietf-poly1305
python3 xmagic.py keys list        # 本机可用的 SSH 密钥：~/.ssh、~/.xmagic/keys、ssh-agent
python3 xmagic.py keys generate alice   # 在 ~/.xmagic/keys 下生成一对 ed25519 密钥
python3 xmagic.py users add alice --ssh-key alice   # 把这把钥登记为她的登录凭据
python3 xmagic.py users add bob --ssh-key-generate  # 生成 + 登记一步完成
python3 xmagic.py update           # 与所选节点打包的副本按字节对齐更新
```

- 节点注册表在 `~/.xmagic/config.json`；目标节点的选择优先级：
  **命令行参数 > 环境变量 > 配置文件**（`--node` / `--url` > `XMAGIC_NODE` /
  `XMAGIC_URL` > 配置里的 current）。全局参数写在子命令前后都行。
- 登录流程：CLI 在本机回环起一个临时监听，把浏览器送到节点的 `/cli-auth`
  页完成 Passkey；页面拿到加密的网页会话后（已有有效网页会话时直接
  复用，不再走仪式），在这个加密通道里向节点申请一个绑 CLI 公钥的
  会话，再带着 CLI 打开页面时给的参数（state 标记）访问 CLI 的本地
  回环监听口，只回传公开值（会话 id 与服务端公钥）。会话密钥由 CLI
  用自己的私钥在本地派生：密钥本身不经过任何传输，CLI 也从不向服务
  器索取——浏览器与 CLI 就算落在集群的不同实例上也没关系，跨实例的
  只有业务库里的会话行。
- 会话默认存 `~/.xmagic/sessions/<节点名>.json`（0600）；`login --session-file
  路径` 可存到指定位置，其它命令同名参数（或 `XMAGIC_SESSION_FILE`）选用哪份
  会话——一份会话一个文件，脚本里按节点切换，适合批量管理。
- SSH 密钥不用再找外部工具，且用户的私钥只在客户端生成：网页里就在
  页面本身生成、远程 CLI 在本机生成——私钥从不出现在服务器上，节点
  只收到公钥（users.py 根本不能生成用户密钥）；节点侧生成只用于节点
  自有的密钥：给 SSH 上级生成时私钥按托管密钥存于节点。控制台的
  用户列表会给登记了公钥的用户直接显示现成的
  `ssh -D 1080 -N -i xmagic-<用户名>.key -p <端口> proxy@<节点>` 命令
  （sshd 登录名恒为 `proxy`，是哪位网关用户由钥决定）——普通 SSH 客户端
  就是可用的代理客户端。
- `xmagic update` 从仓库自更新：下载先过版本校验与自检（--version
  探针），通过才替换当前文件，旧版保留为 `xmagic.py.bak`
  （`--check` 只报告，`--from URL` 换下载源）。
- 退出码约定：0 成功、1 接口错误、2 配置/用法错误、3 未登录或会话过期，
  脚本可据此决定是否重跑 `login`。

## 数据库

业务数据（用户、上级、路由、设置、管理员凭证、管理员会话）默认存 SQLite
（`./data/users.db`），也可以跑在 PostgreSQL 或 MySQL 上：

- **多套配置，随时切换**：每个库是一套命名参数（sqlite 是文件路径，
  postgres / mysql 是 DSN），同时只能启用一套，切换立即重新渲染生效。
- **表自动重建**：切到一个还没有表的空库（或对它执行测试）时，
  全部业务表自动按当前结构建好，不需要手工跑迁移脚本。
- **跨库迁移**：任意两套配置之间可以整库复制全部业务表
  （含管理员凭证与管理员会话）；目标非空时默认拒绝，显式选覆盖才清表。
- **配置本身存本地**：数据库配置是引导信息，存在节点本地的 SQLite
  文件里（默认 `./data/local.db`，可用 `XMAGIC_LOCAL_DB` 改位置），
  不进任何业务库——这样无论当前启用的是哪个库，节点总能找回全部配置。
- 三个界面操作一致：Web 后台「数据库」区；节点 CLI
  `users.py db-list | db-add | db-edit | db-remove | db-test | db-switch | db-migrate`；
  远程 CLI `xmagic.py db list | add | edit | remove | test | switch | migrate`。
- 列表与输出里的 DSN 密码一律打码。postgres / mysql 驱动
  （psycopg / PyMySQL）已装进 admin 镜像；脱离 Docker 单独跑 users.py 时
  需自行 `pip install "psycopg[binary]" pymysql`，只用 SQLite 不需要。

注意：管理员会话也在业务库里。迁移会把会话一并复制过去；只切换、不迁移
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
- ssh 上级的私钥有三种给法：`--key-file` 给节点上已有文件的路径；在控制台
  里直接粘贴私钥内容或选本地文件上传（远程 CLI 用 `--key-upload <本地文件>`、
  节点 CLI 用 `--key-content-file <本地文件>`）——内容由节点存进
  `data/ssh_client_keys/`（权限 0600），上级记录的路径记为 `/keys/<名称>.key`，
  删除该上级时一并删除。用户的 SSH 公钥同理，可粘贴、也可在控制台选文件填入。
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

## 组内互访

同一分组的用户可以经网关互访彼此的服务，像在同一个局域网里。
**默认开启**；设置里的「关闭组内互访的分组」（或
`settings --interconnect-off-groups`）填入的分组退出互访。

- 暴露：用户用反向转发把服务挂到网关回环，如
  `ssh -R 127.0.0.1:20005:127.0.0.1:8080 -N -i <私钥文件> -p <端口> proxy@<节点>`
  把本机 8080 暴露出来。每人固定一段 16 个端口（20000–21599，
  见控制台用户列表），sshd 按钥逐段限制（authorized_keys 的
  `permitlisten`），谁也占不了别人的端口。
- 访问：同组成员经自己的代理拨 `127.0.0.1:<端口>`，与拨任何目标
  无异。路由只把成员的端口段放给同组成员；其余回环目标一律在
  网关拦截，节点自身的回环服务不会因此暴露。
- 范围：仅 TCP、仅用户显式转发的服务——这是网关中转的可达性，
  不是虚拟局域网（没有虚拟 IP、UDP 与服务发现）。

## 镜像与 CI

四个镜像由 GitHub Actions 构建并推到 GHCR（amd64 + arm64 双架构）：

| 镜像 | 内容 |
| --- | --- |
| `ghcr.io/xnetsc/xmagic-xray` | 上游 Xray 核心，按 `versions.env` 的钉版号重打标签（不改内容） |
| `ghcr.io/xnetsc/xmagic-dispatcher` | sniff.py 首字节分发器 |
| `ghcr.io/xnetsc/xmagic-sshd` | SSH 入口（公钥-only） |
| `ghcr.io/xnetsc/xmagic-admin` | 管理后台 + users.py 引擎 |
| `ghcr.io/xnetsc/xmagic-single` | 单容器形态（全部进程一个镜像，见「单容器形态」节） |

- `build` 工作流：推送到 main 先跑 `tests/` 下的测试套件（后台协议、
  双界面一致性、远程 CLI、分发器分流、数据库多方言），全过才构建推送；
  构建后还有 `e2e` 作业把打出来的镜像按 compose 与单容器两种形态
  真实拉起做全功能测试（加用户、apply、各协议取数、SSH 登录）。
- `upstream-check` 工作流：每天查一次 XTLS/Xray-core 的最新 Release，
  有新版就自动改 `versions.env` 的钉版、提交，并触发 `build` 重走构建——
  部署侧的 watchtower 随后自动拉新镜像，整条链无人值守。
- 上游基础镜像（python:3.12-alpine、alpine）不钉版：每次构建自然拉最新。

## 部署

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

### 单容器形态（不支持 docker compose 的环境）

`Dockerfile.single` 把全部进程打进一个镜像：入口脚本拉起 admin / xray /
sshd / 分发器 / 隧道进程，对外仍只有 XRAY_PORT 一个端口，状态全在 /data
一个卷里。没有进程监控：**任意关键进程自行退出，入口脚本就把其余进程
全部带走、整容器以该进程的状态码退出**，靠运行时的重启策略整体拉回，
因此必须带重启策略运行。配置变更（apply）不同：apply 比较渲染前后的
产物，只向受影响的进程发出重启请求（改用户 / 上级 / 路由只重启 xray，
改 SSH 公钥只重启 sshd，改 ssh 上级只重启隧道进程），入口脚本将其原地
拉起、其余进程不受影响；若拉起后立即退出（重启失败），仍按整容器退出
处理、由运行时整体拉回。

```bash
docker build -f Dockerfile.single -t xmagic-single .
docker run -d --name xmagic --restart unless-stopped \
  -p 8080:8080 -v xmagic-data:/data xmagic-single
# 浏览器打开 http://<节点地址>:8080 注册管理员 Passkey → 加用户
```

compose 形态仍是推荐部署方式（各容器独立的更新节奏与重启边界）；
单容器只是给只能跑单个镜像 / 裸 `docker run` 的环境用的兼容形态。
配置项与 compose 相同（见 .env.example），在 `docker run -e` 里给。

平台适配（Heroku 式环境）：环境里有 `PORT` 时它就是公共端口（盖过
`XRAY_PORT`）；有 `DATABASE_URL` 时，入口脚本把它注册为名为 `heroku`
的 postgres 配置并启用——身份数据因此不落在平台的临时文件系统上，
dyno 重启不丢用户。

### 一键部署（Heroku，单容器形态）

[![Deploy to Heroku](https://www.herokucdn.com/deploy/button.svg)](https://heroku.com/deploy?template=https://github.com/xnetsc/xmagic)

按钮用仓库里的 `app.json` + `heroku.yml` 拉起单容器镜像，并自动配一个
Heroku Postgres（业务库，见上文的平台适配）。部署完成后，把两个环境
变量设成你的应用域名并重启 dyno，后台的 Passkey 才能按该域名工作：
`XMAGIC_ADMIN_RPID=<应用域名>`、`XMAGIC_ADMIN_ORIGINS=https://<应用域名>`。

降级范围说清：Heroku 路由只放 HTTP(S)，能用的是**后台、HTTP 代理、
VLESS-WS / Trojan-WS / Shadowsocks-WS**；SOCKS5、SSH、裸 Shadowsocks、裸 VLESS-TCP
这些裸 TCP 协议进不来。另外 Heroku 现在没有免费档（dyno 与 Postgres
都按月计费），路由对空闲连接有超时，长连接空闲会被切断——这个形态
适合轻量自用，完整形态仍推荐 VPS + compose。

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
  `data/ssh_client_keys/` 一起按密钥材料对待，不要外发。活着的会话密钥
  也存在库里（会话密钥没法存哈希，服务端解密要用），同样在此列。
- sshd 容器里 `proxy` 账户已解锁但只允许公钥登录（Dockerfile 里 `passwd -u`）。

## 文件清单

- `admin.py` — Web 管理后台（Passkey、会话管理、配置 API；纯标准库，含 WebAuthn 校验实现）
- `users.py` — 身份库引擎 + 节点侧 CLI（用户/上级/路由/数据库/渲染/apply/设置/会话）
- `xmagic.py` — 远程 CLI（节点注册表、浏览器 Passkey 登录、会话文件、多节点批量管理）
- `sniff.py` — 首字节协议分发器（纯标准库）
- `docker-compose.yml` — xray / dispatcher / sshd / admin / tunnels（可选）/ watchtower
- `Dockerfile.xray`、`Dockerfile.dispatcher`、`Dockerfile.sshd`、`Dockerfile.admin`、`sshd_config`
- `Dockerfile.single`、`single-entrypoint.sh`、`single-tunnels.sh` — 单容器形态（无 compose 时用；任一关键进程自行退出即整容器退出）
- `app.json`、`heroku.yml` — Heroku 一键部署描述（单容器形态 + Postgres 业务库）
- `versions.env` — 上游钉版（Xray 版本，upstream-check 工作流自动维护）
- `.github/workflows/` — `build.yml`（测试 + 构建推 GHCR）、`upstream-check.yml`（上游新版自动跟进）
- `tests/` — test_admin.py（后台协议与会话）、test_cli.py（双界面一致性）、test_client.py（远程 CLI 全流程）、test_dispatch.py（分发器分流）、test_databases.py（多数据库：注册表/切换/迁移/方言）、ci_e2e.sh（CI 里对构建出的镜像做 compose / 单容器全功能测试）
- `.env.example` — 配置模板
