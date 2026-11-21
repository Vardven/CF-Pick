# CF-Pick · Cloudflare 入口优选测速台

> 一键并发测速几百个 Cloudflare 优选域名 / IP，**真实回源校验**，实时输出 TOP 20 榜单。
> 单文件 Windows 应用，双击即用，不需要装 Python、不需要命令行。

![platform](https://img.shields.io/badge/platform-Windows%2010%2F11-0a7bd4?style=flat-square)
![python](https://img.shields.io/badge/python-3.9%2B-3776ab?style=flat-square&logo=python&logoColor=white)
![license](https://img.shields.io/badge/license-MIT-22c55e?style=flat-square)
![release](https://img.shields.io/github/v/release/Vardven/CF-Pick?style=flat-square)

---

## 它解决什么问题

用 Cloudflare 中转的节点（VLESS-WS-TLS / Trojan-gRPC 之类），客户端连的是「优选入口」而不是源站。
常见做法是抄一份公共优选域名清单，或者用 CloudflareSpeedTest 扫 IP —— 但这两种做法都有同一个盲区：

**它们只测「你 → CF 边缘」这一段，测不出「CF 边缘 → 你的源站」这一段。**

CFST 默认测的是 `speed.cloudflare.com`，请求在 CF 边缘就被应答了，根本不会回源到你的机器。
所以它排名第一的 IP，装到你的节点上未必好用 —— 你测到的是 CF 的缓存节点，不是你的线路。

**CF-Pick 的做法是复刻真实代理行为**：连到候选 IP，用**你自己的域名做 SNI** 完成 TLS 握手，再发一个普通 HTTP 请求。
CF 按 SNI 认出你的 zone 并回源，于是这个耗时天然包含两段：

```
你的电脑 ────[这段优选能优化]──── CF 边缘 ────[这段优选管不了]──── 你的源站
              └──────────── 本工具测的就是这条完整路径 ────────────┘
```

顺带能筛掉三类「假可用」入口：

| 情况 | 现象 | 本工具判定 |
|---|---|---|
| 域名没走 CF（灰云） | 直连到别人的服务器，照样返回 404 | `非CF节点`，拒绝排名 |
| 落在 CF 中国合作节点 | 172.64.52.x 之类的京东云节点，仅服务企业版 | `被CF拦截`（403） |
| 源站没起来 / 证书错 | CF 自己报错 | `回源异常`（52x/530） |

---

## 特性

- **一键跑完全程**：内置 426 个常用优选域名，点一下 ≈ 75 秒出榜（并发 40，每项 2 次取均值）
- **真实回源**：内置 CF 官方 22 个网段校验（15×IPv4 + 7×IPv6），非 CF 地址一律剔除
- **IPv4 / IPv6 分开测**：同一个域名同时测 A 与 AAAA，榜单上直接标出谁更快
- **实时榜单**：进度、可用数、最快/均值延迟、拦截与超时统计边跑边更新
- **一键取用**：「复制 TOP20」直接粘进 v2rayN / Clash 的地址栏；「导出 CSV」带 BOM，Excel 不乱码
- **零依赖运行**：单文件 exe，配置与候选清单写在 exe 同级，换目录不影响
- **源码干净**：纯标准库（`socket` / `ssl` / `http.server`），前端是单个 `ui.html`，没有框架、没有 npm

---

## 快速开始

1. 到 [Releases](https://github.com/Vardven/CF-Pick/releases) 下载 `CF-Pick.exe`
2. **先退出代理软件**（v2rayN / Clash 等，包括 TUN 模式），这一步不做，测出来的数据没有意义
3. 双击 `CF-Pick.exe` —— 会自动打开浏览器界面
4. 左侧填你的 **SNI / Host**（就是你在 CF 里开了橙云的那个子域，例如 `cdn-test.example.com`）
5. 点「开始测速」，等进度跑完，看右侧 TOP 20
6. 点「复制 TOP20」，回客户端里把节点**地址**换成榜单里的域名，端口 / SNI / 路径 / ALPN 一律不动

> exe 放到了只读目录（如 `Program Files`）也能跑，配置文件会自动落到 `%LOCALAPPDATA%\CF-Pick`。

### 界面

| 区域 | 说明 |
|---|---|
| 左栏 · 目标 | SNI/Host、端口、每项测试次数、并发数、地址族（自动 / 仅 v6 / 仅 v4） |
| 左栏 · 候选入口 | 一行一个域名或 IP，改动后直接点开始即可，会自动先保存 |
| 中部 KPI | 可用入口数、最快延迟、可用均值、已测/总数 |
| 中部进度 | 解析阶段 → 探测阶段，右侧统计被拦截 / 回源异常 / 非CF / 不通 |
| 右侧榜单 | 前十名金银铜标记，延迟条横向对比，点任意一行复制该域名 |

---

## 判定规则

只认 **HTTP 状态码**，不看延迟高低：

| 状态 | 含义 | 能不能用 |
|---|---|---|
| `200` `301` `400` `404` … | 请求到达你的源站，被正常应答或拒绝普通请求 | ✅ 可用 |
| `403` | CF 层就拒了：Host/SNI 不对，或该 IP 是 CF 中国合作节点 | ❌ 被CF拦截 |
| `521` `522` `523` `525` `530` | CF 连不上 / 握不上 / 解析不到你的源站 | ❌ 回源异常 |
| `000` / 超时 | 根本没连上 | ❌ 淘汰 |
| IP 不在 CF 网段 | 该域名没走 CF | ❌ 非CF节点 |

> 返回 `404` 是**最好的结果**：说明 CF 成功回源到了你的机器，只是你那条 WS 入站不接受普通 GET 请求，于是自己回了个 404。

---

## 参数说明

| 参数 | 默认 | 说明 |
|---|---|---|
| SNI / Host | — | 你开了橙云的 CDN 子域，TLS 握手和 `Host` 头都用它 |
| 端口 | `443` | 你的 CDN 节点监听端口。gRPC 节点改成 `2053` 等对应端口 |
| 每项测几次 | `2` | 取成功次数的平均值；网络抖动大就调到 3 |
| 并发数 | `32` | 太高容易被运营商 QoS，64 是上限 |
| 地址族 | 自动 | 自动 = A + AAAA 都测，各取前 2 个地址 |

---

## 常见问题

**测出来和我实际用起来的体验对不上？**
先确认测速时**代理是真的退出了**。TUN 模式在路由层劫持流量，普通「关系统代理」拦不住它，会让所有候选都变成「你 → VPS → CF」的绕行路径，数据全废。

**为什么延迟和我之前用 curl 脚本测的不一样？**
本工具把 DNS 解析放在测速之前单独做，计时只算「连接 + TLS + 首字节」；`curl --connect-to` 会把 DNS 也算进 `time_total`。**同一份清单换个工具会差 200ms 左右，跨工具别横比，看排名。**

**杀毒软件报毒？**
PyInstaller 单文件 exe 的自解压特征会触发误报，加信任即可。介意的话按下面的步骤自己从源码打包。

**一定要选 IPv6 吗？**
不一定，但实测差得很明显 —— 同一条宽带下 v6 入口常在 300ms 档，v4 在 500ms 档。前提是你的 VPS 有可用 IPv6 出口。

**榜单里同一个域名出现两三次？**
那是它解析出的不同 IP / 不同地址族，各自独立测速。想要「一个域名只留最快一条」，可以按延迟手动挑，或者在客户端里只保留排名最高的那行。

---

## 从源码构建

```bash
git clone https://github.com/Vardven/CF-Pick.git
cd CF-Pick

python -m pip install pyinstaller
python gen_icon.py            # 生成 icon.ico（纯标准库，不需要 Pillow）

# Windows（--add-data 用分号）
python -m PyInstaller --noconfirm --onefile --noconsole --name CF-Pick ^
  --icon icon.ico --add-data "ui.html;." --add-data "cf-domains.txt;." cfpick.py

# macOS / Linux（--add-data 用冒号，产物不是 exe）
python -m PyInstaller --noconfirm --onefile --name CF-Pick \
  --add-data "ui.html:." --add-data "cf-domains.txt:." cfpick.py
```

Windows 上也可以直接双击 `build.cmd`。

只调试界面的话，`ui.html` 用浏览器直接打开即可 —— 会加载一份内置的演示数据。

### 目录结构

```
CF-Pick/
├─ cfpick.py                     # 测速引擎 + 本地 HTTP 服务（纯标准库）
├─ ui.html                       # 界面（原生 JS，无框架）
├─ gen_icon.py                   # 生成多尺寸 ICO
├─ icon.ico
├─ cf-domains.txt                # 内置候选清单（一行一个）
├─ build.cmd                     # Windows 一键打包
└─ .github/workflows/release.yml # 打 tag 自动构建并发布
```

---

## 原理备注

每个候选都会被执行：

1. `getaddrinfo` 解析出 IPv4 / IPv6 地址，逐个校验是否落在 CF 官方的 22 个网段内
2. `socket.connect` 连到候选地址（**不是**连你的域名，这一步就是优选的全部意义）
3. `SSLContext.wrap_socket(server_hostname=<你的 SNI>)`，ALPN 固定 `http/1.1`
4. 发送 `GET / HTTP/1.1` + `Host: <你的 SNI>`
5. 读首字节，计时结束，按状态码分类

任何一个候选出问题，只会影响它自己那一行 —— 不会让整轮测试崩掉。

---

## 免责声明

本项目仅用于网络质量测试与线路诊断。使用者应自行确保其使用方式符合所在地法律法规及所接入服务商的条款。作者不对任何因使用本工具产生的后果承担责任。

## License

[MIT](LICENSE) © Vardven
