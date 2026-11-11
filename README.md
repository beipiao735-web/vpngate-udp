# gate-udp

从 [VPN Gate](https://www.vpngate.net/) 全量节点里自动筛 **日韩住宅 UDP 节点**，
生成可直接导入 OpenVPN 的 `.ovpn` 配置包，发布到你自己的 GitHub Pages。

改自 hezhanleiok/gate 的验货思路，但目标相反：gate 只筛 SSTP/TCP（edgetunnel
链式代理只能吃 TCP），这版专筛 **UDP 直连** —— 少一层隧道，延迟低得多。

## 它做了什么

1. 抓 VPN Gate 官方 API 全量节点（约 100 个），只留 KR/JP；
2. 用 ip-api 批量查每个节点 IP 的 hosting 标记，分出住宅 / 机房
   （`public-vpn-*` 官方服务器单独剔除）；
3. 对住宅候选逐个做 **OpenVPN UDP 握手探测**：很多志愿者的 SoftEther
   服务端在配置写的 TCP 端口上同时监听 UDP，API 却只给 TCP 配置。
   探通的生成 `proto udp` 配置并标「已验证」，探不通的保留 TCP 配置兜底；
4. 按 已验证 UDP → 住宅 → API Ping → 在线人数 排序，每国取前 15 个；
5. 产物发到 GitHub Pages：面板 `index.html`、结构化 `nodes.json`、
   单个 `.ovpn` 文件、`bundle-udp.zip` / `bundle-all.zip` 配置包。

## 部署（约 5 分钟，不需要任何 Secret，不需要 Cloudflare Worker）

1. 把本仓库全部文件上传到**你自己新建的 GitHub 仓库**（或 Fork 后改用本版文件）；
2. 仓库 `Settings → Pages`，Source 选 **GitHub Actions**；
3. `Actions → gate-udp node check → Run workflow` 手动跑一次；
4. 跑完后访问 `https://<你的用户名>.github.io/<仓库名>/` 就是你的节点面板，
   之后每 6 小时自动刷新。

## 使用

手机装 **OpenVPN for Android**（或 OpenVPN Connect），从你的面板下载
`.ovpn` 导入，连接时账号填 `vpn`、密码填 `vpn`（VPN Gate 统一账号）。
优先连标着 UDP 的；连不上就换下一个，或用同节点的 TCP 兜底配置。

优先在家里的 WiFi 上、**关掉其他代理**再连：节点列表和配置在你自己的
Pages 上，但 GitHub 在国内直连不稳定时，可先开你现有的 edgetunnel 订阅
把配置下下来，连接本身是直连的，不走代理。

## 改配置

工作流文件里改环境变量即可：`COUNTRIES`（如 `KR,JP,TH,US`）、
`MAX_PER_COUNTRY`。脚本本身纯 Python 标准库，本地也能跑：
`python fetch_udp.py`，产物在 `./public`。

## 已知限制与风险

- UDP 探测在 GitHub Actions 的网络里跑，探的是「Actions → 节点」通不通，
  不等于「你家 → 节点」通不通；最终可用性以你本地导入实测为准。
- API Ping 是 VPN Gate 服务端测的值，只作预排序参考，不是你本地的延迟。
- 住宅/机房分类依据 ip-api 的 hosting 标记，偶有误判，面板里有 ISP 列可人工复核。
- **隐私**：VPN Gate 官方政策明示连接日志（你的真实 IP、目标主机名、时间、
  流量）保存 3 个月以上并可依法披露；出口是陌生志愿者的电脑。
  只适合临时解锁/一次性验证，**不要**登录银行、支付、主力邮箱和学校账号。
- 节点是志愿者的，随时下线；6 小时刷新一次也追不上实时变化，连不上就换。

## 许可

脚本部分 MIT。节点数据来自 VPN Gate，请遵守其使用条款。
