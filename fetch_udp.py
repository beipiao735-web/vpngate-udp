#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
gate-udp: 从 VPN Gate 全量节点里筛「日韩住宅 UDP」节点，生成可直接导入
OpenVPN for Android / OpenVPN Connect 的 .ovpn 配置包。

与 hezhanleiok/gate 的区别：
- gate 只筛 SSTP/TCP（因为 edgetunnel 链式代理只能吃 TCP），把 UDP 全筛掉了；
- 本脚本反过来：优先 UDP。办法是对每个候选节点做一次真实的 OpenVPN
  UDP 握手探测（发送 HARD_RESET 探测包，看服务端是否回包）——很多志愿者
  的 SoftEther 服务端在同一个端口上同时监听 UDP，只是 API 给出的默认
  配置写的是 TCP。探测通过的，生成 proto=udp 的配置并标记「已验证」；
  探测不通的，保留原始 TCP 配置作兜底。
- 住宅/机房分类沿用 xehn 的办法：把节点 IP 批量发 ip-api 查 hosting 标记；
  public-vpn-* 是 VPN Gate 官方服务器（大学机房），单独归类为 official。

纯标准库，无第三方依赖。全部配置走环境变量：
  COUNTRIES        默认 "KR,JP"
  MAX_PER_COUNTRY  每个国家最多输出多少个住宅节点，默认 15
  PROBE_TIMEOUT    单个 UDP 探测超时秒数，默认 4
  PROBE_WORKERS    探测并发，默认 16
  CLASSIFY         1=做 ip-api 分类（默认），0=跳过（全部算未验证）
  PUBLIC_DIR       产物目录，默认 ./public
  VPNGATE_API      数据源，默认官方 API
"""
import base64
import csv
import io
import json
import os
import re
import socket
import struct
import sys
import time
import urllib.request
import zipfile
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

API = os.environ.get("VPNGATE_API", "http://www.vpngate.net/api/iphone/")
COUNTRIES = [c.strip().upper() for c in os.environ.get("COUNTRIES", "KR,JP").split(",") if c.strip()]
MAX_PER_COUNTRY = int(os.environ.get("MAX_PER_COUNTRY", "15"))
PROBE_TIMEOUT = float(os.environ.get("PROBE_TIMEOUT", "4"))
PROBE_WORKERS = int(os.environ.get("PROBE_WORKERS", "16"))
CLASSIFY = os.environ.get("CLASSIFY", "1") == "1"
PUBLIC_DIR = os.environ.get("PUBLIC_DIR", "./public")
IPAPI = "http://ip-api.com/batch?fields=status,countryCode,isp,org,as,hosting,query"


def log(*a):
    print(*a, flush=True)


def fetch_api() -> str:
    last = None
    for attempt in range(3):
        try:
            req = urllib.request.Request(API, headers={"User-Agent": "gate-udp/1.0"})
            with urllib.request.urlopen(req, timeout=30) as r:
                return r.read().decode("utf-8", "replace")
        except Exception as e:  # noqa: BLE001
            last = e
            time.sleep(3 * (attempt + 1))
    raise SystemExit(f"抓取 VPN Gate API 失败: {last}")


def _int(v, default=0):
    """VPN Gate API 偶尔把数字字段写成 '-'（如 Ping 为 '-'），直接 int() 会让整轮崩掉。"""
    try:
        return int(str(v).strip())
    except (ValueError, TypeError, AttributeError):
        return default


def parse_nodes(raw: str) -> list[dict]:
    lines = [l for l in raw.splitlines() if l and not l.startswith("*")]
    if not lines:
        return []
    lines[0] = lines[0].lstrip("#")
    nodes = []
    for row in csv.DictReader(lines):
        try:
            cfg = base64.b64decode(row["OpenVPN_ConfigData_Base64"]).decode("utf-8", "replace")
        except Exception:  # noqa: BLE001
            continue
        pm = re.search(r"^proto\s+(\S+)", cfg, re.M)
        rm = re.search(r"^remote\s+(\S+)\s+(\d+)", cfg, re.M)
        if not rm:
            continue
        nodes.append({
            "host": row["HostName"],
            "ip": row["IP"],
            "score": _int(row["Score"], 0),
            "ping": _int(row["Ping"], 9999),
            "speed": _int(row["Speed"], 0),
            "country": row["CountryLong"],
            "cc": row["CountryShort"].upper(),
            "sessions": _int(row["NumVpnSessions"], 0),
            "operator": row.get("Operator", ""),
            "api_proto": (pm.group(1).lower() if pm else "tcp"),
            "port": int(rm.group(2)),
            "config": cfg,
            "cls": "unknown",       # residential / datacenter / official / unknown
            "isp": "",
            "udp_verified": False,  # UDP 探测是否通过
        })
    return nodes


def classify(nodes: list[dict]) -> None:
    """public-vpn-* 直接判 official；其余用 ip-api 的 hosting 标记分住宅/机房。"""
    targets = []
    for n in nodes:
        if n["host"].lower().startswith("public-vpn"):
            n["cls"] = "official"
        else:
            targets.append(n)
    if not CLASSIFY or not targets:
        return
    for i in range(0, len(targets), 100):
        chunk = targets[i:i + 100]
        try:
            body = json.dumps([{"query": n["ip"]} for n in chunk]).encode()
            req = urllib.request.Request(IPAPI, data=body,
                                         headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=30) as r:
                rows = json.loads(r.read().decode("utf-8", "replace"))
        except Exception as e:  # noqa: BLE001
            log(f"ip-api 分类失败（整批按未验证处理）: {e}")
            return
        by_ip = {row.get("query"): row for row in rows if isinstance(row, dict)}
        for n in chunk:
            row = by_ip.get(n["ip"])
            if not row or row.get("status") != "success":
                continue
            n["isp"] = row.get("isp") or row.get("org") or ""
            n["cls"] = "datacenter" if row.get("hosting") else "residential"


def probe_udp(ip: str, port: int) -> bool:
    """发一个 OpenVPN HARD_RESET_CLIENT_V2 探测包，服务端回包即说明该端口有 UDP OpenVPN。"""
    pkt = bytes([0x38]) + os.urandom(8) + bytes([0]) + struct.pack(">I", 0)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(PROBE_TIMEOUT)
    try:
        s.sendto(pkt, (ip, port))
        data, _ = s.recvfrom(2048)
        return bool(data) and (data[0] >> 3) in (8, 9, 7, 10)
    except OSError:
        return False
    finally:
        s.close()


def make_ovpn(n: dict, proto: str, verified: bool) -> str:
    cfg = n["config"]
    if proto == "udp":
        cfg = re.sub(r"^proto\s+\S+", "proto udp", cfg, count=1, flags=re.M)
    # 让客户端弹出账号输入（VPN Gate 统一 vpn / vpn），已注释的行改为生效
    cfg = cfg.replace("#auth-user-pass", "auth-user-pass")
    if "auth-user-pass" not in cfg:
        cfg = cfg.rstrip() + "\nauth-user-pass\n"
    # 保活: 官方配置没有任何 ping/keepalive 指令，家宽 NAT 的 UDP 映射几十秒就过期，
    # 表现为"连上一两分钟被掐"。补上客户端保活（每 5 秒一个保活包，60 秒无响应才重连）。
    if not re.search(r"^(ping|keepalive)\s", cfg, re.M):
        keepalive_block = (
            "\n# gate-udp keepalive: ping every 5s so home NAT UDP mappings stay alive\n"
            "keepalive 5 60\n"
            "explicit-exit-notify 1\n"
        )
        if "\n<ca>" in cfg:
            cfg = cfg.replace("\n<ca>", keepalive_block + "\n<ca>", 1)
        else:
            cfg = cfg.rstrip() + "\n" + keepalive_block
    tag = "UDP已验证" if (proto == "udp" and verified) else ("UDP待试" if proto == "udp" else "TCP兜底")
    header = (f"# gate-udp | {n['cc']} {n['country']} | {tag} | 出口分类:{n['cls']} "
              f"| ISP:{n['isp'] or '未知'} | API Ping:{n['ping']}ms | 在线:{n['sessions']}人 "
              f"| 生成:{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}\n"
              f"# 连接账号 vpn 密码 vpn\n")
    return header + cfg


def main() -> int:
    log(f"目标国家: {COUNTRIES}，每国上限 {MAX_PER_COUNTRY}")
    nodes = parse_nodes(fetch_api())
    log(f"API 全量节点: {len(nodes)}")
    cand = [n for n in nodes if n["cc"] in COUNTRIES]
    log(f"目标国家候选: {len(cand)}")
    if not cand:
        log("没有候选节点，拒绝发布空结果")
        return 1

    classify(cand)
    # 只保留住宅 + 未验证（机房和官方单独少量输出，见后）
    pool = [n for n in cand if n["cls"] in ("residential", "unknown")]
    log(f"住宅/未验证候选: {len(pool)}（机房 {sum(1 for n in cand if n['cls']=='datacenter')}，"
        f"官方 {sum(1 for n in cand if n['cls']=='official')} 已剔除出主列表）")

    # UDP 探测：先按 API ping 预排序，每国先探前 MAX*3 个，避免跑满全量
    by_cc: dict[str, list[dict]] = {}
    for n in pool:
        by_cc.setdefault(n["cc"], []).append(n)
    probe_targets: list[dict] = []
    for cc, lst in by_cc.items():
        lst.sort(key=lambda x: (x["ping"], x["sessions"]))
        probe_targets.extend(lst[: MAX_PER_COUNTRY * 3])
    log(f"开始 UDP 探测: {len(probe_targets)} 个，并发 {PROBE_WORKERS}")
    with ThreadPoolExecutor(max_workers=PROBE_WORKERS) as ex:
        results = list(ex.map(lambda n: probe_udp(n["ip"], n["port"]), probe_targets))
    for n, ok in zip(probe_targets, results):
        n["udp_verified"] = ok
    controls = [n for n in probe_targets if n["api_proto"] == "udp"]
    env_blocked = bool(controls) and not any(n["udp_verified"] for n in controls)
    verified = sum(1 for n in probe_targets if n["udp_verified"])
    log(f"UDP 探测通过: {verified}/{len(probe_targets)}"
        + ("（注意：连 API 自带 UDP 节点都没探通，当前网络可能封 UDP，以下 UDP 配置按待试输出）" if env_blocked else ""))

    os.makedirs(os.path.join(PUBLIC_DIR, "ovpn"), exist_ok=True)
    out_nodes: list[dict] = []
    udp_files: list[str] = []
    all_files: list[str] = []

    for cc in COUNTRIES:
        lst = by_cc.get(cc, [])
        # 排序：已验证 UDP 优先，其次住宅优先，再按 Score 从高到低
        # （Score 是 VPN Gate 的累计质量分，高分节点多为长期在线的老志愿者，
        #  比只看 ping 更能挑到"活得久"的节点，用户要的是能持续用），最后看 ping
        lst.sort(key=lambda x: (not x["udp_verified"], x["cls"] != "residential",
                                -x["score"], x["ping"], x["sessions"]))
        picked = lst[:MAX_PER_COUNTRY]
        for idx, n in enumerate(picked, 1):
            entry = {k: n[k] for k in ("host", "ip", "port", "cc", "country", "ping",
                                       "sessions", "speed", "score", "cls", "isp",
                                       "api_proto", "udp_verified")}
            if n["udp_verified"]:
                fn = f"{cc}-UDP-{idx:02d}-{n['host']}.ovpn"
                with open(os.path.join(PUBLIC_DIR, "ovpn", fn), "w", encoding="utf-8") as f:
                    f.write(make_ovpn(n, "udp", True))
                entry["file_udp"] = f"ovpn/{fn}"
                udp_files.append(fn)
                all_files.append(fn)
            elif env_blocked:
                fn = f"{cc}-TRYUDP-{idx:02d}-{n['host']}.ovpn"
                with open(os.path.join(PUBLIC_DIR, "ovpn", fn), "w", encoding="utf-8") as f:
                    f.write(make_ovpn(n, "udp", False))
                entry["file_udp_try"] = f"ovpn/{fn}"
                all_files.append(fn)
            fn = f"{cc}-TCP-{idx:02d}-{n['host']}.ovpn"
            with open(os.path.join(PUBLIC_DIR, "ovpn", fn), "w", encoding="utf-8") as f:
                f.write(make_ovpn(n, "tcp", False))
            entry["file_tcp"] = f"ovpn/{fn}"
            all_files.append(fn)
            out_nodes.append(entry)

    if not out_nodes:
        log("筛选结果为空，拒绝发布")
        return 1

    def bundle(name: str, files: list[str]) -> None:
        if not files:
            return
        with zipfile.ZipFile(os.path.join(PUBLIC_DIR, name), "w", zipfile.ZIP_DEFLATED) as z:
            for fn in files:
                z.write(os.path.join(PUBLIC_DIR, "ovpn", fn), arcname=fn)

    bundle("bundle-udp.zip", udp_files)
    bundle("bundle-all.zip", all_files)

    data = {
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "source": "vpngate.net/api/iphone",
        "udp_probe_env_blocked": env_blocked,
        "stats": {
            "api_total": len(nodes), "candidates": len(cand),
            "residential_pool": len(pool), "published": len(out_nodes),
            "udp_verified": sum(1 for n in out_nodes if n["udp_verified"]),
        },
        "nodes": out_nodes,
    }
    with open(os.path.join(PUBLIC_DIR, "nodes.json"), "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

    # 注意：链接先算成变量再拼行。Python 3.11 及以下禁止在 f-string 的
    # 大括号表达式里出现反斜杠（转义引号），那样脚本在解析阶段就直接
    # SyntaxError，整轮跑不起来（GitHub Actions 默认 3.11 踩过一次）。
    def _row(n):
        udp_link = ""
        if n.get("file_udp"):
            udp_link = " <a href='" + n["file_udp"] + "'>UDP配置</a>"
        elif n.get("file_udp_try"):
            udp_link = " <a href='" + n["file_udp_try"] + "'>UDP待试</a>"
        tcp_link = " <a href='" + n["file_tcp"] + "'>TCP配置</a>"
        proto = "UDP ✓" if n["udp_verified"] else "TCP"
        return ("<tr><td>" + n["cc"] + "</td><td>" + proto + "</td><td>" + n["cls"]
                + "</td><td>" + (n["isp"] or "-") + "</td><td>" + str(n["ping"])
                + "</td><td>" + str(n["sessions"]) + "</td><td>" + n["ip"] + ":" + str(n["port"])
                + "</td><td>" + udp_link + tcp_link + "</td></tr>")

    rows_html = "\n".join(_row(n) for n in out_nodes)
    html = f"""<!DOCTYPE html><html lang="zh-CN"><head><meta charset="utf-8">
<title>gate-udp 节点面板</title><style>body{{font-family:sans-serif;margin:2em}}
table{{border-collapse:collapse}}td,th{{border:1px solid #ccc;padding:4px 8px}}</style></head>
<body><h1>gate-udp：日韩住宅节点（UDP 优先）</h1>
<p>更新时间：{data['generated_at']}｜共 {len(out_nodes)} 个，其中 UDP 已验证 {data['stats']['udp_verified']} 个</p>
<p>下载：<a href="bundle-udp.zip">UDP 配置包</a>｜<a href="bundle-all.zip">全部配置包</a>｜<a href="nodes.json">nodes.json</a></p>
<p>用法：把 .ovpn 导入 OpenVPN for Android / OpenVPN Connect，连接时账号填 <b>vpn</b>，密码填 <b>vpn</b>。</p>
<table><tr><th>国家</th><th>协议</th><th>分类</th><th>ISP</th><th>API Ping</th><th>在线</th><th>地址</th><th>配置</th></tr>
{rows_html}</table>
<p style="color:#666">节点来自 VPN Gate 志愿者网络（筑波大学学术项目），连接日志按其官方政策保存 3 个月以上，只适合临时用途，不要登录重要账号。</p>
</body></html>"""
    with open(os.path.join(PUBLIC_DIR, "index.html"), "w", encoding="utf-8") as f:
        f.write(html)
    log(f"完成：发布 {len(out_nodes)} 个节点，UDP 已验证 {data['stats']['udp_verified']} 个 -> {PUBLIC_DIR}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
