#!/usr/bin/env python3
"""VPN Gate SSTP 节点筛选流水线（edgetunnel 订阅版）

流程:
  1. 抓取 VPN Gate 官方 API
  2. 只保留 KR/JP 的 TCP 配置节点（SoftEther 的 TCP 监听口同时提供 MS-SSTP 服务）
  3. ip-api 分类住宅/机房，public-vpn-* 官方节点排除
  4. 对每个候选做真实的 MS-SSTP 握手探测:
     TLS 连接 -> SSTP_DUPLEX_POST -> Call Connect Request -> 期望 Call Connect Ack
  5. 已验证节点按 edgetunnel「自定义优选 IP」格式写出 public/sstp/nodes.txt:
       入口域名:端口#韩国-住宅-01$sstp://vpn:vpn@节点.opengw.net:端口
     另产出 public/sstp/data.json 与一个简单的说明页 public/sstp/index.html
  6. 若本轮 0 个已验证（例如探测环境被封），尝试保留线上已发布的旧 nodes.txt，
     避免把用户的订阅清空。

纯 Python 标准库，无需 pip install，无需任何 Secret。

环境变量:
  COUNTRIES        国家代码，逗号分隔，默认 KR,JP
  PUBLIC_DIR       产物根目录，默认 ./public（产物写到其 sstp/ 子目录）
  PROBE_TIMEOUT    单节点 SSTP 探测超时秒数，默认 7
  PROBE_WORKERS    并发数，默认 16
  SSTP_MAX_LINES   nodes.txt 最多行数，默认 30
  CLASSIFY         1=启用 ip-api 分类（默认），0=跳过
"""

from __future__ import annotations

import base64
import csv
import io
import json
import os
import re
import socket
import ssl
import struct
import sys
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

API = os.environ.get("VPNGATE_API", "http://www.vpngate.net/api/iphone/")
COUNTRIES = [c.strip().upper() for c in os.environ.get("COUNTRIES", "KR,JP").split(",") if c.strip()]
PUBLIC_DIR = os.environ.get("PUBLIC_DIR", "./public")
PROBE_TIMEOUT = float(os.environ.get("PROBE_TIMEOUT", "7"))
PROBE_WORKERS = int(os.environ.get("PROBE_WORKERS", "16"))
SSTP_MAX_LINES = int(os.environ.get("SSTP_MAX_LINES", "30"))
CLASSIFY = os.environ.get("CLASSIFY", "1") == "1"

COUNTRY_ZH = {"KR": "韩国", "JP": "日本"}

# edgetunnel 入口优选域名池（与 hezhanleiok/gate 模板的内置池一致，公开的 CF 优选域名）
EDGE_HOSTS = [
    "saas.sin.fan:443",
    "www.mfyx.cn:443",
    "cf.nyanya.moe:443",
    "cf.877774.xyz:443",
    "cdn.204910.best:443",
    "cdn.ctn32.us.kg:443",
    "p.etime.vip:443",
    "cmcc.vvvv.ee:443",
    "cfsaas.080112.xyz:443",
    "cdn.aneko.ink:443",
]

SSTP_GUID = "{BA195980-CD49-458b-9E23-C84EE0ADCD75}"
CORRELATION = "{11111111-2222-3333-4444-555555555555}"


def _int(v, default=999999):
    try:
        return int(str(v).strip())
    except Exception:
        return default


def log(msg):
    print(msg, flush=True)


# ---------------------------------------------------------------------------
# 数据抓取
# ---------------------------------------------------------------------------
def fetch_rows():
    req = urllib.request.Request(API, headers={"User-Agent": "Mozilla/5.0"})
    text = urllib.request.urlopen(req, timeout=30).read().decode("utf-8", "replace")
    lines = [ln for ln in text.splitlines() if ln.strip() and not ln.startswith("*")]
    hdr = None
    for i, ln in enumerate(lines):
        if ln.lstrip("#").startswith("HostName"):
            hdr = i
            break
    if hdr is None:
        raise RuntimeError("API 响应里找不到表头")
    header = [h.strip().lstrip("#").strip("*").lower() for h in lines[hdr].split(",")]
    col = {n: i for i, n in enumerate(header)}
    rows = []
    for ln in lines[hdr + 1:]:
        try:
            f = next(csv.reader(io.StringIO(ln)))
        except Exception:
            continue
        if len(f) < len(header):
            continue
        rows.append({name: f[idx] for name, idx in col.items()})
    return rows


def parse_candidates(rows):
    """保留目标国家、带 TCP 配置的志愿者节点，解析出 SSTP 端口（= 配置里的 TCP remote 端口）。"""
    out = []
    for r in rows:
        cc = (r.get("countryshort") or "").strip().upper()
        if cc not in COUNTRIES:
            continue
        host = (r.get("hostname") or "").strip()
        if not host or host.lower().startswith("public-vpn"):
            continue  # 官方机房节点排除
        b64 = r.get("openvpn_configdata_base64") or ""
        if not b64:
            continue
        try:
            cfg = base64.b64decode(b64).decode("utf-8", "replace")
        except Exception:
            continue
        pm = re.search(r"^proto\s+(\w+)", cfg, re.M)
        rm = re.search(r"^remote\s+(\S+)\s+(\d+)", cfg, re.M)
        if not pm or not rm or not pm.group(1).lower().startswith("tcp"):
            continue
        fqdn = host if "." in host else host + ".opengw.net"
        out.append({
            "host": host,
            "fqdn": fqdn,
            "ip": (r.get("ip") or "").strip(),
            "port": int(rm.group(2)),
            "cc": cc,
            "country": (r.get("countrylong") or "").strip(),
            "ping": _int(r.get("ping")),
            "sessions": _int(r.get("numvpnsessions"), 0),
            "speed": _int(r.get("speed"), 0),
            "score": _int(r.get("score"), 0),
            "isp": "",
            "cls": "unknown",
        })
    return out


# ---------------------------------------------------------------------------
# 住宅/机房分类（ip-api batch，hosting 标记）
# ---------------------------------------------------------------------------
def classify(nodes):
    if not CLASSIFY or not nodes:
        return
    ips = []
    seen = set()
    for n in nodes:
        if n["ip"] and n["ip"] not in seen:
            seen.add(n["ip"])
            ips.append(n["ip"])
    info = {}
    for i in range(0, len(ips), 100):
        batch = ips[i:i + 100]
        payload = json.dumps([{"query": ip, "fields": "query,isp,org,hosting"} for ip in batch]).encode()
        req = urllib.request.Request(
            "http://ip-api.com/batch", data=payload,
            headers={"Content-Type": "application/json", "User-Agent": "Mozilla/5.0"},
        )
        try:
            resp = json.loads(urllib.request.urlopen(req, timeout=20).read().decode("utf-8", "replace"))
            for item in resp:
                info[item.get("query", "")] = item
        except Exception as exc:
            log("ip-api 分类失败（本批）: " + str(exc)[:80])
    for n in nodes:
        item = info.get(n["ip"])
        if not item:
            continue
        n["isp"] = item.get("isp") or item.get("org") or ""
        n["cls"] = "datacenter" if item.get("hosting") else "residential"


# ---------------------------------------------------------------------------
# MS-SSTP 握手探测
# ---------------------------------------------------------------------------
def sstp_probe(node):
    """返回 (stage, detail):
    stage = 'ack'     收到 Call Connect Ack -> SSTP 已验证
            'nak'     收到 Call Connect Nak -> 服务在，但参数被拒
            'http'    TLS 通了但 HTTP 层没给 200
            'tls'     TLS 阶段失败（端口不提供 SSL 服务 / 不通）
            'tcp'     TCP 连接失败
    """
    ip, port, fqdn = node["ip"], node["port"], node["fqdn"]
    ctx = ssl._create_unverified_context()
    try:
        raw = socket.create_connection((ip, port), timeout=PROBE_TIMEOUT)
    except Exception as exc:
        return "tcp", type(exc).__name__
    raw.settimeout(PROBE_TIMEOUT)
    try:
        s = ctx.wrap_socket(raw, server_hostname=fqdn)
    except Exception as exc:
        raw.close()
        return "tls", type(exc).__name__ + ": " + str(exc)[:60]
    try:
        http_req = (
            "SSTP_DUPLEX_POST /sra_" + SSTP_GUID + "/ HTTP/1.1\r\n"
            "Host: " + fqdn + "\r\n"
            "Content-Length: 18446744073709551615\r\n"
            "SSTPCORRELATIONID: " + CORRELATION + "\r\n\r\n"
        )
        s.sendall(http_req.encode())
        resp = b""
        while b"\r\n\r\n" not in resp and len(resp) < 8192:
            chunk = s.recv(4096)
            if not chunk:
                break
            resp += chunk
        first = resp.split(b"\r\n", 1)[0].decode("latin1", "replace") if resp else ""
        if " 200" not in first:
            return "http", first[:60] or "empty response"
        # Call Connect Request: header(6) + NumAttributes(2) + EncapsulatedProtocolId attr(6)
        pkt = struct.pack(">BBHH", 1, 0, 1, 14) + struct.pack(">H", 1) + struct.pack(">BBHH", 0, 1, 8, 1)
        s.sendall(pkt)
        data = s.recv(1024)
        if len(data) >= 4:
            _ver, _res, mtype, _ln = struct.unpack(">BBHH", data[:4])
            if mtype == 2:
                return "ack", "Call Connect Ack"
            if mtype == 3:
                return "nak", "Call Connect Nak"
            return "http", "unexpected sstp type " + str(mtype)
        return "http", "no sstp reply"
    except Exception as exc:
        return "http", type(exc).__name__ + ": " + str(exc)[:60]
    finally:
        try:
            s.close()
        except Exception:
            pass


def probe_all(nodes):
    def run(n):
        stage, detail = sstp_probe(n)
        n["probe"] = stage
        n["probe_detail"] = detail
        return n
    with ThreadPoolExecutor(max_workers=PROBE_WORKERS) as pool:
        return list(pool.map(run, nodes))


# ---------------------------------------------------------------------------
# 产物
# ---------------------------------------------------------------------------
def fallback_nodes_text():
    """从当前已发布的 Pages 拉旧 nodes.txt（本轮 0 验证时保留订阅不被清空）。"""
    repo = os.environ.get("GITHUB_REPOSITORY", "").strip()
    url = os.environ.get("SSTP_FALLBACK_URL", "").strip()
    if not url and "/" in repo:
        owner, name = repo.split("/", 1)
        url = "https://" + owner + ".github.io/" + name + "/sstp/nodes.txt"
    if not url:
        return ""
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        text = urllib.request.urlopen(req, timeout=15).read().decode("utf-8", "replace")
        lines = [ln for ln in text.splitlines() if "$sstp://" in ln]
        return "\n".join(lines) + ("\n" if lines else "")
    except Exception:
        return ""


def build_nodes_text(verified):
    lines = []
    counters = {}
    ordered = sorted(
        verified,
        key=lambda n: (n["cls"] != "residential", n["ping"], n["sessions"]),
    )[:SSTP_MAX_LINES]
    for i, n in enumerate(ordered):
        kind = "住宅" if n["cls"] == "residential" else "未知"
        key = (n["cc"], kind)
        counters[key] = counters.get(key, 0) + 1
        num = counters[key]
        name = COUNTRY_ZH.get(n["cc"], n["cc"])
        remark = name + "-" + kind + "-" + format(num, "02d")
        link = "sstp://vpn:vpn@" + n["fqdn"] + ":" + str(n["port"])
        entry = EDGE_HOSTS[i % len(EDGE_HOSTS)]
        lines.append(entry + "#" + remark + "$" + link)
    return "\n".join(lines) + ("\n" if lines else ""), len(lines)


def write_outputs(out_dir, data, nodes_text):
    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, "nodes.txt"), "w", encoding="utf-8", newline="\n") as f:
        f.write(nodes_text)
    with open(os.path.join(out_dir, "data.json"), "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, separators=(",", ":"))
    stats = data["stats"]
    html_lines = [
        "<!doctype html><html lang='zh'><head><meta charset='utf-8'>",
        "<meta name='viewport' content='width=device-width,initial-scale=1'>",
        "<title>VPN Gate SSTP 节点（edgetunnel 订阅）</title></head><body>",
        "<h1>VPN Gate SSTP 节点</h1>",
        "<p>更新时间：" + data["generated_at"] + "｜候选 " + str(stats["candidates"])
        + "｜SSTP 已验证 " + str(stats["sstp_verified"]) + "</p>",
        "<p>订阅文件：<a href='nodes.txt'>nodes.txt</a>（填入 edgetunnel 后台「自定义优选 IP / 订阅」）</p>",
        "<p>说明：每行 = 优选入口 # 备注 $ sstp://vpn:vpn@节点:端口；出口为志愿者住宅 IP，",
        "链路经 Cloudflare 中转，延迟高于 UDP 直连。</p>",
        "</body></html>",
    ]
    with open(os.path.join(out_dir, "index.html"), "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(html_lines))


def main():
    started = time.time()
    rows = fetch_rows()
    log("API 原始节点: " + str(len(rows)))
    cand = parse_candidates(rows)
    log("KR/JP TCP 志愿者候选: " + str(len(cand)))
    classify(cand)
    pool = [n for n in cand if n["cls"] != "datacenter"]
    log("分类后保留（住宅+未知）: " + str(len(pool)))

    probed = probe_all(pool)
    verified = [n for n in probed if n.get("probe") == "ack"]
    nak = [n for n in probed if n.get("probe") == "nak"]
    tls_fail = [n for n in probed if n.get("probe") in ("tls", "tcp")]
    env_blocked = bool(probed) and len(verified) == 0 and len(nak) == 0 and len(tls_fail) == len(probed)
    log("探测结果: ack=" + str(len(verified)) + " nak=" + str(len(nak))
        + " tls/tcp失败=" + str(len(tls_fail)) + " env_blocked=" + str(env_blocked))

    kept_fallback = False
    if verified:
        nodes_text, line_count = build_nodes_text(verified)
    else:
        nodes_text = fallback_nodes_text()
        kept_fallback = bool(nodes_text)
        line_count = nodes_text.count("$sstp://") if nodes_text else 0
        log("本轮 0 个已验证，保留旧订阅: " + str(kept_fallback))

    data = {
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "source": "vpngate.net/api/iphone",
        "sstp_probe_env_blocked": env_blocked,
        "kept_fallback": kept_fallback,
        "stats": {
            "api_total": len(rows),
            "candidates": len(cand),
            "pool": len(pool),
            "sstp_verified": len(verified),
            "published_lines": line_count,
        },
        "nodes": [
            {
                "host": n["host"], "ip": n["ip"], "port": n["port"], "cc": n["cc"],
                "ping": n["ping"], "sessions": n["sessions"], "isp": n["isp"],
                "cls": n["cls"], "probe": n.get("probe"), "probe_detail": n.get("probe_detail"),
                "link": "sstp://vpn:vpn@" + n["fqdn"] + ":" + str(n["port"]),
            }
            for n in sorted(probed, key=lambda x: (x.get("probe") != "ack", x["ping"]))
        ],
        "duration_s": round(time.time() - started, 1),
    }
    out_dir = os.path.join(PUBLIC_DIR, "sstp")
    write_outputs(out_dir, data, nodes_text)
    log("已写出 " + out_dir + "/nodes.txt（" + str(line_count) + " 行）")
    return 0


if __name__ == "__main__":
    sys.exit(main())
