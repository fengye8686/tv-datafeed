#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
tv_probe.py  —  TradingView 境内可用性探测 / 优选 IP / hosts 生成

原理:
  1. 走 DoH(DoT 不可用时退化为 HTTPS JSON) 拿到未被投毒的真实 A 记录。
     实测: doh.pub 干净; dns.alidns.com 对 tradingview 返回 Facebook IP(污染);
           因此 doh.pub 优先, Cloudflare 兜底。
  2. 对每个候选 IP 做 TCP:443 连接 + 真实 TLS 握手(SNI=域名)。
     GFW 的 SNI 阻断发生在握手阶段 —— 握手成功且证书 CN/SAN 匹配, 才算"真能用"。
  3. 按握手耗时排序, 输出最优 IP + 可直接粘贴的 hosts 行。

用法:
  python tv_probe.py                # 探测并打印结果
  python tv_probe.py --hosts        # 额外写出 tv_hosts.txt
  python tv_probe.py --apply        # 直接追写系统 hosts(需管理员) 并 flush DNS
  python tv_probe.py --verify       # 用优选 IP 实际 GET 一次首页, 验证 HTTP 200
"""

import argparse
import json
import os
import socket
import ssl
import subprocess
import sys
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor

# ---------------------------------------------------------------- 配置

DOMAINS = [
    ("www.tradingview.com",      "主站"),
    ("cn.tradingview.com",       "主站(CN 入口)"),
    ("s.tradingview.com",        "静态资源"),
    ("s3.tradingview.com",       "图表库 CDN / widget"),
    ("data.tradingview.com",     "行情推送 WS"),
    ("news-mediator.tradingview.com", "新闻/资讯接口"),
]

# DoH 端点, 按可信度排序。返回 (name, url_template, type)
DOH_ENDPOINTS = [
    ("doh.pub",        "https://doh.pub/dns-query?name={d}&type=A",  "json"),
    ("cloudflare",     "https://1.1.1.1/dns-query?name={d}&type=A",  "json"),
    ("quad9",          "https://9.9.9.9:5053/dns-query?name={d}&type=A", "json"),
    ("alidns",         "https://dns.alidns.com/resolve?name={d}&type=A", "json"),
]

TIMEOUT = 6.0
HOSTS_MARK_BEGIN = "# >>> tradingview-probe begin >>>"
HOSTS_MARK_END = "# <<< tradingview-probe end <<<"


# ---------------------------------------------------------------- DoH 解析

# 已知投毒特征: 这些 IP 段被 GFW 用来假冒被墙域名
POISON_HINT = {
    "199.59.148.", "199.59.149.", "2001::",          # Twitter
    "31.13.", "173.252.", "185.93.2.",               # Facebook / 混入
    "159.138.", "23.106.126.",                       # 华为云 / 无关联主机
    "243.185.187.", "59.24.3.", "8.7.198.",          # 经典投毒
}

def is_suspect(ip: str) -> bool:
    return any(ip.startswith(p) for p in POISON_HINT)


def doh_query(domain: str):
    """向多个 DoH 端点查询, 返回 [(ip, 来源端点), ...] (去重, 保序)"""
    out, seen = [], set()
    for name, tpl, _ in DOH_ENDPOINTS:
        url = tpl.format(d=domain)
        req = urllib.request.Request(url, headers={
            "accept": "application/dns-json",
            "user-agent": "tv-probe/1.0",
        })
        try:
            with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
                data = json.loads(r.read().decode("utf-8", "replace"))
        except Exception:
            continue
        for ans in data.get("Answer", []) or []:
            if ans.get("type") != 1:
                continue
            ip = str(ans.get("data", "")).strip()
            if ip and ip not in seen:
                seen.add(ip)
                out.append((ip, name))
    return out


# ---------------------------------------------------------------- 连通性探测

def probe_ip(domain: str, ip: str):
    """
    做一次完整 TLS 握手, 验证证书是否覆盖该域名。
    返回 dict(ip, domain, ok, ms, cert_ok, err)
    """
    ctx = ssl.create_default_context()
    t0 = time.time()
    sock = None
    try:
        sock = socket.create_connection((ip, 443), timeout=TIMEOUT)
        wrapped = ctx.wrap_socket(sock, server_hostname=domain)
        ms = int((time.time() - t0) * 1000)
        # 证书 SAN 校验: Python 的 match_hostname 在 wrap_socket 里已做,
        # 能走到这里说明 chain + hostname 都通过
        wrapped.close()
        return {"ip": ip, "domain": domain, "ok": True, "ms": ms,
                "cert_ok": True, "err": ""}
    except ssl.SSLCertVerificationError as e:
        ms = int((time.time() - t0) * 1000)
        return {"ip": ip, "domain": domain, "ok": False, "ms": ms,
                "cert_ok": False, "err": "cert: " + str(e)[:80]}
    except Exception as e:
        ms = int((time.time() - t0) * 1000)
        return {"ip": ip, "domain": domain, "ok": False, "ms": ms,
                "cert_ok": False, "err": type(e).__name__ + ": " + str(e)[:60]}
    finally:
        try:
            if sock:
                sock.close()
        except Exception:
            pass


def http_verify(domain: str, ip: str):
    """用指定 IP + SNI + Host 头真实 GET 一次, 看是否 200/301"""
    ctx = ssl.create_default_context()
    try:
        conn = socket.create_connection((ip, 443), timeout=TIMEOUT)
        s = ctx.wrap_socket(conn, server_hostname=domain)
        s.sendall((
            f"GET / HTTP/1.1\r\nHost: {domain}\r\n"
            "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0 Safari/537.36\r\n"
            "Accept: text/html,*/*\r\nConnection: close\r\n\r\n"
        ).encode())
        buf = s.recv(256)
        s.close()
        first = buf.split(b"\r\n", 1)[0].decode("latin-1", "replace")
        return first.strip() or "(empty)"
    except Exception as e:
        return "FAIL " + type(e).__name__


# ---------------------------------------------------------------- hosts 处理

def hosts_path():
    if os.name == "nt":
        return os.path.join(os.environ.get("SystemRoot", r"C:\Windows"),
                            "System32", "drivers", "etc", "hosts")
    return "/etc/hosts"


def build_hosts_block(best: dict):
    lines = [HOSTS_MARK_BEGIN]
    for domain, ip in best.items():
        lines.append(f"{ip:<18} {domain}")
    lines.append(HOSTS_MARK_END)
    return "\n".join(lines) + "\n"


def apply_hosts(best: dict):
    hp = hosts_path()
    try:
        with open(hp, "r", encoding="utf-8", errors="replace") as f:
            cur = f.read()
    except PermissionError:
        print(f"[!] 无权限写 {hp} —— 请用管理员身份运行。")
        return False

    # 剥离旧块
    out, skip = [], False
    for line in cur.splitlines():
        if line.strip() == HOSTS_MARK_BEGIN:
            skip = True
            continue
        if line.strip() == HOSTS_MARK_END:
            skip = False
            continue
        if not skip:
            out.append(line)

    body = "\n".join(out).rstrip("\n") + "\n\n" + build_hosts_block(best)
    try:
        with open(hp, "w", encoding="utf-8") as f:
            f.write(body)
    except PermissionError:
        print(f"[!] 写入被拒绝 —— 请用管理员身份运行。")
        return False

    print(f"[+] 已写入 {hp}")
    if os.name == "nt":
        subprocess.run(["ipconfig", "/flushdns"], capture_output=True)
        print("[+] 已刷新 DNS 缓存")
    else:
        subprocess.run(["sh", "-c", "resolvectl flush-caches 2>/dev/null || true"])
    return True


# ---------------------------------------------------------------- main

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--hosts", action="store_true", help="写出 tv_hosts.txt")
    ap.add_argument("--apply", action="store_true", help="写入系统 hosts(需管理员)")
    ap.add_argument("--verify", action="store_true", help="用优选 IP 实际 GET 首页")
    args = ap.parse_args()

    print("=" * 72)
    print(" TradingView 可用性探测")
    print("=" * 72)

    candidates = {}
    for domain, label in DOMAINS:
        ips = doh_query(domain)
        candidates[domain] = ips
        src = ",".join(sorted({s for _, s in ips})) or "-"
        print(f"\n[{domain}]  {label}")
        print(f"  DoH 解析 -> {len(ips)} 条  来源: {src}")

    # 并发探测
    tasks = []
    for domain, ips in candidates.items():
        for ip, src in ips:
            tasks.append((domain, ip, src))

    if not tasks:
        print("\n[!] 一条记录都没解析出来, 检查 DoH 是否可达。")
        return 1

    print(f"\n正在做 {len(tasks)} 次 TLS 握手探测 ...")
    results = []
    with ThreadPoolExecutor(max_workers=16) as ex:
        futs = [ex.submit(probe_ip, d, ip) for d, ip, _s in tasks]
        for f in futs:
            results.append(f.result())
    # 回填来源
    src_map = {(d, ip): s for d, ip, s in tasks}
    for r in results:
        r["src"] = src_map.get((r["domain"], r["ip"]), "?")

    best = {}
    for domain, _label in DOMAINS:
        rows = [r for r in results if r["domain"] == domain and r["ok"]]
        # 排序: 非疑似投毒 > doh.pub 来源 > 低延迟
        rows.sort(key=lambda r: (is_suspect(r["ip"]),
                                 0 if r["src"] == "doh.pub" else 1,
                                 r["ms"]))
        print(f"\n[{domain}]")
        if not rows:
            fail = [r for r in results if r["domain"] == domain]
            for r in fail[:6]:
                flag = "  疑似投毒IP" if is_suspect(r["ip"]) else ""
                print(f"    {r['ip']:<18} ✗  {r['err']}  [{r['src']}]{flag}")
            print("    -> 无可用 IP (SNI 阻断或全部超时)")
            continue
        for r in rows:
            print(f"    {r['ip']:<18} ✓  {r['ms']:>5} ms   cert=OK  [{r['src']}]")
        best[domain] = rows[0]["ip"]
        print(f"    -> 优选 {rows[0]['ip']}  ({rows[0]['ms']} ms, 来自 {rows[0]['src']})")

    print("\n" + "=" * 72)
    print(" 最优 IP 表 (可直接粘进 hosts)")
    print("=" * 72)
    if best:
        print(build_hosts_block(best))
    else:
        print("(全部不可用 —— 见文末替代方案)")

    if args.hosts and best:
        p = os.path.join(os.path.dirname(os.path.abspath(__file__)), "tv_hosts.txt")
        with open(p, "w", encoding="utf-8") as f:
            f.write(build_hosts_block(best))
        print(f"[+] hosts 片段已写入: {p}")

    if args.apply and best:
        apply_hosts(best)

    if args.verify and best:
        print("\n--- HTTP 验证 ---")
        for domain, ip in best.items():
            st = http_verify(domain, ip)
            print(f"  {domain:<32} -> {st}")
        print("\n提示: 若 TLS ✓ 但 HTTP 返回空/RST, 说明在应用层被重置,")
        print("      此时 hosts 无效, 必须改走方案二(widget)或加密隧道。")

    return 0


if __name__ == "__main__":
    sys.exit(main())
