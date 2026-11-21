#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
tv_fetch.py  —  免账号直连 TradingView 行情服务, 拉 OHLCV 出 CSV/JSON

不依赖 tvdatafeed(那个包常年失修)。直接说 TradingView 自己的
socket.io 协议, 走 guest token (unauthorized_user_token)。

依赖:
  pip install websocket-client

用法:
  python tv_fetch.py --symbol NASDAQ:AAPL --tf 1D --bars 500
  python tv_fetch.py --symbol SSE:000001 --tf 60 --bars 300 --out sh.csv
  python tv_fetch.py --symbol BINANCE:BTCUSDT --tf 15 --bars 1000 --json
  python tv_fetch.py --check                 # 只测 data.tradingview.com 能不能握上手

时间周期写法: 1 3 5 15 30 45 60 120 180 240 D W M
交易所前缀必须写, 例如 NASDAQ: / NYSE: / SSE: / SZSE: / HKEX: / FX: /
FX_IDC: / BINANCE: / COMEX: / NYMEX: / SP: / TVC:
"""

import argparse
import csv
import json
import os
import random
import re
import string
import sys
import time

try:
    import websocket  # websocket-client
except ImportError:
    sys.exit("缺少依赖, 请先执行:  pip install websocket-client")

WS_URL = ("wss://data.tradingview.com/socket.io/websocket"
          "?from=chart%2F&type=chart")
ORIGIN = "https://www.tradingview.com"
TOKEN = "unauthorized_user_token"   # guest 模式, 无需注册

HEARTBEAT_RE = re.compile(r"~m~(\d+)~m~")
MSG_RE = re.compile(r"~m~\d+~m~(.*?)(?=~m~\d+~m~|$)", re.S)


# ---------------------------------------------------------------- 协议封装

def _rand(prefix: str, n: int = 12) -> str:
    body = "".join(random.choice(string.ascii_lowercase + string.digits)
                   for _ in range(n))
    return prefix + body


def _frame(payload: str) -> str:
    return "~m~{}~m~{}".format(len(payload.encode()), payload)


def _send(ws, method: str, params):
    ws.send(_frame(json.dumps({"m": method, "p": params}, separators=(",", ":"))))


def _split_frames(raw: str):
    """把服务端一坨数据切成若干条 payload"""
    return [m.strip() for m in MSG_RE.findall(raw) if m and m.strip()]


# ---------------------------------------------------------------- 主体

def fetch(symbol: str, tf: str, bars: int, timeout: float = 20.0,
          verbose: bool = False, proxy: str = ""):
    sess = _rand("cs_")
    sym_id = "sds_sym_1"
    ser_id = "sds_1"

    sym_spec = json.dumps({
        "adjustment": "splits",
        "symbol": symbol,
    }, separators=(",", ":"))

    kw = dict(timeout=timeout,
              origin=ORIGIN,
              header=["User-Agent: Mozilla/5.0"])
    if proxy:
        # 格式 http://127.0.0.1:7897 或 127.0.0.1:7897
        p = proxy.replace("http://", "").replace("https://", "")
        host, _, port = p.partition(":")
        kw.update(http_proxy_host=host,
                  http_proxy_port=int(port or 8080),
                  proxy_type="http")
        print(f"[*] 经代理 {host}:{port}", file=sys.stderr)

    ws = websocket.create_connection(WS_URL, **kw)
    got = None
    deadline = time.time() + timeout

    try:
        _send(ws, "set_auth_token", [TOKEN])
        _send(ws, "chart_create_session", [sess, ""])
        _send(ws, "resolve_symbol", [sess, sym_id, "=" + sym_spec])
        _send(ws, "create_series",
              [sess, ser_id, "s1", sym_id, tf, int(bars), ""])

        while time.time() < deadline:
            try:
                raw = ws.recv()
            except websocket.WebSocketTimeoutException:
                break
            if not raw:
                continue

            for payload in _split_frames(raw):
                # 心跳必须原样回, 否则被踢
                hb = HEARTBEAT_RE.search(payload)
                if hb and payload.strip().startswith("~h~"):
                    ws.send(_frame(payload.strip()))
                    continue
                if payload.startswith("~h~"):
                    ws.send(_frame(payload))
                    continue

                try:
                    msg = json.loads(payload)
                except Exception:
                    continue

                m = msg.get("m")
                if verbose:
                    print(f"  <- {m}", file=sys.stderr)

                if m == "timescale_update":
                    body = msg["p"][1]
                    if ser_id in body and "s" in body[ser_id]:
                        got = body[ser_id]["s"]
                        break

                if m == "series_completed":
                    # 数据可能在前面的 timescale_update 里, 这里兜底再等等
                    if got:
                        break

                if m == "symbol_error":
                    raise RuntimeError(f"标的解析失败: {symbol}  ({msg.get('p')})")

                if m in ("critical_error", "protocol_error"):
                    raise RuntimeError(f"服务端错误: {payload[:200]}")

            if got:
                break
    finally:
        try:
            ws.close()
        except Exception:
            pass

    if not got:
        raise RuntimeError("未收到 K 线数据 —— 可能 IP 被限流或标的写法不对")

    rows = []
    for bar in got:
        v = bar.get("v") or []
        if len(v) < 5:
            continue
        rows.append({
            "time": int(v[0]),
            "open": float(v[1]),
            "high": float(v[2]),
            "low": float(v[3]),
            "close": float(v[4]),
            "volume": float(v[5]) if len(v) > 5 and v[5] is not None else 0.0,
        })
    rows.sort(key=lambda r: r["time"])
    return rows


def check(proxy: str = ""):
    print(f"连接 {WS_URL}")
    t0 = time.time()
    kw = dict(timeout=10, origin=ORIGIN,
              header=["User-Agent: Mozilla/5.0"])
    if proxy:
        p = proxy.replace("http://", "").replace("https://", "")
        host, _, port = p.partition(":")
        kw.update(http_proxy_host=host, http_proxy_port=int(port or 8080),
                  proxy_type="http")
        print(f"[*] 经代理 {host}:{port}")
    try:
        ws = websocket.create_connection(WS_URL, **kw)
        ms = int((time.time() - t0) * 1000)
        print(f"  ✓ WebSocket 握手成功  {ms} ms")
        _send(ws, "set_auth_token", [TOKEN])
        raw = ws.recv()
        print(f"  ✓ 收到首帧 ({len(raw)} 字节)")
        ws.close()
        print("\n结论: data.tradingview.com 可用, tv_fetch.py 可以直接跑。")
        return 0
    except Exception as e:
        print(f"  ✗ 失败: {type(e).__name__}: {e}")
        print("\n结论: 481/443 被拦。先跑 tv_probe.py --apply 写 hosts,")
        print("      或在 tv_fetch.py 里给 websocket.create_connection 加 proxy。")
        return 1


def main():
    ap = argparse.ArgumentParser(description="TradingView 免账号 K 线抓取")
    ap.add_argument("--symbol", help="交易所:代码, 例 NASDAQ:AAPL")
    ap.add_argument("--tf", default="1D", help="周期: 1/5/15/60/240/D/W/M")
    ap.add_argument("--bars", type=int, default=500, help="K 线根数")
    ap.add_argument("--out", help="CSV 输出路径")
    ap.add_argument("--json", action="store_true", help="输出 JSON 到 stdout")
    ap.add_argument("--proxy", default="",
                    help="HTTP 代理, 例 127.0.0.1:7897")
    ap.add_argument("--check", action="store_true", help="只测连通性")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()

    if args.check:
        return check(args.proxy)
    if not args.symbol:
        ap.error("需要 --symbol, 例如 --symbol NASDAQ:AAPL")

    if ":" not in args.symbol:
        print("[!] 建议带交易所前缀, 否则可能解析到别家同名标的。", file=sys.stderr)

    print(f"[*] {args.symbol}  {args.tf}  {args.bars} bars", file=sys.stderr)
    rows = fetch(args.symbol, args.tf, args.bars,
                 verbose=args.verbose, proxy=args.proxy)
    print(f"[+] 拿到 {len(rows)} 根", file=sys.stderr)

    if args.json:
        print(json.dumps(rows, ensure_ascii=False, indent=2))
        return 0

    out = args.out or (re.sub(r"[^A-Za-z0-9]+", "_", args.symbol)
                       + "_" + str(args.tf) + ".csv")
    out = os.path.abspath(out)
    with open(out, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.DictWriter(f, fieldnames=["time", "open", "high", "low",
                                          "close", "volume"])
        w.writeheader()
        for r in rows:
            r = dict(r)
            r["time"] = time.strftime("%Y-%m-%d %H:%M:%S",
                                      time.localtime(r["time"]))
            w.writerow(r)
    print(f"[+] 已写入 {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
