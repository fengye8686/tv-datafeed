# tv-datafeed

Market data client for TradingView-style charting.

- **tv_fetch.py** — OHLCV fetcher via socket.io protocol, CSV/JSON output
- **tv_probe.py** — DNS probe + TLS handshake tester + hosts generator

## Usage

    python tv_fetch.py --symbol SSE:000001 --tf 60 --bars 300 --proxy 127.0.0.1:7897

Tested with A-share, US equity, crypto symbols.
