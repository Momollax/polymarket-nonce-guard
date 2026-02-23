# Polymarket Nonce

Detect and defend against the **nonce race** on Polymarket's CTF Exchange.
###
LEGIT BOT BOT VALUE BOT VALUE BOT VALUEa
 on Polymarket call `incrementNonce()` on the [CTF Exchange contract](https://polygonscan.com/address/0x4bFb41d5B3570DeFd03C39a9A4D8dE6Bd8B8982E) to invalidate their losing orders before the operator can settle them. This means:

- They place bets on both sides of a market
- When the outcome becomes clear, they cancel the losing side via `incrementNonce()`
- The winning side settles normally → risk-free profit
- **You** end up holding shares that were supposed to be matched but never settle ("ghost fills")


## Tools

### `nonce_monitor.py` — Real-time incrementNonce watcher
Polls Polygon blocks every 2s, filters for `incrementNonce()` calls (method sig `0x627cdcb9`) to the CTF Exchange. Logs every event with timing relative to BTC 5-min market windows.

```bash
python nonce_monitor.py
```

Output: `data/nonce_events.jsonl` — append-only log of every detected call with caller address, tx hash, block, gas price, and market window timing.

### `blacklist.py` — Exploiter address database
Loads known exploiter addresses from `nonce_events.jsonl` + a manual `data/blacklist_manual.txt`. Auto-refreshes every 60s.

```python
from blacklist import Blacklist
bl = Blacklist()
bl.is_blacklisted("0x1234...")  # True/False
```

### `counterparty_checker.py` — On-chain fill analysis
Given a transaction hash, parses CTF Exchange logs to extract maker/taker addresses from settled orders.

```python
from counterparty_checker import get_counterparty
counterparty = get_counterparty(tx_hash="0x...")
```

### `manipulation_detector.py` — Orderbook anomaly detector
Monitors Polymarket orderbook for suspicious patterns (large orders appearing/disappearing, price  around settlement windows).

## Setup

```bash
pip install web3 requests py-clob-client
```

Requires a Polygon RPC endpoint. Default: `https://polygon-bor-rpc.publicnode.com`

## Configuration

Set these environment variables or edit the constants at the top of each file:

- `CTF_EXCHANGE` — CTF Exchange contract address (default: `0x4bFb41d5B3570DeFd03C39a9A4D8dE6Bd8B8982E`)
- Polygon RPC URLs are hardcoded with fallbacks

## Data

## Key Insight

`incrementNonce()` is a **nuclear option** — it invalidates ALL pending orders from the caller's address, not just one. The CLOB API's cancel endpoint is surgical (cancels specific orders). Exploiters who use `incrementNonce` are leaving clear on-chain fingerprints.

## License

MIT
