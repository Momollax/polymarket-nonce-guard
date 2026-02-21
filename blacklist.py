"""
blacklist.py — Maintains a set of known exploiter addresses.
Sources: data/nonce_events.jsonl (caller field) + data/blacklist_manual.txt
Auto-refreshes every 60s.
"""
import json
import logging
import os
import threading
import time

logger = logging.getLogger(__name__)

DATA_DIR = os.path.join(os.path.dirname(__file__), "data")
NONCE_EVENTS_FILE = os.path.join(DATA_DIR, "nonce_events.jsonl")
MANUAL_BLACKLIST_FILE = os.path.join(DATA_DIR, "blacklist_manual.txt")
REFRESH_INTERVAL = 60


class Blacklist:
    def __init__(self):
        self._addresses: set[str] = set()
        self._lock = threading.Lock()
        self._last_refresh = 0.0
        self.refresh()

    def refresh(self):
        addrs = set()

        # nonce_events.jsonl
        if os.path.exists(NONCE_EVENTS_FILE):
            try:
                with open(NONCE_EVENTS_FILE, "r") as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            caller = json.loads(line).get("caller", "").strip().lower()
                            if caller:
                                addrs.add(caller)
                        except json.JSONDecodeError:
                            pass
            except Exception as e:
                logger.warning(f"Failed to read {NONCE_EVENTS_FILE}: {e}")

        # Manual blacklist
        if os.path.exists(MANUAL_BLACKLIST_FILE):
            try:
                with open(MANUAL_BLACKLIST_FILE, "r") as f:
                    for line in f:
                        addr = line.strip().lower()
                        if addr and not addr.startswith("#"):
                            addrs.add(addr)
            except Exception as e:
                logger.warning(f"Failed to read {MANUAL_BLACKLIST_FILE}: {e}")

        with self._lock:
            old_count = len(self._addresses)
            self._addresses = addrs
            self._last_refresh = time.time()
            if len(addrs) != old_count:
                logger.info(f"Blacklist refreshed: {len(addrs)} addresses (was {old_count})")

    def _maybe_refresh(self):
        if time.time() - self._last_refresh >= REFRESH_INTERVAL:
            self.refresh()

    def is_blacklisted(self, address: str) -> bool:
        self._maybe_refresh()
        with self._lock:
            return address.strip().lower() in self._addresses

    @property
    def count(self) -> int:
        with self._lock:
            return len(self._addresses)

    @property
    def addresses(self) -> set[str]:
        with self._lock:
            return set(self._addresses)


# Module-level singleton
_instance: Blacklist | None = None


def get_blacklist() -> Blacklist:
    global _instance
    if _instance is None:
        _instance = Blacklist()
    return _instance


def is_blacklisted(address: str) -> bool:
    return get_blacklist().is_blacklisted(address)
