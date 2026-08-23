"""
DeepSteg v4 — Tamper-Evident Audit Log  (Production Gap PG-02)
===============================================================
Append-only log where each entry is HMAC-chained to the previous one.
Any deletion or modification of an earlier entry breaks the chain.

Format per entry (JSON-lines):
  { "seq": N, "ts": ISO8601, "event": str, "detail": dict,
    "prev_hash": hex, "this_hash": hex }
"""

from __future__ import annotations
import hashlib, hmac, json, os, time
from pathlib import Path
from typing import Optional

AUDIT_SECRET_ENV = "DEEPSTEG_AUDIT_SECRET"

class AuditLog:
    def __init__(self, path: str, secret: Optional[bytes] = None):
        self.path   = Path(path)
        # Secret key for HMAC chain — use env var in production
        self.secret = secret or os.environ.get(
            AUDIT_SECRET_ENV, "deepsteg-audit-dev-key").encode()
        self._seq   = 0
        self._prev  = b'\x00' * 32
        self._load_state()

    def _hmac(self, data: bytes) -> str:
        return hmac.new(self.secret, data, hashlib.sha256).hexdigest()

    def _load_state(self):
        """Read last entry to restore chain state."""
        if not self.path.exists():
            return
        last_line = None
        with open(self.path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line:
                    last_line = line
        if last_line:
            try:
                entry     = json.loads(last_line)
                self._seq = entry.get("seq", 0) + 1
                self._prev = bytes.fromhex(entry.get("this_hash", "0" * 64))
            except Exception:
                pass  # corrupted last line — new chain from here

    def append(self, event: str, detail: dict = None) -> dict:
        """
        Append one event to the audit log.
        Returns the entry dict (for confirmation / display).
        """
        entry_core = {
            "seq":       self._seq,
            "ts":        time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
            "event":     event,
            "detail":    detail or {},
            "prev_hash": self._prev.hex(),
        }
        # Hash = HMAC(prev_hash || seq || event || detail_json)
        chain_input = (self._prev
                       + str(self._seq).encode()
                       + event.encode()
                       + json.dumps(detail or {}, sort_keys=True).encode())
        this_hash = self._hmac(chain_input)
        entry_core["this_hash"] = this_hash

        line = json.dumps(entry_core, separators=(',', ':')) + '\n'
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.path, 'a', encoding='utf-8') as f:
            f.write(line)

        self._prev = bytes.fromhex(this_hash)
        self._seq += 1
        return entry_core

    def verify_chain(self) -> dict:
        """
        Verify the HMAC chain of the entire log.
        Returns {'valid': bool, 'entries': int, 'first_bad': int|None}
        """
        if not self.path.exists():
            return {'valid': True, 'entries': 0, 'first_bad': None}

        prev  = b'\x00' * 32
        count = 0
        with open(self.path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry  = json.loads(line)
                    detail = entry.get('detail', {})
                    chain_input = (prev
                                   + str(entry['seq']).encode()
                                   + entry['event'].encode()
                                   + json.dumps(detail, sort_keys=True).encode())
                    expected = self._hmac(chain_input)
                    if entry['this_hash'] != expected:
                        return {'valid': False, 'entries': count,
                                'first_bad': entry['seq']}
                    prev  = bytes.fromhex(entry['this_hash'])
                    count += 1
                except Exception as e:
                    return {'valid': False, 'entries': count,
                            'first_bad': count, 'error': str(e)}

        return {'valid': True, 'entries': count, 'first_bad': None}

    def tail(self, n: int = 20) -> list:
        """Return the last n entries as a list of dicts."""
        entries = []
        if not self.path.exists():
            return entries
        with open(self.path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        entries.append(json.loads(line))
                    except Exception:
                        pass
        return entries[-n:]
