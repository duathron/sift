"""Alert result caching layer for sift.

Caches triage results by alert fingerprint so repeated pipeline runs over
overlapping alert windows skip reprocessing.  Storage is SQLite in WAL mode
under ``~/.sift/cache/`` (same permission model as other sift directories).

Design decisions
----------------
- Expiry is checked on read (lazy), not via a background thread.
- LRU eviction fires synchronously inside :meth:`AlertCache.put` whenever the
  entry count would exceed ``max_entries``.
- The cache is **disabled by default** (``enabled=False`` in :class:`CacheConfig`)
  so pipelines opt-in explicitly.
- ``get()`` increments a persistent ``hits`` counter and updates an
  ``accessed_at`` column used for LRU ordering.
- Stats (hits / misses) are tracked in-process; they reset when the object is
  garbage-collected.  Persistent hit counts live in the DB.
"""

from __future__ import annotations

import json
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from pydantic import BaseModel

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_DIR_MODE = 0o700
_DB_FILENAME = "alerts.db"


# ---------------------------------------------------------------------------
# Configuration model
# ---------------------------------------------------------------------------


class CacheConfig(BaseModel):
    """Configuration for the alert result cache.

    Attributes
    ----------
    enabled:
        When ``False`` all cache operations become no-ops.  Defaults to
        ``False`` so callers must explicitly opt in.
    ttl_seconds:
        Time-to-live for a cache entry in seconds.  Entries older than this
        are treated as misses on read.
    max_entries:
        Maximum number of entries stored in the database.  When exceeded the
        least-recently-used entry is evicted before writing a new one.
    cache_dir:
        Directory that contains ``alerts.db``.  Created with ``0o700``
        permissions on first use.
    """

    enabled: bool = False
    ttl_seconds: int = 3600
    max_entries: int = 10000
    cache_dir: Path = Path("~/.sift/cache").expanduser()


# ---------------------------------------------------------------------------
# Entry model
# ---------------------------------------------------------------------------


class CacheEntry(BaseModel):
    """A single row retrieved from the cache database.

    Attributes
    ----------
    fingerprint:
        SHA-256 hex digest of the normalized alert content.
    result_json:
        JSON-serialized triage result stored as a string.
    created_at:
        UTC timestamp when this entry was first written.
    hits:
        Number of times this entry has been returned as a cache hit.
    """

    fingerprint: str
    result_json: str
    created_at: datetime
    hits: int = 0


# ---------------------------------------------------------------------------
# Main cache class
# ---------------------------------------------------------------------------


class AlertCache:
    """SQLite-backed LRU cache for alert triage results.

    Parameters
    ----------
    config:
        :class:`CacheConfig` instance controlling behaviour.  When
        ``config.enabled`` is ``False`` all methods become safe no-ops.
    """

    def __init__(self, config: CacheConfig) -> None:
        self._config = config
        self._hits: int = 0
        self._misses: int = 0
        self._conn: Optional[sqlite3.Connection] = None

        if config.enabled:
            self._ensure_db()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get(self, fingerprint: str) -> Optional[dict]:
        """Return the cached result for *fingerprint*, or ``None``.

        Returns ``None`` when:
        - the cache is disabled,
        - no entry exists for *fingerprint*,
        - or the entry has expired per ``ttl_seconds``.

        A successful hit increments the persistent ``hits`` counter and
        updates ``accessed_at`` for LRU tracking.
        """
        if not self._config.enabled:
            return None

        conn = self._get_conn()
        row = conn.execute(
            "SELECT fingerprint, result_json, created_at, hits "
            "FROM cache_entries WHERE fingerprint = ?",
            (fingerprint,),
        ).fetchone()

        if row is None:
            self._misses += 1
            return None

        entry = CacheEntry(
            fingerprint=row[0],
            result_json=row[1],
            created_at=datetime.fromisoformat(row[2]),
            hits=row[3],
        )

        if self._is_expired(entry):
            # Lazy expiry: remove stale entry and report miss.
            conn.execute(
                "DELETE FROM cache_entries WHERE fingerprint = ?",
                (fingerprint,),
            )
            conn.commit()
            self._misses += 1
            return None

        # Update access metadata for LRU ordering.
        now_iso = datetime.now(tz=timezone.utc).isoformat()
        conn.execute(
            "UPDATE cache_entries SET hits = hits + 1, accessed_at = ? "
            "WHERE fingerprint = ?",
            (now_iso, fingerprint),
        )
        conn.commit()

        self._hits += 1
        return json.loads(entry.result_json)

    def put(self, fingerprint: str, result: dict) -> None:
        """Store *result* under *fingerprint*.

        If inserting would exceed ``max_entries``, the least-recently-used
        entry is evicted first.  Has no effect when the cache is disabled.
        """
        if not self._config.enabled:
            return

        conn = self._get_conn()
        now_iso = datetime.now(tz=timezone.utc).isoformat()
        result_json = json.dumps(result, default=str)

        # Evict before inserting so we never breach max_entries.
        count: int = conn.execute(
            "SELECT COUNT(*) FROM cache_entries"
        ).fetchone()[0]

        # Only evict if an entry for this fingerprint does *not* already exist
        # (updates don't change the row count).
        exists: bool = (
            conn.execute(
                "SELECT 1 FROM cache_entries WHERE fingerprint = ?",
                (fingerprint,),
            ).fetchone()
            is not None
        )
        if not exists and count >= self._config.max_entries:
            self._evict_lru()

        conn.execute(
            """
            INSERT INTO cache_entries (fingerprint, result_json, created_at, accessed_at, hits)
            VALUES (?, ?, ?, ?, 0)
            ON CONFLICT(fingerprint) DO UPDATE SET
                result_json = excluded.result_json,
                created_at  = excluded.created_at,
                accessed_at = excluded.accessed_at,
                hits        = 0
            """,
            (fingerprint, result_json, now_iso, now_iso),
        )
        conn.commit()

    def invalidate(self, fingerprint: str) -> None:
        """Remove the entry for *fingerprint* from the cache.

        Silently does nothing if the entry does not exist or the cache is
        disabled.
        """
        if not self._config.enabled:
            return

        conn = self._get_conn()
        conn.execute(
            "DELETE FROM cache_entries WHERE fingerprint = ?",
            (fingerprint,),
        )
        conn.commit()

    def clear(self) -> None:
        """Remove **all** entries from the cache and reset in-process stats.

        Has no effect when the cache is disabled.
        """
        if not self._config.enabled:
            return

        conn = self._get_conn()
        conn.execute("DELETE FROM cache_entries")
        conn.commit()
        self._hits = 0
        self._misses = 0

    def stats(self) -> dict:
        """Return a snapshot of cache statistics.

        Returns
        -------
        dict with keys:
            ``hits``    — in-process hit count since instantiation (or last clear).
            ``misses``  — in-process miss count.
            ``entries`` — current row count in the database.
            ``size_bytes`` — size of the SQLite database file in bytes.
        """
        if not self._config.enabled:
            return {
                "hits": 0,
                "misses": 0,
                "entries": 0,
                "size_bytes": 0,
            }

        conn = self._get_conn()
        entries: int = conn.execute(
            "SELECT COUNT(*) FROM cache_entries"
        ).fetchone()[0]

        db_path = self._config.cache_dir / _DB_FILENAME
        size_bytes = db_path.stat().st_size if db_path.exists() else 0

        return {
            "hits": self._hits,
            "misses": self._misses,
            "entries": entries,
            "size_bytes": size_bytes,
        }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _is_expired(self, entry: CacheEntry) -> bool:
        """Return ``True`` if *entry* has exceeded its TTL."""
        now = datetime.now(tz=timezone.utc)
        # Ensure created_at is timezone-aware.
        created = entry.created_at
        if created.tzinfo is None:
            created = created.replace(tzinfo=timezone.utc)
        age_seconds = (now - created).total_seconds()
        return age_seconds > self._config.ttl_seconds

    def _evict_lru(self) -> None:
        """Delete the single least-recently-used entry from the database."""
        conn = self._get_conn()
        conn.execute(
            """
            DELETE FROM cache_entries
            WHERE fingerprint = (
                SELECT fingerprint FROM cache_entries
                ORDER BY accessed_at ASC
                LIMIT 1
            )
            """
        )
        conn.commit()

    # Sensitive directories that must never be used as cache locations.
    _BLOCKED_DIR_PREFIXES: tuple[Path, ...] = (
        Path.home() / ".ssh",
        Path.home() / ".gnupg",
        Path("/etc"),
        Path("/usr"),
        Path("/bin"),
        Path("/sbin"),
        Path("/boot"),
        Path("/sys"),
        Path("/proc"),
    )

    @classmethod
    def _validate_cache_dir(cls, cache_dir: Path) -> None:
        """Reject cache_dir paths that point at sensitive system directories.

        Prevents path traversal attacks where a crafted CacheConfig writes
        SQLite WAL files into sensitive directories (e.g. ~/.ssh/, /etc/).
        """
        resolved = cache_dir.resolve()
        for blocked in cls._BLOCKED_DIR_PREFIXES:
            try:
                resolved.relative_to(blocked.resolve())
                raise ValueError(
                    f"cache_dir {cache_dir!r} resolves to a sensitive system directory "
                    f"({blocked}) — refusing to create SQLite files there."
                )
            except ValueError as exc:
                if "resolves to a sensitive" in str(exc):
                    raise

    def _ensure_db(self) -> None:
        """Create the cache directory and initialise the SQLite schema."""
        cache_dir = self._config.cache_dir
        self._validate_cache_dir(cache_dir)
        cache_dir.mkdir(mode=_DIR_MODE, parents=True, exist_ok=True)
        # Ensure permissions even if directory already existed.
        cache_dir.chmod(_DIR_MODE)

        db_path = cache_dir / _DB_FILENAME
        conn = sqlite3.connect(str(db_path))
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=5000")
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS cache_entries (
                fingerprint TEXT PRIMARY KEY,
                result_json TEXT NOT NULL,
                created_at  TEXT NOT NULL,
                accessed_at TEXT NOT NULL,
                hits        INTEGER NOT NULL DEFAULT 0
            )
            """
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_accessed_at ON cache_entries(accessed_at)"
        )
        conn.commit()
        self._conn = conn

    def _get_conn(self) -> sqlite3.Connection:
        """Return the open SQLite connection, opening it if necessary."""
        if self._conn is None:
            self._ensure_db()
        assert self._conn is not None
        return self._conn

    def close(self) -> None:
        """Close the underlying database connection."""
        if self._conn is not None:
            self._conn.close()
            self._conn = None

    def __del__(self) -> None:
        self.close()
