"""IP geolocation resolver.

Supports two providers:

* ``ip-api`` — free public API at https://ip-api.com/ (rate limited to 45
  requests/min for the free tier). No key required.
* ``maxmind`` — local MaxMind GeoLite2 City database. Requires the ``geoip2``
  package and a downloaded ``GeoLite2-City.mmdb`` file.

Both are wrapped behind the same :meth:`GeoResolver.resolve` interface and
an in-memory LRU cache so repeat lookups are free.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import urllib.parse
import urllib.request
from collections import OrderedDict
from typing import Any

from honeytrap.core.config import GeoConfig

logger = logging.getLogger(__name__)


_UNKNOWN = {"country_code": "XX", "country_name": "Unknown", "asn": "", "city": ""}


class GeoResolver:
    """Resolve IPs to country-level geography with caching."""

    def __init__(self, config: GeoConfig) -> None:
        """Initialize the GeoIP resolver.
        
                Uses the free ip-api.com service by default, or a local MaxMind
                GeoLite2 database if a path is provided.
        """
        self.config = config
        self._cache: OrderedDict[str, dict[str, str]] = OrderedDict()
        self._maxmind: Any = None
        self._maxmind_tried = False

    async def resolve(self, ip: str) -> dict[str, str]:
        """Return geo info for an IP address."""
        if not ip or not self.config.enabled:
            return dict(_UNKNOWN)

        if ip in self._cache:
            self._cache.move_to_end(ip)
            return dict(self._cache[ip])

        try:
            parsed = ipaddress.ip_address(ip)
            if parsed.is_private or parsed.is_loopback or parsed.is_link_local:
                result = {**_UNKNOWN, "country_name": "Private"}
                self._cache_set(ip, result)
                return result
        except ValueError:
            return dict(_UNKNOWN)

        provider = (self.config.provider or "ip-api").lower()
        try:
            if provider == "maxmind":
                result = self._resolve_maxmind(ip)
            else:
                result = await self._resolve_ip_api(ip)
        except Exception as exc:  # noqa: BLE001
            logger.debug("Geo lookup failed for %s via %s: %s", ip, provider, exc)
            result = dict(_UNKNOWN)

        self._cache_set(ip, result)
        return dict(result)

    # ------------------------------------------------------------------
    # Providers
    # ------------------------------------------------------------------
    async def _resolve_ip_api(self, ip: str) -> dict[str, str]:
        """Use the free ip-api.com JSON endpoint (no key required)."""
        url = f"http://ip-api.com/json/{urllib.parse.quote(ip)}?fields=status,message,countryCode,country,city,as"

        def _call() -> dict[str, Any]:
            req = urllib.request.Request(url, headers={"User-Agent": "HoneyTrapAI/0.1"})
            with urllib.request.urlopen(req, timeout=5) as resp:  # noqa: S310 — public URL
                raw = resp.read().decode("utf-8", errors="replace")
            return json.loads(raw)

        try:
            data = await asyncio.get_running_loop().run_in_executor(None, _call)
        except Exception as exc:  # noqa: BLE001
            logger.debug("ip-api call failed: %s", exc)
            return dict(_UNKNOWN)

        if data.get("status") != "success":
            return dict(_UNKNOWN)
        return {
            "country_code": str(data.get("countryCode", "XX") or "XX"),
            "country_name": str(data.get("country", "Unknown") or "Unknown"),
            "city": str(data.get("city", "") or ""),
            "asn": str(data.get("as", "") or ""),
        }

    def _resolve_maxmind(self, ip: str) -> dict[str, str]:
        """Use a local MaxMind GeoLite2-City database."""
        reader = self._get_maxmind_reader()
        if reader is None:
            return dict(_UNKNOWN)
        try:
            rec = reader.city(ip)
        except Exception as exc:  # noqa: BLE001
            logger.debug("maxmind lookup failed: %s", exc)
            return dict(_UNKNOWN)
        return {
            "country_code": (rec.country.iso_code or "XX"),
            "country_name": (rec.country.name or "Unknown"),
            "city": (rec.city.name or "") if rec.city else "",
            "asn": "",
        }

    def _get_maxmind_reader(self) -> Any | None:
        if self._maxmind_tried:
            return self._maxmind
        self._maxmind_tried = True
        if not self.config.maxmind_db:
            return None
        try:
            import geoip2.database  # type: ignore[import-not-found]
        except ImportError:
            logger.warning("geoip2 package not installed — maxmind provider disabled")
            return None
        try:
            self._maxmind = geoip2.database.Reader(self.config.maxmind_db)
        except Exception as exc:  # noqa: BLE001
            logger.warning("Could not open MaxMind DB: %s", exc)
            self._maxmind = None
        return self._maxmind

    # ------------------------------------------------------------------
    # Cache
    # ------------------------------------------------------------------
    def _cache_set(self, ip: str, value: dict[str, str]) -> None:
        self._cache[ip] = dict(value)
        self._cache.move_to_end(ip)
        if len(self._cache) > self.config.cache_size:
            self._cache.popitem(last=False)
