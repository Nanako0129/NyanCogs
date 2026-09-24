"""Let Red's Audio play Spotify playlists again.

Spotify now answers ``GET /v1/playlists/{id}/tracks`` with 403 for client-credentials tokens, which is the
only kind Red's Audio holds. Red 3.5.24 treats that error body as an empty playlist and replies "This doesn't
seem to be a supported Spotify URL or code." Single tracks and albums still work.

This cog wraps ``SpotifyWrapper.make_get_call``, the one call every Spotify request in Audio goes through. When a
playlist-tracks call comes back as an error, it reads the playlist from Spotify's public embed page and returns it
in the Web API's own paging shape, so Audio's YouTube matching, queueing and caching run unchanged.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import re
from typing import Any, Dict, List, Optional

import aiohttp
from redbot.core import commands
from redbot.core.bot import Red

log = logging.getLogger("red.nyancogs.spotifyplaylist")

PLAYLIST_TRACKS_RE = re.compile(r"^https://api\.spotify\.com/v1/playlists/([A-Za-z0-9]{22})/tracks$")
NEXT_DATA_RE = re.compile(r'<script id="__NEXT_DATA__" type="application/json">(.*?)</script>', re.S)
EMBED_URL = "https://open.spotify.com/embed/playlist/{}"
_PATCH_FLAG = "_nyancogs_spotifyplaylist_original"


def parse_embed(html: str) -> List[Dict[str, Any]]:
    """Turn an embed page into Web API playlist items (``[{"track": {...}}]``) carrying the fields Audio reads."""
    match = NEXT_DATA_RE.search(html)
    if not match:
        return []
    try:
        entity = json.loads(match.group(1))["props"]["pageProps"]["state"]["data"]["entity"]
    except (ValueError, KeyError, TypeError):
        return []
    items = []
    for entry in entity.get("trackList") or []:
        uri = entry.get("uri") or ""
        track_id = uri.rpartition(":")[2]
        if not entry.get("title") or not uri.startswith("spotify:track:") or not track_id:
            continue  # episodes and local files have no track to search for
        artists = [{"name": name} for name in re.split(r",\s*", entry.get("subtitle") or "") if name]  # joined by ",\xa0"
        items.append({"track": {
            "name": entry["title"],
            "artists": artists or [{"name": ""}],
            "external_urls": {"spotify": f"https://open.spotify.com/track/{track_id}"},
            "uri": uri,
            "id": track_id,
            "type": "track",
        }})
    return items


async def fetch_embed_items(session: Any, playlist_id: str) -> List[Dict[str, Any]]:
    # ponytail: the embed page is undocumented and may cap long playlists; switch to user OAuth if it breaks.
    async with session.get(EMBED_URL.format(playlist_id), headers={"User-Agent": "Mozilla/5.0"},
                           timeout=aiohttp.ClientTimeout(total=15)) as resp:
        if resp.status != 200:
            log.warning("Spotify embed fallback failed: HTTP %s", resp.status)
            return []
        return parse_embed(await resp.text())


def _patch(api_cls: type) -> None:
    if hasattr(api_cls, _PATCH_FLAG):
        return
    original = api_cls.make_get_call

    async def make_get_call(self, url: str, params: Optional[Dict] = None) -> Dict:
        data = await original(self, url, params)
        match = PLAYLIST_TRACKS_RE.match(url)
        if not match or not isinstance(data, dict) or "error" not in data:
            return data
        try:
            items = await fetch_embed_items(self.session, match.group(1))
        except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
            log.warning("Spotify embed fallback failed: %s", type(exc).__name__)
            return data
        if not items:
            return data
        log.info("Spotify playlist %s served from embed page (%d tracks)", match.group(1), len(items))
        return {"items": items, "total": len(items), "next": None}

    setattr(api_cls, _PATCH_FLAG, original)
    api_cls.make_get_call = make_get_call


def _unpatch(api_cls: type) -> None:
    original = api_cls.__dict__.get(_PATCH_FLAG)
    if original is not None:
        api_cls.make_get_call = original
        delattr(api_cls, _PATCH_FLAG)


def _spotify_api_cls() -> type:
    # Raises on a Red that renamed the class, so `[p]load` fails loudly instead of the cog silently doing nothing.
    from redbot.cogs.audio.apis.spotify import SpotifyWrapper

    return SpotifyWrapper


class SpotifyPlaylist(commands.Cog):
    """Fall back to Spotify's embed page when the Web API refuses a playlist."""

    def __init__(self, bot: Red) -> None:
        self.bot = bot

    async def red_delete_data_for_user(self, **kwargs: Any) -> None:
        return

    async def cog_load(self) -> None:
        if self.bot.get_cog("Audio"):
            _patch(_spotify_api_cls())

    async def cog_unload(self) -> None:
        with contextlib.suppress(ImportError):
            _unpatch(_spotify_api_cls())

    @commands.Cog.listener()
    async def on_cog_add(self, cog: commands.Cog) -> None:
        # Reloading Audio purges its modules, so the fresh SpotifyWrapper class needs the wrapper again.
        if cog.qualified_name == "Audio":
            _patch(_spotify_api_cls())
