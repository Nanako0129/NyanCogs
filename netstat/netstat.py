"""Live connection metrics for the bot, plus a heartbeat for an external watchdog."""

from __future__ import annotations

import asyncio
import contextlib
import ipaddress
import json
import logging
import math
import time
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urlsplit

import aiohttp
import discord
import lavalink
from redbot.core import Config, commands
from redbot.core.bot import Red

log = logging.getLogger("red.nyancogs.netstat")

SNMP = Path("/proc/net/snmp")
# One edit every 5 s keeps a live embed readable and far below Discord's edit rate limit.
EDIT_EVERY = 5
# Paired with the n8n watchdog's 180 s silence rule: one lost beat leaves a gap of 120 s plus at
# most two 10 s POST timeouts, so it never alerts.
HEARTBEAT_EVERY = 60
# Lavalink sends a playerUpdate every 5 s by default; an older ping belongs to a past session.
PING_MAX_AGE = 15
# Opus sends 20 ms frames, so one playing player emits 50 UDP datagrams/s
# (measured on the Oracle host 2026-11-03: 200 of 200 100 ms windows held 5).
OPUS_PER_SECOND = 50
MIN_SECONDS, MAX_SECONDS = 15, 900

Sample = Optional[tuple[float, int]]  # (time.monotonic(), Udp OutDatagrams)


def parse_udp_out(text: str) -> Optional[int]:
    """Return Udp OutDatagrams from /proc/net/snmp text (a header line, then a value line)."""
    rows = [line.split()[1:] for line in text.splitlines() if line.startswith("Udp:")]
    if len(rows) < 2:
        return None
    try:
        return int(dict(zip(rows[0], rows[1]))["OutDatagrams"])
    except (KeyError, ValueError):
        return None


async def udp_sample() -> Sample:
    """Read the namespace-wide UDP send counter; None where /proc is absent (not Linux)."""
    try:
        text = await asyncio.to_thread(SNMP.read_text)
    except OSError:
        return None
    count = parse_udp_out(text)
    return None if count is None else (time.monotonic(), count)


def udp_rate(prev: Sample, cur: Sample) -> Optional[float]:
    """Datagrams per second between two samples; None without a usable pair."""
    if prev is None or cur is None or cur[0] <= prev[0] or cur[1] < prev[1]:
        return None
    return (cur[1] - prev[1]) / (cur[0] - prev[0])


def ping_from(raw: dict) -> Optional[int]:
    """Voice WS ping from a raw Lavalink playerUpdate; Lavalink sends -1 when unconnected."""
    state = raw.get("state")
    ping = state.get("ping") if isinstance(state, dict) else None
    if isinstance(ping, bool) or not isinstance(ping, (int, float)) or ping < 0:
        return None
    return int(ping)


def _ms(seconds: float) -> Optional[int]:
    return round(seconds * 1000) if math.isfinite(seconds) else None


def _frames(value: Any) -> Optional[int]:
    return value if isinstance(value, int) and value >= 0 else None


def webhook_allowed(url: str) -> bool:
    """https anywhere; plain http only to a non-public IP literal (LAN, loopback, tailnet)."""
    try:
        parts = urlsplit(url)
        parts.port  # raises ValueError when out of range
        if parts.scheme == "https" and parts.hostname:
            return True
        return parts.scheme == "http" and not ipaddress.ip_address(parts.hostname or "").is_global
    except ValueError:
        return False


def snapshot(
    latency: float, pings: dict[int, tuple[Optional[int], float]], now: float
) -> dict[str, Any]:
    """Current metrics; every unknown value is None so the JSON stays valid (no NaN/Infinity)."""
    nodes = lavalink.get_all_nodes()
    # Red-Lavalink never clears Node.stats on disconnect, so only a ready node's stats are current.
    stats = next((n.stats for n in nodes if n.ready and n.stats is not None), None)
    players = lavalink.active_players()
    seen = [pings.get(pl.guild.id) for pl in players]
    voice = [p for p, t in filter(None, seen) if p is not None and now - t <= PING_MAX_AGE]
    return {
        "gateway_ms": _ms(latency),
        "lavalink_ready": any(n.ready for n in nodes),
        "playing": len(players),
        "voice_ping_ms": max(voice, default=None),
        "frames_sent": _frames(getattr(stats, "frames_sent", None)),
        "frames_nulled": _frames(getattr(stats, "frames_nulled", None)),
        "frames_deficit": _frames(getattr(stats, "frames_deficit", None)),
    }


def heartbeat_body(snap: dict[str, Any], rate: Optional[float], ts: int) -> str:
    return json.dumps(
        {"ts": ts, **snap, "udp_out_per_s": None if rate is None else round(rate, 1)},
        allow_nan=False,
    )


def build_embed(snap: dict[str, Any], rate: Optional[float], left: float) -> discord.Embed:
    def show(value: Any, unit: str = " ms") -> str:
        return "N/A" if value is None else f"{value}{unit}"

    frames = (snap["frames_sent"], snap["frames_nulled"], snap["frames_deficit"])
    embed = discord.Embed(title="Network status", colour=discord.Colour.blurple())
    embed.add_field(name="Gateway", value=show(snap["gateway_ms"]))
    embed.add_field(name="Voice WS ping", value=show(snap["voice_ping_ms"]))
    embed.add_field(
        name="Lavalink",
        value=f"{'ready' if snap['lavalink_ready'] else 'not ready'} · {snap['playing']} playing",
    )
    embed.add_field(
        name="Frames (last minute)",
        value="no data" if None in frames else "sent {} · nulled {} · deficit {}".format(*frames),
    )
    embed.add_field(
        name="UDP sent",
        value=f"{show(None if rate is None else round(rate, 1), '/s')} (expect {OPUS_PER_SECOND * snap['playing']}/s)",
    )
    embed.set_footer(
        text=f"Updating every {EDIT_EVERY} s · {int(left)} s left" if int(left) > 0 else "Finished"
    )
    return embed


class NetStat(commands.Cog):
    """Live gateway, Lavalink and voice-send metrics, and a heartbeat for alerting."""

    def __init__(self, bot: Red):
        self.bot = bot
        self.config = Config.get_conf(self, identifier=0x4E45_5453_0129, force_registration=True)
        self.config.register_global(webhook=None)
        self._pings: dict[int, tuple[Optional[int], float]] = {}  # guild -> (ping, monotonic)
        self._session: Optional[aiohttp.ClientSession] = None
        self._task: Optional[asyncio.Task] = None
        self._closed = False  # ends running [p]netstat loops on unload

    async def red_delete_data_for_user(self, *, requester: str, user_id: int) -> None:
        """Nothing to delete: this cog stores no per-user data."""
        return

    async def cog_load(self) -> None:
        lavalink.register_update_listener(self._on_player_update)
        self._session = aiohttp.ClientSession()
        self._task = asyncio.create_task(self._heartbeat())

    async def cog_unload(self) -> None:
        self._closed = True
        lavalink.unregister_update_listener(self._on_player_update)
        if self._task:
            self._task.cancel()
        if self._session:
            await self._session.close()

    async def _on_player_update(self, player: lavalink.Player, _position: Any, raw: dict) -> None:
        self._pings[player.guild.id] = (ping_from(raw), time.monotonic())

    def _snapshot(self) -> dict[str, Any]:
        return snapshot(self.bot.latency, self._pings, time.monotonic())

    async def _heartbeat(self) -> None:
        # Before ready, gateway and Lavalink read as down: a beat then would be a false alarm.
        await self.bot.wait_until_red_ready()
        prev: Sample = None
        while True:
            try:
                url = await self.config.webhook()
                cur = await udp_sample() if url else None
                rate, prev = udp_rate(prev, cur), cur
                if url:
                    body = heartbeat_body(self._snapshot(), rate, int(time.time()))
                    async with self._session.post(
                        url,
                        data=body,
                        headers={"Content-Type": "application/json"},
                        timeout=aiohttp.ClientTimeout(total=10),
                        allow_redirects=False,  # a redirect would turn the POST into a bodiless GET
                    ) as resp:
                        if resp.status >= 300:
                            log.warning("Heartbeat rejected with HTTP %s", resp.status)
            except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
                # The exception text can carry the webhook URL, so only its type is logged.
                log.warning("Heartbeat failed: %s", type(exc).__name__)
            except Exception:
                log.exception("Heartbeat iteration failed")
            await asyncio.sleep(HEARTBEAT_EVERY)

    @commands.is_owner()
    @commands.command()
    async def netstat(self, ctx: commands.Context, seconds: int = 180) -> None:
        """Show live gateway, Lavalink and voice-send metrics for `seconds` (15-900)."""
        seconds = max(MIN_SECONDS, min(MAX_SECONDS, seconds))
        end = time.monotonic() + seconds
        prev = await udp_sample()
        message = await ctx.send(embed=build_embed(self._snapshot(), None, seconds))
        while not self._closed and (left := end - time.monotonic()) > 0:
            await asyncio.sleep(min(EDIT_EVERY, left))
            cur = await udp_sample()
            try:
                await message.edit(
                    embed=build_embed(self._snapshot(), udp_rate(prev, cur), end - time.monotonic())
                )
            except discord.HTTPException:  # deleted message, lost permission, Discord outage
                return
            prev = cur
        if self._closed:  # unloaded mid-run: don't leave a countdown that never finishes
            with contextlib.suppress(discord.HTTPException):
                await message.edit(embed=build_embed(self._snapshot(), None, 0))

    @commands.is_owner()
    @commands.group()
    async def netstatset(self, ctx: commands.Context) -> None:
        """Configure the netstat heartbeat."""

    @netstatset.command(name="webhook")
    async def netstatset_webhook(self, ctx: commands.Context, url: str) -> None:
        """POST a heartbeat to `url` every 60 s; `clear` stops it. Use the n8n production `/webhook/` URL."""
        if url.lower() == "clear":
            await self.config.webhook.set(None)
            await ctx.send("Heartbeat stopped.")
            return
        # The URL is the watchdog's only credential: take it off the channel before anything else.
        note = ""
        try:
            await ctx.message.delete()  # also fails in DMs, where a bot can't delete your messages
        except discord.HTTPException:
            note = " I could not delete your message: delete it yourself, the URL is a secret."
        if not webhook_allowed(url):
            await ctx.send("Use an https URL, or http only to a private, loopback or tailnet IP." + note)
            return
        await self.config.webhook.set(url)
        await ctx.send(f"Heartbeat set; first beat within {HEARTBEAT_EVERY} s." + note)
