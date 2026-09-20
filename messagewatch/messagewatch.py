"""Flag scam and hostile messages to moderators using a System One model.

The cog watches only channels a guild manager enabled one at a time, batches
recent messages into a short rolling window, asks TypeSafe Jev three judgements
about that window, and posts a report when one crosses its threshold. It never
deletes, edits, reacts to, or punishes anything: the whole output is a message
in a moderator channel.

Windows rather than single messages, for two reasons measured on 97 real
messages from the target guild on 2026-09-20. Hostility is a property of an
exchange, so a single message cannot carry it. And the question block is fixed
overhead per request, so batching cut the amortised cost per message by roughly
half.
"""

from __future__ import annotations

import asyncio
import json
import re
import time
from collections import defaultdict, deque
from typing import Any, Iterable, Mapping

import aiohttp
import discord
from redbot.core import Config, checks, commands
from redbot.core.bot import Red
from redbot.core.utils.views import SetApiView

TOKEN_SERVICE = "messagewatch_typesafe"
API_URL = "https://api.typesafe.ai/v1/systemone"
MODEL = "jev-latest"

# Discord's own limit is 4000 for most users; anything longer is truncated
# before it leaves, so one pasted log cannot dominate a request.
MAX_MESSAGE_CHARS = 1_000
# How much of a message is echoed into its `scam_index` option label. An option
# has to describe what it selects: with labels that said only "第 6 則訊息" the
# model pointed at the wrong message 6 times out of 6 on one real window, at
# confidence 0.77 to 0.93, so a confidence gate would not have caught it.
# Echoing the first characters of each message fixed all four planted positions
# at 0.98 to 1.00, for about 32% more input tokens.
SCAM_OPTION_LABEL_CHARS = 48
MAX_REQUEST_BYTES = 262_144
MAX_RESPONSE_BYTES = 65_536
REQUEST_TIMEOUT_SECONDS = 30.0

# Measured 2026-09-20 against jev-1.13.0 through the production key. Synthetic
# cases separated at 0.93+ for scams and 0.95 for hostility, against 0.08 and
# 0.03 for the cases designed to be mistaken for them (a warning *about* a
# phishing mail, and a heated technical argument). 97 real messages from the
# guild produced a maximum of 0.05, 0.15 and 1.53 respectively, so these sit
# far above observed background. False negatives are NOT measured: the real
# sample contained no scam and no argument to catch.
DEFAULT_SCAM_THRESHOLD = 0.90
DEFAULT_HOSTILE_THRESHOLD = 0.80
DEFAULT_HEAT_THRESHOLD = 2.50

DEFAULT_GUILD = {
    "report_channel": 0,
    "watched_channels": [],
    "disclosure_version": 0,
    "scam_threshold": DEFAULT_SCAM_THRESHOLD,
    "hostile_threshold": DEFAULT_HOSTILE_THRESHOLD,
    "heat_threshold": DEFAULT_HEAT_THRESHOLD,
    "window_size": 8,
    "cooldown_seconds": 300,
}

SETTING_RULES: dict[str, tuple[type, Any, Any]] = {
    "scam_threshold": (float, 0.0, 1.0),
    "hostile_threshold": (float, 0.0, 1.0),
    "heat_threshold": (float, 0.0, 3.0),
    "window_size": (int, 4, 25),
    "cooldown_seconds": (int, 0, 86_400),
}

DISCLOSURE_VERSION = 1
DISCLOSURE_TEXT = (
    "**What leaves Discord:** in an enabled channel, the text of recent human messages is sent "
    "to TypeSafe continuously, with nobody triggering it. This is unlike an on-demand command: "
    "enabling a channel is a standing export of what people say in it.\n"
    "**What does not:** Discord user IDs, display names and avatars are never sent. Authors are "
    "replaced with labels such as u1 and u2, generated per request and never stored. Attachments, "
    "embeds and links are not fetched or resolved.\n"
    "**Vendor:** TypeSafe states it does not train on customer input. Its retention terms and the "
    "accuracy of its judgements are unverified by this cog.\n"
    "**What the bot does with a result:** posts a report in the configured moderator channel. It "
    "never deletes, edits, reacts to, or punishes anything.\n"
    "**Scope:** a channel sends nothing until it is enabled individually, and disabling it stops "
    "the sending immediately."
)

QUESTIONS: dict[str, dict[str, Any]] = {
    "any_scam": {
        "type": "noul",
        "instructions": (
            "在 `recent_messages` 裡，是否有任何一則訊息本身正在對讀者進行詐騙或釣魚？"
        ),
        "criteria": {
            "true": "某則訊息假冒官方通知、索取帳號密碼或證件、保證高報酬的投資或打工、誘導至可疑網址領取獎勵",
            "false": "沒有這樣的訊息，或只是在討論、警告、轉述、分析詐騙，或是正常的招募與分享",
        },
    },
    "scam_index": {
        "type": "choice",
        "instructions": (
            "若 `recent_messages` 裡有詐騙訊息，是哪一則？選項是各則訊息的開頭。若沒有任何一則是詐騙，選 none。"
        ),
        "criteria": {},
    },
    "is_hostile": {
        "type": "noul",
        "instructions": (
            "在 `recent_messages` 裡，是否有人對另一位參與者進行人身攻擊、嘲諷或貶低？"
            "判斷的對象是人，不是論點。"
        ),
        "criteria": {
            "true": "出現針對某人能力、人格或智商的貶低、嘲笑或羞辱",
            "false": "只針對做法、數據或論點提出反對，即使語氣強硬或直接；朋友之間的玩笑互虧不算",
        },
    },
    "heat": {
        "type": "score",
        "instructions": "這段對話的人際衝突程度。只看人與人之間的緊張，不看話題本身嚴不嚴肅。",
        "criteria": [
            "平和：閒聊或協作，沒有分歧",
            "有分歧但就事論事",
            "情緒升高、語氣尖銳、開始針對對方態度",
            "吵架、出現人身攻擊或明顯失控，需要有人介入",
        ],
    },
}

log_name = "red.nyancogs.messagewatch"


def _bounded_probability(value: Any) -> float | None:
    """A model-reported probability, or None when it is not one.

    Provider output is untrusted: a wrong number here decides whether a report
    is posted about a real person, so anything outside 0 to 1, a boolean, a
    string or a NaN is discarded rather than coerced.
    """
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    try:
        number = float(value)
    except OverflowError:
        # json.loads produces an unbounded int and float() refuses one past the
        # double range. Bounding the value is not bounding the conversion; this
        # exact mistake shipped in ChannelSummary's cost parser first.
        return None
    return number if 0.0 <= number <= 1.0 else None


def _bounded_score(value: Any, levels: int) -> float | None:
    """A model-reported score, or None when it falls outside the defined levels."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    try:
        number = float(value)
    except OverflowError:
        return None
    return number if 0.0 <= number <= float(levels - 1) else None


def _bounded_index(value: Any, size: int) -> int | None:
    """The index the model picked, or None for `none` and anything unexpected."""
    if not isinstance(value, str) or not value.isdigit():
        return None
    index = int(value)
    return index if 0 <= index < size else None


def build_questions(window: Iterable[Mapping[str, Any]]) -> dict[str, dict[str, Any]]:
    """The question block for this exact window.

    Options are built per request for two reasons. The model can only pick an
    option it was offered, so a short window must not be given indexes that are
    not in it. And each option label echoes the start of the message it selects:
    an ordinal alone describes nothing, and with labels that said only
    "第 6 則訊息" the model pointed one message off, reproducibly.
    """
    items = list(window)
    questions = {key: dict(value) for key, value in QUESTIONS.items()}
    questions["scam_index"]["criteria"] = {
        **{
            str(index): f"{item['alias']}：{item['text'][:SCAM_OPTION_LABEL_CHARS]}"
            for index, item in enumerate(items)
        },
        "none": "沒有任何一則是詐騙",
    }
    return questions


def build_state(channel_name: str, window: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    """The request state: text and a per-request label, never a Discord identity."""
    return {
        "channel": channel_name,
        "recent_messages": [
            {"i": index, "author": item["alias"], "text": item["text"]}
            for index, item in enumerate(window)
        ],
    }


def anonymise(window: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Replace author IDs with labels that mean nothing outside this request."""
    aliases: dict[int, str] = {}
    for item in window:
        author_id = item["author_id"]
        if author_id not in aliases:
            aliases[author_id] = f"u{len(aliases) + 1}"
        item["alias"] = aliases[author_id]
    return window


def clean_text(raw: str) -> str:
    """Bound one message and strip the mention markup that carries an ID."""
    text = re.sub(r"<@[!&]?\d+>|<#\d+>", "[mention]", raw)
    text = re.sub(r"<a?:\w+:\d+>", "[emoji]", text)
    text = " ".join(text.split())
    return text[:MAX_MESSAGE_CHARS]


class MessageWatch(commands.Cog):
    """Report scam and hostile messages in explicitly enabled channels."""

    def __init__(self, bot: Red):
        self.bot = bot
        self.config = Config.get_conf(self, identifier=0x4E59414E4D57415401, force_registration=True)
        self.config.register_guild(**DEFAULT_GUILD)
        # Per channel: the pending window, and when that channel last reported.
        # Both are process memory on purpose. A restart losing a half-filled
        # window costs one late report; persisting message text would
        # contradict the data statement.
        self._pending: defaultdict[int, deque[dict[str, Any]]] = defaultdict(deque)
        self._last_report: dict[int, float] = {}
        self._locks: defaultdict[int, asyncio.Lock] = defaultdict(asyncio.Lock)

    async def red_delete_data_for_user(self, *, requester: str, user_id: int) -> None:
        """Drop any pending message this user wrote that has not been sent yet."""
        for queue in self._pending.values():
            for item in list(queue):
                if item.get("author_id") == user_id:
                    queue.remove(item)

    async def get_api_key(self) -> str | None:
        tokens = await self.bot.get_shared_api_tokens(TOKEN_SERVICE)
        key = tokens.get("api_key") if isinstance(tokens, Mapping) else None
        return key if isinstance(key, str) and key else None

    async def judge(
        self, window: list[dict[str, Any]], channel_name: str, key: str
    ) -> dict[str, Any] | None:
        """One bounded request, or None when the service could not answer.

        Every failure path returns None rather than raising. A moderation aid
        that breaks the message handler is worse than one that misses a window,
        so the caller carries on and the channel keeps working.
        """
        payload = json.dumps(
            {
                "state": build_state(channel_name, window),
                "model": MODEL,
                "questions": build_questions(window),
            },
            ensure_ascii=False,
        ).encode()
        if len(payload) > MAX_REQUEST_BYTES:
            return None
        timeout = aiohttp.ClientTimeout(total=REQUEST_TIMEOUT_SECONDS)
        try:
            async with aiohttp.ClientSession(
                timeout=timeout, trust_env=False, cookie_jar=aiohttp.DummyCookieJar()
            ) as session:
                async with session.post(
                    API_URL,
                    data=payload,
                    headers={
                        "Authorization": f"Bearer {key}",
                        "Content-Type": "application/json",
                    },
                    allow_redirects=False,
                ) as response:
                    if response.status != 200:
                        return None
                    raw = await response.content.read(MAX_RESPONSE_BYTES + 1)
                    if len(raw) > MAX_RESPONSE_BYTES:
                        return None
        except (aiohttp.ClientError, asyncio.TimeoutError):
            return None
        try:
            decoded = json.loads(raw)
        except ValueError:
            return None
        answers = decoded.get("answers") if isinstance(decoded, Mapping) else None
        return answers if isinstance(answers, Mapping) else None

    @staticmethod
    def findings(
        answers: Mapping[str, Any], settings: Mapping[str, Any], window_size: int
    ) -> tuple[int | None, list[str]]:
        """Which thresholds this window crossed, and which message to point at."""
        reasons: list[str] = []
        index: int | None = None

        scam_answer = answers.get("any_scam")
        scam = _bounded_probability(scam_answer.get("noul")) if isinstance(scam_answer, Mapping) else None
        if scam is not None and scam >= float(settings["scam_threshold"]):
            reasons.append(f"詐騙 {scam:.2f}")
            picked = answers.get("scam_index")
            if isinstance(picked, Mapping):
                index = _bounded_index(picked.get("choice"), window_size)

        hostile_answer = answers.get("is_hostile")
        hostile = (
            _bounded_probability(hostile_answer.get("noul"))
            if isinstance(hostile_answer, Mapping)
            else None
        )
        if hostile is not None and hostile >= float(settings["hostile_threshold"]):
            reasons.append(f"敵意 {hostile:.2f}")

        heat_answer = answers.get("heat")
        levels = len(QUESTIONS["heat"]["criteria"])
        heat = _bounded_score(heat_answer.get("score"), levels) if isinstance(heat_answer, Mapping) else None
        if heat is not None and heat >= float(settings["heat_threshold"]):
            reasons.append(f"火藥味 {heat:.2f}/{levels - 1}")

        return index, reasons

    @staticmethod
    def report_embed(
        channel: discord.TextChannel | discord.Thread,
        window: list[dict[str, Any]],
        index: int | None,
        reasons: list[str],
    ) -> discord.Embed:
        """The moderator-facing report. Judgement stays with the moderator."""
        embed = discord.Embed(
            title="MessageWatch",
            description="｜".join(reasons),
            colour=discord.Colour.orange(),
        )
        embed.add_field(
            name="頻道", value=getattr(channel, "mention", f"#{channel.id}"), inline=False
        )
        if index is not None and 0 <= index < len(window):
            flagged = window[index]
            embed.add_field(
                name="指向的訊息",
                value=f"<@{flagged['author_id']}> · [跳至訊息]({flagged['jump_url']})",
                inline=False,
            )
        else:
            embed.add_field(
                name="範圍", value=f"[最後一則]({window[-1]['jump_url']})", inline=False
            )
        embed.set_footer(
            text=f"判斷依據 {len(window)} 則訊息。這是提示，不是裁決；本 Cog 不會刪除、禁言或加反應。"
        )
        return embed

    async def flush(self, channel: discord.TextChannel | discord.Thread) -> None:
        """Judge one full window for this channel and report if it crosses."""
        guild = channel.guild
        settings = await self.config.guild(guild).all()
        report_id = int(settings["report_channel"])
        if not report_id:
            return
        report_channel = guild.get_channel(report_id)
        if report_channel is None:
            return
        key = await self.get_api_key()
        if key is None:
            return

        queue = self._pending[channel.id]
        window_size = int(settings["window_size"])
        if len(queue) < window_size:
            return
        window = anonymise([queue.popleft() for _ in range(window_size)])

        answers = await self.judge(window, getattr(channel, "name", str(channel.id)), key)
        if answers is None:
            return
        index, reasons = self.findings(answers, settings, window_size)
        if not reasons:
            return

        now = time.monotonic()
        last = self._last_report.get(channel.id)
        cooldown = int(settings["cooldown_seconds"])
        # One argument spans many windows; without this the moderator channel
        # gets a report every few messages for the same exchange.
        if last is not None and now - last < cooldown:
            return
        self._last_report[channel.id] = now
        try:
            await report_channel.send(
                embed=self.report_embed(channel, window, index, reasons),
                allowed_mentions=discord.AllowedMentions.none(),
            )
        except discord.HTTPException:
            return

    @commands.Cog.listener()
    async def on_message(self, message: discord.Message) -> None:
        guild = getattr(message, "guild", None)
        channel = getattr(message, "channel", None)
        author = getattr(message, "author", None)
        if guild is None or channel is None or author is None:
            return
        if getattr(author, "bot", False) or getattr(message, "webhook_id", None) is not None:
            return
        settings = await self.config.guild(guild).all()
        if settings["disclosure_version"] != DISCLOSURE_VERSION:
            return
        if channel.id not in set(settings["watched_channels"]):
            return
        text = clean_text(getattr(message, "content", "") or "")
        if not text:
            return
        async with self._locks[channel.id]:
            self._pending[channel.id].append(
                {
                    "author_id": author.id,
                    "text": text,
                    "jump_url": getattr(message, "jump_url", ""),
                }
            )
            if len(self._pending[channel.id]) >= int(settings["window_size"]):
                await self.flush(channel)

    @commands.group(name="watch")
    @commands.guild_only()
    @checks.admin_or_permissions(manage_guild=True)
    async def watch_group(self, ctx: commands.Context) -> None:
        """Configure scam and hostility reporting."""

    @watch_group.command(name="key")
    @checks.is_owner()
    async def watch_key(self, ctx: commands.Context) -> None:
        """Store the TypeSafe API key through Red's shared token storage."""
        view = SetApiView(default_service=TOKEN_SERVICE, default_keys={"api_key": ""})
        await ctx.send("Set the `api_key` through Red's shared API token storage.", view=view)

    @watch_group.command(name="report")
    async def watch_report(self, ctx: commands.Context, channel: discord.TextChannel) -> None:
        """Set the moderator channel that receives reports."""
        await self.config.guild(ctx.guild).report_channel.set(channel.id)
        await ctx.send(f"報告會送到 {channel.mention}。")

    @watch_group.command(name="disclosure")
    async def watch_disclosure(self, ctx: commands.Context, confirmation: str = "") -> None:
        """Show the data-export disclosure, or accept it with I_ACCEPT."""
        if confirmation != "I_ACCEPT":
            embed = discord.Embed(
                title="MessageWatch · 資料輸出揭露",
                description=DISCLOSURE_TEXT
                + "\n\n接受後才能啟用任何頻道：`[p]watch disclosure I_ACCEPT`",
                colour=discord.Colour.orange(),
            )
            await ctx.send(embed=embed, allowed_mentions=discord.AllowedMentions.none())
            return
        await self.config.guild(ctx.guild).disclosure_version.set(DISCLOSURE_VERSION)
        await ctx.send("已記錄接受。現在可以逐一啟用頻道。")

    @watch_group.command(name="enable")
    async def watch_enable(self, ctx: commands.Context, channel: discord.TextChannel) -> None:
        """Start watching one channel. Every channel is opted in separately."""
        scope = self.config.guild(ctx.guild)
        if await scope.disclosure_version() != DISCLOSURE_VERSION:
            await ctx.send("請先閱讀並接受 `[p]watch disclosure`。")
            return
        if not await scope.report_channel():
            await ctx.send("請先用 `[p]watch report` 指定報告頻道。")
            return
        async with scope.watched_channels() as watched:
            if channel.id in watched:
                await ctx.send(f"{channel.mention} 已經在監看中。")
                return
            watched.append(channel.id)
        await ctx.send(f"開始監看 {channel.mention}。該頻道的訊息會送往 TypeSafe 判斷。")

    @watch_group.command(name="disable")
    async def watch_disable(self, ctx: commands.Context, channel: discord.TextChannel) -> None:
        """Stop watching one channel and drop anything pending for it."""
        async with self.config.guild(ctx.guild).watched_channels() as watched:
            if channel.id not in watched:
                await ctx.send(f"{channel.mention} 本來就沒有在監看。")
                return
            watched.remove(channel.id)
        self._pending.pop(channel.id, None)
        self._last_report.pop(channel.id, None)
        await ctx.send(f"停止監看 {channel.mention}，未送出的暫存也已清除。")

    @watch_group.command(name="set")
    async def watch_set(self, ctx: commands.Context, key: str, value: str) -> None:
        """Change one threshold or window setting."""
        if key not in SETTING_RULES:
            await ctx.send(f"可設定：{', '.join(sorted(SETTING_RULES))}")
            return
        kind, low, high = SETTING_RULES[key]
        try:
            parsed = kind(value)
        except ValueError:
            await ctx.send(f"`{key}` 需要 {kind.__name__}。")
            return
        if not low <= parsed <= high:
            await ctx.send(f"`{key}` 必須介於 {low} 與 {high}。")
            return
        await self.config.guild(ctx.guild).set_raw(key, value=parsed)
        await ctx.send(f"`{key}` 設為 `{parsed}`。")

    @watch_group.command(name="show")
    async def watch_show(self, ctx: commands.Context) -> None:
        """Show the effective settings for this guild."""
        settings = await self.config.guild(ctx.guild).all()
        watched = ", ".join(f"<#{item}>" for item in settings["watched_channels"]) or "（無）"
        report = f"<#{settings['report_channel']}>" if settings["report_channel"] else "（未設定）"
        embed = discord.Embed(title="MessageWatch 設定", colour=discord.Colour.blurple())
        embed.add_field(
            name="狀態",
            value=f"揭露=`v{settings['disclosure_version']}` · 報告頻道={report}",
            inline=False,
        )
        embed.add_field(name="監看中的頻道", value=watched, inline=False)
        embed.add_field(
            name="門檻",
            value=(
                f"詐騙=`{settings['scam_threshold']}` · 敵意=`{settings['hostile_threshold']}` · "
                f"火藥味=`{settings['heat_threshold']}`"
            ),
            inline=False,
        )
        embed.add_field(
            name="視窗",
            value=f"每 `{settings['window_size']}` 則判一次 · 冷卻 `{settings['cooldown_seconds']}` 秒",
            inline=False,
        )
        await ctx.send(embed=embed, allowed_mentions=discord.AllowedMentions.none())
