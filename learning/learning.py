"""Catch-up notes for technical channels.

Members who were away ask what they missed and what there was to learn. This
cog answers with notes: takeaways, questions and their answers, terms, open
questions and the links people shared, each pointing back at the messages.

ChannelSummary does the running. It owns the provider, the consent, the
cooldown and quotas, the history access and the window bounds, and is reached
at runtime through `bot.get_cog`, never imported, so each cog stays separately
installable. This cog owns the prompt, the trust-boundary parser for the
provider's JSON and the Embeds.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any, Mapping, Sequence
from urllib.parse import urlsplit

import discord
from discord import app_commands
from redbot.core import Config, commands
from redbot.core.bot import Red

CORE_COG = "ChannelSummary"
# v2: `state.links` numbered once per window, and ChannelJob merge fields for long windows.
# v3: jobs reach as far as job_max_messages, whatever max_duration_hours says.
CORE_API_VERSION = 3
# v2: long windows are split into several requests plus a merging one.
# v3: reach is bounded by job_max_messages, not max_duration_hours, and `from` exists.
LEARNING_DISCLOSURE_VERSION = 3
LEARNING_DISCLOSURE_TEXT = (
    "**Runs on ChannelSummary:** Learning sends the same data as a summary (message text, user and message "
    "IDs, timestamps, reply and embed metadata, inlined images and Firecrawl queries when those are enabled) "
    "through ChannelSummary's provider, and only while ChannelSummary is enabled here under its own consent.\n"
    "**No new-message gate:** any channel reader can request notes for the same window again, limited only "
    "by ChannelSummary's cooldown and hourly guild quotas (runs, provider calls, images), which Learning shares "
    "and can use up.\n"
    "**Reach:** a window of any age: the last hours or days, from a given message or time, a window ending in "
    "the past, or the time since the requester's own last message. It is not limited by `max_duration_hours`; "
    "instead up to `job_max_messages` messages are read, newest first, and a window holding more than the "
    "limits below allow is cut to its newest part, and the notes say so.\n"
    "**Long windows:** a window too long for one request is split into up to `job_max_chunks` requests of at "
    "most `max_input_chars` characters each, plus one merging request that resends the parts' model-written "
    "notes to the same provider. Up to `max_images` images are sent per run, newest first.\n"
    "**Links:** URLs that members posted are re-published as clickable links in a bot Embed, chosen by the "
    "model, each shown with the member who posted it.\n"
    "**Stored:** only whether Learning is enabled and which disclosure version was accepted."
)
# Hours or days only: a learning window is a stretch of the day, not minutes.
WINDOW_RE = re.compile(r"([1-9]\d{0,3})\s*([hd])")
# Caps on the provider's JSON. A list over its cap is cut to it rather than failing
# the run: a merged whole day, after several paid calls, must not be lost to an
# eleventh takeaway. Text over its length cap, or a list past MAX_LIST_ITEMS, is
# still rejected as malformed.
MAX_LIST_ITEMS = 100
LIMITS = {"takeaways": 10, "qa": 10, "glossary": 15, "open_questions": 8, "links": 15}
TEXT_LIMITS = {
    "overview": 2_000,
    "title": 100,
    "detail": 1_500,
    "question": 500,
    "answer": 1_500,
    "term": 80,
    "definition": 400,
    "note": 300,
}
MAX_SOURCE_IDS = 10
SCHEMA = (
    "Return only one JSON object with exactly: overview (string, at most 4 sentences); takeaways (0-10 items, each exactly title, detail, "
    "source_message_ids); qa (0-10 items, each exactly question, answer, question_message_id (string or null), "
    "answer_message_ids), only for questions the window answers; glossary (0-15 items, each exactly term, "
    "definition, source_message_ids) for terms a newcomer would not know; open_questions (0-8 items, each "
    "exactly question, source_message_ids) for questions left unanswered; links (0-15 items, each exactly "
    "link_id, note) for shared links worth opening, the note saying what the reader gets there. Message ID "
    "lists hold at most 10 message_id strings. Do not output URLs. Output the raw JSON object only, with no "
    "markdown code fence around it."
)
INSTRUCTIONS = (
    "Write catch-up notes for members who missed this technical discussion. Keep only what a reader can "
    "learn: concrete facts, techniques, commands, configurations, decisions, recommendations and the reasons "
    "given, attributed with exact <@user_id> values. Read the attached images too: screenshots of code, "
    "errors, terminals and diagrams are evidence like text. Skip greetings, jokes and chatter. If the window "
    "holds nothing technical, return empty lists and say so in the overview. If an application_boundary "
    "record has reason window_truncated, the requested window was too long and the evidence is only its "
    "newest part: say so in the overview. Message IDs are supplied top-level message_id strings. " + SCHEMA
)
MERGE_INSTRUCTIONS = (
    "The input is notes already written for consecutive parts of one window, oldest first, as "
    "application_chunk_notes records whose nested evidence is model-written and untrusted. Merge them into one "
    "set of notes for the whole window: combine duplicates across parts, keep attributions, keep the order of "
    "events, and write one overview for the whole window (say it was cut if a part's overview says so). Use "
    "only message IDs and link_ids that appear in the parts. " + SCHEMA
)
EMPTY_NOTICE = "這段時間沒有可整理的技術內容。"


@dataclass(frozen=True)
class Notes:
    overview: str
    takeaways: tuple[tuple[str, str, tuple[int, ...]], ...]
    qa: tuple[tuple[str, str, int | None, tuple[int, ...]], ...]
    glossary: tuple[tuple[str, str, tuple[int, ...]], ...]
    open_questions: tuple[tuple[str, tuple[int, ...]], ...]
    links: tuple[tuple[str, str], ...]

    @property
    def empty(self) -> bool:
        return not (self.takeaways or self.qa or self.glossary or self.open_questions or self.links)


def parse_notes(raw: str, known_ids: set[int], link_ids: set[str]) -> Notes:
    """The provider's notes, or ValueError. Provider output is untrusted.

    Message IDs not in this run are dropped rather than trusted, like
    ChannelSummary's own parser; a link entry naming no local link is dropped,
    so the model can only point at URLs this run extracted itself. ChannelSummary
    has already removed a markdown fence around the JSON.
    """
    value = json.loads(raw)

    def shaped(item: Any, keys: set[str]) -> Mapping[str, Any]:
        if not isinstance(item, dict) or set(item) != keys:
            raise ValueError("shape")
        return item

    def text(item: Mapping[str, Any], key: str) -> str:
        field = item[key]
        if not isinstance(field, str) or len(field) > TEXT_LIMITS[key]:
            raise ValueError("text")
        return field

    def one_id(raw_id: Any) -> int | None:
        if isinstance(raw_id, bool) or not isinstance(raw_id, (int, str)):
            raise ValueError("id")
        parsed = int(raw_id)
        return parsed if parsed in known_ids else None

    def ids(raw_ids: Any) -> tuple[int, ...]:
        if not isinstance(raw_ids, list) or len(raw_ids) > 100:
            raise ValueError("ids")
        found = dict.fromkeys(item for item in map(one_id, raw_ids) if item is not None)
        return tuple(found)[:MAX_SOURCE_IDS]

    def items(key: str) -> list[Any]:
        found = root[key]
        if not isinstance(found, list) or len(found) > MAX_LIST_ITEMS:
            raise ValueError("list")
        return found[: LIMITS[key]]

    root = shaped(value, {"overview", *LIMITS})
    takeaways = tuple(
        (text(item, "title"), text(item, "detail"), ids(item["source_message_ids"]))
        for item in (shaped(raw_item, {"title", "detail", "source_message_ids"}) for raw_item in items("takeaways"))
    )
    qa = []
    for raw_item in items("qa"):
        item = shaped(raw_item, {"question", "answer", "question_message_id", "answer_message_ids"})
        question_id = item["question_message_id"]
        qa.append(
            (
                text(item, "question"),
                text(item, "answer"),
                None if question_id is None else one_id(question_id),
                ids(item["answer_message_ids"]),
            )
        )
    glossary = tuple(
        (text(item, "term"), text(item, "definition"), ids(item["source_message_ids"]))
        for item in (shaped(raw_item, {"term", "definition", "source_message_ids"}) for raw_item in items("glossary"))
    )
    open_questions = tuple(
        (text(item, "question"), ids(item["source_message_ids"]))
        for item in (shaped(raw_item, {"question", "source_message_ids"}) for raw_item in items("open_questions"))
    )
    links = []
    for raw_item in items("links"):
        item = shaped(raw_item, {"link_id", "note"})
        if not isinstance(item["link_id"], str):
            raise ValueError("link")
        if item["link_id"] in link_ids:
            links.append((item["link_id"], text(item, "note")))
    return Notes(text(root, "overview"), takeaways, tuple(qa), glossary, open_questions, tuple(links))


def merge_input(notes: Notes, max_chars: int) -> tuple[dict[str, Any], set[int], set[str]]:
    """One part's notes as merge input, shrunk to `max_chars`.

    Items are dropped from the end of whichever list is largest until the JSON
    fits, then the overview is shortened if it still does not. Returns the data
    and the message IDs and link IDs it still cites, which are all the merging
    call may cite.
    """
    data: dict[str, Any] = {
        "overview": notes.overview,
        "takeaways": [
            {"title": title, "detail": detail, "source_message_ids": [str(i) for i in ids]}
            for title, detail, ids in notes.takeaways
        ],
        "qa": [
            {
                "question": question,
                "answer": answer,
                "question_message_id": None if question_id is None else str(question_id),
                "answer_message_ids": [str(i) for i in ids],
            }
            for question, answer, question_id, ids in notes.qa
        ],
        "glossary": [
            {"term": term, "definition": definition, "source_message_ids": [str(i) for i in ids]}
            for term, definition, ids in notes.glossary
        ],
        "open_questions": [
            {"question": question, "source_message_ids": [str(i) for i in ids]} for question, ids in notes.open_questions
        ],
        "links": [{"link_id": link_id, "note": note} for link_id, note in notes.links],
    }

    def size(value: Any) -> int:
        return len(json.dumps(value, ensure_ascii=False, separators=(",", ":")))

    while size(data) > max_chars and any(data[key] for key in LIMITS):
        largest = max((key for key in LIMITS if data[key]), key=lambda key: size(data[key]))
        data[largest].pop()
    if size(data) > max_chars:
        data["overview"] = data["overview"][: max(0, len(data["overview"]) - (size(data) - max_chars))]
    if size(data) > max_chars:
        raise ValueError("merge budget")
    ids: set[int] = set()
    for item in data["takeaways"] + data["glossary"] + data["open_questions"]:
        ids.update(int(i) for i in item["source_message_ids"])
    for item in data["qa"]:
        ids.update(int(i) for i in item["answer_message_ids"])
        if item["question_message_id"] is not None:
            ids.add(int(item["question_message_id"]))
    return data, ids, {item["link_id"] for item in data["links"]}


def render_notes(
    core: Any,
    guild: discord.Guild,
    channel: discord.TextChannel | discord.Thread,
    author: discord.Member | discord.User,
    settings: Mapping[str, Any],
    state: Any,
    notes: Notes,
    citations: Sequence[Any],
    actual_model: str | None,
) -> list[discord.Embed]:
    """Embeds for the notes. No network I/O; every link is built here.

    Provider text goes through ChannelSummary's sanitizer, which strips links and
    mentions it did not allow, so a URL appears only where this function puts
    one: a jump link it builds, a link from the run's own extracted table, or a
    citation the core validated.
    """
    allowed = {message.author.id for message in state.messages.values()}
    cited: set[int] = set()

    def clean(value: str) -> str:
        return core.sanitize_text(value, allowed)

    def line(value: str) -> str:
        # A single-line field cannot open a fake heading or list on a new line.
        return clean(" ".join(value.split()))

    def jumps(message_ids: Sequence[int]) -> str:
        shown = message_ids[:3]
        # Only what is linked counts as cited, so the footer matches the page.
        cited.update(shown)
        return " ".join(f"[↗](https://discord.com/channels/{guild.id}/{channel.id}/{message_id})" for message_id in shown)

    overview = clean(notes.overview) or (EMPTY_NOTICE if notes.empty else "")
    sections = ["## 概要\n" + overview] if overview else []
    if notes.takeaways:
        sections.append(
            "## 學到什麼\n"
            + "\n\n".join(f"**{line(title)}** {jumps(ids)}\n{clean(detail)}" for title, detail, ids in notes.takeaways)
        )
    if notes.qa:
        sections.append(
            "## 問與答\n"
            + "\n\n".join(
                f"**Q：**{line(question)} {jumps([question_id] if question_id else [])}\n"
                f"**A：**{clean(answer)} {jumps(answer_ids)}"
                for question, answer, question_id, answer_ids in notes.qa
            )
        )
    if notes.glossary:
        sections.append(
            "## 名詞\n"
            + "\n".join(f"**{line(term)}**：{line(definition)} {jumps(ids)}" for term, definition, ids in notes.glossary)
        )
    if notes.open_questions:
        sections.append(
            "## 還沒解決\n" + "\n".join(f"• {line(question)} {jumps(ids)}" for question, ids in notes.open_questions)
        )
    if notes.links:
        table = {link.link_id: link for link in state.links}
        rows = []
        for link_id, note in notes.links:
            link = table.get(link_id)
            if link is None:
                continue
            # One link per line, so a page break cannot fall inside one.
            rows.append(
                f"[{discord.utils.escape_markdown(link.host)}]({link.url}) — {line(note)} · "
                f"<@{link.author_id}> {jumps([link.message_id])}"
            )
        if rows:
            sections.append("## 參考連結\n" + "\n".join(rows))
    if citations:
        sections.append(
            "## 外部來源\n"
            + "\n".join(
                f"[{index}. {discord.utils.escape_markdown(urlsplit(citation.url).hostname or 'source')}]({citation.url})"
                for index, citation in enumerate(citations[:15], 1)
            )
        )
    pages = core.split_embed_text(sections)
    footer = core.footer(settings, state, cited, actual_model)
    avatar = getattr(getattr(author, "display_avatar", None), "url", None)
    embeds = []
    for index, page in enumerate(pages, 1):
        embed = discord.Embed(
            title=f"#{getattr(channel, 'name', channel.id)} 學習筆記" + (f" ({index}/{len(pages)})" if len(pages) > 1 else ""),
            description=page,
            colour=discord.Colour.teal(),
        )
        embed.set_author(name=getattr(author, "display_name", str(author)), icon_url=avatar)
        embed.set_footer(text=footer)
        embeds.append(embed)
    return embeds


class Learning(commands.Cog):
    """Catch-up notes for technical channels, run on ChannelSummary."""

    def __init__(self, bot: Red):
        self.bot = bot
        self.config = Config.get_conf(self, identifier=0x1EA2_0129, force_registration=True)
        self.config.register_guild(enabled=False, disclosure_version=0)

    async def red_delete_data_for_user(self, *, requester: str, user_id: int) -> None:
        """Nothing to delete: this cog stores no per-user data."""
        return

    async def _send(self, ctx: commands.Context, text: str) -> None:
        kwargs: dict[str, Any] = {"allowed_mentions": discord.AllowedMentions.none()}
        if getattr(ctx, "interaction", None) is not None:
            kwargs["ephemeral"] = True
        await ctx.send(text, **kwargs)

    async def _run(self, ctx: commands.Context, **window: Any) -> None:
        # Looked up per call and never kept: a reloaded ChannelSummary is a new object.
        core = self.bot.get_cog(CORE_COG)
        if core is None or getattr(core, "CORE_API_VERSION", None) != CORE_API_VERSION:
            await self._send(ctx, f"Learning needs ChannelSummary (core API v{CORE_API_VERSION}) to be loaded.")
            return
        settings = await self.config.guild(ctx.guild).all()
        if not settings["enabled"] or settings["disclosure_version"] != LEARNING_DISCLOSURE_VERSION:
            await self._send(
                ctx, "This server has not enabled Learning. A manager reads `[p]learningset show` first."
            )
            return

        def finalize(text: str, state: Any) -> Notes:
            return parse_notes(text, set(state.messages), {link.link_id for link in state.links})

        def render(guild, channel, author, guild_settings, state, notes, citations, actual_model):
            return render_notes(core, guild, channel, author, guild_settings, state, notes, citations, actual_model)

        job = core.ChannelJob(
            name="學習筆記",
            instructions=INSTRUCTIONS,
            finalize=finalize,
            render=render,
            include_links=True,
            merge_instructions=MERGE_INSTRUCTIONS,
            merge_input=merge_input,
            **window,
        )
        await core.run_channel_job(ctx, job)

    @commands.hybrid_group(name="learning", invoke_without_command=True)
    @commands.guild_only()
    async def learning_group(self, ctx: commands.Context) -> None:
        """補課筆記：學到什麼、問與答、名詞、未解問題與參考連結。"""
        await self._send(
            ctx,
            "`/learning recent <6h|1d> [多久以前結束]` — 整理最近幾小時或幾天\n"
            "`/learning from <訊息連結|2026-10-03T21:00|2d> [終點]` — 從指定的訊息或時間開始整理\n"
            "`/learning since-me` — 整理你在這裡最後一則訊息之後的討論\n"
            "每次最多讀伺服器設定的訊息數，從最新的開始；區間更長時只整理最新的部分，頁尾會註明。",
        )

    @learning_group.command(name="recent")
    @commands.guild_only()
    @app_commands.describe(
        window="整理多久：以小時或天為單位，例如 6h、1d、3d",
        ended_ago="（選填）讓區間停在多久以前，例如 1d 表示整理到一天前為止",
    )
    async def learning_recent(self, ctx: commands.Context, window: str, ended_ago: str | None = None) -> None:
        """整理最近幾小時或幾天的補課筆記，例如 6h、1d。"""
        def hours(text: str) -> int | None:
            match = WINDOW_RE.fullmatch(text.strip().casefold())
            return int(match.group(1)) * (24 if match.group(2) == "d" else 1) if match else None

        span = hours(window)
        ended = 0 if ended_ago is None else hours(ended_ago)
        if span is None or ended is None:
            await self._send(ctx, "請用小時或天為單位，例如 6h 或 2d。")
            return
        # Both ends relative to now; ChannelSummary resolves them and bounds the read by job_max_messages.
        await self._run(ctx, start=f"{span + ended}h", end=f"{ended}h" if ended else None)

    @learning_group.command(name="from")
    @commands.guild_only()
    @app_commands.describe(
        start="起點：訊息連結（右鍵「複製訊息連結」）、時間 2026-10-03T21:00，或 2d（多久以前）",
        end="終點（選填，不填就是現在）：訊息連結、時間，或 1h（多久以前）",
    )
    async def learning_from(self, ctx: commands.Context, start: str, end: str | None = None) -> None:
        """從指定的訊息或時間開始整理補課筆記（太長時取最新的部分）。"""
        await self._run(ctx, start=start, end=end)

    @learning_group.command(name="since-me")
    @commands.guild_only()
    async def learning_since_me(self, ctx: commands.Context) -> None:
        """整理你在這個頻道最後一則訊息之後的討論（太長時取最新的部分）。"""
        await self._run(ctx, since_author=True)

    @commands.group(name="learningset", invoke_without_command=True)
    @commands.guild_only()
    async def learningset_group(self, ctx: commands.Context) -> None:
        """Enable, disable, or review Learning for this server (guild-level Manage Messages)."""
        await self.learningset_show(ctx)

    @staticmethod
    def _require_guild_manager(ctx: commands.Context) -> None:
        permissions = getattr(ctx.author, "guild_permissions", None)
        if permissions is None or not permissions.manage_messages:
            raise commands.UserFeedbackCheckFailure("Guild-level Manage Messages is required.")

    @learningset_group.command(name="show")
    async def learningset_show(self, ctx: commands.Context) -> None:
        """Show the data-export disclosure and whether Learning is enabled."""
        self._require_guild_manager(ctx)
        settings = await self.config.guild(ctx.guild).all()
        embed = discord.Embed(
            title="Learning",
            description=(
                "**Data-export disclosure** — `[p]learningset enable I_ACCEPT` records your acceptance.\n"
                + LEARNING_DISCLOSURE_TEXT
            ),
            colour=discord.Colour.green() if settings["enabled"] else discord.Colour.orange(),
        )
        embed.add_field(
            name="State",
            value=f"enabled=`{settings['enabled']}` · disclosure=`v{settings['disclosure_version']}`",
        )
        await ctx.send(embed=embed, allowed_mentions=discord.AllowedMentions.none())

    @learningset_group.command(name="enable")
    async def learningset_enable(self, ctx: commands.Context, confirmation: str) -> None:
        """Enable after reading `[p]learningset show`; confirmation must be I_ACCEPT."""
        self._require_guild_manager(ctx)
        if confirmation != "I_ACCEPT":
            await self._send(ctx, "Read `[p]learningset show`, then run this with the exact confirmation I_ACCEPT.")
            return
        await self.config.guild(ctx.guild).disclosure_version.set(LEARNING_DISCLOSURE_VERSION)
        await self.config.guild(ctx.guild).enabled.set(True)
        await ctx.tick()

    @learningset_group.command(name="disable")
    async def learningset_disable(self, ctx: commands.Context) -> None:
        """Disable Learning in this server."""
        self._require_guild_manager(ctx)
        await self.config.guild(ctx.guild).enabled.set(False)
        await ctx.tick()
