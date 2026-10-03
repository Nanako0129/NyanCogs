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
from redbot.core import Config, commands
from redbot.core.bot import Red

CORE_COG = "ChannelSummary"
CORE_API_VERSION = 1
LEARNING_DISCLOSURE_VERSION = 1
LEARNING_DISCLOSURE_TEXT = (
    "**Runs on ChannelSummary:** Learning sends the same data as a summary (message text, user and message "
    "IDs, timestamps, reply and embed metadata, inlined images and Firecrawl queries when those are enabled) "
    "through ChannelSummary's provider, and only while ChannelSummary is enabled here under its own consent.\n"
    "**No new-message gate:** any channel reader can request notes for the same window again, limited only "
    "by ChannelSummary's cooldown and guild quota, which Learning shares and can use up.\n"
    "**Reach:** the last hours or days up to `max_duration_hours`, a window ending in the past, or everything "
    "since the requester's own last message.\n"
    "**Links:** URLs that members posted are re-published as clickable links in a bot Embed, chosen by the "
    "model, each shown with the member who posted it.\n"
    "**Stored:** only whether Learning is enabled and which disclosure version was accepted."
)
# Hours or days only: a learning window is a stretch of the day, not minutes.
WINDOW_RE = re.compile(r"([1-9]\d{0,3})\s*([hd])")
# Caps on the provider's JSON. Above them the output is rejected, not truncated,
# so a runaway model fails visibly instead of filling eight pages.
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
INSTRUCTIONS = (
    "Write catch-up notes for members who missed this technical discussion. Keep only what a reader can "
    "learn: concrete facts, techniques, commands, configurations, decisions, recommendations and the reasons "
    "given, attributed with exact <@user_id> values. Skip greetings, jokes and chatter. If the window holds "
    "nothing technical, return empty lists and say so in the overview. Return only one JSON object with "
    "exactly: overview (string, at most 4 sentences); takeaways (0-10 items, each exactly title, detail, "
    "source_message_ids); qa (0-10 items, each exactly question, answer, question_message_id (string or null), "
    "answer_message_ids), only for questions the window answers; glossary (0-15 items, each exactly term, "
    "definition, source_message_ids) for terms a newcomer would not know; open_questions (0-8 items, each "
    "exactly question, source_message_ids) for questions left unanswered; links (0-15 items, each exactly "
    "link_id, note) for shared links worth opening, the note saying what the reader gets there. Message ID "
    "lists hold at most 10 supplied top-level message_id strings. Do not output URLs. Output the raw JSON "
    "object only, with no markdown code fence around it."
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
        if not isinstance(found, list) or len(found) > LIMITS[key]:
            raise ValueError("list")
        return found

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
        table = {link.link_id: link for link in core.extract_links(state.messages.values())}
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
            link_ids = {link.link_id for link in core.extract_links(state.messages.values())}
            return parse_notes(text, set(state.messages), link_ids)

        def render(guild, channel, author, guild_settings, state, notes, citations, actual_model):
            return render_notes(core, guild, channel, author, guild_settings, state, notes, citations, actual_model)

        job = core.ChannelJob(
            name="學習筆記",
            instructions=INSTRUCTIONS,
            finalize=finalize,
            render=render,
            include_links=True,
            **window,
        )
        await core.run_channel_job(ctx, job)

    @commands.hybrid_group(name="learning", invoke_without_command=True)
    @commands.guild_only()
    async def learning_group(self, ctx: commands.Context) -> None:
        """Catch-up notes: what was learned, Q&A, terms, open questions and links."""
        await self._send(
            ctx,
            "`/learning recent <6h|1d> [ended 1d ago]` — notes for a window of hours or days\n"
            "`/learning since-me` — notes for everything since your last message here",
        )

    @learning_group.command(name="recent")
    @commands.guild_only()
    async def learning_recent(self, ctx: commands.Context, window: str, ended_ago: str | None = None) -> None:
        """Notes for the last hours or days, such as 6h or 1d, optionally ending that long ago."""
        def hours(text: str) -> int | None:
            match = WINDOW_RE.fullmatch(text.strip().casefold())
            return int(match.group(1)) * (24 if match.group(2) == "d" else 1) if match else None

        span = hours(window)
        ended = 0 if ended_ago is None else hours(ended_ago)
        if span is None or ended is None:
            await self._send(ctx, "Use hours or days, such as 6h or 2d.")
            return
        # Both ends relative to now, so ChannelSummary resolves and bounds them itself.
        await self._run(ctx, start=f"{span + ended}h", end=f"{ended}h" if ended else None)

    @learning_group.command(name="since-me")
    @commands.guild_only()
    async def learning_since_me(self, ctx: commands.Context) -> None:
        """Notes for everything said here since your last message."""
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
