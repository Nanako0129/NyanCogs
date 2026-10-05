"""Learning: the provider-output boundary, rendering, gates and command wiring.

ChannelSummary is imported here only to stand in as the runtime core; the cog
itself reaches it through `bot.get_cog` and never imports it.
"""

from __future__ import annotations

import json
import re
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import discord

from channelsummary.channelsummary import GUILD_DEFAULTS, ChannelSummary, Citation, RunState, extract_links
from channelsummary.test_channelsummary import FakeMessage
from learning import learning as lr

GUILD, CHANNEL = 123456789012345678, 987654321098765432
ASK, ANSWER = 100000000000000001, 100000000000000002
ALICE, BOB = 444444444444444444, 555555555555555555


def notes_json(**overrides) -> str:
    value = {
        "overview": "Discussed asyncio.",
        "takeaways": [{"title": "TaskGroup", "detail": "Use TaskGroup.", "source_message_ids": [str(ANSWER)]}],
        "qa": [
            {
                "question": "How to cancel?",
                "answer": "Cancel the group.",
                "question_message_id": str(ASK),
                "answer_message_ids": [str(ANSWER)],
            }
        ],
        "glossary": [{"term": "TaskGroup", "definition": "Structured concurrency.", "source_message_ids": []}],
        "open_questions": [{"question": "Python 3.10?", "source_message_ids": [str(ASK)]}],
        "links": [{"link_id": "L1", "note": "The official docs."}],
    }
    value.update(overrides)
    return json.dumps(value)


def run_state() -> RunState:
    ask = FakeMessage(ASK, ALICE, "how do I cancel a TaskGroup?", 1)
    answer = FakeMessage(ANSWER, BOB, "see https://docs.python.org/3/library/asyncio-task.html#task-groups", 2)
    state = RunState(ANSWER, {ASK, ANSWER}, {ASK: ask, ANSWER: answer})
    state.links = extract_links([ask, answer])
    return state


class ParseNotesTest(unittest.TestCase):
    def test_valid_notes_keep_only_known_ids_and_links(self):
        notes = lr.parse_notes(
            notes_json(
                takeaways=[{"title": "T", "detail": "D", "source_message_ids": [str(ANSWER), "999", ANSWER, str(ASK)]}],
                links=[{"link_id": "L1", "note": "docs"}, {"link_id": "L9", "note": "invented"}],
            ),
            {ASK, ANSWER},
            {"L1"},
        )
        self.assertEqual(notes.takeaways, (("T", "D", (ANSWER, ASK)),))
        self.assertEqual(notes.qa[0][2], ASK)
        self.assertEqual(notes.links, (("L1", "docs"),))
        self.assertFalse(notes.empty)

    def test_a_list_over_its_cap_is_cut_not_fatal(self):
        notes = lr.parse_notes(
            notes_json(open_questions=[{"question": f"q{index}", "source_message_ids": []} for index in range(9)]),
            {ASK, ANSWER},
            {"L1"},
        )
        self.assertEqual([question for question, _ in notes.open_questions], [f"q{index}" for index in range(8)])

    def test_malformed_output_is_rejected(self):
        bad = {
            "extra root key": notes_json(extra=1),
            "extra item key": notes_json(glossary=[{"term": "a", "definition": "b", "source_message_ids": [], "url": "x"}]),
            "oversize text": notes_json(overview="x" * 2_001),
            "far too many items": notes_json(open_questions=[{"question": "q", "source_message_ids": []}] * 101),
            "non-string link id": notes_json(links=[{"link_id": 1, "note": "n"}]),
            "boolean id": notes_json(open_questions=[{"question": "q", "source_message_ids": [True]}]),
            "not json": "notes: none",
        }
        for name, raw in bad.items():
            with self.subTest(name), self.assertRaises(ValueError):
                lr.parse_notes(raw, {ASK, ANSWER}, {"L1"})


class RenderNotesTest(unittest.TestCase):
    def render(self, notes, citations=()):
        core = object.__new__(ChannelSummary)
        channel = SimpleNamespace(id=CHANNEL, name="python")
        author = SimpleNamespace(display_name="reader", display_avatar=SimpleNamespace(url="https://cdn.discordapp.com/a.png"))
        embeds = lr.render_notes(
            core, SimpleNamespace(id=GUILD), channel, author, {**GUILD_DEFAULTS, "model": "m"}, run_state(), notes, citations, "m"
        )
        return "\n".join(embed.description for embed in embeds), embeds

    def test_provider_text_cannot_add_links_or_mentions_in_any_field(self):
        hostile = "[x](https://evil.co) <https://evil.co> https://evil.co <@&1> @everyone <@999>"
        raw = notes_json(
            overview=hostile,
            takeaways=[{"title": hostile, "detail": hostile, "source_message_ids": []}],
            qa=[{"question": hostile, "answer": hostile, "question_message_id": None, "answer_message_ids": []}],
            glossary=[{"term": hostile, "definition": hostile, "source_message_ids": []}],
            open_questions=[{"question": hostile, "source_message_ids": []}],
            links=[{"link_id": "L1", "note": hostile}],
        )
        text, _ = self.render(lr.parse_notes(raw, {ASK, ANSWER}, {"L1"}))
        self.assertNotIn("evil", text)
        self.assertNotIn("<@&", text)
        self.assertNotIn("<@999>", text)
        self.assertNotIn("@everyone", text)
        targets = re.findall(r"\]\((https?://[^)\s]+)\)", text)
        self.assertIn("https://docs.python.org/3/library/asyncio-task.html#task-groups", targets)
        for target in targets:
            self.assertTrue(
                target.startswith(f"https://discord.com/channels/{GUILD}/{CHANNEL}/")
                or target == "https://docs.python.org/3/library/asyncio-task.html#task-groups",
                target,
            )

    def test_sections_link_back_and_credit_the_sharer(self):
        text, embeds = self.render(
            lr.parse_notes(notes_json(), {ASK, ANSWER}, {"L1"}), (Citation("https://peps.python.org/pep-0654/", "PEP"),)
        )
        for heading in ("## 概要", "## 學到什麼", "## 問與答", "## 名詞", "## 還沒解決", "## 參考連結", "## 外部來源"):
            self.assertIn(heading, text)
        self.assertIn(f"[docs.python.org](https://docs.python.org/3/library/asyncio-task.html#task-groups)", text)
        self.assertIn(f"<@{BOB}>", text)
        self.assertIn(f"https://discord.com/channels/{GUILD}/{CHANNEL}/{ASK}", text)
        self.assertIn("學習筆記", embeds[0].title)
        self.assertIn("實際引用", embeds[0].footer.text)

    def test_nothing_technical_renders_a_notice_not_an_error(self):
        empty = notes_json(overview="", takeaways=[], qa=[], glossary=[], open_questions=[], links=[])
        text, _ = self.render(lr.parse_notes(empty, {ASK, ANSWER}, set()))
        self.assertEqual(text.count(lr.EMPTY_NOTICE), 1)
        notes_only = lr.Notes("", (("T", "D", ()),), (), (), (), ())
        text, _ = self.render(notes_only)
        self.assertNotIn(lr.EMPTY_NOTICE, text)

    def test_only_linked_sources_count_as_cited(self):
        many = notes_json(takeaways=[{"title": "T", "detail": "D", "source_message_ids": [str(ASK), str(ANSWER)]}],
                          qa=[], glossary=[], open_questions=[], links=[])
        notes = lr.parse_notes(many, {ASK, ANSWER}, set())
        notes = lr.Notes(notes.overview, (("T", "D", (ASK, ANSWER, ASK + 10, ANSWER + 10)),), (), (), (), ())
        _, embeds = self.render(notes)
        # Four sources, three linked: the fourth must not be counted.
        self.assertIn("實際引用 3 則", embeds[0].footer.text)


class MergeInputTest(unittest.TestCase):
    def test_parts_are_shrunk_from_their_largest_list_and_cite_only_what_remains(self):
        notes = lr.Notes(
            "Overview.",
            tuple((f"T{index}", "d" * 300, (ASK + index,)) for index in range(10)),
            (("Q?", "A.", ASK, (ANSWER,)),),
            (("term", "def", (ANSWER,)),),
            (),
            (("L1", "docs"),),
        )
        full, ids, links = lr.merge_input(notes, 100_000)
        self.assertEqual(len(full["takeaways"]), 10)
        self.assertIn(ASK + 9, ids)
        self.assertEqual(links, {"L1"})
        small, ids, _ = lr.merge_input(notes, 1_500)
        self.assertLessEqual(len(json.dumps(small, ensure_ascii=False, separators=(",", ":"))), 1_500)
        self.assertLess(len(small["takeaways"]), 10)
        self.assertEqual(small["takeaways"], full["takeaways"][: len(small["takeaways"])])  # dropped from the end
        self.assertNotIn(ASK + 9, ids)
        with self.assertRaises(ValueError):
            lr.merge_input(notes, 10)

    def test_merged_notes_round_trip_through_the_parser(self):
        notes = lr.parse_notes(notes_json(), {ASK, ANSWER}, {"L1"})
        data, ids, links = lr.merge_input(notes, 100_000)
        self.assertEqual(lr.parse_notes(json.dumps(data), ids, links), notes)


class WindowLinksTest(unittest.TestCase):
    def test_a_link_from_a_later_part_renders_its_own_url_and_poster(self):
        first = FakeMessage(ASK, ALICE, "see https://first.example.org/a", 1)
        second = FakeMessage(ANSWER, BOB, "see https://second.example.org/b", 2)
        state = RunState(ANSWER, {ASK, ANSWER}, {ASK: first, ANSWER: second})
        state.links = extract_links([first, second])  # numbered once over the window: L1 first, L2 second
        notes = lr.Notes("o", (), (), (), (), (("L2", "the second one"),))
        core = object.__new__(ChannelSummary)
        embeds = lr.render_notes(
            core, SimpleNamespace(id=GUILD), SimpleNamespace(id=CHANNEL, name="c"), SimpleNamespace(display_name="r"),
            {**GUILD_DEFAULTS, "model": "m"}, state, notes, (), "m",
        )
        text = embeds[0].description
        self.assertIn("(https://second.example.org/b)", text)
        self.assertIn(f"<@{BOB}>", text)
        self.assertNotIn("first.example.org", text)


class DisclosureTest(unittest.TestCase):
    def test_every_place_states_the_long_window_terms(self):
        root = Path(__file__).resolve().parents[1]
        info = json.loads((root / "learning" / "info.json").read_text(encoding="utf-8"))["end_user_data_statement"]
        readme = (root / "README.md").read_text(encoding="utf-8")
        for text in (lr.LEARNING_DISCLOSURE_TEXT, info, readme):
            normalized = " ".join(text.split())
            for phrase in ("job_max_messages", "job_max_chunks", "merging request", "max_images", "not limited by"):
                with self.subTest(phrase=phrase, place=normalized[:30]):
                    self.assertIn(phrase, normalized)
            self.assertNotIn("everything since", normalized)


class LearningCommandTest(unittest.IsolatedAsyncioTestCase):
    def cog(self, *, core=None, enabled=True):
        bot = MagicMock()
        bot.get_cog.return_value = core
        cog = object.__new__(lr.Learning)
        cog.bot = bot
        scope = MagicMock()
        scope.all = AsyncMock(
            return_value={"enabled": enabled, "disclosure_version": lr.LEARNING_DISCLOSURE_VERSION if enabled else 0}
        )
        cog.config = MagicMock()
        cog.config.guild.return_value = scope
        return cog

    def ctx(self):
        ctx = MagicMock()
        ctx.guild = SimpleNamespace(id=GUILD)
        ctx.interaction = None
        ctx.send = AsyncMock()
        return ctx

    def core(self):
        core = MagicMock()
        core.CORE_API_VERSION = 3
        core.ChannelJob = ChannelSummary.ChannelJob
        core.run_channel_job = AsyncMock(return_value=True)
        return core

    async def test_windows_become_relative_endpoints_for_the_core(self):
        cases = {
            ("6h", None): {"start": "6h", "end": None},
            ("2d", None): {"start": "48h", "end": None},
            ("6h", "1d"): {"start": "30h", "end": "24h"},
        }
        for (window, ended), expected in cases.items():
            with self.subTest(window=window, ended=ended):
                core = self.core()
                cog = self.cog(core=core)
                await lr.Learning.learning_recent.callback(cog, self.ctx(), window, ended)
                job = core.run_channel_job.await_args.args[1]
                self.assertEqual((job.start, job.end, job.since_author), (expected["start"], expected["end"], False))
                self.assertTrue(job.include_links)
                self.assertEqual(job.instructions, lr.INSTRUCTIONS)

    async def test_minutes_and_garbage_are_refused_without_a_run(self):
        for window, ended in (("30m", None), ("6h", "10m"), ("0h", None), ("soon", None)):
            with self.subTest(window=window, ended=ended):
                core = self.core()
                ctx = self.ctx()
                await lr.Learning.learning_recent.callback(self.cog(core=core), ctx, window, ended)
                core.run_channel_job.assert_not_awaited()
                self.assertIn("小時或天", ctx.send.await_args.args[0])

    async def test_from_passes_its_endpoints_to_the_core(self):
        core = self.core()
        await lr.Learning.learning_from.callback(self.cog(core=core), self.ctx(), "https://discord.com/x", "2h")
        job = core.run_channel_job.await_args.args[1]
        self.assertEqual((job.start, job.end, job.since_author), ("https://discord.com/x", "2h", False))

    async def test_since_me_is_resolved_by_the_core(self):
        core = self.core()
        await lr.Learning.learning_since_me.callback(self.cog(core=core), self.ctx())
        job = core.run_channel_job.await_args.args[1]
        self.assertTrue(job.since_author)
        self.assertIsNone(job.start)

    async def test_gates_answer_before_any_run(self):
        stale = self.core()
        stale.CORE_API_VERSION = 2
        cases = (
            (self.cog(core=None), "needs ChannelSummary"),
            (self.cog(core=stale), "needs ChannelSummary"),
            (self.cog(core=self.core(), enabled=False), "not enabled Learning"),
        )
        for cog, text in cases:
            with self.subTest(text=text):
                ctx = self.ctx()
                await lr.Learning.learning_since_me.callback(cog, ctx)
                self.assertIn(text, ctx.send.await_args.args[0])
                core = cog.bot.get_cog.return_value
                if core is not None:
                    core.run_channel_job.assert_not_awaited()

    async def test_a_disabled_core_answers_with_its_public_text(self):
        core = object.__new__(ChannelSummary)
        core._channel_locks = {}
        guild_scope = MagicMock()
        guild_scope.all = AsyncMock(return_value={**GUILD_DEFAULTS, "enabled": False})
        core.config = MagicMock()
        core.config.guild.return_value = guild_scope
        ctx = self.ctx()
        ctx.guild = SimpleNamespace(id=GUILD, me=object())
        ctx.channel = MagicMock(spec=discord.TextChannel)
        ctx.channel.permissions_for.return_value = SimpleNamespace(
            view_channel=True, read_message_history=True, send_messages=True, send_messages_in_threads=False, embed_links=True
        )
        ctx.author = SimpleNamespace(id=ALICE)
        await lr.Learning.learning_recent.callback(self.cog(core=core), ctx, "6h", None)
        self.assertEqual(ctx.send.await_args.args[0], "This server has not enabled ChannelSummary.")

    async def test_enable_needs_a_manager_and_the_exact_confirmation(self):
        cog = self.cog(core=self.core(), enabled=False)
        scope = cog.config.guild.return_value
        scope.enabled.set = AsyncMock()
        scope.disclosure_version.set = AsyncMock()
        ctx = self.ctx()
        ctx.author = SimpleNamespace(guild_permissions=SimpleNamespace(manage_messages=False))
        with self.assertRaises(Exception):
            await lr.Learning.learningset_enable.callback(cog, ctx, "I_ACCEPT")
        ctx.author = SimpleNamespace(guild_permissions=SimpleNamespace(manage_messages=True))
        ctx.tick = AsyncMock()
        await lr.Learning.learningset_enable.callback(cog, ctx, "yes")
        scope.enabled.set.assert_not_awaited()
        await lr.Learning.learningset_enable.callback(cog, ctx, "I_ACCEPT")
        scope.disclosure_version.set.assert_awaited_once_with(lr.LEARNING_DISCLOSURE_VERSION)
        scope.enabled.set.assert_awaited_once_with(True)


if __name__ == "__main__":
    unittest.main()
