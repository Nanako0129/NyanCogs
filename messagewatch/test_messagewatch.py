"""Focused tests for MessageWatch: what leaves, what is trusted, what is reported."""

from __future__ import annotations

import json
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import discord

from . import messagewatch as module
from .messagewatch import (
    DEFAULT_GUILD,
    DISCLOSURE_VERSION,
    MAX_MESSAGE_CHARS,
    MessageWatch,
    anonymise,
    build_questions,
    build_rule_questions,
    build_state,
    clean_text,
)


# The one wording every statement of the outbound contract has to use, so the
# three of them can be reconciled by a single assertion.
CHANNEL_CLAUSE = "name of the channel"


def window(*authors: int, at: float = 0.0) -> list[dict[str, object]]:
    return [
        {"author_id": author, "text": f"m{index}", "jump_url": f"https://d/{index}", "at": at}
        for index, author in enumerate(authors)
    ]


def pending() -> "module.defaultdict":
    """The same bounded queue the cog builds, so tests cannot outgrow it."""
    return module.defaultdict(lambda: module.deque(maxlen=module.MAX_PENDING_MESSAGES))


class ValueContext:
    """Stand-in for a Config value used as `async with scope.field() as value`."""

    def __init__(self, value: object) -> None:
        self.value = value

    async def __aenter__(self) -> object:
        return self.value

    async def __aexit__(self, *exc: object) -> bool:
        return False


class TestOutboundPayload(unittest.TestCase):
    def test_authors_become_per_request_labels_and_ids_never_leave(self) -> None:
        items = anonymise(window(111111111111111111, 222222222222222222, 111111111111111111))
        self.assertEqual([item["alias"] for item in items], ["u1", "u2", "u1"])

        body = json.dumps(build_state("交誼廳", items), ensure_ascii=False)
        for author in ("111111111111111111", "222222222222222222"):
            with self.subTest(author=author):
                self.assertNotIn(author, body)
        self.assertNotIn("jump_url", body)
        self.assertNotIn("https://d/", body)
        self.assertIn("u1", body)

    def test_labels_do_not_carry_across_requests(self) -> None:
        first = anonymise(window(111, 222))
        second = anonymise(window(222, 111))
        # u1 is the first author seen in that request and nothing more. A label
        # that meant the same person across requests would be an identifier.
        self.assertEqual(first[0]["alias"], "u1")
        self.assertEqual(second[0]["alias"], "u1")
        self.assertNotEqual(first[0]["author_id"], second[0]["author_id"])

    def test_mention_markup_and_length_are_bounded(self) -> None:
        self.assertEqual(
            clean_text("嗨 <@123456789012345678> 看 <#987654321> 這個 <a:party:112233> 訊息"),
            "嗨 [mention] 看 [mention] 這個 [emoji] 訊息",
        )
        self.assertEqual(clean_text("<@!123456789012345678>"), "[mention]")
        self.assertEqual(clean_text("  多   個    空白 "), "多 個 空白")
        self.assertEqual(clean_text(""), "")
        self.assertEqual(len(clean_text("字" * (MAX_MESSAGE_CHARS + 500))), MAX_MESSAGE_CHARS)

    def test_the_question_block_carries_no_identity_either(self) -> None:
        # build_state is not the only thing that leaves: the scam_index option
        # labels carry the alias and the message text too. The data statement
        # test pins build_state's fields, so a new field added here alone would
        # ship with the statement unchanged and every test green.
        items = anonymise(window(111111111111111111, 222222222222222222))
        body = json.dumps(build_questions(items), ensure_ascii=False)
        for secret in ("111111111111111111", "222222222222222222", "jump_url", "https://d/"):
            with self.subTest(secret=secret):
                self.assertNotIn(secret, body)
        criteria = build_questions(items)["scam_index"]["criteria"]
        self.assertEqual(criteria["0"], f"u1：{items[0]['text']}")

    def test_scam_options_describe_the_message_they_select(self) -> None:
        # An ordinal describes nothing. With labels that said only "第 6 則訊息"
        # the model pointed one message off, 6 times out of 6 at confidence
        # 0.77 to 0.93, so the label has to carry the message itself.
        items = anonymise(window(111, 222, 111))
        items[1]["text"] = "詐" * (module.SCAM_OPTION_LABEL_CHARS + 20)
        criteria = build_questions(items)["scam_index"]["criteria"]
        self.assertEqual(sorted(criteria), ["0", "1", "2", "none"])
        self.assertTrue(criteria["0"].startswith("u1："))
        self.assertTrue(criteria["1"].startswith("u2："))
        self.assertEqual(
            len(criteria["1"]), len("u2：") + module.SCAM_OPTION_LABEL_CHARS
        )
        # The model can only pick an option it was offered, so a short window
        # must not be given indexes that are not in it.
        self.assertEqual(len(build_questions(anonymise(window(*range(8))))["scam_index"]["criteria"]), 9)
        self.assertEqual(module.QUESTIONS["scam_index"]["criteria"], {})


class TestUntrustedAnswers(unittest.TestCase):
    def test_probabilities_scores_and_indexes_are_bounded(self) -> None:
        for value in (0.0, 0.5, 1.0):
            self.assertEqual(module._bounded_probability(value), value)
        for value in (True, False, -0.1, 1.1, "0.9", None, float("nan"), 10**400):
            with self.subTest(value=value):
                self.assertIsNone(module._bounded_probability(value))

        self.assertEqual(module._bounded_score(2.5, 4), 2.5)
        for value in (-0.1, 3.1, True, "2", None, float("nan"), 10**400):
            with self.subTest(value=value):
                self.assertIsNone(module._bounded_score(value, 4))

        self.assertEqual(module._bounded_index("2", 8), 2)
        # "²" and a 5000-digit string both pass str.isdigit() and both make
        # int() raise; they are provider-controlled and must not escape.
        for value in ("none", "8", "-1", "", 2, None, "1.5", "²", "9" * 5000):
            with self.subTest(value=str(value)[:12]):
                self.assertIsNone(module._bounded_index(value, 8))

    def test_findings_fire_only_above_their_threshold(self) -> None:
        settings = dict(DEFAULT_GUILD)
        quiet = {
            "any_scam": {"noul": 0.05},
            "is_hostile": {"noul": 0.15},
            "heat": {"score": 1.53},
        }
        self.assertEqual(MessageWatch.findings(quiet, settings, 8), (None, [], None))

        scam = {
            "any_scam": {"noul": 0.97},
            "scam_index": {"choice": "2"},
            "is_hostile": {"noul": 0.02},
            "heat": {"score": 0.3},
        }
        index, reasons, _ = MessageWatch.findings(scam, settings, 8)
        self.assertEqual(index, 2)
        self.assertEqual(reasons, ["詐騙 0.97"])

        fight = {
            "any_scam": {"noul": 0.01},
            "is_hostile": {"noul": 0.95},
            "heat": {"score": 2.6},
        }
        index, reasons, _ = MessageWatch.findings(fight, settings, 8)
        self.assertIsNone(index)
        self.assertEqual(reasons, ["敵意 0.95", "火藥味 2.60/3"])

    def test_a_malformed_answer_reports_nothing_rather_than_guessing(self) -> None:
        settings = dict(DEFAULT_GUILD)
        for answers in (
            {},
            {"any_scam": "not a mapping"},
            {"any_scam": {"noul": "0.99"}},
            {"any_scam": {"noul": 1.4}},
            {"is_hostile": {"noul": None}},
            {"heat": {"score": 99}},
        ):
            with self.subTest(answers=answers):
                self.assertEqual(MessageWatch.findings(answers, settings, 8), (None, [], None))

    def test_an_out_of_range_index_degrades_to_a_range_report(self) -> None:
        settings = dict(DEFAULT_GUILD)
        answers = {"any_scam": {"noul": 0.99}, "scam_index": {"choice": "99"}}
        index, reasons, _ = MessageWatch.findings(answers, settings, 8)
        self.assertIsNone(index)
        self.assertEqual(reasons, ["詐騙 0.99"])


class TestReport(unittest.TestCase):
    def test_two_findings_about_two_people_get_two_links(self) -> None:
        # A scam and a rule violation in one window are findings about two
        # different members. One link beside both reasons would put a rule's
        # name next to somebody else's message.
        channel = SimpleNamespace(id=5, mention="<#5>")
        items = anonymise(window(111, 222, 333))
        rendered = json.dumps(
            MessageWatch.report_embed(
                channel, items, 0, ["詐騙 0.97", "違反第 2 條：下指導棋"], 2
            ).to_dict(),
            ensure_ascii=False,
        )
        self.assertIn("https://d/0", rendered)
        self.assertIn("https://d/2", rendered)
        self.assertIn("<@111>", rendered)
        self.assertIn("<@333>", rendered)
        self.assertIn("違規的訊息", rendered)

        # The same message for both needs only one link.
        one = json.dumps(
            MessageWatch.report_embed(channel, items, 1, ["違反第 2 條"], 1).to_dict(),
            ensure_ascii=False,
        )
        self.assertNotIn("違規的訊息", one)

    def test_report_points_at_the_message_and_claims_no_authority(self) -> None:
        channel = SimpleNamespace(id=5, mention="<#5>")
        items = anonymise(window(111, 222, 333))
        embed = MessageWatch.report_embed(channel, items, 1, ["詐騙 0.97"])
        rendered = json.dumps(embed.to_dict(), ensure_ascii=False)
        self.assertIn("<@222>", rendered)
        self.assertIn("https://d/1", rendered)
        self.assertIn("<#5>", rendered)
        self.assertIn("不會刪除、禁言或加反應", rendered)

        # No index: the report says where to look without pointing at anyone.
        # Linking one message here reads as an accusation of whoever wrote it.
        fallback = json.dumps(
            MessageWatch.report_embed(channel, items, None, ["敵意 0.95"]).to_dict(),
            ensure_ascii=False,
        )
        self.assertIn("https://d/0", fallback)
        self.assertIn("https://d/2", fallback)
        for author in ("<@111>", "<@222>", "<@333>"):
            with self.subTest(author=author):
                self.assertNotIn(author, fallback)


class TestJudgeTransport(unittest.IsolatedAsyncioTestCase):
    def cog(self) -> MessageWatch:
        cog = object.__new__(MessageWatch)
        cog.bot = MagicMock()
        return cog

    async def request_with(self, status: int, body: bytes, text: str = ""):
        response = MagicMock()
        response.status = status
        response.content.read = AsyncMock(return_value=body)
        response_ctx = MagicMock()
        response_ctx.__aenter__ = AsyncMock(return_value=response)
        response_ctx.__aexit__ = AsyncMock(return_value=False)
        session = MagicMock()
        session.post.return_value = response_ctx
        session_ctx = MagicMock()
        session_ctx.__aenter__ = AsyncMock(return_value=session)
        session_ctx.__aexit__ = AsyncMock(return_value=False)
        items = anonymise(window(111)) if text else []
        if items:
            items[0]["text"] = text
        with patch("messagewatch.messagewatch.aiohttp.ClientSession", return_value=session_ctx):
            return await self.cog().judge(items, "c", "k")

    async def test_a_good_answer_is_returned(self) -> None:
        body = json.dumps({"answers": {"any_scam": {"noul": 0.9}}}).encode()
        self.assertEqual(await self.request_with(200, body), {"any_scam": {"noul": 0.9}})

    async def test_every_failure_returns_none_instead_of_raising(self) -> None:
        # A moderation aid that breaks on_message is worse than one that misses
        # a window, so none of these may escape.
        for status, body in (
            (401, b"{}"),
            (429, b"{}"),
            (500, b"{}"),
            (200, b"not json"),
            (200, json.dumps({"answers": "not a mapping"}).encode()),
            (200, json.dumps({"no_answers": 1}).encode()),
            (200, b"x" * (module.MAX_RESPONSE_BYTES + 1)),
            # Measured: 60,000 bytes of nesting is inside the byte cap and
            # raises RecursionError, which is not a ValueError.
            (200, (b"[" * 30000) + (b"]" * 30000)),
        ):
            with self.subTest(status=status, body=body[:20]):
                self.assertIsNone(await self.request_with(status, body))

    async def test_every_failure_is_logged_and_carries_no_message_content(self) -> None:
        # Without this the failures are silent, and a moderator cannot tell a
        # broken provider from a quiet week. The log must say what happened and
        # must not repeat what people wrote.
        secret = "這句話不可以出現在日誌裡"
        for status, body in ((500, b"{}"), (429, b"{}"), (200, b"not json"),
                             (200, json.dumps({"answers": "not a mapping"}).encode())):
            with self.subTest(status=status):
                with self.assertLogs(module.log, level="WARNING") as captured:
                    self.assertIsNone(await self.request_with(status, body, text=secret))
                blob = " ".join(captured.output)
                self.assertNotIn(secret, blob)
                self.assertIn("messagewatch:", blob)

    async def test_a_transport_error_returns_none(self) -> None:
        with patch(
            "messagewatch.messagewatch.aiohttp.ClientSession",
            side_effect=module.aiohttp.ClientError("boom"),
        ):
            self.assertIsNone(
                await self.cog().judge([], "c", "k")
            )


class TestGating(unittest.IsolatedAsyncioTestCase):
    def cog(self, *, still_watched=None, **overrides):
        cog = object.__new__(MessageWatch)
        cog.bot = MagicMock()
        settings = {**DEFAULT_GUILD, "disclosure_version": DISCLOSURE_VERSION,
                    "watched_channels": [5], **overrides}
        scope = MagicMock()
        scope.all = AsyncMock(return_value=settings)
        # What the in-lock recheck sees, which `[p]watch disable` can have
        # changed since the gate above it read the same field.
        scope.watched_channels = AsyncMock(
            return_value=settings["watched_channels"] if still_watched is None else still_watched
        )
        cog.config = MagicMock()
        cog.config.guild.return_value = scope
        cog._pending = pending()
        cog._last_report = {}
        cog._locks = module.defaultdict(module.asyncio.Lock)
        cog.flush = AsyncMock()
        return cog

    @staticmethod
    def message(*, channel_id: int = 5, bot: bool = False, content: str = "hello", webhook=None):
        return SimpleNamespace(
            guild=SimpleNamespace(id=1),
            channel=SimpleNamespace(id=channel_id, guild=SimpleNamespace(id=1), name="c"),
            author=SimpleNamespace(id=42, bot=bot),
            content=content,
            webhook_id=webhook,
            jump_url="https://d/1",
        )

    async def test_a_watched_channel_queues_the_message(self) -> None:
        cog = self.cog()
        await cog.on_message(self.message())
        self.assertEqual(len(cog._pending[5]), 1)
        self.assertEqual(cog._pending[5][0]["author_id"], 42)

    async def test_nothing_is_queued_without_an_accepted_disclosure(self) -> None:
        cog = self.cog(disclosure_version=0)
        await cog.on_message(self.message())
        self.assertEqual(len(cog._pending[5]), 0)

    async def test_nothing_is_queued_for_an_unwatched_channel(self) -> None:
        cog = self.cog(watched_channels=[])
        await cog.on_message(self.message())
        self.assertEqual(len(cog._pending[5]), 0)
        cog = self.cog()
        await cog.on_message(self.message(channel_id=6))
        self.assertEqual(len(cog._pending[6]), 0)

    async def test_bots_webhooks_and_empty_text_are_ignored(self) -> None:
        for kwargs in ({"bot": True}, {"webhook": 9}, {"content": "   "}, {"content": ""}):
            with self.subTest(kwargs=kwargs):
                cog = self.cog()
                await cog.on_message(self.message(**kwargs))
                self.assertEqual(len(cog._pending[5]), 0)

    async def test_the_window_flushes_only_when_it_is_full(self) -> None:
        cog = self.cog(window_size=3)
        for _ in range(2):
            await cog.on_message(self.message())
        cog.flush.assert_not_awaited()
        await cog.on_message(self.message())
        cog.flush.assert_awaited_once()

    async def test_a_channel_disabled_mid_flight_queues_nothing(self) -> None:
        # The handler passed the gate before `[p]watch disable` ran; the recheck
        # inside the lock is what stops it appending after the queue was
        # cleared, which would leave a disabled channel holding message text.
        cog = self.cog(still_watched=[])
        await cog.on_message(self.message())
        self.assertEqual(len(cog._pending[5]), 0)

    async def test_the_pending_queue_is_bounded(self) -> None:
        # A channel enabled with no API key never consumes its queue, so
        # without a cap it retains every message in process memory.
        with patch("messagewatch.messagewatch.Config"):
            cog = MessageWatch(MagicMock())
        self.assertGreater(module.MAX_PENDING_MESSAGES, module.SETTING_RULES["window_size"][2])
        queue = cog._pending[5]
        for index in range(module.MAX_PENDING_MESSAGES + 5):
            queue.append({"text": str(index)})
        self.assertEqual(len(queue), module.MAX_PENDING_MESSAGES)
        # The oldest go, not the newest: the current exchange is the one worth
        # judging.
        self.assertEqual(queue[0]["text"], "5")


class TestFlush(unittest.IsolatedAsyncioTestCase):
    def cog(self, *, answers, rules=None, route=0, **overrides):
        cog = object.__new__(MessageWatch)
        settings = {**DEFAULT_GUILD, "disclosure_version": DISCLOSURE_VERSION,
                    "report_channel": 77, "watched_channels": [5], "window_size": 3,
                    **overrides}
        scope = MagicMock()
        scope.all = AsyncMock(return_value=settings)
        cog.config = MagicMock()
        cog.config.guild.return_value = scope
        channel_scope = MagicMock()
        channel_scope.all = AsyncMock(
            return_value={**module.DEFAULT_CHANNEL, "rules": list(rules or ()),
                          "report_channel": route or 0}
        )
        cog.config.channel.return_value = channel_scope
        cog.get_api_key = AsyncMock(return_value="k")
        cog.judge = AsyncMock(return_value=answers)
        cog._pending = pending()
        cog._last_report = {}
        cog._locks = module.defaultdict(module.asyncio.Lock)
        cog._last_judged = {}
        cog._last_error = {}
        scope.watched_channels = AsyncMock(return_value=settings["watched_channels"])
        cog._pending[5].extend(window(111, 222, 333))
        return cog

    @staticmethod
    def channel():
        report = MagicMock(spec=discord.TextChannel)
        report.send = AsyncMock()
        guild = MagicMock()
        guild.get_channel.return_value = report
        channel = SimpleNamespace(id=5, guild=guild, name="c", mention="<#5>")
        return channel, report

    SCAM = {"any_scam": {"noul": 0.97}, "scam_index": {"choice": "1"},
            "is_hostile": {"noul": 0.01}, "heat": {"score": 0.1}}
    QUIET = {"any_scam": {"noul": 0.03}, "is_hostile": {"noul": 0.05}, "heat": {"score": 0.4}}

    async def test_a_crossing_window_reports_once(self) -> None:
        cog = self.cog(answers=self.SCAM)
        channel, report = self.channel()
        await cog.flush(channel)
        report.send.assert_awaited_once()
        kwargs = report.send.await_args.kwargs
        self.assertEqual(kwargs["allowed_mentions"].users, False)

    async def test_windows_overlap_so_an_exchange_is_never_split(self) -> None:
        # Consuming the whole batch would mean an exchange straddling a
        # boundary is never judged together, and hostility is a property of an
        # exchange. Window 4, stride 2: every message is judged twice.
        cog = self.cog(answers=self.QUIET, window_size=4)
        cog._pending[5].clear()
        cog._pending[5].extend(window(1, 2, 3, 4))
        channel, _ = self.channel()
        await cog.flush(channel)
        first = [item["text"] for item in cog.judge.await_args.args[0]]
        self.assertEqual(first, ["m0", "m1", "m2", "m3"])

        cog._pending[5].extend(
            {"author_id": 9, "text": f"m{index}", "jump_url": f"https://d/{index}"}
            for index in (4, 5)
        )
        await cog.flush(channel)
        second = [item["text"] for item in cog.judge.await_args.args[0]]
        # m3 and m4 sit either side of the first boundary and are judged
        # together here; with no overlap they never would be.
        self.assertEqual(second, ["m2", "m3", "m4", "m5"])

    async def test_the_whole_flush_runs_under_the_channel_lock(self) -> None:
        # The replaced version of this test asserted the opposite, and pinning
        # that choice is what let three defects grow in the seam it created:
        # the request ran outside the lock, so a second piece of shared state
        # had to stand in for it and disable had to be re-checked twice. One
        # rule, one lock. The cost is this channel's ingestion pausing for the
        # length of one request, which is asserted here rather than implied.
        cog = self.cog(answers=self.QUIET)
        channel, report = self.channel()
        observed = []
        cog.judge = AsyncMock(
            side_effect=lambda *a, **k: observed.append(cog._locks[5].locked()) or self.SCAM
        )
        await cog.flush(channel)
        self.assertEqual(observed, [True])
        report.send.assert_awaited_once()
        self.assertFalse(cog._locks[5].locked())

    async def test_a_quiet_window_reports_nothing(self) -> None:
        cog = self.cog(answers=self.QUIET)
        channel, report = self.channel()
        await cog.flush(channel)
        report.send.assert_not_awaited()

    async def test_the_cooldown_suppresses_a_second_report(self) -> None:
        # One argument spans many windows; without this the moderator channel
        # gets a report every few messages about the same exchange.
        cog = self.cog(answers=self.SCAM, cooldown_seconds=300)
        channel, report = self.channel()
        await cog.flush(channel)
        cog._pending[5].extend(window(111, 222, 333))
        await cog.flush(channel)
        self.assertEqual(report.send.await_count, 1)

    async def test_nothing_is_sent_without_a_report_channel_or_a_key(self) -> None:
        for overrides, key in (({"report_channel": 0}, "k"), ({}, None)):
            with self.subTest(overrides=overrides, key=key):
                cog = self.cog(answers=self.SCAM, **overrides)
                cog.get_api_key = AsyncMock(return_value=key)
                channel, report = self.channel()
                await cog.flush(channel)
                report.send.assert_not_awaited()
                cog.judge.assert_not_awaited()

    async def test_a_service_failure_leaves_the_channel_working(self) -> None:
        cog = self.cog(answers=None)
        channel, report = self.channel()
        await cog.flush(channel)
        report.send.assert_not_awaited()

    async def test_a_failed_send_does_not_start_the_cooldown(self) -> None:
        # Recording it before the send would silence the channel for up to a
        # day while nothing was ever delivered.
        cog = self.cog(answers=self.SCAM)
        channel, report = self.channel()
        report.send = AsyncMock(side_effect=discord.HTTPException(MagicMock(), "boom"))
        await cog.flush(channel)
        self.assertNotIn(5, cog._last_report)

    async def test_a_stale_disclosure_stops_the_export_in_flush_too(self) -> None:
        # on_message checks consent outside the lock; flush is where text
        # actually leaves. Nothing revokes consent at runtime today, so this
        # closes a window that is currently unreachable -- the point is that
        # it stops depending on that argument being re-derived correctly.
        cog = self.cog(answers=self.SCAM, disclosure_version=DISCLOSURE_VERSION - 1)
        channel, report = self.channel()
        await cog.flush(channel)
        cog.judge.assert_not_awaited()
        report.send.assert_not_awaited()
        self.assertEqual(len(cog._pending[5]), 0)
        self.assertEqual(cog._last_error[5][1], "disclosure_stale")

    async def test_an_unwatched_channel_exports_nothing(self) -> None:
        # `[p]watch disable` leaves the watched set before it clears the queue;
        # a window that filled just before it must not still be sent.
        cog = self.cog(answers=self.SCAM, watched_channels=[])
        channel, report = self.channel()
        await cog.flush(channel)
        cog.judge.assert_not_awaited()
        report.send.assert_not_awaited()
        self.assertEqual(len(cog._pending[5]), 0)

    async def test_disable_leaves_the_watched_set_and_clears_under_one_lock(self) -> None:
        cog = self.cog(answers=self.SCAM)
        watched = [5]
        cog.config.guild.return_value.watched_channels = MagicMock(
            return_value=ValueContext(watched)
        )
        ctx = SimpleNamespace(guild=MagicMock(), send=AsyncMock(), typing=lambda: ValueContext(None))
        channel = SimpleNamespace(id=5, mention="<#5>")

        # Asserting the effects alone does not observe the lock, and a version
        # that dropped it passed that way. Hold the lock and watch disable wait.
        await cog._locks[5].acquire()
        task = module.asyncio.create_task(
            MessageWatch.watch_disable.callback(cog, ctx, channel)
        )
        try:
            for _ in range(12):
                await module.asyncio.sleep(0)
            self.assertFalse(task.done())
            self.assertEqual(watched, [5])
            self.assertEqual(len(cog._pending[5]), 3)
        finally:
            cog._locks[5].release()
        await task

        self.assertEqual(watched, [])
        self.assertEqual(len(cog._pending[5]), 0)
        self.assertIn("已清除", ctx.send.await_args.args[0])
        self.assertFalse(cog._locks[5].locked())

    async def test_a_window_that_fills_during_a_request_is_still_judged(self) -> None:
        # The design this replaced dropped that window: a flush arriving while
        # a request was out returned immediately, and nothing ever came back
        # for the queue. On a quiet channel a complete window could sit
        # unjudged indefinitely -- the silent no-op this project cares about.
        # Waiting on the lock is what makes it impossible.
        cog = self.cog(answers=self.QUIET, cooldown_seconds=0)
        cog._pending[5].extend(window(4, 5, 6))
        channel, _ = self.channel()
        gate = module.asyncio.Event()

        async def blocked(*args, **kwargs):
            await gate.wait()
            return self.QUIET

        cog.judge = AsyncMock(side_effect=blocked)
        first = module.asyncio.create_task(cog.flush(channel))
        for _ in range(12):
            await module.asyncio.sleep(0)
        second = module.asyncio.create_task(cog.flush(channel))
        for _ in range(12):
            await module.asyncio.sleep(0)
        self.assertEqual(cog.judge.await_count, 1)
        self.assertFalse(second.done())
        gate.set()
        await module.asyncio.wait_for(module.asyncio.gather(first, second), timeout=5)
        self.assertEqual(cog.judge.await_count, 2)

    async def test_a_forbidden_report_channel_backs_off_instead_of_spinning(self) -> None:
        # Without the backoff, every later window opens another paid request for
        # a report that can never be delivered, silently, forever. A permission
        # problem does not fix itself inside one cooldown.
        cog = self.cog(answers=self.SCAM)
        channel, report = self.channel()
        report.send = AsyncMock(side_effect=discord.Forbidden(MagicMock(), "no"))
        with self.assertLogs(module.log, level="WARNING"):
            await cog.flush(channel)
        self.assertIn(5, cog._last_report)
        self.assertEqual(cog._last_error[5][1], "report_forbidden")

    async def test_a_silent_failure_is_recorded_for_watch_show(self) -> None:
        # Seven failure paths return silently, and to a moderator they look
        # exactly like a quiet week. This is where the difference is kept.
        for override, key, reason in (
            ({"report_channel": 0}, "k", "no_report_channel"),
            ({}, None, "no_api_key"),
        ):
            with self.subTest(reason=reason):
                cog = self.cog(answers=self.SCAM, **override)
                cog.get_api_key = AsyncMock(return_value=key)
                channel, _ = self.channel()
                await cog.flush(channel)
                self.assertEqual(cog._last_error[5][1], reason)

        cog = self.cog(answers=None)
        channel, _ = self.channel()
        await cog.flush(channel)
        self.assertEqual(cog._last_error[5][1], "provider_unavailable")
        self.assertNotIn(5, cog._last_judged)

    async def test_a_successful_judgement_clears_the_recorded_problem(self) -> None:
        cog = self.cog(answers=self.QUIET)
        cog._last_error[5] = (0.0, "provider_unavailable")
        channel, _ = self.channel()
        await cog.flush(channel)
        self.assertNotIn(5, cog._last_error)
        self.assertIn(5, cog._last_judged)

    async def test_a_routed_channel_reports_somewhere_else(self) -> None:
        # A report quotes the channel it came from. A venting channel's
        # findings carry what someone wrote there, and fewer people should see
        # those than see a scam alert.
        cog = self.cog(answers=self.SCAM, route=99)
        channel, report = self.channel()
        await cog.flush(channel)
        channel.guild.get_channel.assert_called_with(99)
        report.send.assert_awaited_once()

    async def test_no_route_falls_back_to_the_guild_channel(self) -> None:
        cog = self.cog(answers=self.SCAM)
        channel, report = self.channel()
        await cog.flush(channel)
        channel.guild.get_channel.assert_called_with(77)
        report.send.assert_awaited_once()

    async def test_a_route_is_enough_to_report_without_a_guild_default(self) -> None:
        cog = self.cog(answers=self.SCAM, route=99, report_channel=0)
        channel, report = self.channel()
        await cog.flush(channel)
        report.send.assert_awaited_once()
        self.assertNotIn(5, cog._last_error)

    async def test_a_partial_window_is_not_judged(self) -> None:
        cog = self.cog(answers=self.SCAM, window_size=8)
        channel, report = self.channel()
        await cog.flush(channel)
        cog.judge.assert_not_awaited()
        self.assertEqual(len(cog._pending[5]), 3)


class TestRules(unittest.TestCase):
    RULES = ["心靈雞湯：用勵志、正能量、「明天會更好」這類話語回應",
              "下指導棋：告訴發文者應該怎麼做、給建議或行動方案",
              "這我有經驗：把話題轉到自己身上，講自己也遇過"]

    @staticmethod
    def settings(**overrides):
        return {**DEFAULT_GUILD, **overrides}

    @staticmethod
    def answers(*, violation=0.96, meta="none", rule="2", confidence=0.98, index="1"):
        return {
            "any_scam": {"noul": 0.01},
            "is_hostile": {"noul": 0.02},
            "heat": {"score": 0.3},
            "any_violation": {"noul": violation},
            "meta_index": {"choice": meta},
            "which_rule": {"choice": rule, "confidence": confidence},
            "rule_index": {"choice": index},
        }

    def test_a_channel_without_rules_asks_exactly_what_it_asked_before(self) -> None:
        # The feature has to be absent, not disabled: an unused question still
        # costs tokens and still returns answers that could be misread.
        items = anonymise(window(1, 2))
        self.assertEqual(build_rule_questions(items, []), {})
        self.assertEqual(set(build_questions(items)), set(module.QUESTIONS))
        self.assertNotIn("channel_rules", build_state("c", items))
        self.assertNotIn("channel_purpose", build_state("c", items))
        # A purpose can be set without any rules, and `[p]watch rule clear`
        # leaves one behind. Neither may keep an outbound field alive on its
        # own: the purpose exists to sharpen a rule judgement.
        self.assertEqual(set(build_state("c", items, "倒垃圾用")), {"channel", "recent_messages"})
        # And a rule answer present without configured rules is ignored.
        self.assertEqual(
            MessageWatch.findings(self.answers(), self.settings(), 2), (None, [], None)
        )

    def test_the_rule_text_is_the_option_label_and_never_the_state(self) -> None:
        # The same lesson the scam question learned: an option has to describe
        # what it selects. And the text stays out of state, where a member
        # writes, so a member cannot introduce or edit a rule.
        items = anonymise(window(1, 2))
        questions = build_rule_questions(items, self.RULES)
        self.assertEqual(
            questions["which_rule"]["criteria"],
            {"1": self.RULES[0], "2": self.RULES[1], "3": self.RULES[2],
             "none": "沒有任何一則違反上列規則"},
        )
        body = json.dumps(build_state("樹洞", items, "倒垃圾用", self.RULES), ensure_ascii=False)
        for rule in self.RULES:
            with self.subTest(rule=rule[:8]):
                self.assertNotIn(rule, body)
        self.assertIn("第 1 條", body)
        self.assertIn("倒垃圾用", body)

    def test_a_violation_names_the_rule_and_the_message(self) -> None:
        index, reasons, rule_index = MessageWatch.findings(
            self.answers(), self.settings(), 4, self.RULES
        )
        # The rule carries its own pointer; `index` belongs to the scam finding
        # and stays empty when there is none.
        self.assertIsNone(index)
        self.assertEqual(rule_index, 1)
        self.assertEqual(len(reasons), 1)
        self.assertTrue(reasons[0].startswith("違反第 2 條：下指導棋"))

    def test_commentary_about_a_rule_is_vetoed(self) -> None:
        # Measured against the real ruleset: "你這樣算下指導棋喔" was reported as
        # a violation of the very rule it was citing, because jev reads
        # literally and the words were in the sentence. The veto is a separate
        # question compared in code -- and it has to name the message, not
        # merely say commentary is present.
        self.assertEqual(
            MessageWatch.findings(self.answers(meta="1"), self.settings(), 4, self.RULES),
            (None, [], None),
        )

    def test_commentary_elsewhere_does_not_veto_a_real_violation(self) -> None:
        # One member breaking a rule while another points at a different
        # message must still be reported; a veto that fired on any commentary
        # anywhere would silence the violation.
        _, reasons, rule_index = MessageWatch.findings(
            self.answers(meta="3", index="1"), self.settings(), 4, self.RULES
        )
        self.assertEqual(rule_index, 1)
        self.assertTrue(reasons[0].startswith("違反第 2 條"))

    def test_an_unreadable_veto_is_treated_as_a_veto(self) -> None:
        # This decides whether to name a person, so "cannot tell" must mean
        # "do not accuse".
        for meta in ("9", "-1", "", "²", 1, None, float("nan")):
            with self.subTest(meta=str(meta)[:10]):
                self.assertEqual(
                    MessageWatch.findings(
                        self.answers(meta=meta), self.settings(), 4, self.RULES
                    ),
                    (None, [], None),
                )
        answers = self.answers()
        del answers["meta_index"]
        self.assertEqual(
            MessageWatch.findings(answers, self.settings(), 4, self.RULES), (None, [], None)
        )

    def test_a_rule_report_must_name_a_message(self) -> None:
        # Without one there is nothing to act on, and no way to tell the
        # violation apart from a message commenting on it.
        for index in ("none", "9", "", None):
            with self.subTest(index=str(index)):
                self.assertEqual(
                    MessageWatch.findings(
                        self.answers(index=index), self.settings(), 4, self.RULES
                    ),
                    (None, [], None),
                )

    def test_an_uncertain_choice_reports_nothing(self) -> None:
        # Measured: "我也是" came back at 0.61 with confidence 0.43 -- the model
        # correctly saying it did not know -- while real violations held 0.87
        # to 1.00. Probability alone would have reported it.
        self.assertEqual(
            MessageWatch.findings(
                self.answers(violation=0.61, confidence=0.43), self.settings(), 4, self.RULES
            ),
            (None, [], None),
        )

    def test_a_rule_number_outside_the_configured_set_is_discarded(self) -> None:
        for rule in ("none", "0", "4", "-1", "", "²", 2, None):
            with self.subTest(rule=str(rule)[:8]):
                self.assertEqual(
                    MessageWatch.findings(
                        self.answers(rule=rule), self.settings(), 4, self.RULES
                    ),
                    (None, [], None),
                )

    def test_a_quiet_window_under_rules_reports_nothing(self) -> None:
        self.assertEqual(
            MessageWatch.findings(
                self.answers(violation=0.07, rule="none"), self.settings(), 4, self.RULES
            ),
            (None, [], None),
        )

    def test_an_uncertain_rule_is_reported_as_uncertain_not_suppressed(self) -> None:
        # Measured: "他應該不是針對你，可能只是那天壓力大" came back with
        # any_violation 0.94 and the right rule at confidence 0.67 -- sure a
        # rule was broken, unsure which of two neighbouring rules. Suppressing
        # that threw away a true positive to hide an uncertainty the moderator
        # is better off seeing. Whether a violation happened at all is decided
        # by a separate calibrated probability.
        _, reasons, rule_index = MessageWatch.findings(
            self.answers(violation=0.94, confidence=0.67), self.settings(), 4, self.RULES
        )
        self.assertEqual(rule_index, 1)
        self.assertTrue(reasons[0].startswith("疑似違規，條文不確定，最接近第 2 條"))

        # An unreadable confidence is uncertainty too, not a reason to drop it.
        for bad in (None, "0.9", float("nan"), True, 10**400):
            with self.subTest(confidence=str(bad)[:10]):
                _, reasons, _rule = MessageWatch.findings(
                    self.answers(confidence=bad), self.settings(), 4, self.RULES
                )
                self.assertTrue(reasons and reasons[0].startswith("疑似違規"))

    def test_a_rule_pointer_never_stands_in_for_a_missing_scam_pointer(self) -> None:
        # A scam whose own pointer was unreadable leaves index None on purpose
        # so the report shows a range. Borrowing the rule's pointer there puts
        # the rule-breaker's name under a 詐騙 reason -- the same
        # mis-attribution the scam option labels were rebuilt to stop.
        answers = self.answers(index="2")
        answers["any_scam"] = {"noul": 0.97}
        answers["scam_index"] = {"choice": "99"}
        index, reasons, rule_index = MessageWatch.findings(
            answers, self.settings(), 4, self.RULES
        )
        self.assertIsNone(index)
        self.assertEqual(rule_index, 2)
        self.assertTrue(reasons[0].startswith("詐騙"))

        # Rendered, that is a range for the scam and a named message for the
        # rule, never one link serving both.
        rendered = json.dumps(
            MessageWatch.report_embed(
                SimpleNamespace(id=5, mention="<#5>"),
                anonymise(window(11, 22, 33, 44)),
                index, reasons, rule_index,
            ).to_dict(),
            ensure_ascii=False,
        )
        self.assertIn("範圍", rendered)
        self.assertIn("違規的訊息", rendered)
        self.assertNotIn("指向的訊息", rendered)

    def test_a_rule_finding_joins_the_other_reasons(self) -> None:
        answers = self.answers()
        answers["is_hostile"] = {"noul": 0.95}
        index, reasons, _ = MessageWatch.findings(answers, self.settings(), 4, self.RULES)
        self.assertEqual(len(reasons), 2)
        self.assertTrue(reasons[0].startswith("敵意"))
        self.assertTrue(reasons[1].startswith("違反第 2 條"))


class TestRuleCommands(unittest.IsolatedAsyncioTestCase):
    @staticmethod
    def cog(rules):
        cog = object.__new__(MessageWatch)
        scope = MagicMock()
        scope.rules = MagicMock(return_value=ValueContext(rules))
        cog.config = MagicMock()
        cog.config.channel.return_value = scope
        return cog

    async def test_echoed_rule_text_cannot_ping_the_guild(self) -> None:
        # A rule is moderator-written text echoed back verbatim, so a rule
        # containing @everyone would otherwise notify the whole guild from the
        # confirmation message.
        channel = SimpleNamespace(id=5, mention="<#5>", name="c")
        rule = "禁止 @everyone 與 <@&123> 這類標記"

        cog = self.cog([])
        ctx = SimpleNamespace(guild=MagicMock(), send=AsyncMock())
        await MessageWatch.watch_rule_add.callback(cog, ctx, channel, text=rule)
        self.assertEqual(ctx.send.await_args.kwargs["allowed_mentions"].everyone, False)
        self.assertIn(rule, ctx.send.await_args.args[0])

        cog = self.cog([rule])
        ctx = SimpleNamespace(guild=MagicMock(), send=AsyncMock())
        await MessageWatch.watch_rule_remove.callback(cog, ctx, channel, 1)
        self.assertEqual(ctx.send.await_args.kwargs["allowed_mentions"].everyone, False)

    async def test_a_bare_group_answers_instead_of_doing_nothing(self) -> None:
        # Without invoke_without_command the callback never runs, so the help
        # these groups try to send is unreachable and `[p]watch` answers
        # nothing at all. The flag is the load-bearing part; the send_help call
        # alone is not enough.
        for group in (MessageWatch.watch_group, MessageWatch.watch_rule):
            with self.subTest(group=group.name):
                self.assertTrue(group.invoke_without_command)
                cog = object.__new__(MessageWatch)
                ctx = SimpleNamespace(
                    guild=MagicMock(), send=AsyncMock(),
                    send_help=AsyncMock(), invoked_subcommand=None,
                )
                await group.callback(cog, ctx)
                ctx.send_help.assert_awaited_once()

    async def test_a_route_alone_is_enough_to_enable_a_channel(self) -> None:
        # The guild default and a per-channel route are two ways to have a
        # report channel, and requiring the default anyway would force a
        # moderator to name a destination they do not intend to use.
        channel = SimpleNamespace(id=5, mention="<#5>", name="c")
        watched = []
        guild_scope = MagicMock()
        guild_scope.disclosure_version = AsyncMock(return_value=DISCLOSURE_VERSION)
        guild_scope.report_channel = AsyncMock(return_value=0)
        guild_scope.watched_channels = MagicMock(return_value=ValueContext(watched))
        channel_scope = MagicMock()
        channel_scope.report_channel = AsyncMock(return_value=99)

        cog = object.__new__(MessageWatch)
        cog.config = MagicMock()
        cog.config.guild.return_value = guild_scope
        cog.config.channel.return_value = channel_scope
        cog.get_api_key = AsyncMock(return_value="k")
        ctx = SimpleNamespace(guild=MagicMock(), send=AsyncMock())

        await MessageWatch.watch_enable.callback(cog, ctx, channel)
        self.assertEqual(watched, [5])
        self.assertIn("開始監看", ctx.send.await_args_list[0].args[0])

        # And with neither, it says both ways out.
        channel_scope.report_channel = AsyncMock(return_value=0)
        watched.clear()
        ctx = SimpleNamespace(guild=MagicMock(), send=AsyncMock())
        await MessageWatch.watch_enable.callback(cog, ctx, channel)
        self.assertEqual(watched, [])
        message = ctx.send.await_args.args[0]
        self.assertIn("watch report", message)
        self.assertIn("watch route", message)

    async def test_a_threshold_cannot_be_set_to_something_that_is_not_a_number(self) -> None:
        # Not a defect in the current guard: `if not low <= parsed <= high` is
        # False for NaN, so `not` makes it reject, which was measured. It is
        # pinned because the obvious rewrite, `if parsed < low or parsed >
        # high`, lets NaN through -- and a NaN threshold makes every comparison
        # against it false, so every rule probability would pass.
        #
        # This drives the command rather than re-evaluating the comparison. A
        # test that restates the logic it is checking cannot fail when that
        # logic is rewritten, which is how the first version of this passed
        # against the rewrite it exists to catch.
        floats = [key for key, (kind, _, _) in module.SETTING_RULES.items() if kind is float]
        self.assertTrue(floats)
        for key in floats:
            for raw in ("nan", "inf", "-inf", "NaN"):
                with self.subTest(key=key, raw=raw):
                    cog = object.__new__(MessageWatch)
                    scope = MagicMock()
                    scope.set_raw = AsyncMock()
                    cog.config = MagicMock()
                    cog.config.guild.return_value = scope
                    ctx = SimpleNamespace(guild=MagicMock(), send=AsyncMock())
                    await MessageWatch.watch_set.callback(cog, ctx, key, raw)
                    scope.set_raw.assert_not_awaited()
                    self.assertIn("必須介於", ctx.send.await_args.args[0])

        # And a value inside the range still stores.
        cog = object.__new__(MessageWatch)
        scope = MagicMock()
        scope.set_raw = AsyncMock()
        cog.config = MagicMock()
        cog.config.guild.return_value = scope
        ctx = SimpleNamespace(guild=MagicMock(), send=AsyncMock())
        await MessageWatch.watch_set.callback(cog, ctx, "rule_threshold", "0.5")
        scope.set_raw.assert_awaited_once()

    async def test_a_rule_is_bounded_and_counted(self) -> None:
        channel = SimpleNamespace(id=5, mention="<#5>", name="c")
        cog = self.cog([])
        ctx = SimpleNamespace(guild=MagicMock(), send=AsyncMock())
        await MessageWatch.watch_rule_add.callback(
            cog, ctx, channel, text="字" * (module.MAX_RULE_CHARS + 1)
        )
        self.assertIn(str(module.MAX_RULE_CHARS), ctx.send.await_args.args[0])

        full = ["規則"] * module.MAX_RULES
        cog = self.cog(full)
        ctx = SimpleNamespace(guild=MagicMock(), send=AsyncMock())
        await MessageWatch.watch_rule_add.callback(cog, ctx, channel, text="再一條")
        self.assertEqual(len(full), module.MAX_RULES)
        self.assertIn(str(module.MAX_RULES), ctx.send.await_args.args[0])


class TestIdleSweep(unittest.IsolatedAsyncioTestCase):
    """A window that never fills was never judged, which is the silent no-op
    this cog is most exposed to: a venting channel is a post, two replies and
    then nothing, and that is the shape the rules feature exists for."""

    def cog(self, *, idle=600):
        cog = object.__new__(MessageWatch)
        cog.bot = MagicMock()
        scope = MagicMock()
        scope.idle_seconds = AsyncMock(return_value=idle)
        cog.config = MagicMock()
        cog.config.guild.return_value = scope
        cog._pending = pending()
        cog._locks = module.defaultdict(module.asyncio.Lock)
        cog.flush = AsyncMock()
        return cog

    @staticmethod
    def channel():
        guild = MagicMock()
        channel = SimpleNamespace(id=5, guild=guild, name="c")
        return channel

    async def test_a_quiet_channel_is_judged_short_of_a_full_window(self) -> None:
        cog = self.cog()
        cog._pending = pending()
        cog._pending[5].extend(window(1, 2, 3, at=module.time.monotonic() - 900))
        channel = self.channel()
        cog.bot.get_channel.return_value = channel
        cog.flush = AsyncMock()
        await MessageWatch._sweep.coro(cog)
        cog.flush.assert_awaited_once_with(channel, partial=True)

    async def test_a_channel_that_just_spoke_is_left_alone(self) -> None:
        cog = self.cog()
        cog._pending = pending()
        cog._pending[5].extend(window(1, 2, 3, at=module.time.monotonic()))
        cog.bot.get_channel.return_value = self.channel()
        cog.flush = AsyncMock()
        await MessageWatch._sweep.coro(cog)
        cog.flush.assert_not_awaited()

    async def test_idle_zero_restores_the_old_behaviour_exactly(self) -> None:
        cog = self.cog(idle=0)
        cog._pending = pending()
        cog._pending[5].extend(window(1, 2, 3, at=module.time.monotonic() - 100_000))
        cog.bot.get_channel.return_value = self.channel()
        cog.flush = AsyncMock()
        await MessageWatch._sweep.coro(cog)
        cog.flush.assert_not_awaited()

    async def test_an_empty_or_unresolvable_channel_is_skipped(self) -> None:
        cog = self.cog()
        cog._pending = pending()
        cog._pending[5].extend([])
        cog._pending[6].extend(window(1, 2, at=module.time.monotonic() - 900))
        cog.bot.get_channel.return_value = None   # left the guild, or not cached
        cog.flush = AsyncMock()
        await MessageWatch._sweep.coro(cog)
        cog.flush.assert_not_awaited()

    async def test_unloading_stops_the_sweep(self) -> None:
        # The cog had no unload path at all before this, so an unloaded cog
        # kept a loop running for the life of the process. Started and
        # cancelled for real rather than asserting the call.
        cog = self.cog()
        cog.bot.wait_until_red_ready = AsyncMock()
        cog.bot.get_channel.return_value = None
        await cog.cog_load()
        self.assertTrue(cog._sweep.is_running())
        await cog.cog_unload()
        for _ in range(6):
            await module.asyncio.sleep(0)
        self.assertFalse(cog._sweep.is_running())

    async def test_a_conversation_that_resumed_is_not_consumed_as_finished(self) -> None:
        # The sweep measures idleness outside the lock and on_message appends
        # under it. A message arriving in that gap would otherwise have the
        # partial path eat a live conversation whole, without overlap.
        cog = object.__new__(MessageWatch)
        cog._pending = pending()
        cog._locks = module.defaultdict(module.asyncio.Lock)
        cog._last_report = {}
        cog._last_judged = {}
        cog._last_error = {}
        cog.get_api_key = AsyncMock(return_value="k")
        cog.judge = AsyncMock(return_value=None)
        settings = {**DEFAULT_GUILD, "disclosure_version": DISCLOSURE_VERSION,
                    "report_channel": 77, "watched_channels": [5], "idle_seconds": 600}
        scope = MagicMock()
        scope.all = AsyncMock(return_value=settings)
        scope.watched_channels = AsyncMock(return_value=[5])
        cog.config = MagicMock()
        cog.config.guild.return_value = scope
        channel_scope = MagicMock()
        channel_scope.all = AsyncMock(return_value=dict(module.DEFAULT_CHANNEL))
        cog.config.channel.return_value = channel_scope

        report = MagicMock(spec=discord.TextChannel)
        report.send = AsyncMock()
        guild = MagicMock()
        guild.get_channel.return_value = report
        channel = SimpleNamespace(id=5, guild=guild, name="c", mention="<#5>")

        # Three old messages, and one that just arrived.
        cog._pending[5].extend(window(1, 2, 3, at=module.time.monotonic() - 900))
        cog._pending[5].extend(window(4, at=module.time.monotonic()))
        await cog.flush(channel, partial=True)
        cog.judge.assert_not_awaited()
        self.assertEqual(len(cog._pending[5]), 4)

        # Once it is quiet again, the same call judges it.
        for item in cog._pending[5]:
            item["at"] = module.time.monotonic() - 900
        await cog.flush(channel, partial=True)
        cog.judge.assert_awaited_once()

    def test_a_short_window_is_consumed_whole(self) -> None:
        # There is no later message for an overlap to join a finished
        # conversation to, and leaving half behind would have the next sweep
        # judge the same tail again.
        cog = object.__new__(MessageWatch)
        cog._pending = pending()
        cog._pending[5].extend(window(1, 2, 3))
        taken = cog._take_window(5, 8, module.MIN_PARTIAL_WINDOW)
        self.assertEqual(len(taken), 3)
        self.assertEqual(len(cog._pending[5]), 0)

    def test_a_full_window_still_overlaps(self) -> None:
        cog = object.__new__(MessageWatch)
        cog._pending = pending()
        cog._pending[5].extend(window(1, 2, 3, 4))
        taken = cog._take_window(5, 4, module.MIN_PARTIAL_WINDOW)
        self.assertEqual(len(taken), 4)
        self.assertEqual(len(cog._pending[5]), 2)

    def test_one_message_is_not_an_exchange(self) -> None:
        # Hostility is a property of an exchange, so a lone message cannot
        # carry it; it waits for the next one instead.
        cog = object.__new__(MessageWatch)
        cog._pending = pending()
        cog._pending[5].extend(window(1))
        self.assertIsNone(cog._take_window(5, 8, module.MIN_PARTIAL_WINDOW))
        self.assertEqual(len(cog._pending[5]), 1)
        # And without the partial floor, nothing short of a full window moves.
        cog._pending[5].extend(window(2, 3))
        self.assertIsNone(cog._take_window(5, 8))


class TestDiagnosticSurface(unittest.IsolatedAsyncioTestCase):
    async def test_watch_show_stays_inside_the_embed_field_limit(self) -> None:
        # The guild that needs this surface most is the one watching enough
        # channels to overflow the field, which Discord rejects outright.
        cog = object.__new__(MessageWatch)
        cog._pending = pending()
        cog._last_judged = {}
        cog._last_error = {item: (1_700_000_000.0, "report_forbidden") for item in range(80)}
        settings = {**DEFAULT_GUILD, "report_channel": 77, "watched_channels": list(range(80))}
        scope = MagicMock()
        scope.all = AsyncMock(return_value=settings)
        cog.config = MagicMock()
        cog.config.guild.return_value = scope
        cog.config.channel_from_id.return_value.report_channel = AsyncMock(return_value=0)
        ctx = SimpleNamespace(guild=MagicMock(), send=AsyncMock())

        await MessageWatch.watch_show.callback(cog, ctx)
        embed = ctx.send.await_args.kwargs["embed"]
        field = next(f for f in embed.fields if f.name == "監看中的頻道")
        self.assertLessEqual(len(field.value), module.EMBED_FIELD_LIMIT)
        self.assertIn("未顯示", field.value)

    async def test_watch_show_says_so_when_the_disclosure_is_stale(self) -> None:
        # A bumped disclosure halts every channel. A list that still reads
        # "監看中" while nothing is judged is the silent no-op this cog exists
        # to avoid producing.
        cog = object.__new__(MessageWatch)
        cog._pending = pending()
        cog._last_judged = {}
        cog._last_error = {}
        settings = {**DEFAULT_GUILD, "report_channel": 77, "watched_channels": [5],
                    "disclosure_version": DISCLOSURE_VERSION - 1}
        scope = MagicMock()
        scope.all = AsyncMock(return_value=settings)
        cog.config = MagicMock()
        cog.config.guild.return_value = scope
        cog.config.channel_from_id.return_value.report_channel = AsyncMock(return_value=0)
        ctx = SimpleNamespace(guild=MagicMock(), send=AsyncMock())

        await MessageWatch.watch_show.callback(cog, ctx)
        fields = {f.name: f.value for f in ctx.send.await_args.kwargs["embed"].fields}
        self.assertIn("已暫停", fields["狀態"])
        self.assertIn("watch disclosure", fields["狀態"])

    async def test_watch_show_prints_every_tunable_threshold(self) -> None:
        # Every key `[p]watch set` accepts has to be readable back, or a
        # moderator cannot tell what the cog is actually using.
        cog = object.__new__(MessageWatch)
        cog._pending = pending()
        cog._last_judged = {}
        cog._last_error = {}
        settings = {**DEFAULT_GUILD, "report_channel": 77, "watched_channels": [5]}
        scope = MagicMock()
        scope.all = AsyncMock(return_value=settings)
        cog.config = MagicMock()
        cog.config.guild.return_value = scope
        cog.config.channel_from_id.return_value.report_channel = AsyncMock(return_value=0)
        ctx = SimpleNamespace(guild=MagicMock(), send=AsyncMock())

        await MessageWatch.watch_show.callback(cog, ctx)
        rendered = json.dumps(
            ctx.send.await_args.kwargs["embed"].to_dict(), ensure_ascii=False
        )
        for key in module.SETTING_RULES:
            with self.subTest(key=key):
                self.assertIn(str(settings[key]), rendered)

    async def test_watch_show_does_not_promise_more_than_the_sweep_delivers(self) -> None:
        # The first wording said an incomplete window is judged after the idle
        # period, which is not true of a one-message queue. This pins the text
        # to the constant rather than to a sentence, so the claim cannot
        # outlive the behaviour it describes.
        cog = object.__new__(MessageWatch)
        cog._pending = pending()
        cog._last_judged = {}
        cog._last_error = {}
        settings = {**DEFAULT_GUILD, "report_channel": 77, "watched_channels": [5],
                    "idle_seconds": 600}
        scope = MagicMock()
        scope.all = AsyncMock(return_value=settings)
        cog.config = MagicMock()
        cog.config.guild.return_value = scope
        cog.config.channel_from_id.return_value.report_channel = AsyncMock(return_value=0)
        ctx = SimpleNamespace(guild=MagicMock(), send=AsyncMock())

        await MessageWatch.watch_show.callback(cog, ctx)
        window_field = next(
            f.value for f in ctx.send.await_args.kwargs["embed"].fields if f.name == "視窗"
        )
        self.assertIn(str(module.MIN_PARTIAL_WINDOW), window_field)

        # With the sweep off it says so instead of describing a minimum.
        settings["idle_seconds"] = 0
        ctx = SimpleNamespace(guild=MagicMock(), send=AsyncMock())
        await MessageWatch.watch_show.callback(cog, ctx)
        off = next(
            f.value for f in ctx.send.await_args.kwargs["embed"].fields if f.name == "視窗"
        )
        self.assertIn("關閉", off)

    async def test_watch_show_reports_the_last_problem_per_channel(self) -> None:
        cog = object.__new__(MessageWatch)
        cog._pending = pending()
        cog._pending[5].extend(window(1, 2))
        cog._last_judged = {5: 1_700_000_000.0}
        cog._last_error = {5: (1_700_000_900.0, "report_forbidden")}
        settings = {**DEFAULT_GUILD, "report_channel": 77, "watched_channels": [5]}
        scope = MagicMock()
        scope.all = AsyncMock(return_value=settings)
        cog.config = MagicMock()
        cog.config.guild.return_value = scope
        cog.config.channel_from_id.return_value.report_channel = AsyncMock(return_value=0)
        ctx = SimpleNamespace(guild=MagicMock(), send=AsyncMock())

        await MessageWatch.watch_show.callback(cog, ctx)
        field = next(
            f for f in ctx.send.await_args.kwargs["embed"].fields if f.name == "監看中的頻道"
        )
        self.assertIn("待判 `2`", field.value)
        self.assertIn("report_forbidden", field.value)


class TestEndToEnd(unittest.IsolatedAsyncioTestCase):
    """on_message into the real flush -- the path every fix was made on and no
    test had ever walked. Both concurrency defects of review round 2 lived
    here, and each was verified only at the seam it was written for."""

    def cog(self, **overrides):
        cog = object.__new__(MessageWatch)
        cog.bot = MagicMock()
        settings = {**DEFAULT_GUILD, "disclosure_version": DISCLOSURE_VERSION,
                    "watched_channels": [5], "report_channel": 77,
                    "window_size": 4, "cooldown_seconds": 0, **overrides}
        scope = MagicMock()
        scope.all = AsyncMock(return_value=settings)
        scope.watched_channels = AsyncMock(return_value=settings["watched_channels"])
        cog.config = MagicMock()
        cog.config.guild.return_value = scope
        channel_scope = MagicMock()
        channel_scope.all = AsyncMock(return_value=dict(module.DEFAULT_CHANNEL))
        cog.config.channel.return_value = channel_scope
        cog.get_api_key = AsyncMock(return_value="k")
        cog._pending = pending()
        cog._last_report = {}
        cog._locks = module.defaultdict(module.asyncio.Lock)
        cog._last_judged = {}
        cog._last_error = {}
        return cog

    @staticmethod
    def message(index: int):
        report = MagicMock(spec=discord.TextChannel)
        guild = MagicMock()
        guild.id = 1
        guild.get_channel.return_value = report
        channel = SimpleNamespace(id=5, guild=guild, name="c", mention="<#5>")
        return SimpleNamespace(
            guild=guild, channel=channel, author=SimpleNamespace(id=40 + index, bot=False),
            content=f"訊息 {index}", webhook_id=None, jump_url=f"https://d/{index}",
        ), report

    async def test_messages_flow_through_to_one_report(self) -> None:
        cog = self.cog()
        cog.judge = AsyncMock(return_value={"any_scam": {"noul": 0.97},
                                            "scam_index": {"choice": "1"},
                                            "is_hostile": {"noul": 0.01},
                                            "heat": {"score": 0.2}})
        report = None
        for index in range(4):
            message, report = self.message(index)
            await cog.on_message(message)
        cog.judge.assert_awaited_once()
        report.send.assert_awaited_once()
        # Half the window is kept, so the next exchange is not split from it.
        self.assertEqual(len(cog._pending[5]), 2)
        self.assertIn(5, cog._last_judged)

    async def test_a_burst_produces_no_overlapping_requests(self) -> None:
        # Eight handlers dispatched at once on one channel. Each judgement runs
        # to completion before the next begins, because they share one lock.
        cog = self.cog()
        depth = 0
        peak = 0

        async def judging(*args, **kwargs):
            nonlocal depth, peak
            depth += 1
            peak = max(peak, depth)
            await module.asyncio.sleep(0)
            depth -= 1
            return {"any_scam": {"noul": 0.01}, "is_hostile": {"noul": 0.01}, "heat": {"score": 0.1}}

        cog.judge = AsyncMock(side_effect=judging)
        messages = [self.message(index)[0] for index in range(8)]
        await module.asyncio.gather(*(cog.on_message(message) for message in messages))
        self.assertEqual(peak, 1)
        self.assertGreaterEqual(cog.judge.await_count, 1)


class TestDataStatement(unittest.TestCase):
    @staticmethod
    def statement() -> str:
        from pathlib import Path

        return json.loads(
            (Path(__file__).parent / "info.json").read_text(encoding="utf-8")
        )["end_user_data_statement"]

    def test_the_statement_enumerates_exactly_what_build_state_sends(self) -> None:
        # The statement claimed the message ID was sent; build_state never
        # captured one. A list of phrases cannot catch a claim about a field
        # that does not exist, so this pins the payload's own shape: adding a
        # field here fails until the statement is rewritten to name it.
        items = anonymise(window(111, 222))
        state = build_state("交誼廳", items)
        self.assertEqual(set(state), {"channel", "recent_messages"})
        self.assertEqual(set(state["recent_messages"][0]), {"i", "author", "text"})
        # With a channel's rules configured, two moderator-written fields go
        # out as well, and the statement has to name them.
        with_rules = build_state("樹洞", items, "倒垃圾用", ["第一條規則"])
        self.assertEqual(
            set(with_rules), {"channel", "recent_messages", "channel_purpose", "channel_rules"}
        )

        statement = self.statement()
        self.assertNotIn("message ID", statement)
        for phrase in (
            "the text of each recent human message",
            "its position in the window",
            "a per-run pseudonymous author label",
            CHANNEL_CLAUSE,
            "those rules and the channel's purpose note",
            "are stored per channel",
        ):
            with self.subTest(phrase=phrase):
                self.assertIn(phrase, statement)

    def test_every_statement_of_the_contract_names_the_channel(self) -> None:
        # The payload carries the channel name. info.json was corrected for it
        # and the other two statements of the same contract were not, because
        # only one of the three had been opened. Reconciling one place is not
        # reconciling the contract, so all three are asserted here together.
        from pathlib import Path

        readme = (Path(__file__).resolve().parents[1] / "README.md").read_text(encoding="utf-8")
        section = readme.split("## MessageWatch", 1)[1].split("\n## ", 1)[0]
        self.assertIn("channel", build_state("交誼廳", anonymise(window(111))))
        for source, text in (
            ("info.json", self.statement()),
            ("DISCLOSURE_TEXT", module.DISCLOSURE_TEXT),
            ("README", section),
        ):
            with self.subTest(source=source):
                self.assertIn(CHANNEL_CLAUSE, text)

    def test_a_guild_on_the_pre_rules_disclosure_is_not_treated_as_consenting(self) -> None:
        # Version 1's text said nothing about rules, and rules now leave
        # Discord with every request, so a guild still on 1 consented to a
        # different export than the one happening.
        #
        # What this holds: the version cannot be reverted below the one whose
        # text first covered rules, and the text of the current version must
        # actually mention them. What it cannot hold: that a *future* outbound
        # field is accompanied by another bump. Nothing automated can check
        # that a human noticed what they changed; it is written here so the
        # next reader knows the gap is known rather than missed.
        self.assertGreaterEqual(DISCLOSURE_VERSION, 2)
        self.assertIn("rules are configured", module.DISCLOSURE_TEXT)
        self.assertIn("purpose note", module.DISCLOSURE_TEXT)

    def test_the_model_is_pinned_to_the_version_the_thresholds_were_measured_on(self) -> None:
        # An alias moves on the vendor's schedule and the probabilities behind
        # it change with it, which would leave the thresholds calibrated against
        # something no longer being deployed.
        from pathlib import Path

        self.assertNotIn("latest", module.MODEL)
        self.assertNotIn("preview", module.MODEL)
        readme = (Path(__file__).resolve().parents[1] / "README.md").read_text(encoding="utf-8")
        section = readme.split("## MessageWatch", 1)[1].split("\n## ", 1)[0]
        self.assertIn(module.MODEL, section)

    def test_the_statement_enumerates_every_stored_per_channel_field(self) -> None:
        # The statement listed what is stored and a new stored field was added
        # without it -- the same shape as the message-ID claim, where the
        # statement and the code disagreed and only the prose was checked.
        # Anchoring on the config keys is what makes the next added field fail
        # here until the statement names it.
        phrases = {
            "rules": "The configured rules",
            "purpose": "the purpose note",
            "report_channel": "the report-route channel ID set by [p]watch route",
        }
        self.assertEqual(set(module.DEFAULT_CHANNEL), set(phrases))
        statement = self.statement()
        for key, phrase in phrases.items():
            with self.subTest(key=key):
                self.assertIn(phrase, statement)

    def test_the_statement_names_what_leaves_and_what_does_not(self) -> None:
        statement = self.statement()
        for phrase in (
            "Discord user IDs, display names, and avatars are never sent",
            "never deletes, edits, reacts to, or punishes anything",
            "a guild manager enables it individually",
            "It does not store message content",
        ):
            with self.subTest(phrase=phrase):
                self.assertIn(phrase, statement)

    def test_the_disclosure_says_it_is_continuous_and_untriggered(self) -> None:
        for phrase in (
            "with nobody triggering it",
            "never deletes, edits, reacts to, or punishes anything",
            "generated per request and never stored",
        ):
            with self.subTest(phrase=phrase):
                self.assertIn(phrase, module.DISCLOSURE_TEXT)


if __name__ == "__main__":
    unittest.main()
