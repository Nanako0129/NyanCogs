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
    build_state,
    clean_text,
)


# The one wording every statement of the outbound contract has to use, so the
# three of them can be reconciled by a single assertion.
CHANNEL_CLAUSE = "name of the channel"


def window(*authors: int) -> list[dict[str, object]]:
    return [
        {"author_id": author, "text": f"m{index}", "jump_url": f"https://d/{index}"}
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
        self.assertEqual(MessageWatch.findings(quiet, settings, 8), (None, []))

        scam = {
            "any_scam": {"noul": 0.97},
            "scam_index": {"choice": "2"},
            "is_hostile": {"noul": 0.02},
            "heat": {"score": 0.3},
        }
        index, reasons = MessageWatch.findings(scam, settings, 8)
        self.assertEqual(index, 2)
        self.assertEqual(reasons, ["詐騙 0.97"])

        fight = {
            "any_scam": {"noul": 0.01},
            "is_hostile": {"noul": 0.95},
            "heat": {"score": 2.6},
        }
        index, reasons = MessageWatch.findings(fight, settings, 8)
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
                self.assertEqual(MessageWatch.findings(answers, settings, 8), (None, []))

    def test_an_out_of_range_index_degrades_to_a_range_report(self) -> None:
        settings = dict(DEFAULT_GUILD)
        answers = {"any_scam": {"noul": 0.99}, "scam_index": {"choice": "99"}}
        index, reasons = MessageWatch.findings(answers, settings, 8)
        self.assertIsNone(index)
        self.assertEqual(reasons, ["詐騙 0.99"])


class TestReport(unittest.TestCase):
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
    def cog(self, *, answers, **overrides):
        cog = object.__new__(MessageWatch)
        settings = {**DEFAULT_GUILD, "disclosure_version": DISCLOSURE_VERSION,
                    "report_channel": 77, "watched_channels": [5], "window_size": 3,
                    **overrides}
        scope = MagicMock()
        scope.all = AsyncMock(return_value=settings)
        cog.config = MagicMock()
        cog.config.guild.return_value = scope
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

    async def test_a_partial_window_is_not_judged(self) -> None:
        cog = self.cog(answers=self.SCAM, window_size=8)
        channel, report = self.channel()
        await cog.flush(channel)
        cog.judge.assert_not_awaited()
        self.assertEqual(len(cog._pending[5]), 3)


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
        ctx = SimpleNamespace(guild=MagicMock(), send=AsyncMock())

        await MessageWatch.watch_show.callback(cog, ctx)
        embed = ctx.send.await_args.kwargs["embed"]
        field = next(f for f in embed.fields if f.name == "監看中的頻道")
        self.assertLessEqual(len(field.value), module.EMBED_FIELD_LIMIT)
        self.assertIn("未顯示", field.value)

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
        state = build_state("交誼廳", anonymise(window(111, 222)))
        self.assertEqual(set(state), {"channel", "recent_messages"})
        self.assertEqual(set(state["recent_messages"][0]), {"i", "author", "text"})

        statement = self.statement()
        self.assertNotIn("message ID", statement)
        for phrase in (
            "the text of each recent human message",
            "its position in the window",
            "a per-run pseudonymous author label",
            CHANNEL_CLAUSE,
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
