"""Focused tests for MessageWatch: what leaves, what is trusted, what is reported."""

from __future__ import annotations

import json
import pathlib
import re
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
        {"author_id": author, "message_id": 900 + index, "text": f"m{index}",
         "jump_url": f"https://d/{index}", "at": at}
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
        # The footer no longer claims the cog cannot act -- it can, on a press.
        # What it must still say is that nothing happens without one.
        self.assertIn("只有你按才會發生", rendered)
        self.assertNotIn("不會刪除", rendered)

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
        cog._reset_state()
        cog.bot = MagicMock()
        return cog

    async def request_with(self, status: int, body: bytes, text: str = "", cog: MessageWatch | None = None):
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
            return await (cog or self.cog()).judge(items, "c", "k")

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

    async def test_judge_surfaces_input_tokens_without_widening_the_none_contract(self) -> None:
        # judge() used to throw usage.input_tokens away entirely. A caller
        # needs it to accumulate spend, but every failure path must still
        # return None -- the token count travels on `self`, not in the
        # return value, so it cannot change that contract.
        cog = self.cog()
        body = json.dumps(
            {"answers": {"any_scam": {"noul": 0.9}}, "usage": {"input_tokens": 512}}
        ).encode()
        answers = await self.request_with(200, body, cog=cog)
        self.assertEqual(answers, {"any_scam": {"noul": 0.9}})
        self.assertEqual(cog._last_input_tokens, 512)

        # A later failure on the same cog must not leave the previous call's
        # count readable -- a caller reading it after a None would silently
        # attribute someone else's tokens to a judgement that never happened.
        self.assertIsNone(await self.request_with(500, b"{}", cog=cog))
        self.assertIsNone(cog._last_input_tokens)

    async def test_an_untrusted_token_count_is_bounded_like_every_other_provider_field(self) -> None:
        for value in (True, False, -5, "512", None, float("nan"), 10**400):
            with self.subTest(value=value):
                self.assertIsNone(module._bounded_token_count(value))
        self.assertEqual(module._bounded_token_count(512), 512)
        self.assertEqual(module._bounded_token_count(0), 0)

        cog = self.cog()
        body = json.dumps(
            {"answers": {"any_scam": {"noul": 0.9}}, "usage": {"input_tokens": "not a number"}}
        ).encode()
        await self.request_with(200, body, cog=cog)
        self.assertIsNone(cog._last_input_tokens)


class TestGating(unittest.IsolatedAsyncioTestCase):
    def cog(self, *, still_watched=None, images=False, **overrides):
        cog = object.__new__(MessageWatch)
        cog._reset_state()
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
        channel_scope = MagicMock()
        channel_scope.images = AsyncMock(return_value=images)
        cog.config.channel.return_value = channel_scope
        cog._pending = pending()
        cog._last_report = {}
        cog._locks = module.defaultdict(module.asyncio.Lock)
        cog.flush = AsyncMock()
        return cog

    @staticmethod
    def message(*, channel_id: int = 5, bot: bool = False, content: str = "hello",
                webhook=None, attachments=()):
        return SimpleNamespace(
            attachments=list(attachments),
            guild=SimpleNamespace(id=1),
            channel=SimpleNamespace(id=channel_id, guild=SimpleNamespace(id=1), name="c"),
            author=SimpleNamespace(id=42, bot=bot),
            content=content,
            webhook_id=webhook,
            jump_url="https://d/1",
            id=4242,
        )

    async def test_a_watched_channel_queues_the_message(self) -> None:
        cog = self.cog()
        await cog.on_message(self.message())
        self.assertEqual(len(cog._pending[5]), 1)
        self.assertEqual(cog._pending[5][0]["author_id"], 42)

    async def test_an_image_only_message_is_queued_where_images_are_read(self) -> None:
        # A bare screenshot is the commonest shape a scam takes here and it
        # carries no text at all, so the empty-text gate made the image feature
        # unreachable for the case it was built for.
        shot = SimpleNamespace(content_type="image/png", filename="s.png", size=4000,
                               width=800, height=600, id=991,
                               url="https://cdn.discordapp.com/x.png")
        cog = self.cog(images=True)
        await cog.on_message(self.message(content="   ", attachments=[shot]))
        self.assertEqual(len(cog._pending[5]), 1)
        self.assertEqual(cog._pending[5][0]["images"], [{"id": 991, "url": shot.url}])

    async def test_an_image_only_message_is_dropped_where_images_are_not_read(self) -> None:
        # Otherwise a channel with images off accumulates empty messages that
        # push real ones out of the window.
        shot = SimpleNamespace(content_type="image/png", filename="s.png", size=4000,
                               width=800, height=600, id=991,
                               url="https://cdn.discordapp.com/x.png")
        cog = self.cog(images=False)
        await cog.on_message(self.message(content="", attachments=[shot]))
        self.assertEqual(len(cog._pending[5]), 0)

    async def test_the_ordinary_path_does_not_read_the_channel_settings(self) -> None:
        # The channel read sits on the image-only branch so a message with text
        # still costs one settings lookup, not two.
        cog = self.cog(images=True)
        await cog.on_message(self.message(content="hello"))
        cog.config.channel.assert_not_called()

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

    async def test_a_queued_item_carries_what_both_features_read(self) -> None:
        # Every other test seeds the queue directly, so a field dropped from
        # this append would be invisible: the sweep would never fire on real
        # messages and the buttons would address message 0, with the suite
        # green. The fields have to come from the ingestion path.
        cog = self.cog()
        before = module.time.monotonic()
        await cog.on_message(self.message())
        item = cog._pending[5][0]
        self.assertEqual(
            set(item), {"author_id", "message_id", "text", "jump_url", "at", "images"}
        )
        # Captured at ingest because the Message with its attachments is gone
        # by the time the window is judged.
        self.assertEqual(item["images"], [])
        self.assertGreaterEqual(item["at"], before)
        self.assertEqual(item["message_id"], 4242)
        self.assertEqual(item["author_id"], 42)

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
        self.assertGreater(module.MAX_PENDING_MESSAGES, module.SETTING_RULES["window_size"].high)
        queue = cog._pending[5]
        for index in range(module.MAX_PENDING_MESSAGES + 5):
            queue.append({"text": str(index)})
        self.assertEqual(len(queue), module.MAX_PENDING_MESSAGES)
        # The oldest go, not the newest: the current exchange is the one worth
        # judging.
        self.assertEqual(queue[0]["text"], "5")


class TestFlush(unittest.IsolatedAsyncioTestCase):
    def cog(self, *, answers, rules=None, route=0, channel_threshold=0.0, **overrides):
        cog = object.__new__(MessageWatch)
        cog._reset_state()
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
                          "report_channel": route or 0, "rule_threshold": channel_threshold}
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

    # Rules are per-channel but rule_threshold was per-guild, and measured
    # 2026-09-20 the separation between violating and clean messages differs
    # by ruleset -- see DEFAULT_CHANNEL's comment. These four pin the effective
    # value flush() actually judges against.
    RULE_ANSWERS = {
        "any_scam": {"noul": 0.01}, "is_hostile": {"noul": 0.01}, "heat": {"score": 0.1},
        "any_violation": {"noul": 0.75}, "meta_index": {"choice": "none"},
        "which_rule": {"choice": "1", "confidence": 0.9}, "rule_index": {"choice": "0"},
    }

    async def test_a_channel_with_no_override_uses_the_guild_value(self) -> None:
        # No channel override (0.0, the inherit sentinel) and a guild threshold
        # of 0.5: the violation probability is 0.75, above the guild value, so
        # this only reports if the guild value is actually what's compared.
        cog = self.cog(
            answers=self.RULE_ANSWERS, rules=["dummy"], channel_threshold=0.0, rule_threshold=0.5
        )
        channel, report = self.channel()
        await cog.flush(channel)
        report.send.assert_awaited_once()

    async def test_a_channel_override_wins_and_the_guild_value_is_ignored(self) -> None:
        # Channel override 0.95 against a guild threshold of 0.5: probability
        # 0.75 clears the guild value but not the channel's, so a report here
        # would mean the guild value was used instead of the channel's.
        cog = self.cog(
            answers=self.RULE_ANSWERS, rules=["dummy"], channel_threshold=0.95, rule_threshold=0.5
        )
        channel, report = self.channel()
        await cog.flush(channel)
        report.send.assert_not_awaited()

    async def test_an_override_of_zero_inherits_rather_than_reporting_everything(self) -> None:
        # The one that matters most: `channel_value or guild_value` treats 0.0
        # as "inherit" correctly, but `if channel_value is not None` treats it
        # as a real override of 0.0, under which every probability -- 0.01
        # included -- clears the threshold and every window gets reported.
        answers = {**self.RULE_ANSWERS, "any_violation": {"noul": 0.01}}
        cog = self.cog(
            answers=answers, rules=["dummy"], channel_threshold=0.0, rule_threshold=0.99
        )
        channel, report = self.channel()
        await cog.flush(channel)
        report.send.assert_not_awaited()


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
        cog._reset_state()
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
                cog._reset_state()
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
        cog._reset_state()
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
        floats = [key for key, rule in module.SETTING_RULES.items() if rule.kind is float]
        self.assertTrue(floats)
        for key in floats:
            for raw in ("nan", "inf", "-inf", "NaN"):
                with self.subTest(key=key, raw=raw):
                    cog = object.__new__(MessageWatch)
                    cog._reset_state()
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
        cog._reset_state()
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

    @staticmethod
    def threshold_cog(channel_threshold, guild_threshold=module.DEFAULT_RULE_THRESHOLD):
        cog = object.__new__(MessageWatch)
        channel_scope = MagicMock()
        channel_scope.all = AsyncMock(
            return_value={**module.DEFAULT_CHANNEL, "rule_threshold": channel_threshold}
        )
        channel_scope.rule_threshold = MagicMock()
        channel_scope.rule_threshold.set = AsyncMock()
        guild_scope = MagicMock()
        guild_scope.all = AsyncMock(return_value={**DEFAULT_GUILD, "rule_threshold": guild_threshold})
        cog.config = MagicMock()
        cog.config.channel.return_value = channel_scope
        cog.config.guild.return_value = guild_scope
        return cog

    async def test_the_threshold_command_rejects_a_value_outside_0_to_1(self) -> None:
        channel = SimpleNamespace(id=5, mention="<#5>", name="c")
        for raw in ("1.5", "-0.1", "nan"):
            with self.subTest(raw=raw):
                cog = self.threshold_cog(0.0)
                ctx = SimpleNamespace(guild=MagicMock(), send=AsyncMock())
                await MessageWatch.watch_rule_threshold.callback(cog, ctx, channel, raw)
                cog.config.channel.return_value.rule_threshold.set.assert_not_awaited()
                self.assertIn("必須介於", ctx.send.await_args.args[0])

    async def test_the_threshold_command_stores_a_valid_value(self) -> None:
        channel = SimpleNamespace(id=5, mention="<#5>", name="c")
        cog = self.threshold_cog(0.0)
        ctx = SimpleNamespace(guild=MagicMock(), send=AsyncMock())
        await MessageWatch.watch_rule_threshold.callback(cog, ctx, channel, "0.5")
        cog.config.channel.return_value.rule_threshold.set.assert_awaited_once_with(0.5)
        self.assertIn("0.5", ctx.send.await_args.args[0])

    async def test_rule_list_states_the_effective_threshold_and_whether_it_is_inherited(
        self,
    ) -> None:
        channel = SimpleNamespace(id=5, mention="<#5>", name="c")

        # Inherited: the channel value is the sentinel, so the embed must show
        # the guild's value with an "inherited" label.
        cog = self.threshold_cog(0.0, guild_threshold=0.5)
        ctx = SimpleNamespace(guild=MagicMock(), send=AsyncMock())
        await MessageWatch.watch_rule_list.callback(cog, ctx, channel)
        rendered = json.dumps(ctx.send.await_args.kwargs["embed"].to_dict(), ensure_ascii=False)
        self.assertIn("0.5", rendered)
        self.assertIn("沿用伺服器設定", rendered)

        # Overridden: the channel's own value shows, not the guild's.
        cog = self.threshold_cog(0.9, guild_threshold=0.5)
        ctx = SimpleNamespace(guild=MagicMock(), send=AsyncMock())
        await MessageWatch.watch_rule_list.callback(cog, ctx, channel)
        rendered = json.dumps(ctx.send.await_args.kwargs["embed"].to_dict(), ensure_ascii=False)
        self.assertIn("0.9", rendered)
        self.assertIn("此頻道獨立設定", rendered)


class TestActionAddressing(unittest.TestCase):
    def test_a_custom_id_round_trips_and_fits_discord_limit(self) -> None:
        # Discord rejects the whole message when a custom_id is too long, so
        # the failure would be an alert that never arrives. discord.py does not
        # check it, which was measured.
        widest = module.build_custom_id("mute", "s", 10**19 - 1, 10**19 - 1, 10**19 - 1)
        self.assertLessEqual(len(widest), module.CUSTOM_ID_LIMIT)
        # Asserting the built length only restates what the function produced;
        # it cannot fail when the guard is deleted. This drives the guard.
        with self.assertRaises(ValueError):
            module.build_custom_id("x" * 120, "s", 1, 2, 3)
        self.assertEqual(
            module.parse_custom_id(widest), ("mute", "s", 10**19 - 1, 10**19 - 1, 10**19 - 1)
        )

    def test_a_custom_id_is_untrusted_input(self) -> None:
        # It names a message about to be deleted and a member about to be
        # punished, and it arrives from Discord.
        for bad in (
            "", "nope:del:s:1:2:3", "mw:evict:s:1:2:3", "mw:del:s:1:2",
            "mw:del:s:1:2:3:4", "mw:del:s:1:2:٣", "mw:del:s:1:2:-3",
            "mw:del::1:2:3", "mw:del:s:1:2:" + "9" * 21, None, 7,
        ):
            with self.subTest(bad=str(bad)[:24]):
                self.assertIsNone(module.parse_custom_id(bad))

    def test_the_buttons_offered_are_the_ones_configured(self) -> None:
        view = module.build_action_view(["ok", "no", "del"], "s", 5, 900, 42)
        self.assertEqual([item.label for item in view.children], ["屬實", "誤判", "刪除訊息"])
        self.assertIsNone(view.timeout)
        # An action needing a target message is dropped when there is none,
        # rather than offered and failing on the click.
        partial = module.build_action_view(["ok", "del", "mute"], "s", 5, 0, 0)
        self.assertEqual([item.label for item in partial.children], ["屬實"])
        self.assertIsNone(module.build_action_view([], "s", 5, 900, 42))
        self.assertIsNone(module.build_action_view(["nonsense"], "s", 5, 900, 42))

    def test_the_mark_kind_names_the_judgement_that_was_marked(self) -> None:
        # A mark is only useful for calibration if it says which judgement it
        # was about.
        self.assertEqual(module.reason_kind(["詐騙 0.97"]), "s")
        self.assertEqual(module.reason_kind(["敵意 0.95", "火藥味 2.60/3"]), "h")
        self.assertEqual(module.reason_kind(["違反第 2 條：下指導棋"]), "r")
        self.assertEqual(module.reason_kind(["疑似違規，條文不確定，最接近第 6 條"]), "r")
        self.assertEqual(module.reason_kind(["火藥味 2.60/3"]), "t")


class TestActionPermissions(unittest.IsolatedAsyncioTestCase):
    @staticmethod
    def interaction(custom_id, *, perms=None, member=True):
        guild = MagicMock()
        clicker = MagicMock()
        clicker.guild_permissions = SimpleNamespace(
            **{"manage_messages": False, "moderate_members": False, "manage_roles": False,
               **(perms or {})}
        )
        guild.get_member.return_value = clicker if member else None
        interaction = MagicMock()
        interaction.type = discord.InteractionType.component
        interaction.data = {"custom_id": custom_id}
        interaction.guild = guild
        interaction.user = SimpleNamespace(id=7, mention="<@7>")
        interaction.response.send_message = AsyncMock()
        interaction.response.send_modal = AsyncMock()
        interaction.message = None
        return interaction, guild

    @staticmethod
    def cog():
        cog = object.__new__(MessageWatch)
        cog._reset_state()
        cog.bot = MagicMock()
        cog.config = MagicMock()
        return cog

    async def test_permission_is_the_clickers_not_the_channels(self) -> None:
        # Anyone who can read the moderator channel could otherwise act on a
        # report just by pressing.
        for action, needed in (("del", "manage_messages"), ("mute", "moderate_members"),
                               ("role", "manage_roles")):
            with self.subTest(action=action):
                custom_id = module.build_custom_id(action, "s", 5, 900, 42)
                interaction, _ = self.interaction(custom_id)
                await MessageWatch.on_interaction(self.cog(), interaction)
                sent = interaction.response.send_message.await_args
                self.assertIn(needed, sent.args[0])
                self.assertTrue(sent.kwargs["ephemeral"])
                interaction.response.send_modal.assert_not_awaited()

    async def test_a_mark_needs_no_permission_because_it_acts_on_nothing(self) -> None:
        cog = self.cog()
        scope = MagicMock()
        scope.marks = MagicMock(return_value=ValueContext({}))
        cog.config.guild.return_value = scope
        cog._audit = AsyncMock()
        interaction, _ = self.interaction(module.build_custom_id("ok", "s", 5, 900, 42))
        await MessageWatch.on_interaction(cog, interaction)
        self.assertIn("屬實", interaction.response.send_message.await_args.args[0])

    async def test_an_unrelated_interaction_is_left_alone(self) -> None:
        for data in ({"custom_id": "someone-elses-button"}, {}, None):
            with self.subTest(data=str(data)[:24]):
                interaction, _ = self.interaction("x")
                interaction.data = data
                await MessageWatch.on_interaction(self.cog(), interaction)
                interaction.response.send_message.assert_not_awaited()

        # And a non-component interaction, such as a slash command.
        interaction, _ = self.interaction(module.build_custom_id("ok", "s", 5, 900, 42))
        interaction.type = discord.InteractionType.application_command
        await MessageWatch.on_interaction(self.cog(), interaction)
        interaction.response.send_message.assert_not_awaited()

    async def test_a_departed_member_stops_the_action(self) -> None:
        custom_id = module.build_custom_id("mute", "s", 5, 900, 42)
        interaction, guild = self.interaction(custom_id, perms={"moderate_members": True})
        clicker = guild.get_member.return_value
        # The clicker resolves; the member the button names does not.
        guild.get_member.side_effect = lambda uid: clicker if uid == 7 else None
        await MessageWatch.on_interaction(self.cog(), interaction)
        self.assertIn("找不到這位成員", interaction.response.send_message.await_args.args[0])
        interaction.response.send_modal.assert_not_awaited()


class TestModlogAndRole(unittest.IsolatedAsyncioTestCase):
    async def test_every_case_type_the_cog_uses_is_registered(self) -> None:
        # create_case raises for an unregistered action type and _case swallows
        # it, so without registration every action succeeds and none is logged
        # -- while the disclosure, the data statement and the README all promise
        # each one is recorded. Measured: Red raises
        # "<name> is not a valid action type."
        cog = object.__new__(MessageWatch)
        cog._reset_state()
        # cog_load also starts the sweep now, so the instance has to be
        # loadable and the loop has to be stopped. Cancelling alone was not
        # enough: without a `bot`, `_before_sweep` raises before the cleanup
        # runs and the task is collected with an unretrieved exception.
        cog.bot = MagicMock()
        cog.bot.wait_until_red_ready = AsyncMock()
        cog._pending = pending()
        self.addCleanup(cog._sweep.cancel)
        registered = []
        with patch("messagewatch.messagewatch.modlog.register_casetype",
                   new=AsyncMock(side_effect=lambda **kw: registered.append(kw["name"]))):
            await cog.cog_load()
        self.assertEqual(sorted(registered), sorted(c["name"] for c in module.CASE_TYPES))

        # Every name passed to _case has to be one of them.
        source = (pathlib.Path(__file__).parent / "messagewatch.py").read_text(encoding="utf-8")
        used = set(re.findall(r'self\._case\(\s*[^,]+,\s*"([a-z_]+)"', source))
        self.assertTrue(used)
        self.assertEqual(used - {c["name"] for c in module.CASE_TYPES}, set())

    async def test_an_already_registered_case_type_is_not_fatal(self) -> None:
        cog = object.__new__(MessageWatch)
        cog._reset_state()
        cog.bot = MagicMock()
        cog.bot.wait_until_red_ready = AsyncMock()
        cog._pending = pending()
        self.addCleanup(cog._sweep.cancel)
        with patch("messagewatch.messagewatch.modlog.register_casetype",
                   new=AsyncMock(side_effect=RuntimeError("already registered"))):
            await cog.cog_load()  # must not raise

    async def test_the_role_comes_from_the_watched_channel_not_the_report_channel(self) -> None:
        # `[p]watch action role` stores it on the watched channel; the report
        # can be routed elsewhere entirely. Reading the interaction's channel
        # found no role in any configuration.
        cog = object.__new__(MessageWatch)
        cog._reset_state()
        cog.bot = MagicMock()
        scopes = {}

        def channel_from_id(cid):
            scope = MagicMock()
            scope.all = AsyncMock(
                return_value={**module.DEFAULT_CHANNEL,
                              "action_role": 777 if cid == 5 else 0}
            )
            scopes[cid] = scope
            return scope

        cog.config = MagicMock()
        cog.config.channel_from_id.side_effect = channel_from_id
        cog._case = AsyncMock()
        cog._audit = AsyncMock()

        role = MagicMock()
        role.name = "樹洞黑名單"
        guild = MagicMock()
        guild.get_role.return_value = role
        member = MagicMock()
        member.add_roles = AsyncMock()
        member.mention = "<@42>"
        interaction = MagicMock()
        interaction.channel_id = 999  # the report channel, not the watched one
        interaction.user = SimpleNamespace(id=7, mention="<@7>")
        interaction.response.send_message = AsyncMock()

        await cog._add_role(interaction, guild, member, 5)

        guild.get_role.assert_called_once_with(777)
        member.add_roles.assert_awaited_once()
        self.assertIn(5, scopes)
        self.assertNotIn(999, scopes)


class TestIdleSweep(unittest.IsolatedAsyncioTestCase):
    """A window that never fills was never judged, which is the silent no-op
    this cog is most exposed to: a venting channel is a post, two replies and
    then nothing, and that is the shape the rules feature exists for."""

    def cog(self, *, idle=600):
        cog = object.__new__(MessageWatch)
        cog._reset_state()
        cog.bot = MagicMock()
        scope = MagicMock()
        scope.idle_seconds = AsyncMock(return_value=idle)
        cog.config = MagicMock()
        cog.config.guild.return_value = scope
        # The sweep also flushes usage and refreshes dashboards now, so a
        # fixture that drives it needs those to resolve. They were invisible
        # here while the code paths guarded themselves with hasattr.
        cog.config.all_guilds = AsyncMock(return_value={})
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

    async def test_a_stale_single_message_never_reaches_flush(self) -> None:
        # It is waiting for a second message, not failing. Reaching `flush`
        # every minute would record `no_api_key` or `no_report_channel` against
        # it before `_take_window` turns it away, putting a false problem in the
        # surface built to tell a real one from a quiet channel.
        cog = self.cog()
        cog._pending = pending()
        cog._pending[5].extend(window(1, at=module.time.monotonic() - 900))
        cog.bot.get_channel.return_value = self.channel()
        cog.flush = AsyncMock()
        await MessageWatch._sweep.coro(cog)
        cog.flush.assert_not_awaited()
        cog.bot.get_channel.assert_not_called()

        # A second message makes it eligible.
        cog._pending[5].extend(window(2, at=module.time.monotonic() - 900))
        await MessageWatch._sweep.coro(cog)
        cog.flush.assert_awaited_once()

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
        # The loop gets one real tick in before the cancel lands, and this
        # helper has no Config -- without the stub every run of the suite
        # prints a traceback from work this test is not about.
        cog._update_dashboards = AsyncMock()
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
        cog._reset_state()
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

    async def test_a_partial_report_still_carries_working_buttons(self) -> None:
        # The two features meet here: the sweep produces a short window, and the
        # buttons address a message from it. A queue item has to carry both the
        # arrival time the sweep measures and the message id the buttons use,
        # and nothing in either feature's own tests would notice one missing.
        cog = object.__new__(MessageWatch)
        cog._reset_state()
        cog._pending = pending()
        cog._locks = module.defaultdict(module.asyncio.Lock)
        cog._last_report = {}
        cog._last_judged = {}
        cog._last_error = {}
        cog.get_api_key = AsyncMock(return_value="k")
        cog.judge = AsyncMock(return_value={"any_scam": {"noul": 0.97},
                                            "scam_index": {"choice": "1"},
                                            "is_hostile": {"noul": 0.01},
                                            "heat": {"score": 0.2}})
        settings = {**DEFAULT_GUILD, "disclosure_version": DISCLOSURE_VERSION,
                    "report_channel": 77, "watched_channels": [5], "idle_seconds": 600}
        scope = MagicMock()
        scope.all = AsyncMock(return_value=settings)
        scope.watched_channels = AsyncMock(return_value=[5])
        cog.config = MagicMock()
        cog.config.guild.return_value = scope
        channel_scope = MagicMock()
        channel_scope.all = AsyncMock(
            return_value={**module.DEFAULT_CHANNEL, "actions": ["ok", "no", "del"]}
        )
        cog.config.channel.return_value = channel_scope

        report = MagicMock(spec=discord.TextChannel)
        report.send = AsyncMock()
        guild = MagicMock()
        guild.get_channel.return_value = report
        channel = SimpleNamespace(id=5, guild=guild, name="c", mention="<#5>")

        cog._pending[5].extend(window(11, 22, 33, at=module.time.monotonic() - 900))
        await cog.flush(channel, partial=True)

        report.send.assert_awaited_once()
        view = report.send.await_args.kwargs["view"]
        self.assertEqual([item.label for item in view.children], ["屬實", "誤判", "刪除訊息"])
        parsed = module.parse_custom_id(view.children[2].custom_id)
        self.assertIsNotNone(parsed)
        action, kind, channel_id, message_id, author_id = parsed
        self.assertEqual((action, channel_id), ("del", 5))
        # The ids come from the queued item, not from a placeholder.
        self.assertEqual(message_id, 901)
        self.assertEqual(author_id, 22)

    def test_a_short_window_is_consumed_whole(self) -> None:
        # There is no later message for an overlap to join a finished
        # conversation to, and leaving half behind would have the next sweep
        # judge the same tail again.
        cog = object.__new__(MessageWatch)
        cog._reset_state()
        cog._pending = pending()
        cog._pending[5].extend(window(1, 2, 3))
        taken = cog._take_window(5, 8, module.MIN_PARTIAL_WINDOW)
        self.assertEqual(len(taken), 3)
        self.assertEqual(len(cog._pending[5]), 0)

    def test_a_full_window_still_overlaps(self) -> None:
        cog = object.__new__(MessageWatch)
        cog._reset_state()
        cog._pending = pending()
        cog._pending[5].extend(window(1, 2, 3, 4))
        taken = cog._take_window(5, 4, module.MIN_PARTIAL_WINDOW)
        self.assertEqual(len(taken), 4)
        self.assertEqual(len(cog._pending[5]), 2)

    def test_one_message_is_not_an_exchange(self) -> None:
        # Hostility is a property of an exchange, so a lone message cannot
        # carry it; it waits for the next one instead.
        cog = object.__new__(MessageWatch)
        cog._reset_state()
        cog._pending = pending()
        cog._pending[5].extend(window(1))
        self.assertIsNone(cog._take_window(5, 8, module.MIN_PARTIAL_WINDOW))
        self.assertEqual(len(cog._pending[5]), 1)
        # And without the partial floor, nothing short of a full window moves.
        cog._pending[5].extend(window(2, 3))
        self.assertIsNone(cog._take_window(5, 8))




class TestSlashAndSettings(unittest.IsolatedAsyncioTestCase):
    def test_every_command_is_reachable_as_a_slash_command(self) -> None:
        # HybridGroup.command and .group produce hybrid children, so the one
        # decorator on the group converts the tree -- and any command added
        # later is a slash command without touching it.
        with patch("messagewatch.messagewatch.Config"):
            cog = MessageWatch(MagicMock())
        self.addCleanup(cog._sweep.cancel)
        group = cog.watch_group
        self.assertIsNotNone(group.app_command)

        seen = []
        def walk(node):
            for child in getattr(node, "commands", []):
                seen.append(child.qualified_name)
                self.assertIsNotNone(
                    getattr(child, "app_command", None), f"{child.qualified_name} 不是 slash"
                )
                walk(child)
        walk(group)
        # Discord allows one level of group nesting; `/watch rule add` uses it
        # exactly, and a third would be rejected at registration.
        self.assertLessEqual(max(name.count(" ") for name in seen), 2)
        # Named explicitly, because every test that drives a command calls its
        # callback by attribute -- so a command registered under the wrong name
        # passes all of them while being absent from Discord.
        for name in ("watch rule add", "watch action role", "watch images",
                     "watch dashboard", "watch rule threshold", "watch marks"):
            with self.subTest(command=name):
                self.assertIn(name, seen)

    def test_the_tree_is_hidden_from_members_in_discord_ui(self) -> None:
        # A display filter, not the check -- the Red checks still run. Without
        # it every member sees a moderation command tree they cannot use.
        from discord.app_commands import AppCommandContext, AppInstallationType

        with patch("messagewatch.messagewatch.Config"):
            cog = MessageWatch(MagicMock())
        self.addCleanup(cog._sweep.cancel)
        tree = MagicMock()
        tree.allowed_contexts = AppCommandContext()
        tree.allowed_installs = AppInstallationType()
        payload = cog.watch_group.app_command.to_dict(tree)
        self.assertIsNotNone(payload.get("default_member_permissions"))
        self.assertEqual(int(payload["default_member_permissions"]), 32)  # manage_guild

    def test_the_dropdown_offers_exactly_the_settable_keys(self) -> None:
        with patch("messagewatch.messagewatch.Config"):
            cog = MessageWatch(MagicMock())
        self.addCleanup(cog._sweep.cancel)
        choices = cog.watch_set.app_command.parameters[0].choices
        self.assertEqual(sorted(c.value for c in choices), sorted(module.SETTING_RULES))
        self.assertLessEqual(len(choices), 25)  # Discord's ceiling
        for choice in choices:
            with self.subTest(choice=choice.value):
                self.assertIn(module.SETTING_RULES[choice.value].label, choice.name)

    def test_every_setting_says_what_it_means_and_what_it_takes(self) -> None:
        # A list of key names tells a moderator what is spelled correctly and
        # nothing about what any of them does.
        for key, rule in module.SETTING_RULES.items():
            with self.subTest(key=key):
                self.assertTrue(rule.label.strip())
                self.assertGreater(len(rule.help), 20)
                self.assertIn(rule.kind, (int, float))
                self.assertLess(rule.low, rule.high)

    async def test_a_bare_or_mistyped_set_shows_the_table(self) -> None:
        cog = object.__new__(MessageWatch)
        cog._reset_state()
        settings = dict(DEFAULT_GUILD)
        scope = MagicMock()
        scope.all = AsyncMock(return_value=settings)
        cog.config = MagicMock()
        cog.config.guild.return_value = scope
        ctx = SimpleNamespace(guild=MagicMock(), send=AsyncMock())

        await MessageWatch.watch_set.callback(cog, ctx, "", "")
        embed = ctx.send.await_args.kwargs["embed"]
        rendered = json.dumps(embed.to_dict(), ensure_ascii=False)
        for key, rule in module.SETTING_RULES.items():
            with self.subTest(key=key):
                self.assertIn(key, rendered)
                self.assertIn(rule.label, rendered)
                self.assertIn(str(settings[key]), rendered)
                # The help is the point of the table. Key, label and value
                # together still do not say what any of them does.
                self.assertIn(rule.help[:16], rendered)
                self.assertIn(str(rule.low), rendered)
                self.assertIn(str(rule.high), rendered)

        ctx = SimpleNamespace(guild=MagicMock(), send=AsyncMock())
        await MessageWatch.watch_set.callback(cog, ctx, "nonsense", "")
        self.assertIn("nonsense", json.dumps(
            ctx.send.await_args.kwargs["embed"].to_dict(), ensure_ascii=False))

    async def test_a_key_with_no_value_explains_that_one_setting(self) -> None:
        cog = object.__new__(MessageWatch)
        cog._reset_state()
        scope = MagicMock()
        scope.get_raw = AsyncMock(return_value=0.9)
        cog.config = MagicMock()
        cog.config.guild.return_value = scope
        ctx = SimpleNamespace(guild=MagicMock(), send=AsyncMock())
        await MessageWatch.watch_set.callback(cog, ctx, "scam_threshold", "")
        said = ctx.send.await_args.args[0]
        rule = module.SETTING_RULES["scam_threshold"]
        self.assertIn(rule.label, said)
        self.assertIn(rule.help[:12], said)
        self.assertIn("0.9", said)


class TestDiagnosticSurface(unittest.IsolatedAsyncioTestCase):
    async def test_watch_show_stays_inside_the_embed_field_limit(self) -> None:
        # The guild that needs this surface most is the one watching enough
        # channels to overflow the field, which Discord rejects outright.
        cog = object.__new__(MessageWatch)
        cog._reset_state()
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
        cog._reset_state()
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
        cog._reset_state()
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
        cog._reset_state()
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
        cog._reset_state()
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
        cog._reset_state()
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


class TestUsageAccounting(unittest.IsolatedAsyncioTestCase):
    """The provider bills per input token and `judge()` used to throw the
    count away entirely. These pin that flush() only ever accumulates in
    process memory, and `_flush_usage` -- run from the sweep, not from every
    judged window -- is the one place that turns it into a Config write."""

    QUIET = {"any_scam": {"noul": 0.02}, "is_hostile": {"noul": 0.01}, "heat": {"score": 0.1}}
    SCAM = {"any_scam": {"noul": 0.97}, "scam_index": {"choice": "1"},
            "is_hostile": {"noul": 0.01}, "heat": {"score": 0.1}}

    def cog(self):
        cog = object.__new__(MessageWatch)
        cog._reset_state()
        settings = {**DEFAULT_GUILD, "disclosure_version": DISCLOSURE_VERSION,
                    "report_channel": 77, "watched_channels": [5], "window_size": 3,
                    "cooldown_seconds": 0}
        scope = MagicMock()
        scope.all = AsyncMock(return_value=settings)
        scope.watched_channels = AsyncMock(return_value=[5])
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
        cog._usage_delta = module.defaultdict(
            lambda: {"messages_queued": 0, "windows_judged": 0, "reports_sent": 0, "input_tokens": 0}
        )
        return cog, scope

    @staticmethod
    def channel():
        report = MagicMock(spec=discord.TextChannel)
        report.send = AsyncMock()
        guild = MagicMock()
        guild.id = 1
        guild.get_channel.return_value = report
        return SimpleNamespace(id=5, guild=guild, name="c", mention="<#5>"), report

    async def test_token_counts_accumulate_across_judgements_and_survive_a_flush(self) -> None:
        cog, scope = self.cog()
        channel, report = self.channel()

        # `judge` is mocked in every flush test, including this one, so the
        # attribute it normally sets on success has to be set here too.
        async def first(*args, **kwargs):
            cog._last_input_tokens = 500
            return self.QUIET
        cog.judge = AsyncMock(side_effect=first)
        cog._pending[5].extend(window(1, 2, 3))
        await cog.flush(channel)

        async def second(*args, **kwargs):
            cog._last_input_tokens = 300
            return self.SCAM
        cog.judge = AsyncMock(side_effect=second)
        cog._pending[5].extend(window(4, 5, 6))
        await cog.flush(channel)

        self.assertEqual(cog._usage_delta[1]["windows_judged"], 2)
        self.assertEqual(cog._usage_delta[1]["input_tokens"], 800)
        # The report from the second window is the only one of the two.
        self.assertEqual(cog._usage_delta[1]["reports_sent"], 1)
        report.send.assert_awaited_once()

        # Flushing to Config adds the delta once and zeroes it, so the next
        # sweep tick does not double-count what this one already wrote.
        stored = dict(DEFAULT_GUILD["usage"])
        usage_ctx = ValueContext(stored)
        scope.usage = MagicMock(return_value=usage_ctx)
        cog.bot = MagicMock()
        cog.bot.get_guild.return_value = channel.guild
        await cog._flush_usage()
        self.assertEqual(stored["windows_judged"], 2)
        self.assertEqual(stored["input_tokens"], 800)
        self.assertEqual(stored["reports_sent"], 1)
        self.assertGreater(stored["started_at"], 0)
        self.assertEqual(
            cog._usage_delta[1],
            {"messages_queued": 0, "windows_judged": 0, "reports_sent": 0, "input_tokens": 0},
        )

        # A third judgement after the flush starts counting fresh from zero,
        # not from the total the flush already moved into Config.
        async def third(*args, **kwargs):
            cog._last_input_tokens = 250
            return self.QUIET
        cog.judge = AsyncMock(side_effect=third)
        cog._pending[5].extend(window(7, 8, 9))
        await cog.flush(channel)
        self.assertEqual(cog._usage_delta[1]["input_tokens"], 250)

    async def test_nothing_is_written_to_config_per_judgement(self) -> None:
        # The write belongs to the sweep (`_flush_usage`), not to flush() --
        # a Config write per judged window is a disk write every few
        # messages. scope.usage is never touched here at all.
        cog, scope = self.cog()
        channel, _ = self.channel()

        async def fake_judge(*args, **kwargs):
            cog._last_input_tokens = 42
            return self.QUIET
        cog.judge = AsyncMock(side_effect=fake_judge)

        cog._pending[5].extend(window(1, 2, 3))
        await cog.flush(channel)
        scope.usage.assert_not_called()
        self.assertEqual(cog._usage_delta[1]["windows_judged"], 1)
        self.assertEqual(cog._usage_delta[1]["input_tokens"], 42)


class TestUsageEdges(unittest.IsolatedAsyncioTestCase):
    def test_an_infinite_token_count_is_discarded_not_converted(self) -> None:
        # json.loads turns a bare `Infinity` into float("inf"), which is
        # neither NaN nor negative, and int(inf) raises OverflowError from
        # outside judge's JSON handler -- so it would escape a function that
        # documents every failure as returning None and take the message event
        # with it. Fourth conversion in this repo to meet this shape:
        # float(10**400), int("²"), json.loads recursion, now int(inf).
        for bad in (float("inf"), float("-inf"), float("nan"), -1, "500", True, None, 10**400):
            with self.subTest(value=str(bad)[:12]):
                self.assertIsNone(module._bounded_token_count(bad))
        self.assertEqual(module._bounded_token_count(1234), 1234)
        self.assertEqual(module._bounded_token_count(1234.0), 1234)

    async def test_an_infinite_token_count_does_not_escape_judge(self) -> None:
        # The guard is only worth having if the failure stays inside judge.
        response = MagicMock()
        response.status = 200
        response.content.read = AsyncMock(
            return_value=b'{"answers": {"any_scam": {"noul": 0.5}}, "usage": {"input_tokens": Infinity}}'
        )
        response_ctx = MagicMock()
        response_ctx.__aenter__ = AsyncMock(return_value=response)
        response_ctx.__aexit__ = AsyncMock(return_value=False)
        session = MagicMock()
        session.post.return_value = response_ctx
        session_ctx = MagicMock()
        session_ctx.__aenter__ = AsyncMock(return_value=session)
        session_ctx.__aexit__ = AsyncMock(return_value=False)

        cog = object.__new__(MessageWatch)
        cog._reset_state()
        cog.bot = MagicMock()
        with patch("messagewatch.messagewatch.aiohttp.ClientSession", return_value=session_ctx):
            answers = await cog.judge([], "c", "k")
        self.assertEqual(answers, {"any_scam": {"noul": 0.5}})
        self.assertIsNone(cog._last_input_tokens)

    async def test_a_flush_keeps_what_arrived_during_its_awaits(self) -> None:
        # Red's context manager awaits on entry and on exit, and `flush` or
        # `on_message` can increment the same dict in between. Popping the
        # entry afterwards discarded those and undercounted silently.
        cog = object.__new__(MessageWatch)
        cog._reset_state()
        cog.bot = MagicMock()
        guild = MagicMock()
        guild.id = 1
        cog.bot.get_guild.return_value = guild
        cog._usage_delta[1] = {"messages_queued": 10, "windows_judged": 2,
                               "reports_sent": 0, "input_tokens": 3000}
        stored: dict = {}

        class Ctx:
            async def __aenter__(self):
                # A message arriving while Config is being read.
                cog._usage_delta[1]["messages_queued"] += 5
                return stored

            async def __aexit__(self, *exc):
                # And another while it is being written back.
                cog._usage_delta[1]["input_tokens"] += 700
                return False

        scope = MagicMock()
        scope.usage = MagicMock(return_value=Ctx())
        cog.config = MagicMock()
        cog.config.guild.return_value = scope

        await cog._flush_usage()

        self.assertEqual(stored["messages_queued"], 10)
        self.assertEqual(stored["input_tokens"], 3000)
        # The increments that landed mid-flush are still pending, not lost.
        self.assertEqual(cog._usage_delta[1]["messages_queued"], 5)
        self.assertEqual(cog._usage_delta[1]["input_tokens"], 700)


class TestDashboard(unittest.IsolatedAsyncioTestCase):
    """`[p]watch dashboard` posts a live embed the sweep keeps current. These
    pin the two failure modes a message the sweep edits forever invites:
    editing nothing when it was deleted (an exception, from `on_message`'s
    own precedent of never breaking on a Discord failure), and retrying a
    channel that is never coming back once a minute forever."""

    def cog(self, *, dashboard_channel=9, dashboard_message=0, last_error=None):
        cog = object.__new__(MessageWatch)
        cog._reset_state()
        cog._pending = pending()
        cog._last_judged = {}
        cog._last_error = last_error or {}
        cog._dashboard_error = {}
        cog._dashboard_last_render = {}
        settings = {
            **DEFAULT_GUILD, "watched_channels": [5],
            "dashboard_channel": dashboard_channel, "dashboard_message": dashboard_message,
        }
        cog.config = MagicMock()
        cog.config.all_guilds = AsyncMock(return_value={1: settings})
        guild_scope = MagicMock()
        guild_scope.all = AsyncMock(return_value=settings)
        guild_scope.dashboard_message.set = AsyncMock()
        cog.config.guild.return_value = guild_scope
        cog.config.channel_from_id.return_value.report_channel = AsyncMock(return_value=0)
        cog.bot = MagicMock()
        guild = MagicMock()
        guild.id = 1
        channel = MagicMock(spec=discord.TextChannel)
        channel.send = AsyncMock()
        guild.get_channel.return_value = channel
        cog.bot.get_guild.return_value = guild
        return cog, guild, channel, guild_scope

    async def test_a_fresh_dashboard_message_is_created_when_none_exists(self) -> None:
        cog, guild, channel, guild_scope = self.cog(dashboard_message=0)
        await cog._update_dashboards()
        channel.send.assert_awaited_once()
        guild_scope.dashboard_message.set.assert_awaited_once()

    async def test_the_dashboard_message_is_edited_rather_than_reposted_when_it_already_exists(
        self,
    ) -> None:
        cog, guild, channel, guild_scope = self.cog(dashboard_message=555)
        message = MagicMock()
        message.edit = AsyncMock()
        channel.fetch_message = AsyncMock(return_value=message)
        await cog._update_dashboards()
        message.edit.assert_awaited_once()
        channel.send.assert_not_awaited()

        # The other half, and the half that was missing: an unchanged
        # dashboard is not edited again. Asserting only that an edit happened
        # passes just as well when the render signature is ignored entirely
        # and every tick rewrites the message.
        await cog._update_dashboards()
        message.edit.assert_awaited_once()

    async def test_a_deleted_dashboard_message_results_in_a_new_one_rather_than_an_exception(
        self,
    ) -> None:
        cog, guild, channel, guild_scope = self.cog(dashboard_message=555)
        channel.fetch_message = AsyncMock(side_effect=discord.NotFound(MagicMock(), "gone"))
        await cog._update_dashboards()
        channel.send.assert_awaited_once()
        guild_scope.dashboard_message.set.assert_awaited_once()

    async def test_a_missing_channel_is_recorded_and_stops_being_retried(self) -> None:
        cog, guild, channel, guild_scope = self.cog(dashboard_channel=9)
        guild.get_channel.return_value = None
        await cog._update_dashboards()
        self.assertIn(1, cog._dashboard_error)
        self.assertEqual(cog._dashboard_error[1][1], "dashboard_channel_missing")

        # A permission problem or a missing channel does not fix itself in a
        # minute -- the next tick must not even try to resolve it again.
        guild.get_channel.reset_mock()
        await cog._update_dashboards()
        guild.get_channel.assert_not_called()

    async def test_a_forbidden_dashboard_channel_is_recorded_and_stops_being_retried(self) -> None:
        cog, guild, channel, guild_scope = self.cog(dashboard_message=0)
        channel.send = AsyncMock(side_effect=discord.Forbidden(MagicMock(), "no"))
        await cog._update_dashboards()
        self.assertEqual(cog._dashboard_error[1][1], "dashboard_forbidden")
        channel.send.reset_mock()
        await cog._update_dashboards()
        channel.send.assert_not_called()

    async def test_the_estimate_is_labelled_an_estimate_and_the_marks_line_says_precision_not_recall(
        self,
    ) -> None:
        cog, guild, _, _ = self.cog()
        embed = await cog.dashboard_embed(guild)
        rendered = json.dumps(embed.to_dict(), ensure_ascii=False)
        # The word appears in several places, so finding it proves nothing
        # about the caveat. What must survive is the sentence saying the price
        # goes stale silently when the vendor changes it.
        footer = embed.footer.text or ""
        self.assertIn("估計值", footer)
        self.assertIn("不會自動更新", footer)
        self.assertIn("精確率", rendered)
        self.assertIn("不是召回率", rendered)
        # The key is bot-global, so the figure shown is this guild's share of
        # a shared bill, not an independent one -- otherwise a moderator would
        # read it as this guild's whole cost.
        self.assertIn("整個機器人共用", rendered)

    async def test_the_dashboard_colour_turns_orange_when_a_watched_channel_has_a_problem(
        self,
    ) -> None:
        # A dashboard's whole point is being readable at a glance, so the
        # colour alone has to say whether something needs attention.
        sick, guild, _, _ = self.cog(last_error={5: (1_700_000_000.0, "no_api_key")})
        sick_embed = await sick.dashboard_embed(guild)
        self.assertEqual(sick_embed.colour, discord.Colour.orange())

        healthy, healthy_guild, _, _ = self.cog(last_error={})
        healthy_embed = await healthy.dashboard_embed(healthy_guild)
        self.assertEqual(healthy_embed.colour, discord.Colour.blurple())


class TestImageAux(unittest.IsolatedAsyncioTestCase):
    @staticmethod
    def attachment(**over):
        return SimpleNamespace(**{
            "content_type": "image/png", "filename": "shot.png", "size": 40_000,
            "width": 800, "height": 600, "url": "https://cdn.discordapp.com/x.png",
            "id": 991, **over})

    def test_only_real_bounded_images_are_captured(self) -> None:
        # The declared size and dimensions come from Discord and are
        # attacker-adjacent, so they narrow the set here and the real bytes are
        # checked again after download.
        good = SimpleNamespace(attachments=[self.attachment()])
        self.assertEqual(module.eligible_attachments(good),
                         [{"id": 991, "url": "https://cdn.discordapp.com/x.png"}])
        for over in (
            {"content_type": "application/pdf"},
            {"content_type": "image/png", "filename": "shot.pdf"},
            {"size": module.MAX_IMAGE_BYTES + 1},
            {"width": 20_000, "height": 20_000},
            {"size": 0}, {"width": -1}, {"size": True},
            {"url": "http://cdn.discordapp.com/x.png"},
            {"url": None}, {"id": None},
        ):
            with self.subTest(over=str(over)[:34]):
                bad = SimpleNamespace(attachments=[self.attachment(**over)])
                self.assertEqual(module.eligible_attachments(bad), [])
        self.assertEqual(module.eligible_attachments(SimpleNamespace(attachments=None)), [])
        # Bounded per message as well as per window.
        many = SimpleNamespace(attachments=[self.attachment(id=i) for i in range(20)])
        self.assertEqual(len(module.eligible_attachments(many)), module.MAX_IMAGES_PER_WINDOW)

    def test_transcoding_validates_and_strips(self) -> None:
        from PIL import Image as PILImage
        buf = module.BytesIO()
        PILImage.new("RGB", (4000, 40)).save(buf, format="PNG")
        kind, data = module.transcode_image(buf.getvalue())
        self.assertEqual(kind, "image/jpeg")
        with PILImage.open(module.BytesIO(data)) as out:
            # Downscaled to the long edge, which is where the cost saving is.
            self.assertEqual(max(out.size), module.IMAGE_MAX_EDGE)
        # Transparency survives as PNG rather than being flattened onto an
        # invented background, which would change what a screenshot says.
        buf = module.BytesIO()
        PILImage.new("RGBA", (10, 10)).save(buf, format="PNG")
        self.assertEqual(module.transcode_image(buf.getvalue())[0], "image/png")
        # The header dimensions are read before any pixel is decoded, because
        # Pillow's own bomb guard does not fire until twice the limit and the
        # ingest step only saw the dimensions Discord declared.
        buf = module.BytesIO()
        PILImage.new("RGB", (300, 300)).save(buf, format="PNG")
        with patch.object(module, "MAX_IMAGE_PIXELS", 100):
            self.assertIsNone(module.transcode_image(buf.getvalue()))

        # Not an image at all.
        self.assertIsNone(module.transcode_image(b"not an image"))
        self.assertIsNone(module.transcode_image(b""))

    async def test_turning_images_on_says_what_is_still_missing(self) -> None:
        # A channel that looks configured and silently reads nothing is this
        # project's most common failure, so the command names the gaps at the
        # moment someone would otherwise assume it is working.
        cog = object.__new__(MessageWatch)
        cog._reset_state()
        cog.bot = MagicMock()
        cog.bot.get_shared_api_tokens = AsyncMock(return_value={})
        scope = MagicMock()
        scope.images = MagicMock()
        scope.images.set = AsyncMock()
        cog.config = MagicMock()
        cog.config.channel.return_value = scope
        cog.config.all = AsyncMock(return_value={"image_model": "", "image_api_base": ""})
        ctx = SimpleNamespace(guild=MagicMock(), send=AsyncMock())
        channel = SimpleNamespace(id=5, mention="<#5>", name="c")

        await MessageWatch.watch_images.callback(cog, ctx, channel, "on")
        scope.images.set.assert_awaited_once_with(True)
        warning = ctx.send.await_args.args[0]
        self.assertIn("image_model", warning)
        self.assertIn("image_api_base", warning)
        self.assertIn("api key", warning.casefold())
        self.assertIn("不會送出", warning)

    async def test_turning_images_off_needs_no_configuration(self) -> None:
        cog = object.__new__(MessageWatch)
        cog._reset_state()
        scope = MagicMock()
        scope.images = MagicMock()
        scope.images.set = AsyncMock()
        cog.config = MagicMock()
        cog.config.channel.return_value = scope
        ctx = SimpleNamespace(guild=MagicMock(), send=AsyncMock())
        await MessageWatch.watch_images.callback(
            cog, ctx, SimpleNamespace(id=5, mention="<#5>", name="c"), "off")
        scope.images.set.assert_awaited_once_with(False)

    async def test_nothing_is_sent_when_the_channel_has_images_off(self) -> None:
        # The default, and the state every channel starts in.
        cog = object.__new__(MessageWatch)
        cog._reset_state()
        cog.image_text = AsyncMock()
        window = [{"images": [{"id": 1, "url": "https://x/y.png"}]}]
        self.assertFalse(module.DEFAULT_CHANNEL["images"])
        # _attach_image_text is only reached when the channel opted in; this
        # asserts the call site's gate, not the method.
        source = (pathlib.Path(__file__).parent / "messagewatch.py").read_text(encoding="utf-8")
        self.assertIn('if channel_settings["images"]:\n                await self._attach_image_text(', source)

    async def test_no_model_or_key_means_no_request(self) -> None:
        # Refusing rather than guessing a default: no model has been measured
        # for CJK screenshot transcription yet.
        cog = object.__new__(MessageWatch)
        cog._reset_state()
        cog.bot = MagicMock()
        cog.bot.get_shared_api_tokens = AsyncMock(return_value={"api_key": "k"})
        cog._extract_text = AsyncMock()
        cog.config = MagicMock()
        for settings in ({"image_model": "", "image_api_base": "https://x"},
                         {"image_model": "m", "image_api_base": ""}):
            with self.subTest(settings=settings):
                cog.config.all = AsyncMock(return_value=settings)
                with patch("messagewatch.messagewatch.aiohttp.ClientSession") as session:
                    got = await cog.image_text({"id": 1, "url": "https://x/y.png"})
                self.assertIsNone(got)
                # Not merely "no model call" -- the image is not even fetched,
                # so an unconfigured channel costs nothing and sends nothing.
                session.assert_not_called()
                cog._extract_text.assert_not_awaited()

    async def test_a_cached_attachment_is_not_fetched_twice(self) -> None:
        # The same meme reposted ten times is paid for once.
        cog = object.__new__(MessageWatch)
        cog._reset_state()
        cog._image_cache[991] = "已經讀過的文字"
        cog.bot = MagicMock()
        cog.bot.get_shared_api_tokens = AsyncMock(return_value={"api_key": "k"})
        cog._extract_text = AsyncMock()
        cog.config = MagicMock()
        cog.config.all = AsyncMock(
            return_value={"image_model": "m", "image_api_base": "https://x"})
        got = await cog.image_text({"id": 991, "url": "https://x/y.png"})
        self.assertEqual(got, "已經讀過的文字")
        cog._extract_text.assert_not_awaited()

    async def test_the_cache_is_bounded_and_drops_the_oldest(self) -> None:
        # Driven through `image_text`, not by re-running the eviction in the
        # test: an assertion that restates the loop passes whatever the loop
        # does.
        cog = object.__new__(MessageWatch)
        cog._reset_state()
        cog.bot = MagicMock()
        cog.bot.get_shared_api_tokens = AsyncMock(return_value={"api_key": "k"})
        cog.config = MagicMock()
        cog.config.all = AsyncMock(
            return_value={"image_model": "m", "image_api_base": "https://x"})
        response = MagicMock()
        response.status = 200
        response.content.read = AsyncMock(return_value=b"bytes")
        response_ctx = MagicMock()
        response_ctx.__aenter__ = AsyncMock(return_value=response)
        response_ctx.__aexit__ = AsyncMock(return_value=False)
        session = MagicMock()
        session.get.return_value = response_ctx
        session_ctx = MagicMock()
        session_ctx.__aenter__ = AsyncMock(return_value=session)
        session_ctx.__aexit__ = AsyncMock(return_value=False)
        with patch("messagewatch.messagewatch.aiohttp.ClientSession", return_value=session_ctx), \
                patch("messagewatch.messagewatch.transcode_image",
                      return_value=("image/png", b"x")):
            for i in range(module.IMAGE_CACHE_SIZE + 5):
                cog._extract_text = AsyncMock(return_value=str(i))
                await cog.image_text({"id": i, "url": f"https://x/{i}.png"})
        self.assertEqual(len(cog._image_cache), module.IMAGE_CACHE_SIZE)
        self.assertNotIn(0, cog._image_cache)
        self.assertIn(module.IMAGE_CACHE_SIZE + 4, cog._image_cache)

    async def test_the_vision_endpoint_must_be_https(self) -> None:
        # The image leaves Discord over this. Plain HTTP would put a member's
        # screenshot on the wire in clear, so the command refuses rather than
        # storing a setting that silently downgrades the transport.
        cog = object.__new__(MessageWatch)
        cog.config = MagicMock()
        cog.config.set_raw = AsyncMock()
        scope = cog.config
        cog.bot = MagicMock()
        cog.bot.is_owner = AsyncMock(return_value=True)
        ctx = MagicMock()
        ctx.send = AsyncMock()
        command = MessageWatch.watch_vision.callback

        await command(cog, ctx, "api_base", value="http://openrouter.ai")
        scope.set_raw.assert_not_awaited()
        await command(cog, ctx, "api_base", value="x" * 201)
        scope.set_raw.assert_not_awaited()

        await command(cog, ctx, "api_base", value="https://openrouter.ai")
        scope.set_raw.assert_awaited_with("image_api_base", value="https://openrouter.ai")
        # The model is a free string; only the endpoint carries the scheme rule.
        await command(cog, ctx, "model", value="google/gemini-3.8-flash")
        scope.set_raw.assert_awaited_with("image_model", value="google/gemini-3.8-flash")
        # And clearing is allowed, which is how a guild turns the aux off
        # without touching every channel.
        await command(cog, ctx, "api_base", value="")
        scope.set_raw.assert_awaited_with("image_api_base", value="")

    async def test_only_the_bot_owner_can_aim_the_vision_endpoint(self) -> None:
        # The API key these two spend is bot-wide and the owner's. An
        # administrator of any guild the bot has joined who could set the
        # endpoint would be able to send that bearer token, and every image, to
        # a host of their own -- so the setting lives at the same scope as the
        # credential and only the owner writes it.
        cog = object.__new__(MessageWatch)
        cog.config = MagicMock()
        cog.config.set_raw = AsyncMock()
        cog.bot = MagicMock()
        cog.bot.is_owner = AsyncMock(return_value=False)
        ctx = MagicMock()
        ctx.send = AsyncMock()
        for key, value in (("api_base", "https://evil.example"), ("model", "m")):
            with self.subTest(key=key):
                await MessageWatch.watch_vision.callback(cog, ctx, key, value=value)
                cog.config.set_raw.assert_not_awaited()
        # And the endpoint is not a guild setting at all any more, so there is
        # no per-guild copy left for an administrator to reach.
        self.assertNotIn("image_api_base", DEFAULT_GUILD)
        self.assertNotIn("image_model", DEFAULT_GUILD)
        self.assertIn("image_api_base", module.DEFAULT_GLOBAL)

    async def test_turning_images_off_takes_the_channel_lock(self) -> None:
        # `flush` reads `images` and then awaits a download and a vision call
        # while holding this lock. Without taking it, an in-flight window sends
        # an attachment after the command has reported image reading is off --
        # the same disable contract `[p]watch disable` holds.
        cog = object.__new__(MessageWatch)
        cog._reset_state()
        scope = MagicMock()
        scope.images = MagicMock()
        held = []
        async def record(_value):
            held.append(cog._locks[5].locked())
        scope.images.set = AsyncMock(side_effect=record)
        cog.config = MagicMock()
        cog.config.channel.return_value = scope
        ctx = SimpleNamespace(guild=MagicMock(), send=AsyncMock())
        channel = SimpleNamespace(id=5, mention="<#5>", name="c")
        await MessageWatch.watch_images.callback(cog, ctx, channel, "off")
        self.assertEqual(held, [True])

    def test_the_transcription_is_part_of_what_reaches_typesafe(self) -> None:
        # It travels twice -- shown in the report, and sent on with the message
        # text -- so words that existed only inside an image reach both
        # providers. The disclosure says so because this is what happens.
        items = anonymise(window(11, 22))
        items[1]["image_text"] = "您的帳號異常 請至 http://fake/verify 驗證"
        sent = json.dumps(module.build_state("c", items), ensure_ascii=False)
        self.assertIn("http://fake/verify", sent)

    async def test_the_cache_is_dropped_on_unload_and_on_a_deletion_request(self) -> None:
        # It is the only member content this cog holds. Keyed by attachment id
        # with no author, it cannot be filtered to one person, so a deletion
        # request drops all of it.
        for drop in (
            lambda cog: cog.cog_unload(),
            lambda cog: cog.red_delete_data_for_user(requester="user", user_id=42),
        ):
            with self.subTest(drop=drop):
                cog = object.__new__(MessageWatch)
                cog._reset_state()
                cog._image_cache[991] = "秘密"
                cog._sweep = MagicMock()
                cog._flush_usage = AsyncMock()
                await drop(cog)
                self.assertEqual(len(cog._image_cache), 0)

    def test_the_report_shows_what_the_machine_read(self) -> None:
        # The transcription is generated text with nothing calibrated behind
        # it, so a moderator has to be able to check it against the image
        # rather than trust a verdict built on it.
        items = anonymise(window(11, 22))
        items[1]["image_text"] = "您的帳號異常 請至 http://fake/verify 驗證"
        rendered = json.dumps(
            MessageWatch.report_embed(
                SimpleNamespace(id=5, mention="<#5>"), items, 1, ["詐騙 0.97"]
            ).to_dict(), ensure_ascii=False)
        self.assertIn("圖片中讀到的文字", rendered)
        self.assertIn("http://fake/verify", rendered)
        # Nothing to show when no image was read.
        clean = json.dumps(MessageWatch.report_embed(
            SimpleNamespace(id=5, mention="<#5>"), anonymise(window(11, 22)), 1, ["詐騙 0.97"]
        ).to_dict(), ensure_ascii=False)
        self.assertNotIn("圖片中讀到的文字", clean)

    def test_extracted_text_reaches_the_state_only_when_present(self) -> None:
        items = anonymise(window(11, 22))
        items[0]["image_text"] = "圖片裡的字"
        state = build_state("c", items)
        self.assertEqual(state["recent_messages"][0]["image_text"], "圖片裡的字")
        # An empty key would claim the image had no text, which is a different
        # statement from not having read one.
        self.assertNotIn("image_text", state["recent_messages"][1])


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
            "actions": "the list of report buttons",
            "action_role": "the role ID the role button adds",
            "images": "whether image reading is enabled",
            "rule_threshold": "a per-channel rule-violation threshold set by [p]watch rule threshold",
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
            "The bot never acts on its own",
            "only a moderator holding the matching Discord permission can press one",
            "recorded in the modlog under that moderator's name",
            "a guild manager enables it individually",
            "It does not store message content",
        ):
            with self.subTest(phrase=phrase):
                self.assertIn(phrase, statement)

    def test_the_disclosure_says_it_is_continuous_and_untriggered(self) -> None:
        # Images began leaving Discord in version 4, to a provider that is not
        # TypeSafe. A disclosure silent about that is the defect this cog has
        # produced more than any other.
        self.assertGreaterEqual(DISCLOSURE_VERSION, 4)
        self.assertIn("Images:", module.DISCLOSURE_TEXT)
        self.assertIn("off unless a manager enables it", module.DISCLOSURE_TEXT)
        for phrase in (
            "with nobody triggering it",
            "The bot never acts on its own",
            "only a moderator with the matching Discord permission can press one",
            "generated per request and never stored",
        ):
            with self.subTest(phrase=phrase):
                self.assertIn(phrase, module.DISCLOSURE_TEXT)


if __name__ == "__main__":
    unittest.main()
