"""Focused security and transport tests for ChannelSummary."""

from __future__ import annotations

import inspect
import socket
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock
from unittest.mock import MagicMock, patch

from redbot.core import commands

from .channelsummary import (
    CHANNEL_DEFAULTS,
    GUILD_DEFAULTS,
    MAX_PROVIDER_PROFILES,
    MAX_RESPONSE_BYTES,
    ErrorCode,
    AgentSummary,
    ChannelSummary,
    Citation,
    FunctionCall,
    NormalizedResponse,
    ProviderProfile,
    RunState,
    SummaryTopic,
    SummaryError,
    build_payload,
    message_record,
    normalize_origin,
    normalize_response,
    parse_agent_summary,
    parse_duration,
    parse_message_reference,
    public_addresses,
    read_bounded_response,
    sanitize_summary_text,
    SettingsView,
    split_embed_text,
    validate_profile,
    validate_tool_arguments,
)


def profile(dialect: str) -> ProviderProfile:
    return ProviderProfile("main", dialect, "https://example.com", "channelsummary_main", ("model-1",))


class TestConfiguration(unittest.TestCase):
    def test_defaults_are_exact_and_contain_no_content(self) -> None:
        self.assertEqual(CHANNEL_DEFAULTS, {"checkpoint_message_id": 0, "checkpoint_timestamp": 0.0})
        self.assertEqual(GUILD_DEFAULTS["enabled"], False)
        self.assertEqual(GUILD_DEFAULTS["auto_message_count"], 100)
        self.assertEqual(GUILD_DEFAULTS["new_messages_required"], 20)
        self.assertFalse({"api_key", "prompt", "response", "messages"} & set(GUILD_DEFAULTS))

    def test_profile_and_origin_validation(self) -> None:
        raw = {
            "dialect": "openrouter_responses",
            "origin": "https://OPENROUTER.AI/",
            "token_service": "channelsummary_router",
            "models": ["openai/gpt-5.6"],
        }
        parsed = validate_profile("Main_1", raw)
        self.assertEqual(parsed.name, "main_1")
        self.assertEqual(parsed.origin, "https://openrouter.ai")
        self.assertEqual(parsed.endpoint, "https://openrouter.ai/api/v1/responses")
        self.assertEqual(parsed.web_kind, "openrouter")
        for bad in (
            "https://user@example.com",
            "https://example.com/path",
            "https://example.com:8443",
            "https://example.com?secret=yes",
            "http://example.com/path",
            "http://example.com:0",
            "http://example.com:65536",
            "http://example.com:",
        ):
            with self.subTest(bad=bad), self.assertRaises(SummaryError) as caught:
                normalize_origin(bad)
            self.assertEqual(caught.exception.code, ErrorCode.ENDPOINT_INVALID)

    def test_http_origin_preserves_host_ipv6_and_explicit_ports(self) -> None:
        self.assertEqual(normalize_origin("http://LLM.LAN/"), "http://llm.lan")
        self.assertEqual(normalize_origin("http://10.0.0.2:11434"), "http://10.0.0.2:11434")
        self.assertEqual(normalize_origin("http://[FD12::1]:80/"), "http://[fd12::1]:80")
        self.assertEqual(
            ProviderProfile("lan", "generic_chat", "http://[::1]:8080", "lan", ("model",)).endpoint,
            "http://[::1]:8080/v1/chat/completions",
        )

    def test_https_default_port_behavior_is_unchanged(self) -> None:
        self.assertEqual(normalize_origin("https://EXAMPLE.COM:443/"), "https://example.com")

    def test_profile_rejects_extra_fields_and_duplicate_models(self) -> None:
        base = {
            "dialect": "openai_responses",
            "origin": "https://api.openai.com",
            "token_service": "channelsummary_openai",
            "models": ["gpt-5.6"],
        }
        for raw in ({**base, "api_key": "sentinel"}, {**base, "models": ["gpt-5.6", "gpt-5.6"]}):
            with self.assertRaises(SummaryError) as caught:
                validate_profile("openai", raw)
            self.assertEqual(caught.exception.code, ErrorCode.PROFILE_INVALID)


class TestNetworkBoundary(unittest.IsolatedAsyncioTestCase):
    @staticmethod
    def record(address: str) -> tuple[object, ...]:
        family = socket.AF_INET6 if ":" in address else socket.AF_INET
        sockaddr = (address, 443, 0, 0) if family == socket.AF_INET6 else (address, 443)
        return family, socket.SOCK_STREAM, 6, "", sockaddr

    def test_only_global_addresses_are_accepted(self) -> None:
        result = public_addresses([self.record("8.8.8.8"), self.record("2606:4700:4700::1111")])
        self.assertEqual(len(result), 2)
        for address in (
            "127.0.0.1",
            "10.0.0.1",
            "169.254.1.1",
            "100.64.0.1",
            "224.0.0.1",
            "::1",
            "fe80::1",
            "::ffff:127.0.0.1",
        ):
            with self.subTest(address=address), self.assertRaises(SummaryError) as caught:
                public_addresses([self.record(address)])
            self.assertEqual(caught.exception.code, ErrorCode.ENDPOINT_UNSAFE)

    def test_one_unsafe_answer_rejects_the_whole_resolution(self) -> None:
        with self.assertRaises(SummaryError):
            public_addresses([self.record("8.8.8.8"), self.record("127.0.0.1")])

    def test_private_lan_policy_accepts_only_explicit_networks(self) -> None:
        accepted = {
            "10.0.0.0": "10.0.0.0",
            "10.255.255.255": "10.255.255.255",
            "172.16.0.1": "172.16.0.1",
            "172.31.255.254": "172.31.255.254",
            "192.168.0.1": "192.168.0.1",
            "127.255.255.254": "127.255.255.254",
            "fc00::1": "fc00::1",
            "fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff": "fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
            "::1": "::1",
            "::ffff:10.1.2.3": "10.1.2.3",
            "::ffff:127.0.0.1": "127.0.0.1",
        }
        for address, normalized in accepted.items():
            with self.subTest(address=address):
                result = public_addresses([self.record(address)], allow_private_lan=True)
                self.assertEqual(result[0][0], normalized)

        for address in (
            "8.8.8.8",
            "100.64.0.1",
            "169.254.1.1",
            "224.0.0.1",
            "0.0.0.0",
            "192.0.2.1",
            "240.0.0.1",
            "fe80::1",
            "ff02::1",
            "::",
            "2001:db8::1",
            "::ffff:8.8.8.8",
        ):
            with self.subTest(address=address), self.assertRaises(SummaryError) as caught:
                public_addresses([self.record(address)], allow_private_lan=True)
            self.assertEqual(caught.exception.code, ErrorCode.ENDPOINT_UNSAFE)

    def test_private_lan_policy_rejects_mixed_answers(self) -> None:
        with self.assertRaises(SummaryError):
            public_addresses(
                [self.record("192.168.1.10"), self.record("8.8.8.8")],
                allow_private_lan=True,
            )

    async def test_resolve_profile_selects_scheme_policy_and_endpoint_port(self) -> None:
        cog = object.__new__(ChannelSummary)
        loop = MagicMock()
        loop.getaddrinfo = AsyncMock(
            side_effect=[
                [self.record("192.168.1.10")],
                [self.record("::1")],
                [self.record("8.8.8.8")],
            ]
        )
        profiles = (
            ProviderProfile("lan", "generic_chat", "http://llm.lan:11434", "lan", ("model",)),
            ProviderProfile("loopback", "generic_chat", "http://[::1]", "lan", ("model",)),
            ProviderProfile("public", "generic_chat", "https://api.example", "public", ("model",)),
        )
        with patch("channelsummary.channelsummary.asyncio.get_running_loop", return_value=loop):
            resolved = [await cog._resolve_profile(item) for item in profiles]

        self.assertEqual(resolved[0], ("llm.lan", 11434, (("192.168.1.10", socket.AF_INET),)))
        self.assertEqual(resolved[1], ("::1", 80, (("::1", socket.AF_INET6),)))
        self.assertEqual(resolved[2], ("api.example", 443, (("8.8.8.8", socket.AF_INET),)))
        self.assertEqual([item.args[:2] for item in loop.getaddrinfo.await_args_list], [
            ("llm.lan", 11434),
            ("::1", 80),
            ("api.example", 443),
        ])

    async def test_connector_tls_and_host_authority_follow_normalized_scheme(self) -> None:
        expected = NormalizedResponse("ok", None, (), (), "model", 0)
        cases = (
            ("http://[::1]:80", "::1", 80, False, "[::1]:80"),
            ("https://api.example", "api.example", 443, "tls", "api.example"),
        )
        for origin, host, port, expected_ssl, expected_host in cases:
            with self.subTest(origin=origin):
                cog = object.__new__(ChannelSummary)
                cog.get_api_key = AsyncMock(return_value="secret")
                cog._resolve_profile = AsyncMock(
                    return_value=(host, port, (("127.0.0.1", socket.AF_INET),))
                )
                resolver = MagicMock()
                resolver.close = AsyncMock()
                response = SimpleNamespace(status=200)
                response_context = MagicMock()
                response_context.__aenter__ = AsyncMock(return_value=response)
                response_context.__aexit__ = AsyncMock(return_value=False)
                session = MagicMock()
                session.post.return_value = response_context
                session_context = MagicMock()
                session_context.__aenter__ = AsyncMock(return_value=session)
                session_context.__aexit__ = AsyncMock(return_value=False)
                tls = object()
                with (
                    patch("channelsummary.channelsummary.PinnedResolver", return_value=resolver),
                    patch("channelsummary.channelsummary.aiohttp.TCPConnector", return_value=object()) as connector,
                    patch("channelsummary.channelsummary.aiohttp.ClientSession", return_value=session_context),
                    patch("channelsummary.channelsummary.ssl.create_default_context", return_value=tls),
                    patch("channelsummary.channelsummary.read_bounded_response", AsyncMock(return_value=b"{}")),
                    patch("channelsummary.channelsummary.normalize_response", return_value=expected),
                ):
                    result = await cog.request_provider(
                        ProviderProfile("main", "generic_chat", origin, "service", ("model",)),
                        {},
                        timeout_seconds=15,
                    )
                self.assertIs(result, expected)
                self.assertEqual(connector.call_args.kwargs["ssl"], tls if expected_ssl == "tls" else False)
                self.assertEqual(session.post.call_args.args[0], origin + "/v1/chat/completions")
                self.assertEqual(session.post.call_args.kwargs["headers"]["Host"], expected_host)


class TestPayloads(unittest.TestCase):
    def build(self, dialect: str, hosted: int = 4, results: int = 7, web: bool = True):
        return build_payload(
            profile(dialect),
            model="model-1",
            system="system",
            input_items="input",
            effort="high",
            output_tokens=2_500,
            remaining_app_calls=3,
            remaining_hosted_calls=hosted,
            remaining_web_results=results,
            web_enabled=web,
        )

    def test_openai_and_openrouter_have_separate_budgets(self) -> None:
        openai = self.build("openai_responses", hosted=3, results=5)
        self.assertEqual(openai["max_tool_calls"], 3)
        self.assertEqual(openai["tools"][1]["type"], "web_search")
        router = self.build("openrouter_responses", hosted=2, results=7)
        self.assertEqual(router["max_tool_calls"], 2)
        self.assertEqual(router["tools"][1]["parameters"], {"max_results": 5, "max_total_results": 7})
        self.assertNotIn("_remaining_app_calls", router)

    def test_zero_hosted_budget_omits_server_web_tool(self) -> None:
        payload = self.build("openrouter_responses", hosted=0)
        self.assertEqual(len(payload["tools"]), 1)
        self.assertNotIn("max_tool_calls", payload)

    def test_generic_chat_never_gets_web_or_reasoning(self) -> None:
        payload = self.build("generic_chat")
        self.assertEqual(len(payload["tools"]), 1)
        self.assertNotIn("reasoning", payload)
        self.assertNotIn("max_tool_calls", payload)


class TestResponseBoundary(unittest.TestCase):
    @staticmethod
    def citation_response(dialect: str, url: str) -> dict:
        annotation = {"type": "url_citation", "url": url, "title": "source"}
        if dialect == "generic_chat":
            return {
                "choices": [
                    {"message": {"role": "assistant", "content": "x", "annotations": [annotation]}}
                ]
            }
        return {
            "output": [
                {
                    "type": "message",
                    "id": "message",
                    "role": "assistant",
                    "content": [{"type": "output_text", "text": "x", "annotations": [annotation]}],
                }
            ]
        }

    def test_responses_fixture_normalizes_and_discards_reasoning(self) -> None:
        raw = {
            "model": "gpt-5.6",
            "output": [
                {"type": "reasoning", "id": "reason_1", "summary": []},
                {"type": "web_search_call", "id": "web_1", "status": "completed"},
                {
                    "type": "message",
                    "id": "msg_1",
                    "role": "assistant",
                    "content": [
                        {
                            "type": "output_text",
                            "text": "summary",
                            "annotations": [
                                {"type": "url_citation", "url": "https://example.com/a", "title": "A"}
                            ],
                        }
                    ],
                },
            ],
        }
        result = normalize_response("openai_responses", raw)
        self.assertEqual(result.text, "summary")
        self.assertEqual(result.hosted_calls, 1)
        self.assertEqual(result.citations[0].url, "https://example.com/a")
        self.assertNotIn("reason", repr(result))

    def test_chat_tool_call_normalizes(self) -> None:
        raw = {
            "model": "vendor/model",
            "choices": [
                {
                    "message": {
                        "role": "assistant",
                        "content": None,
                        "tool_calls": [
                            {
                                "id": "call_1",
                                "type": "function",
                                "function": {"name": "search_channel_history", "arguments": "{}"},
                            }
                        ],
                    }
                }
            ],
        }
        result = normalize_response("generic_chat", raw)
        self.assertEqual(result.function_calls[0].call_id, "call_1")

    def test_citation_controls_and_whitespace_fail_closed_in_both_dialects(self) -> None:
        for dialect in ("openai_responses", "generic_chat"):
            for control in ("\x00", "\x01", "\x07", "\x1b", "\x7f", " ", "\t", "\n", "\u00a0"):
                with self.subTest(dialect=dialect, control=ord(control)), self.assertRaises(
                    SummaryError
                ) as caught:
                    normalize_response(
                        dialect, self.citation_response(dialect, f"https://example.com/{control}")
                    )
                self.assertEqual(caught.exception.code, ErrorCode.RESPONSE_INVALID)
            encoded = normalize_response(
                dialect, self.citation_response(dialect, "https://example.com/%00%29")
            )
            self.assertEqual(encoded.citations[0].url, "https://example.com/%00%29")

    def test_unknown_duplicate_and_unsafe_citation_fail_closed(self) -> None:
        fixtures = [
            {"output": [{"type": "shell_call", "id": "x"}]},
            {
                "output": [
                    {"type": "web_search_call", "id": "same", "status": "completed"},
                    {"type": "web_search_call", "id": "same", "status": "completed"},
                ]
            },
            {
                "output": [
                    {
                        "type": "message",
                        "id": "m",
                        "role": "assistant",
                        "content": [
                            {
                                "type": "output_text",
                                "text": "x",
                                "annotations": [
                                    {"type": "url_citation", "url": "file:///etc/passwd", "title": "x"}
                                ],
                            }
                        ],
                    }
                ]
            },
            {
                "output": [
                    {
                        "type": "message",
                        "id": "private",
                        "role": "assistant",
                        "content": [
                            {
                                "type": "output_text",
                                "text": "x",
                                "annotations": [
                                    {"type": "url_citation", "url": "http://127.0.0.1/admin", "title": "x"}
                                ],
                            }
                        ],
                    }
                ]
            },
            {
                "output": [
                    {
                        "type": "message",
                        "id": "internal-name",
                        "role": "assistant",
                        "content": [
                            {
                                "type": "output_text",
                                "text": "x",
                                "annotations": [
                                    {"type": "url_citation", "url": "https://metadata.internal.example/path", "title": "x"}
                                ],
                            }
                        ],
                    }
                ]
            },
            {
                "output": [
                    {
                        "type": "message",
                        "id": "single-label",
                        "role": "assistant",
                        "content": [
                            {
                                "type": "output_text",
                                "text": "x",
                                "annotations": [
                                    {"type": "url_citation", "url": "https://intranet/admin", "title": "x"}
                                ],
                            }
                        ],
                    }
                ]
            },
            {
                "output": [
                    {
                        "type": "message",
                        "id": "markdown-url",
                        "role": "assistant",
                        "content": [
                            {
                                "type": "output_text",
                                "text": "x",
                                "annotations": [
                                    {
                                        "type": "url_citation",
                                        "url": "https://example.com/) [More](https://evil.example",
                                        "title": "x",
                                    }
                                ],
                            }
                        ],
                    }
                ]
            },
        ]
        for raw in fixtures:
            with self.subTest(raw=raw), self.assertRaises(SummaryError) as caught:
                normalize_response("openai_responses", raw)
            self.assertEqual(caught.exception.code, ErrorCode.RESPONSE_INVALID)

    def test_public_errors_never_include_failure_source(self) -> None:
        sentinel = "sk-secret prompt query provider-body"
        for code in ErrorCode:
            self.assertNotIn(sentinel, str(SummaryError(code)))


class _Chunks:
    def __init__(self, chunks: list[bytes]):
        self.chunks = chunks

    async def iter_chunked(self, size: int):
        for chunk in self.chunks:
            yield chunk


class TestStreamingLimit(unittest.IsolatedAsyncioTestCase):
    async def test_decompressed_stream_limit_is_checked_before_json(self) -> None:
        response = type("Response", (), {"content": _Chunks([b"x" * MAX_RESPONSE_BYTES, b"x"])})()
        with self.assertRaises(SummaryError) as caught:
            await read_bounded_response(response)
        self.assertEqual(caught.exception.code, ErrorCode.RESPONSE_TOO_LARGE)


class FakeAuthor:
    def __init__(self, user_id: int, *, bot: bool = False):
        self.id = user_id
        self.bot = bot
        self.display_name = f"user-{user_id}"
        self.display_avatar = SimpleNamespace(url="https://cdn.example/avatar.png")

    def __str__(self) -> str:
        return self.display_name


class FakeMessage:
    def __init__(self, message_id: int, user_id: int, content: str, minute: int):
        self.id = message_id
        self.author = FakeAuthor(user_id)
        self.content = content
        self.created_at = datetime(2026, 8, 14, 13, minute, tzinfo=UTC)
        self.reference = None
        self.attachments = []
        self.embeds = []

    def is_system(self) -> bool:
        return False


class FakeChannel:
    def __init__(self, messages: list[FakeMessage]):
        self.messages = messages
        self.id = 987654321098765432
        self.name = "general"

    def history(self, *, limit=None, before=None, after=None, oldest_first=False):
        async def iterator():
            selected = []
            for message in self.messages:
                if before is not None:
                    bound = before.id if hasattr(before, "id") else int(before.timestamp() * 1_000)
                    if hasattr(before, "id") and message.id >= bound:
                        continue
                    if not hasattr(before, "id") and message.created_at >= before:
                        continue
                if after is not None:
                    if hasattr(after, "id") and message.id <= after.id:
                        continue
                    if not hasattr(after, "id") and message.created_at <= after:
                        continue
                selected.append(message)
            selected.sort(key=lambda item: item.id, reverse=not oldest_first)
            for message in selected[:limit]:
                yield message

        return iterator()


class TestAgentAndRendering(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self.messages = [
            FakeMessage(111111111111111111, 444444444444444444, "old topic", 2),
            FakeMessage(222222222222222222, 555555555555555555, "new topic begins", 10),
            FakeMessage(333333333333333333, 444444444444444444, "follow up", 36),
        ]
        self.channel = FakeChannel(self.messages)

    def test_duration_message_reference_and_tool_arguments(self) -> None:
        self.assertEqual(parse_duration("2h").total_seconds(), 7_200)
        self.assertEqual(
            parse_message_reference(
                "https://discord.com/channels/123456789012345678/987654321098765432/333333333333333333",
                123456789012345678,
                987654321098765432,
            ),
            333333333333333333,
        )
        args = validate_tool_arguments(
            '{"query":"topic","author_id":"","before_message_id":"","after_message_id":"",'
            '"start_unix":0,"end_unix":0,"limit":10}'
        )
        self.assertEqual(args["limit"], 10)
        with self.assertRaises(SummaryError) as caught:
            validate_tool_arguments(
                '{"query":"","author_id":"","before_message_id":"","after_message_id":"",'
                '"start_unix":100000000000000000000,"end_unix":0,"limit":10}'
            )
        self.assertEqual(caught.exception.code, ErrorCode.RESPONSE_INVALID)

    def test_summary_schema_rejects_forged_sources_and_unconfirms_bad_opener(self) -> None:
        raw = {
            "overview": "overview",
            "topics": [
                {
                    "title": "Topic",
                    "opener_message_id": str(self.messages[1].id),
                    "opener_user_id": str(self.messages[0].author.id),
                    "boundary_reason": "topic_change",
                    "summary": "<@555555555555555555> began it.",
                    "source_message_ids": [str(self.messages[1].id)],
                }
            ],
        }
        parsed = parse_agent_summary(__import__("json").dumps(raw), {item.id: item for item in self.messages})
        self.assertIsNone(parsed.topics[0].opener_message_id)
        raw["topics"][0]["source_message_ids"] = ["999999999999999999"]
        with self.assertRaises(SummaryError):
            parse_agent_summary(__import__("json").dumps(raw), {item.id: item for item in self.messages})

    def test_safe_summary_rendering_keeps_only_valid_user_mentions(self) -> None:
        text = (
            "<@444444444444444444> [Discord Support](https://evil.example) "
            "https://evil.example <@&111111111111111111> <#222222222222222222> @everyone "
            "<@999999999999999999>"
        )
        rendered = sanitize_summary_text(text, {444444444444444444})
        self.assertIn("<@444444444444444444>", rendered)
        self.assertNotIn("evil.example", rendered)
        self.assertNotIn("<@&", rendered)
        self.assertNotIn("<#", rendered)
        self.assertNotIn("@everyone", rendered)
        self.assertNotIn("999999999999999999", rendered)

    async def test_channel_tool_cannot_search_before_explicit_start(self) -> None:
        cog = object.__new__(ChannelSummary)
        state = RunState(
            self.messages[-1].id,
            {self.messages[-1].id},
            {self.messages[-1].id: self.messages[-1]},
            hard_start_id=self.messages[1].id,
        )
        args = (
            '{"query":"","author_id":"","before_message_id":"","after_message_id":"",'
            '"start_unix":0,"end_unix":0,"limit":10}'
        )
        result = await cog._search_channel_history(
            self.channel,
            state,
            {"max_distinct_messages": 10, "include_bots": False},
            args,
            None,
        )
        self.assertNotIn(str(self.messages[0].id), result)
        self.assertIn(str(self.messages[1].id), result)

    async def test_base_range_rejects_zero_and_never_exceeds_one_message(self) -> None:
        cog = object.__new__(ChannelSummary)
        settings = dict(GUILD_DEFAULTS)
        settings["max_distinct_messages"] = 1
        with self.assertRaises(commands.UserFeedbackCheckFailure):
            await cog._base_messages(
                self.channel, self.messages[-1], settings, "auto", 0, None, 0
            )
        with self.assertRaises(commands.UserFeedbackCheckFailure):
            await cog._base_messages(
                self.channel, self.messages[-1], settings, "from", self.messages[0].id, None, 0
            )
        state = await cog._base_messages(
            self.channel, self.messages[-1], settings, "time", timedelta(hours=1), None, 0
        )
        self.assertEqual(set(state.messages), {self.messages[-1].id})

    async def test_agent_tool_round_then_structured_final(self) -> None:
        cog = object.__new__(ChannelSummary)
        cog._guild_attempts = __import__("collections").defaultdict(__import__("collections").deque)
        cog._guild_quota_locks = __import__("collections").defaultdict(__import__("asyncio").Lock)
        args = (
            '{"query":"begins","author_id":"","before_message_id":"","after_message_id":"",'
            '"start_unix":0,"end_unix":0,"limit":10}'
        )
        final = {
            "overview": "Overview",
            "topics": [
                {
                    "title": "Topic",
                    "opener_message_id": str(self.messages[1].id),
                    "opener_user_id": str(self.messages[1].author.id),
                    "boundary_reason": "topic_change",
                    "summary": "Details",
                    "source_message_ids": [str(self.messages[1].id), str(self.messages[2].id)],
                }
            ],
        }
        cog.request_provider = AsyncMock(
            side_effect=[
                NormalizedResponse(None, None, (FunctionCall("call_1", "search_channel_history", args),), (), "model-1", 0),
                NormalizedResponse(__import__("json").dumps(final), None, (), (Citation("https://example.com", "Example"),), "model-1", 0),
            ]
        )
        settings = dict(GUILD_DEFAULTS)
        settings.update({"model": "model-1", "web_enabled": False})
        state = RunState(
            self.messages[-1].id,
            {self.messages[-1].id},
            {self.messages[-1].id: self.messages[-1]},
        )
        result, citations, actual = await cog._run_agent(
            SimpleNamespace(id=123456789012345678),
            self.channel,
            profile("openai_responses"),
            settings,
            state,
            "auto",
            None,
        )
        self.assertEqual(result.topics[0].opener_user_id, self.messages[1].author.id)
        self.assertEqual(citations[0].url, "https://example.com")
        self.assertEqual(actual, "model-1")
        self.assertEqual(cog.request_provider.await_count, 2)

    def test_footer_is_exact_requested_format(self) -> None:
        settings = dict(GUILD_DEFAULTS)
        settings.update({"model": "gpt-5.6-luna", "reasoning_effort": "high", "timezone": "Asia/Taipei"})
        state = RunState(
            self.messages[-1].id,
            {item.id for item in self.messages[:2]},
            {item.id: item for item in self.messages},
        )
        footer = ChannelSummary._footer(settings, state, {item.id for item in self.messages}, "gpt-5.6-luna")
        self.assertEqual(
            footer,
            "範圍 2 則｜Agent 加讀 1 則｜實際引用 3 則\n"
            "2026/08/14 21:02–21:36 Asia/Taipei｜model: gpt-5.6-luna｜effort: high",
        )

    def test_cross_day_footer_keeps_the_exact_single_date_shape(self) -> None:
        first = FakeMessage(111111111111111111, 444444444444444444, "first", 2)
        second = FakeMessage(222222222222222222, 555555555555555555, "second", 10)
        first.created_at = datetime(2026, 8, 13, 13, 2, tzinfo=UTC)
        settings = dict(GUILD_DEFAULTS)
        settings.update({"model": "model-1", "timezone": "Asia/Taipei"})
        state = RunState(second.id, {first.id, second.id}, {first.id: first, second.id: second})
        footer = ChannelSummary._footer(settings, state, {first.id, second.id}, "model-1")
        self.assertEqual(
            footer.splitlines()[1],
            "2026/08/13 21:02–21:10 Asia/Taipei｜model: model-1｜effort: medium",
        )

    def test_embed_has_trigger_author_validated_mentions_and_cog_links(self) -> None:
        cog = object.__new__(ChannelSummary)
        settings = dict(GUILD_DEFAULTS)
        settings.update({"model": "gpt-5.6-luna", "reasoning_effort": "high"})
        state = RunState(
            self.messages[-1].id,
            {item.id for item in self.messages},
            {item.id: item for item in self.messages},
        )
        summary = AgentSummary(
            "<@444444444444444444> reviewed it.",
            (
                SummaryTopic(
                    "Topic",
                    self.messages[0].id,
                    self.messages[0].author.id,
                    "range_start",
                    "faithful record",
                    tuple(item.id for item in self.messages),
                ),
            ),
        )
        embeds = cog._render_embeds(
            SimpleNamespace(id=123456789012345678),
            self.channel,
            self.messages[1].author,
            settings,
            state,
            summary,
            (Citation("https://example.com/source", "ignored title"),),
            "gpt-5.6-luna",
        )
        self.assertEqual(embeds[0].author.name, self.messages[1].author.display_name)
        self.assertIn("<@444444444444444444>", embeds[0].description)
        self.assertIn("discord.com/channels/123456789012345678", embeds[0].description)
        self.assertIn("[1. example.com](https://example.com/source)", embeds[0].description)
        self.assertIn("model: gpt-5.6-luna｜effort: high", embeds[0].footer.text)

    def test_embed_page_limit_is_explicit(self) -> None:
        pages = split_embed_text("\n\n".join("x" * 3_900 for _ in range(10)))
        self.assertEqual(len(pages), 8)
        self.assertIn("8 頁安全上限", pages[-1])

    def test_command_tree_exposes_all_surfaces(self) -> None:
        root = ChannelSummary.summary_group
        self.assertEqual({item.name for item in root.commands}, {"auto", "from", "time", "settings", "provider", "help"})
        settings = next(item for item in root.commands if item.name == "settings")
        self.assertIsNotNone(settings.app_command.callback)
        self.assertEqual(
            {item.name for item in ChannelSummary.summaryset_group.commands},
            {"show", "set", "reset", "enable", "disable", "checkpoint"},
        )

    def test_all_text_setting_commands_are_documented(self) -> None:
        root = Path(__file__).resolve().parents[1]
        documentation = (root / "README.md").read_text(encoding="utf-8")
        runtime = (root / "channelsummary" / "channelsummary.py").read_text(encoding="utf-8")
        for command in ("show", "set", "reset", "enable", "disable", "checkpoint"):
            token = f"[p]summaryset {command}"
            self.assertIn(token, documentation)
            self.assertIn(token, runtime)

    async def test_atomic_guild_attempt_quota_admits_exactly_one(self) -> None:
        cog = object.__new__(ChannelSummary)
        cog._guild_attempts = __import__("collections").defaultdict(__import__("collections").deque)
        cog._guild_quota_locks = __import__("collections").defaultdict(__import__("asyncio").Lock)

        async def reserve():
            try:
                await cog._reserve_guild_attempt(123, 1)
                return True
            except Exception as error:
                self.assertEqual(type(error).__name__, "CommandOnCooldown")
                return False

        self.assertEqual(sum(await __import__("asyncio").gather(reserve(), reserve())), 1)

    async def test_settings_view_contains_selects_and_enable_controls(self) -> None:
        current = dict(GUILD_DEFAULTS)
        current.update({"provider_profile": "main", "model": "model-1"})
        view = SettingsView(MagicMock(), 42, {"main": profile("openai_responses")}, current)
        self.assertEqual(len(view.children), 5)
        labels = {getattr(child, "label", None) for child in view.children}
        self.assertIn("Enable / accept disclosure", labels)
        self.assertIn("Disable", labels)

    def test_settings_profile_select_never_exceeds_discord_limit(self) -> None:
        profiles = {
            f"profile-{index}": ProviderProfile(
                f"profile-{index}", "generic_chat", "https://example.com", "service", ("model",)
            )
            for index in range(MAX_PROVIDER_PROFILES + 1)
        }
        view = SettingsView(MagicMock(), 42, profiles, GUILD_DEFAULTS)
        selector = next(
            child
            for child in view.children
            if getattr(child, "placeholder", None) == "Select provider profile"
        )
        self.assertEqual(len(selector.options), MAX_PROVIDER_PROFILES)

    def test_slash_command_defers_before_channel_history_scans(self) -> None:
        source = inspect.getsource(ChannelSummary._execute_summary)
        self.assertLess(source.index("await ctx.defer()"), source.index("await self._snapshot_message("))

    async def test_model_allowlist_change_disables_invalid_guild_selections(self) -> None:
        cog = object.__new__(ChannelSummary)
        invalid_scope = MagicMock()
        invalid_scope.enabled.set = AsyncMock()
        invalid_scope.disclosure_version.set = AsyncMock()
        valid_scope = MagicMock()
        valid_scope.enabled.set = AsyncMock()
        valid_scope.disclosure_version.set = AsyncMock()
        cog.config = MagicMock()
        cog.config.all_guilds = AsyncMock(
            return_value={
                1: {"provider_profile": "main", "model": "removed"},
                2: {"provider_profile": "main", "model": "kept"},
                3: {"provider_profile": "other", "model": "removed"},
            }
        )
        cog.config.guild_from_id.side_effect = {1: invalid_scope, 2: valid_scope}.__getitem__

        await cog._disable_guilds_using_profile("main", valid_models=("kept",))

        invalid_scope.enabled.set.assert_awaited_once_with(False)
        invalid_scope.disclosure_version.set.assert_awaited_once_with(0)
        valid_scope.enabled.set.assert_not_awaited()

    async def test_single_setting_reset_preserves_configuration_invariants(self) -> None:
        cog = object.__new__(ChannelSummary)
        scope = MagicMock()
        scope.all = AsyncMock(
            return_value={**GUILD_DEFAULTS, "enabled": True, "disclosure_version": 1, "provider_profile": "main"}
        )
        scope.set = AsyncMock()
        cog.config = MagicMock()
        cog.config.guild.return_value = scope
        cog.apply_settings_values = AsyncMock(side_effect=ValueError("invalid default"))
        cog._send_plain = AsyncMock()
        ctx = MagicMock()
        ctx.author.guild_permissions.manage_messages = True
        ctx.tick = AsyncMock()

        await ChannelSummary.settings_reset.callback(cog, ctx, "provider_profile")
        saved = scope.set.await_args.args[0]
        self.assertEqual(saved["provider_profile"], "")
        self.assertFalse(saved["enabled"])
        self.assertEqual(saved["disclosure_version"], 0)

        await ChannelSummary.settings_reset.callback(cog, ctx, "web_enabled")
        cog.apply_settings_values.assert_awaited_once_with(ctx.guild, {"web_enabled": "true"})
        cog._send_plain.assert_awaited_once_with(ctx, "invalid default")
        self.assertEqual(ctx.tick.await_count, 1)


class TestHttpDisclosure(unittest.IsolatedAsyncioTestCase):
    policy = "HTTP is restricted to RFC1918, IPv6 ULA, or loopback destinations"
    warning = "API keys and selected Discord data traverse the LAN unencrypted"

    async def test_provider_profile_limit_and_model_change_invalidation(self) -> None:
        raw = {
            "dialect": "generic_chat",
            "origin": "https://example.com",
            "token_service": "service",
            "models": ["old"],
        }
        cog = object.__new__(ChannelSummary)
        cog.config = MagicMock()
        cog.config.profiles = AsyncMock(
            return_value={f"profile-{index}": raw for index in range(MAX_PROVIDER_PROFILES)}
        )
        cog.config.profiles.set = AsyncMock()
        cog._disable_guilds_using_profile = AsyncMock()
        cog._send_plain = AsyncMock()
        ctx = MagicMock()
        ctx.tick = AsyncMock()

        await ChannelSummary.provider_add.callback(
            cog, ctx, "overflow", "generic_chat", "https://example.com", "service", models="model"
        )
        cog.config.profiles.set.assert_not_awaited()
        self.assertIn("At most 25", cog._send_plain.await_args.args[1])

        cog.config.profiles.return_value = {"main": raw}
        await ChannelSummary.provider_models.callback(cog, ctx, "main", models="kept")
        cog._disable_guilds_using_profile.assert_awaited_once_with(
            "main", valid_models=("kept",)
        )

    async def test_http_provider_add_warns_but_https_does_not(self) -> None:
        cog = object.__new__(ChannelSummary)
        cog.config = MagicMock()
        cog.config.profiles = AsyncMock(return_value={})
        cog.config.profiles.set = AsyncMock()
        cog._disable_guilds_using_profile = AsyncMock()
        cog._send_plain = AsyncMock()
        ctx = MagicMock()

        await ChannelSummary.provider_add.callback(
            cog,
            ctx,
            "lan",
            "generic_chat",
            "http://llm.lan:11434",
            "lan",
            models="model",
        )
        self.assertIn(self.policy, cog._send_plain.await_args.args[1])
        self.assertIn(self.warning, cog._send_plain.await_args.args[1])

        cog.config.profiles.return_value = {}
        cog._send_plain.reset_mock()
        await ChannelSummary.provider_add.callback(
            cog,
            ctx,
            "public",
            "generic_chat",
            "https://api.example",
            "public",
            models="model",
        )
        self.assertNotIn(self.warning, cog._send_plain.await_args.args[1])

    async def test_settings_and_help_disclose_unencrypted_http(self) -> None:
        cog = object.__new__(ChannelSummary)
        scope = MagicMock()
        scope.all = AsyncMock(return_value=dict(GUILD_DEFAULTS))
        cog.config = MagicMock()
        cog.config.guild.return_value = scope
        settings_embed = await cog._settings_embed(MagicMock())
        self.assertIn(self.policy, settings_embed.description)
        self.assertIn(self.warning, settings_embed.description)

        ctx = MagicMock()
        ctx.send = AsyncMock()
        ctx.interaction = None
        await ChannelSummary.summary_group.callback(cog, ctx)
        self.assertIn(self.policy, ctx.send.await_args.kwargs["embed"].description)
        self.assertIn(self.warning, ctx.send.await_args.kwargs["embed"].description)

        ctx.send.reset_mock()
        await ChannelSummary.summary_help.callback(cog, ctx)
        help_text = " ".join(embed.description for embed in ctx.send.await_args.kwargs["embeds"])
        self.assertIn(self.policy, help_text)
        self.assertIn(self.warning, help_text)

    def test_readme_and_info_disclose_unencrypted_http(self) -> None:
        root = Path(__file__).resolve().parents[1]
        for path in (root / "README.md", root / "channelsummary" / "info.json"):
            with self.subTest(path=path):
                text = " ".join(path.read_text(encoding="utf-8").split())
                self.assertIn(self.policy, text)
                self.assertIn(self.warning, text)


class TestSetup(unittest.IsolatedAsyncioTestCase):
    async def test_async_setup_registers_a_loadable_cog_without_network(self) -> None:
        from . import setup

        config = MagicMock()
        bot = MagicMock()
        bot.add_cog = AsyncMock()
        with patch("channelsummary.channelsummary.Config.get_conf", return_value=config):
            await setup(bot)
        bot.add_cog.assert_awaited_once()
        loaded = bot.add_cog.await_args.args[0]
        self.assertIsInstance(loaded, ChannelSummary)
        config.register_global.assert_called_once_with(schema_version=1, profiles={})
        config.register_guild.assert_called_once_with(**GUILD_DEFAULTS)


if __name__ == "__main__":
    unittest.main()
