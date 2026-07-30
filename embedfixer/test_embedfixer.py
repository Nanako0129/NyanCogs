"""Focused S1 checks; run with ``.venv/bin/python -m unittest embedfixer.test_embedfixer``."""

from __future__ import annotations

import asyncio
import ast
import copy
import inspect
import json
import socket
import time
import unittest
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

import discord

from .embedfixer import (
    DEFAULT_GLOBAL_SETTINGS,
    DEFAULT_GUILD_SETTINGS,
    DEFAULT_USER_SETTINGS,
    EmbedFixer,
    MediaCandidate,
    MetadataResolver,
    ProviderMetadata,
    ROTATE_EMOJI,
    _bounded_json,
    _export_payload,
    _metadata_endpoint_allowed,
    _normalize_translation,
    _normalize_legacy_settings,
    _TWITTER_SOURCE_RE,
    _validated_import,
    canonical_media_url,
    extract_candidates,
    fixed_targets,
    format_fixed,
)
from .embedfixer import _permission_ok
from .fixes import DOMAINS, DomainId, apply_fix, clean_query, source_domain_for
from . import __red_end_user_data_statement__


class ProviderInventoryTests(unittest.TestCase):
    def test_frozen_inventory_order_defaults_and_representative_urls(self) -> None:
        expected = {
            DomainId.TWITTER: ([1, 2, 29], 1, True, "https://x.com/a/status/1"),
            DomainId.PIXIV: ([3], 3, True, "https://pixiv.net/artworks/1"),
            DomainId.TIKTOK: ([4, 27, 31], 4, True, "https://tiktok.com/@a/video/1"),
            DomainId.REDDIT: ([6, 7, 26], 6, True, "https://reddit.com/r/a/comments/b/c"),
            DomainId.INSTAGRAM: ([8, 9, 23, 34, 35, 37], 37, True, "https://instagram.com/p/a"),
            DomainId.FURAFFINITY: ([10, 28], 10, True, "https://furaffinity.net/view/1"),
            DomainId.TWITCH_CLIPS: ([11], 11, True, "https://clips.twitch.tv/abc"),
            DomainId.IWARA: ([12], 12, True, "https://iwara.tv/video/a/b"),
            DomainId.BLUESKY: ([13, 14], 13, True, "https://bsky.app/profile/a/post/b"),
            DomainId.KEMONO: ([], None, True, "https://kemono.su/a/user/b/post/c"),
            DomainId.FACEBOOK: ([15, 16, 25], 25, True, "https://facebook.com/reel/1"),
            DomainId.BILIBILI: ([17, 18, 22], 17, True, "https://bilibili.com/video/a"),
            DomainId.BILIBILI_OPUS: ([36], 36, True, "https://bilibili.com/opus/1"),
            DomainId.TUMBLR: ([19], 19, True, "https://tumblr.com/a/1"),
            DomainId.THREADS: ([20, 21, 33], 20, True, "https://threads.net/@a/post/b"),
            DomainId.PTT: ([24], 24, True, "https://ptt.cc/bbs/a/M.1.A.A.html"),
            DomainId.DEVIANTART: ([32], 32, True, "https://deviantart.com/a/art/b-1"),
            DomainId.PINTEREST: ([38], 38, True, "https://pinterest.com/pin/1"),
            DomainId.YOUTUBE: ([39], 39, False, "https://youtube.com/watch?v=abc"),
        }
        self.assertEqual([domain.id for domain in DOMAINS], list(expected))
        for domain in DOMAINS:
            ids, default_id, enabled, representative = expected[domain.id]
            self.assertEqual([method.id for method in domain.fix_methods], ids)
            self.assertEqual(domain.default_fix_method.id if domain.default_fix_method else None, default_id)
            self.assertEqual(domain.enabled_by_default, enabled)
            self.assertIs(source_domain_for(representative), domain)
            for method in domain.fix_methods:
                self.assertIsNotNone(
                    apply_fix(representative, method, domain.id),
                    f"{domain.name} method {method.id}",
                )

    def test_transform_query_optouts_and_append_facebook(self) -> None:
        self.assertEqual(
            clean_query("https://x.com/a/status/1?utm_source=x&x=1"),
            "https://x.com/a/status/1",
        )
        self.assertEqual(
            clean_query("https://youtube.com/watch?v=abc&utm_source=x"),
            "https://youtube.com/watch?v=abc",
        )
        threads = next(d for d in DOMAINS if d.id == DomainId.THREADS)
        append = threads.get_fix_method(33)
        self.assertEqual(
            apply_fix("https://threads.net/share/v/abc", append, DomainId.THREADS),
            "https://fixembed.app/embed?url=https://threads.net/share/v/abc",
        )
        facebook = next(d for d in DOMAINS if d.id == DomainId.FACEBOOK)
        append = facebook.get_fix_method(15)
        # Facebook's method is ReplaceFix; this asserts the exact source method.
        self.assertEqual(apply_fix("https://facebook.com/share/v/abc", append, DomainId.FACEBOOK), "https://facebookez.com/share/v/abc")
        self.assertEqual(fixed_targets("https://clips.twitch.tv/abc")[0].fixed_url, "https://fxtwitch.seria.moe/clip/abc")
        self.assertEqual(fixed_targets("https://b23.tv/abc")[0].fixed_url, "https://fxbilibili.seria.moe/b23/abc")

    def test_parser_bounds_spoilers_and_host_hardening(self) -> None:
        self.assertTrue(extract_candidates("||https://x.com/a/status/1||")[0].spoiler)
        self.assertEqual(extract_candidates("$https://x.com/a/status/1 <https://x.com/a/status/2>"), [])
        self.assertEqual(extract_candidates("https://[x.com/a/status/1"), [])
        self.assertEqual(extract_candidates("https://x.com.evil/a/status/1"), [])
        self.assertEqual(extract_candidates("https://x.com./a/status/1"), [])
        self.assertEqual(extract_candidates("https://user:x@x.com/a/status/1"), [])
        self.assertEqual(extract_candidates("https://x.com:443/a/status/1"), [])
        self.assertEqual(extract_candidates("https://x.com/a/status/1" + "x" * 2048), [])
        self.assertLessEqual(len(extract_candidates(" ".join("https://x.com/a/status/1" for _ in range(20)))), 10)
        started = time.perf_counter()
        self.assertEqual(extract_candidates("https://" + "x" * 3992), [])
        self.assertLess(time.perf_counter() - started, 0.1)
        plain = fixed_targets("https://x.com/a/status/1")
        self.assertEqual(fixed_targets("(https://x.com/a/status/1)"), plain)
        self.assertEqual(fixed_targets("[https://x.com/a/status/1]"), plain)
        self.assertEqual(fixed_targets("{https://x.com/a/status/1}"), plain)

    def test_twitter_source_suffix_inventory(self) -> None:
        for suffix in ("", "/photo", "/photo/1", "/video/42"):
            self.assertIsNotNone(
                _TWITTER_SOURCE_RE.fullmatch(f"/alice/status/1{suffix}/")
            )

    def test_format_and_default_gates(self) -> None:
        targets = fixed_targets("https://x.com/alice/status/1")
        self.assertEqual(len(targets), 1)
        rendered = format_fixed(targets[0])
        self.assertEqual(rendered, "[Tweet](https://fixupx.com/alice/status/1) • [@alice](https://x.com/alice) • [FxTwitter](https://fixupx.com/alice/status/1)")
        better = fixed_targets("https://x.com/alice/status/1", provider_choices={"1": 2})[0]
        self.assertIn("[vxTwitter](https://fixvx.com/alice/status/1)", format_fixed(better))
        bluesky = fixed_targets("https://bsky.app/profile/alice/post/1", provider_choices={"9": 14})[0]
        self.assertIn("[FxBluesky](https://fxbsky.app/profile/alice/post/1)", format_fixed(bluesky))
        mixed = fixed_targets("||https://x.com/alice/status/1|| https://x.com/bob/status/2")
        self.assertEqual([target.spoiler for target in mixed], [True, False])
        self.assertTrue(format_fixed(mixed[0]).startswith("||") and format_fixed(mixed[0]).endswith("||"))
        self.assertEqual(fixed_targets("https://youtube.com/watch?v=abc"), [])
        self.assertEqual(DEFAULT_GUILD_SETTINGS["schema_version"], 1)
        self.assertEqual(DEFAULT_USER_SETTINGS["schema_version"], 1)


class _Sent:
    def __init__(self, channel, content: str, *, embeds=True, embed_url=None):
        self.channel = channel
        self.guild = channel.guild
        self.author = SimpleNamespace(id=99, bot=True)
        self.id = len(channel.sent) + 100
        self.content = content
        fixed_url = content.split("](", 1)[1].split(")", 1)[0]
        self.embeds = [SimpleNamespace(url=embed_url or fixed_url)] if embeds else []
        self.deleted = False
        self.edits = []
        self.reactions = []
        self.removed_reactions = []
        self.view = None

    async def delete(self):
        self.deleted = True

    async def edit(self, **kwargs):
        self.edits.append(kwargs)
        if "content" in kwargs:
            self.content = kwargs["content"]
            fixed_url = self.content.split("](", 1)[1].split(")", 1)[0]
            self.embeds = [SimpleNamespace(url=fixed_url)]
        if "view" in kwargs:
            self.view = kwargs["view"]
        return self

    async def add_reaction(self, emoji):
        self.reactions.append(str(emoji))

    async def remove_reaction(self, emoji, member):
        self.removed_reactions.append((str(emoji), getattr(member, "id", None)))

    async def clear_reactions(self):
        self.reactions.clear()


class _Channel:
    def __init__(self, failures=(), *, embeds=True, embed_url=None, refetch=True):
        self.id = 1
        self.guild = SimpleNamespace(id=9, me=object())
        self.sent = []
        self.failures = iter(failures)
        self.embeds = embeds
        self.embed_url = embed_url
        self.refetch = refetch
        self.original = None

    def permissions_for(self, _member):
        return SimpleNamespace(view_channel=True, send_messages=True, embed_links=True, manage_messages=True, read_message_history=True)

    async def send(self, content, **kwargs):
        self.last_kwargs = kwargs
        failure = next(self.failures, None)
        if failure:
            raise failure
        message = _Sent(self, content, embeds=self.embeds, embed_url=self.embed_url)
        self.sent.append(message)
        return message

    async def fetch_message(self, message_id):
        if not self.refetch:
            raise RuntimeError("refetch transport failure")
        if self.original is not None and message_id == self.original.id:
            return self.original
        for message in self.sent:
            if message.id == message_id:
                return message
        raise RuntimeError("unknown message")


class _HTTPResponse:
    def __init__(
        self,
        payload=None,
        *,
        body=None,
        status=200,
        headers=None,
        chunk_size=65536,
    ):
        self.status = status
        self.headers = headers or {}
        self._body = (
            json.dumps(payload).encode("utf-8")
            if body is None
            else body
        )
        self._offset = 0
        self._chunk_size = chunk_size
        self.content = self

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_args):
        return False

    async def read(self, size):
        size = min(size, self._chunk_size)
        chunk = self._body[self._offset : self._offset + size]
        self._offset += len(chunk)
        return chunk


class _HTTPSession:
    def __init__(self, responses=None):
        self.responses = responses or {}
        self.calls = []
        self.closed = False

    def get(self, url, **kwargs):
        self.calls.append((url, kwargs))
        response = self.responses[url]
        response._offset = 0
        return response

    async def close(self):
        self.closed = True


class _ConfigValue:
    def __init__(self, config, data, key):
        self.config = config
        self.data = data
        self.key = key

    async def __call__(self):
        await self.config._hook("read", self.key)
        return copy.deepcopy(self.data.get(self.key))

    async def set(self, value):
        await self.config._hook("set", self.key)
        self.data[self.key] = copy.deepcopy(value)

    async def clear(self):
        await self.config._hook("clear", self.key)
        self.data.pop(self.key, None)


class _ConfigScope:
    def __init__(self, config, data):
        self.config = config
        self.data = data

    async def all(self):
        await self.config._hook("read", "scope")
        return copy.deepcopy(self.data)

    async def set(self, value):
        await self.config._hook("set", "scope")
        self.data.clear()
        self.data.update(copy.deepcopy(value))

    async def clear(self):
        await self.config._hook("clear", "scope")
        self.data.clear()

    def __getattr__(self, key):
        return _ConfigValue(self.config, self.data, key)


class _TestConfig:
    def __init__(self):
        self.global_data = copy.deepcopy(DEFAULT_GLOBAL_SETTINGS)
        self.guilds = {}
        self.users = {}
        self.hook = None
        self.events = []

    async def _hook(self, action, key):
        self.events.append((action, key))
        if self.hook is not None:
            result = self.hook(action, key)
            if inspect.isawaitable(result):
                await result

    @property
    def replacement_records(self):
        return _ConfigValue(self, self.global_data, "replacement_records")

    def guild_from_id(self, guild_id):
        return _ConfigScope(
            self,
            self.guilds.setdefault(guild_id, copy.deepcopy(DEFAULT_GUILD_SETTINGS)),
        )

    def guild(self, guild):
        return self.guild_from_id(guild.id)

    async def all_guilds(self):
        return copy.deepcopy(self.guilds)

    def user_from_id(self, user_id):
        return _ConfigScope(
            self,
            self.users.setdefault(user_id, copy.deepcopy(DEFAULT_USER_SETTINGS)),
        )

    def user(self, user):
        return self.user_from_id(user.id)


def _record(
    message_id=100,
    *,
    guild_id=9,
    channel_id=1,
    author_id=22,
    source_message_id=10,
    source_edited_at=None,
    target_index=0,
    domain_id=1,
    method_id=1,
    created_at="2026-01-01T00:00:00+00:00",
):
    return str(message_id), {
        "guild_id": guild_id,
        "channel_id": channel_id,
        "author_id": author_id,
        "source_message_id": source_message_id,
        "source_edited_at": source_edited_at,
        "target_index": target_index,
        "domain_id": domain_id,
        "method_id": method_id,
        "created_at": created_at,
    }


def _s3_cog(config, channel, *, recipient=None):
    cog = EmbedFixer.__new__(EmbedFixer)
    cog.config = config
    cog._context_menu_registered = False
    channel.guild.get_member = lambda user_id: SimpleNamespace(id=user_id, bot=False)
    cog.bot = SimpleNamespace(
        user=SimpleNamespace(id=99),
        tree=None,
        get_channel=lambda channel_id: channel if channel_id == channel.id else None,
        get_guild=lambda guild_id: channel.guild if guild_id == channel.guild.id else None,
        get_user=lambda user_id: recipient if recipient is not None and user_id == 22 else None,
    )
    cog._ensure_s3_runtime()
    return cog


def _text_channel(channel_id, guild, *, nsfw=False, permissions=None):
    channel = Mock(spec=discord.TextChannel)
    channel.id = channel_id
    channel.guild = guild
    channel.parent = None
    channel.nsfw = nsfw
    channel.is_nsfw.return_value = nsfw
    channel.permissions_for.return_value = permissions or SimpleNamespace(
        view_channel=True,
        send_messages=True,
        embed_links=True,
        manage_messages=False,
        read_message_history=True,
    )
    return channel


class TransactionTests(unittest.TestCase):
    def _message(self, channel):
        message = SimpleNamespace(
            id=10,
            guild=SimpleNamespace(me=object()),
            channel=channel,
            author=SimpleNamespace(bot=False, id=22, roles=[]),
            webhook_id=None,
            edited_at=None,
            content="https://x.com/a/status/1",
            flags=SimpleNamespace(suppress_embeds=False),
            edits=[],
            deleted=False,
        )
        channel.original = message

        async def edit(**kwargs):
            message.edits.append(kwargs)
            message.flags.suppress_embeds = kwargs.get("suppress", False)

        message.edit = edit

        async def reply(content, **kwargs):
            message.reply_kwargs = kwargs
            return await channel.send(content, **kwargs)

        message.reply = reply

        async def delete():
            message.deleted = True

        message.delete = delete
        return message

    def test_success_sends_bot_identity_link_and_suppresses_only_after_confirmation(self):
        channel = _Channel()
        message = self._message(channel)
        cog = EmbedFixer.__new__(EmbedFixer)
        cog.bot = SimpleNamespace(user=SimpleNamespace(id=99))
        asyncio.run(cog._process(message, fixed_targets(message.content)))
        self.assertEqual(len(channel.sent), 1)
        self.assertIsInstance(channel.last_kwargs["allowed_mentions"], discord.AllowedMentions)
        self.assertFalse(channel.last_kwargs["allowed_mentions"].users)
        self.assertEqual(message.edits, [{"suppress": True}])

    def test_confirmation_failure_never_suppresses_original(self):
        channel = _Channel(embeds=False)
        original_send = channel.send

        async def send(*args, **kwargs):
            result = await original_send(*args, **kwargs)
            result.provider_rejected = True
            return result

        channel.send = send
        message = self._message(channel)
        cog = EmbedFixer.__new__(EmbedFixer)
        cog.bot = SimpleNamespace(user=SimpleNamespace(id=99))
        cog.confirm_timeout = 0.001
        cog.confirm_poll = 0
        asyncio.run(cog._process(message, fixed_targets(message.content)))
        self.assertEqual(message.edits, [])
        self.assertTrue(channel.sent[0].deleted)
        self.assertFalse(message.deleted)

    def test_unrelated_embed_never_suppresses_original(self):
        channel = _Channel(embed_url="https://x.com/a")
        message = self._message(channel)
        cog = EmbedFixer.__new__(EmbedFixer)
        cog.bot = SimpleNamespace(user=SimpleNamespace(id=99))
        cog.confirm_timeout = 0.001
        cog.confirm_poll = 0
        asyncio.run(cog._process(message, fixed_targets(message.content)))
        self.assertEqual(message.edits, [])
        self.assertTrue(channel.sent[0].deleted)

    def test_reply_mode_uses_bot_reply_without_mentioning_author(self):
        channel = _Channel()
        message = self._message(channel)
        cog = EmbedFixer.__new__(EmbedFixer)
        cog.bot = SimpleNamespace(user=SimpleNamespace(id=99))
        asyncio.run(cog._process(message, fixed_targets(message.content), mode="reply"))
        self.assertFalse(message.reply_kwargs["mention_author"])
        self.assertEqual(message.edits, [{"suppress": True}])

    def test_send_only_partial_failure_keeps_confirmed_provider_embed(self):
        class Rejection(Exception):
            status = 403

        channel = _Channel(failures=(None, Rejection()))
        targets = fixed_targets("https://x.com/a/status/1 https://bsky.app/profile/b/post/2")
        cog = EmbedFixer.__new__(EmbedFixer)
        cog.bot = SimpleNamespace(user=SimpleNamespace(id=99))
        result = asyncio.run(
            cog._process(None, targets, sender=channel.send, may_suppress=False)
        )
        self.assertTrue(result)
        self.assertFalse(channel.sent[0].deleted)

    def test_provider_timeout_cleans_replacement_before_suppression(self):
        channel = _Channel(embeds=False)
        message = self._message(channel)
        cog = EmbedFixer.__new__(EmbedFixer)
        cog.bot = SimpleNamespace(user=SimpleNamespace(id=99))
        cog.confirm_timeout = 0.001
        cog.confirm_poll = 0
        asyncio.run(cog._process(message, fixed_targets(message.content)))
        self.assertEqual(message.edits, [])
        self.assertTrue(channel.sent[0].deleted)
        self.assertFalse(message.deleted)

    def test_indeterminate_suppression_timeout_retains_confirmed_replacement(self):
        channel = _Channel()
        message = self._message(channel)

        async def timeout_edit(**kwargs):
            message.edits.append(kwargs)
            raise TimeoutError("response state unknown")

        message.edit = timeout_edit
        cog = EmbedFixer.__new__(EmbedFixer)
        cog.bot = SimpleNamespace(user=SimpleNamespace(id=99))
        asyncio.run(cog._process(message, fixed_targets(message.content)))
        self.assertEqual(message.edits, [{"suppress": True}])
        self.assertFalse(channel.sent[0].deleted)
        self.assertFalse(message.deleted)

    def test_definitive_suppression_rejection_cleans_replacement(self):
        class Rejection(Exception):
            status = 403

        channel = _Channel()
        message = self._message(channel)

        async def reject_edit(**kwargs):
            message.edits.append(kwargs)
            raise Rejection()

        message.edit = reject_edit
        cog = EmbedFixer.__new__(EmbedFixer)
        cog.bot = SimpleNamespace(user=SimpleNamespace(id=99))
        asyncio.run(cog._process(message, fixed_targets(message.content)))
        self.assertEqual(message.edits, [{"suppress": True}])
        self.assertTrue(channel.sent[0].deleted)
        self.assertFalse(message.deleted)

    def test_definitive_second_send_failure_cleans_known_replacements(self):
        class Rejection(Exception):
            status = 403

        channel = _Channel(failures=(None, Rejection()))
        message = self._message(channel)
        targets = fixed_targets("https://x.com/a/status/1 https://bsky.app/profile/b/post/2")
        cog = EmbedFixer.__new__(EmbedFixer)
        cog.bot = SimpleNamespace(user=SimpleNamespace(id=99))
        asyncio.run(cog._process(message, targets))
        self.assertEqual(len(channel.sent), 1)
        self.assertTrue(channel.sent[0].deleted)
        self.assertEqual(message.edits, [])
        self.assertFalse(message.deleted)

    def test_refetch_failure_and_cleanup_failure_retain_replacements(self):
        class Rejection(Exception):
            status = 403

        channel = _Channel(failures=(None, Rejection()), refetch=False)
        message = self._message(channel)
        targets = fixed_targets("https://x.com/a/status/1 https://bsky.app/profile/b/post/2")
        cog = EmbedFixer.__new__(EmbedFixer)
        cog.bot = SimpleNamespace(user=SimpleNamespace(id=99))
        asyncio.run(cog._process(message, targets))
        self.assertFalse(channel.sent[0].deleted)

        channel = _Channel(failures=(None, Rejection()))
        message = self._message(channel)
        original_send = channel.send

        async def send(*args, **kwargs):
            if not channel.sent:
                sent = await original_send(*args, **kwargs)
                async def fail_delete():
                    raise RuntimeError("cleanup failed")
                sent.delete = fail_delete
                return sent
            return await original_send(*args, **kwargs)

        channel.send = send
        asyncio.run(cog._process(message, targets))
        self.assertFalse(channel.sent[0].deleted)

    def test_permission_and_id_gate_normalization(self):
        channel = _Channel()
        message = self._message(channel)
        permissions = channel.permissions_for(None)
        permissions.view_channel = False
        channel.permissions_for = lambda _member: permissions
        self.assertFalse(_permission_ok(message, SimpleNamespace(user=object())))
        message.channel = SimpleNamespace()
        self.assertFalse(_permission_ok(message, SimpleNamespace(user=object())))

        channel = _Channel()
        message = self._message(channel)
        message.channel.id = "1"
        message.author.roles = [SimpleNamespace(id=42)]
        scope = SimpleNamespace(
            enabled=True,
            ignored=False,
            ignored_users=[],
            whitelist_role_ids=["42"],
            disable_fix_channels=["1"],
            enable_fix_channels=["1"],
            fix_mode="resend",
            provider_choices={},
            disabled_fixes=[],
            disabled_domains=[],
            enabled_domains=[],
        )
        user_scope = SimpleNamespace(ignored=False, fix_mode=None)
        called = []
        cog = EmbedFixer.__new__(EmbedFixer)
        cog.bot = SimpleNamespace(user=object())
        cog.config = SimpleNamespace(guild=lambda _guild: scope, user=lambda _user: user_scope)

        async def process(_message, _targets, **_kwargs):
            called.append(True)

        cog._process = process
        asyncio.run(cog.on_message(message))
        self.assertEqual(called, [True])

    def test_listener_skips_valid_red_commands_before_config_access(self):
        channel = _Channel()
        message = self._message(channel)

        async def get_context(_message):
            return SimpleNamespace(valid=True)

        cog = EmbedFixer.__new__(EmbedFixer)
        cog.bot = SimpleNamespace(get_context=get_context)
        cog.config = SimpleNamespace(
            guild=lambda _guild: self.fail("guild Config must not be read"),
            user=lambda _user: self.fail("user Config must not be read"),
        )
        asyncio.run(cog.on_message(message))
        self.assertEqual(channel.sent, [])


class SecurityS3Tests(unittest.TestCase):
    def _source(self, channel):
        source = TransactionTests()._message(channel)
        source.guild = channel.guild
        return source

    def test_sr01_deletion_tokens_final_sweep_and_post_release_token(self):
        async def scenario():
            config = _TestConfig()
            channel = _Channel()
            cog = _s3_cog(config, channel)
            old = cog._register_author(22)
            clearing = asyncio.Event()
            release = asyncio.Event()

            async def hook(action, key):
                if action == "clear" and key == "scope":
                    clearing.set()
                    await release.wait()

            config.hook = hook
            deletion = asyncio.create_task(
                cog.red_delete_data_for_user(requester="discord_deleted_user", user_id=22)
            )
            await clearing.wait()
            during_clear = cog._register_author(22)
            release.set()
            await deletion
            self.assertTrue(old.is_set())
            self.assertTrue(during_clear.is_set())
            self.assertNotIn(22, cog._author_inflight)
            post_release = cog._register_author(22)
            self.assertFalse(post_release.is_set())
            self.assertIsNot(post_release, old)

        asyncio.run(scenario())

    def test_sr01_lock_precedes_config_and_discord_for_unknown_author(self):
        async def scenario():
            config = _TestConfig()
            channel = _Channel()
            source = self._source(channel)
            replacement = _Sent(channel, format_fixed(fixed_targets(source.content)[0]))
            channel.sent.append(replacement)
            key, value = _record()
            config.global_data["replacement_records"] = {key: value}
            cog = _s3_cog(config, channel)

            async def hook(_action, _key):
                self.assertTrue(cog._s3_lock.locked())

            config.hook = hook
            original_fetch = channel.fetch_message
            fetched = []

            async def fetch(message_id):
                self.assertTrue(cog._s3_lock.locked())
                fetched.append(message_id)
                return await original_fetch(message_id)

            channel.fetch_message = fetch
            payload = SimpleNamespace(
                user_id=22,
                guild_id=9,
                channel_id=1,
                message_id=100,
                emoji="❌",
                member=SimpleNamespace(id=22, bot=False),
            )
            async with cog._s3_lock:
                blocked = asyncio.create_task(cog.on_raw_reaction_add(payload))
                with self.assertRaises(asyncio.TimeoutError):
                    await asyncio.wait_for(asyncio.shield(blocked), 0.01)
                self.assertEqual(config.events, [])
            await blocked
            self.assertEqual(fetched, [100])
            self.assertNotIn(10, fetched)

        asyncio.run(scenario())

    def test_confirmation_poll_runs_without_global_lock(self):
        async def scenario():
            config = _TestConfig()
            channel = _Channel()
            source = self._source(channel)
            cog = _s3_cog(config, channel)
            entered = asyncio.Event()
            release = asyncio.Event()

            async def confirm(_replacement, _url):
                self.assertFalse(cog._s3_lock.locked())
                entered.set()
                await release.wait()
                return True

            cog._confirm_embed = confirm
            task = asyncio.create_task(cog.on_message(source))
            await entered.wait()
            self.assertFalse(cog._s3_lock.locked())
            release.set()
            await task
            self.assertEqual(source.edits, [{"suppress": True}])

        asyncio.run(scenario())

    def test_source_mutation_during_preview_cleans_replacement_and_aborts(self):
        async def scenario():
            config = _TestConfig()
            channel = _Channel()
            source = self._source(channel)
            cog = _s3_cog(config, channel)
            snapshot = cog._source_snapshot(source)

            async def confirm(_replacement, _url):
                source.content = "https://x.com/changed/status/2"
                return True

            cog._confirm_embed = confirm
            success = await cog._process(
                source,
                fixed_targets(source.content),
                guild=source.guild,
                author=source.author,
                channel=channel,
                destination=channel,
                guild_settings=copy.deepcopy(DEFAULT_GUILD_SETTINGS),
                user_settings=copy.deepcopy(DEFAULT_USER_SETTINGS),
                source_snapshot=snapshot,
            )
            self.assertFalse(success)
            self.assertEqual(config.global_data["replacement_records"], {})
            self.assertTrue(channel.sent[0].deleted)
            self.assertEqual(source.edits, [])

        asyncio.run(scenario())

    def test_destination_policy_change_during_preview_cleans_replacement(self):
        async def scenario():
            config = _TestConfig()
            source_channel = _Channel()
            guild = source_channel.guild
            destination = _text_channel(2, guild)
            destination.sent = []

            async def send(content, **_kwargs):
                replacement = _Sent(destination, content)
                destination.sent.append(replacement)
                return replacement

            async def fetch_message(message_id):
                for replacement in destination.sent:
                    if replacement.id == message_id:
                        return replacement
                raise RuntimeError("unknown replacement")

            destination.send = send
            destination.fetch_message = fetch_message
            guild.get_channel = lambda channel_id: destination if channel_id == 2 else None
            source = self._source(source_channel)
            config.guilds[9] = {
                **copy.deepcopy(DEFAULT_GUILD_SETTINGS),
                "funnel_target_channel": 2,
            }
            cog = _s3_cog(config, source_channel)

            async def confirm(_replacement, _url):
                source_channel.nsfw = True
                return True

            cog._confirm_embed = confirm
            await cog.on_message(source)
            self.assertEqual(config.global_data["replacement_records"], {})
            self.assertEqual(source.edits, [])
            self.assertTrue(destination.sent[0].deleted)

        asyncio.run(scenario())

    def test_destination_policy_revalidated_after_persistence_and_controls(self):
        async def scenario(phase):
            config = _TestConfig()
            source_channel = _Channel()
            guild = source_channel.guild
            destination = _text_channel(2, guild)
            destination.sent = []

            async def send(content, **_kwargs):
                replacement = _Sent(destination, content)
                destination.sent.append(replacement)
                return replacement

            async def fetch_message(message_id):
                for replacement in destination.sent:
                    if replacement.id == message_id:
                        return replacement
                raise RuntimeError("unknown replacement")

            destination.send = send
            destination.fetch_message = fetch_message
            guild.get_channel = lambda channel_id: destination if channel_id == 2 else None
            source = self._source(source_channel)
            config.guilds[9] = {
                **copy.deepcopy(DEFAULT_GUILD_SETTINGS),
                "funnel_target_channel": 2,
            }
            cog = _s3_cog(config, source_channel)
            if phase == "persist":
                changed = False

                async def hook(action, key):
                    nonlocal changed
                    if not changed and action == "read" and key == "replacement_records":
                        changed = True
                        source_channel.nsfw = True

                config.hook = hook
            else:
                original_add_controls = cog._add_controls

                async def add_controls(*args, **kwargs):
                    result = await original_add_controls(*args, **kwargs)
                    source_channel.nsfw = True
                    return result

                cog._add_controls = add_controls
            await cog.on_message(source)
            self.assertEqual(config.global_data["replacement_records"], {})
            self.assertEqual(source.edits, [])
            self.assertTrue(destination.sent[0].deleted)

        asyncio.run(scenario("persist"))
        asyncio.run(scenario("controls"))

    def test_final_revalidation_refetches_after_config_reads(self):
        async def scenario():
            config = _TestConfig()
            channel = _Channel()
            source = self._source(channel)
            cog = _s3_cog(config, channel)
            armed = False
            mutated = False

            async def hook(action, key):
                nonlocal mutated
                if armed and not mutated and action == "read" and key == "scope":
                    mutated = True
                    source.content = "https://x.com/changed/status/2"
                    source.edited_at = datetime.now(timezone.utc)

            config.hook = hook
            original_add_controls = cog._add_controls

            async def add_controls(*args, **kwargs):
                nonlocal armed
                result = await original_add_controls(*args, **kwargs)
                armed = True
                return result

            cog._add_controls = add_controls
            await cog.on_message(source)
            self.assertTrue(mutated)
            self.assertEqual(config.global_data["replacement_records"], {})
            self.assertEqual(source.edits, [])
            self.assertTrue(channel.sent[0].deleted)

        asyncio.run(scenario())

    def test_final_revalidation_rejects_suppressed_source_state(self):
        async def scenario():
            config = _TestConfig()
            channel = _Channel()
            source = self._source(channel)
            cog = _s3_cog(config, channel)
            armed = False
            mutated = False

            async def hook(action, key):
                nonlocal mutated
                if armed and not mutated and action == "read" and key == "scope":
                    mutated = True
                    source.flags.suppress_embeds = True

            config.hook = hook
            original_add_controls = cog._add_controls

            async def add_controls(*args, **kwargs):
                nonlocal armed
                result = await original_add_controls(*args, **kwargs)
                armed = True
                return result

            cog._add_controls = add_controls
            await cog.on_message(source)
            self.assertTrue(mutated)
            self.assertIn("100", config.global_data["replacement_records"])
            self.assertFalse(channel.sent[0].deleted)
            self.assertEqual(source.edits, [])

        asyncio.run(scenario())

    def test_invalid_delete_emoji_mutates_no_controls(self):
        async def scenario():
            config = _TestConfig()
            channel = _Channel()
            source = self._source(channel)
            target = fixed_targets(source.content)[0]
            replacement = _Sent(channel, format_fixed(target))
            channel.sent.append(replacement)
            _key, record = _record(source_message_id=None)
            cog = _s3_cog(config, channel)
            settings = {
                **copy.deepcopy(DEFAULT_GUILD_SETTINGS),
                "delete_msg_emoji": ROTATE_EMOJI,
            }
            with self.assertRaisesRegex(RuntimeError, "invalid delete emoji"):
                await cog._add_controls(replacement, target, record, settings)
            self.assertEqual(replacement.edits, [])
            self.assertEqual(replacement.reactions, [])

        asyncio.run(scenario())

    def test_unknown_delete_emoji_reaction_is_nonfatal(self):
        async def scenario():
            config = _TestConfig()
            channel = _Channel()
            source = self._source(channel)
            settings = {
                **copy.deepcopy(DEFAULT_GUILD_SETTINGS),
                "delete_msg_emoji": "abc",
            }
            config.guilds[9] = copy.deepcopy(settings)
            cog = _s3_cog(config, channel)
            original_send = channel.send

            async def send(*args, **kwargs):
                replacement = await original_send(*args, **kwargs)

                async def reject(_emoji):
                    raise discord.HTTPException(
                        SimpleNamespace(status=400, reason="Bad Request"),
                        {"message": "Unknown emoji"},
                    )

                replacement.add_reaction = reject
                return replacement

            channel.send = send
            self.assertTrue(
                await cog._process(
                    source,
                    fixed_targets(source.content),
                    guild=source.guild,
                    author=source.author,
                    channel=channel,
                    guild_settings=settings,
                )
            )
            self.assertIn("100", config.global_data["replacement_records"])
            self.assertFalse(channel.sent[0].deleted)
            self.assertEqual(source.edits, [{"suppress": True}])

        asyncio.run(scenario())

    def test_programmer_reaction_failure_with_status_stays_fatal(self):
        async def scenario():
            class ProgrammerError(AttributeError):
                status = 500

            config = _TestConfig()
            channel = _Channel()
            source = self._source(channel)
            target = fixed_targets(source.content)[0]
            replacement = _Sent(channel, format_fixed(target))
            channel.sent.append(replacement)
            _key, record = _record(source_message_id=None)
            cog = _s3_cog(config, channel)

            async def reject(_emoji):
                raise ProgrammerError("bug")

            replacement.add_reaction = reject
            with self.assertRaises(ProgrammerError):
                await cog._add_controls(
                    replacement,
                    target,
                    record,
                    copy.deepcopy(DEFAULT_GUILD_SETTINGS),
                )

        asyncio.run(scenario())

    def test_sr02_persist_precedes_controls_and_suppress_and_records_are_scalar_only(self):
        async def scenario():
            config = _TestConfig()
            channel = _Channel()
            source = self._source(channel)
            cog = _s3_cog(config, channel)
            original_edit = source.edit

            async def suppress(**kwargs):
                self.assertIn("100", config.global_data["replacement_records"])
                self.assertEqual(channel.sent[0].reactions, ["❌"])
                await original_edit(**kwargs)

            source.edit = suppress
            settings = copy.deepcopy(DEFAULT_GUILD_SETTINGS)
            success = await cog._process(
                source,
                fixed_targets(source.content),
                guild=source.guild,
                author=source.author,
                channel=channel,
                guild_settings=settings,
            )
            self.assertTrue(success)
            record = config.global_data["replacement_records"]["100"]
            self.assertEqual(
                set(record),
                {
                    "guild_id",
                    "channel_id",
                    "author_id",
                    "source_message_id",
                    "source_edited_at",
                    "target_index",
                    "domain_id",
                    "method_id",
                    "created_at",
                },
            )
            serialized = json.dumps(record)
            self.assertNotIn("x.com", serialized)
            self.assertNotIn("content", serialized)
            self.assertNotIn("url", serialized.casefold())
            button = channel.sent[0].view.children[0]
            self.assertEqual((button.label, button.url), ("View", "https://x.com/a/status/1"))
            self.assertEqual(source.edits, [{"suppress": True}])

        asyncio.run(scenario())

    def test_sr02_persistence_and_control_failures_cleanup_without_suppressing(self):
        async def persistence_failure():
            config = _TestConfig()
            channel = _Channel()
            source = self._source(channel)
            cog = _s3_cog(config, channel)

            def hook(action, key):
                if action == "set" and key == "replacement_records":
                    raise RuntimeError("storage failed")

            config.hook = hook
            self.assertFalse(
                await cog._process(
                    source,
                    fixed_targets(source.content),
                    guild=source.guild,
                    author=source.author,
                    channel=channel,
                    guild_settings=copy.deepcopy(DEFAULT_GUILD_SETTINGS),
                )
            )
            self.assertEqual(source.edits, [])
            self.assertTrue(channel.sent[0].deleted)

        async def control_failure():
            config = _TestConfig()
            channel = _Channel()
            source = self._source(channel)
            cog = _s3_cog(config, channel)
            original_send = channel.send

            async def send(*args, **kwargs):
                replacement = await original_send(*args, **kwargs)

                async def fail(_emoji):
                    raise RuntimeError("reaction failed")

                replacement.add_reaction = fail
                return replacement

            channel.send = send
            self.assertFalse(
                await cog._process(
                    source,
                    fixed_targets(source.content),
                    guild=source.guild,
                    author=source.author,
                    channel=channel,
                    guild_settings=copy.deepcopy(DEFAULT_GUILD_SETTINGS),
                )
            )
            self.assertEqual(source.edits, [])
            self.assertEqual(config.global_data["replacement_records"], {})
            self.assertTrue(channel.sent[0].deleted)

        async def cancellation():
            config = _TestConfig()
            channel = _Channel()
            source = self._source(channel)
            cog = _s3_cog(config, channel)
            persisting = asyncio.Event()
            hold = asyncio.Event()

            async def hook(action, key):
                if action == "set" and key == "replacement_records":
                    persisting.set()
                    await hold.wait()

            config.hook = hook
            task = asyncio.create_task(
                cog._process(
                    source,
                    fixed_targets(source.content),
                    guild=source.guild,
                    author=source.author,
                    channel=channel,
                    guild_settings=copy.deepcopy(DEFAULT_GUILD_SETTINGS),
                )
            )
            await persisting.wait()
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
            self.assertEqual(source.edits, [])
            self.assertEqual(config.global_data["replacement_records"], {})
            self.assertTrue(channel.sent[0].deleted)

        asyncio.run(persistence_failure())
        asyncio.run(control_failure())
        asyncio.run(cancellation())

    def test_sr02_failed_cleanup_retains_replacement_authority(self):
        async def scenario():
            config = _TestConfig()
            channel = _Channel()
            source = self._source(channel)
            cog = _s3_cog(config, channel)
            original_send = channel.send

            async def send(*args, **kwargs):
                replacement = await original_send(*args, **kwargs)

                async def fail_reaction(_emoji):
                    raise RuntimeError("reaction failed")

                async def fail_delete():
                    raise RuntimeError("delete failed")

                replacement.add_reaction = fail_reaction
                replacement.delete = fail_delete
                return replacement

            channel.send = send
            self.assertFalse(
                await cog._process(
                    source,
                    fixed_targets(source.content),
                    guild=source.guild,
                    author=source.author,
                    channel=channel,
                    guild_settings=copy.deepcopy(DEFAULT_GUILD_SETTINGS),
                )
            )
            self.assertEqual(source.edits, [])
            self.assertIn("100", config.global_data["replacement_records"])

        asyncio.run(scenario())

    def test_sr02_cancel_after_config_commit_retains_authority_if_delete_fails(self):
        async def scenario():
            committed = asyncio.Event()
            hold = asyncio.Event()

            class CommitBeforeAwaitValue(_ConfigValue):
                async def set(self, value):
                    self.data[self.key] = copy.deepcopy(value)
                    committed.set()
                    await hold.wait()

            class CommitBeforeAwaitConfig(_TestConfig):
                @property
                def replacement_records(self):
                    return CommitBeforeAwaitValue(
                        self,
                        self.global_data,
                        "replacement_records",
                    )

            config = CommitBeforeAwaitConfig()
            channel = _Channel()
            source = self._source(channel)
            cog = _s3_cog(config, channel)
            original_send = channel.send

            async def send(*args, **kwargs):
                replacement = await original_send(*args, **kwargs)

                async def fail_delete():
                    raise RuntimeError("delete failed")

                replacement.delete = fail_delete
                return replacement

            channel.send = send
            task = asyncio.create_task(
                cog._process(
                    source,
                    fixed_targets(source.content),
                    guild=source.guild,
                    author=source.author,
                    channel=channel,
                    guild_settings=copy.deepcopy(DEFAULT_GUILD_SETTINGS),
                )
            )
            await committed.wait()
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
            self.assertEqual(source.edits, [])
            self.assertIn("100", config.global_data["replacement_records"])
            self.assertFalse(channel.sent[0].deleted)

        asyncio.run(scenario())

    def test_sr02_cancel_before_config_commit_uses_pending_authority(self):
        async def scenario():
            persisting = asyncio.Event()
            hold = asyncio.Event()
            config = _TestConfig()
            channel = _Channel()
            source = self._source(channel)
            cog = _s3_cog(config, channel)
            original_send = channel.send

            async def hook(action, key):
                if action == "set" and key == "replacement_records":
                    persisting.set()
                    await hold.wait()

            async def send(*args, **kwargs):
                replacement = await original_send(*args, **kwargs)

                async def fail_delete():
                    raise RuntimeError("delete failed")

                replacement.delete = fail_delete
                return replacement

            config.hook = hook
            channel.send = send
            task = asyncio.create_task(
                cog._process(
                    source,
                    fixed_targets(source.content),
                    guild=source.guild,
                    author=source.author,
                    channel=channel,
                    guild_settings=copy.deepcopy(DEFAULT_GUILD_SETTINGS),
                )
            )
            await persisting.wait()
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
            self.assertEqual(config.global_data["replacement_records"], {})
            self.assertIn("100", await cog._replacement_records())
            self.assertFalse(channel.sent[0].deleted)
            self.assertEqual(source.edits, [])

        asyncio.run(scenario())

    def test_sr02_repeated_pending_cancellation_preserves_guild_cap(self):
        async def scenario():
            config = _TestConfig()
            channel = _Channel()
            cog = _s3_cog(config, channel)
            config.global_data["replacement_records"] = dict(
                _record(
                    1000 + index,
                    source_message_id=None,
                    created_at="2026-01-01T00:00:00+00:00",
                )
                for index in range(999)
            )

            async def cancel_before_commit(message_id):
                entered = asyncio.Event()
                hold = asyncio.Event()

                async def hook(action, key):
                    if action == "set" and key == "replacement_records":
                        entered.set()
                        await hold.wait()

                config.hook = hook
                key, record = _record(
                    message_id,
                    source_message_id=None,
                    created_at="2026-02-01T00:00:00+00:00",
                )
                task = asyncio.create_task(
                    cog._persist_replacements({key: record}, None)
                )
                await entered.wait()
                task.cancel()
                with self.assertRaises(asyncio.CancelledError):
                    await task

            await cancel_before_commit(9000)
            await cancel_before_commit(9001)
            effective = await cog._replacement_records()
            self.assertLessEqual(len(effective), 1000)
            self.assertEqual(
                sum(record["guild_id"] == 9 for record in effective.values()),
                1000,
            )

        asyncio.run(scenario())

    def test_sr03_bot_only_delete_rejects_source_and_nonbot_replacement(self):
        async def scenario():
            config = _TestConfig()
            channel = _Channel()
            source = self._source(channel)
            cog = _s3_cog(config, channel)
            self.assertFalse(
                await cog._delete_bot_message(9, 1, 10, source_message_id=10)
            )
            self.assertFalse(source.deleted)
            nonbot = _Sent(channel, format_fixed(fixed_targets(source.content)[0]))
            nonbot.author = SimpleNamespace(id=22, bot=False)
            channel.sent.append(nonbot)
            self.assertFalse(await cog._delete_bot_message(9, 1, 100))
            self.assertFalse(nonbot.deleted)

        asyncio.run(scenario())

    def test_sr03_raw_delete_events_remove_only_matching_replacement_records(self):
        async def scenario():
            config = _TestConfig()
            channel = _Channel()
            cog = _s3_cog(config, channel)
            first_key, first = _record(100)
            second_key, second = _record(101)
            config.global_data["replacement_records"] = {
                first_key: first,
                second_key: second,
            }
            await cog.on_raw_message_delete(
                SimpleNamespace(message_id=100, guild_id=9, channel_id=1)
            )
            self.assertNotIn(first_key, config.global_data["replacement_records"])
            self.assertIn(second_key, config.global_data["replacement_records"])
            await cog.on_raw_bulk_message_delete(
                SimpleNamespace(message_ids={101, 102}, guild_id=9, channel_id=1)
            )
            self.assertEqual(config.global_data["replacement_records"], {})

        asyncio.run(scenario())

    def test_sr03_cap_fairness_and_global_full_rejects_without_eviction(self):
        async def scenario():
            config = _TestConfig()
            channel = _Channel()
            cog = _s3_cog(config, channel)
            own = dict(
                _record(
                    1000 + index,
                    source_message_id=None,
                    created_at="2026-01-01T00:00:00+00:00",
                )
                for index in range(1000)
            )
            other_key, other = _record(5000, guild_id=8, source_message_id=None)
            config.global_data["replacement_records"] = {**own, other_key: other}
            new_key, new = _record(9000, source_message_id=None)
            async with cog._s3_lock:
                persisted, victims = await cog._persist_replacements({new_key: new}, None)
            self.assertTrue(persisted)
            self.assertEqual(victims[0][0], 1000)
            current = config.global_data["replacement_records"]
            self.assertNotIn("1000", current)
            self.assertIn(other_key, current)
            self.assertIn(new_key, current)

            full = {}
            for index in range(10000):
                key, record = _record(
                    10000 + index,
                    guild_id=index // 1000 + 1,
                    source_message_id=None,
                )
                full[key] = record
            config.global_data["replacement_records"] = full
            writes = len([event for event in config.events if event == ("set", "replacement_records")])
            key, record = _record(30000, source_message_id=None)
            async with cog._s3_lock:
                persisted, victims = await cog._persist_replacements({key: record}, None)
            self.assertFalse(persisted)
            self.assertEqual(victims, [])
            self.assertEqual(len(config.global_data["replacement_records"]), 10000)
            self.assertEqual(
                len([event for event in config.events if event == ("set", "replacement_records")]),
                writes,
            )

        asyncio.run(scenario())

    def test_sr04_original_button_spoiler_and_timeout_task_never_deletes(self):
        async def scenario():
            targets = fixed_targets("https://x.com/a/status/1 ||https://x.com/b/status/2||")
            plain = next(target for target in targets if not target.spoiler)
            spoiler = next(target for target in targets if target.spoiler)
            settings = copy.deepcopy(DEFAULT_GUILD_SETTINGS)
            plain_view = EmbedFixer._original_link_view(plain, settings)
            self.assertEqual((plain_view.children[0].label, plain_view.children[0].url), ("View", plain.original_url))
            self.assertIsNone(EmbedFixer._original_link_view(spoiler, settings))

            config = _TestConfig()
            channel = _Channel()
            replacement = _Sent(channel, format_fixed(plain))
            channel.sent.append(replacement)
            key, record = _record(source_message_id=None)
            config.global_data["replacement_records"] = {key: record}
            config.guilds[9] = copy.deepcopy(DEFAULT_GUILD_SETTINGS)
            config.guilds[9]["remove_delete_reaction_after"] = 0
            cog = _s3_cog(config, channel)
            cog._track_reaction_timeout(100, record, config.guilds[9])
            await asyncio.gather(*tuple(cog._reaction_tasks))
            self.assertEqual(replacement.removed_reactions, [("❌", 99)])
            self.assertFalse(replacement.deleted)
            config.guilds[9]["remove_delete_reaction_after"] = 60
            cog._track_reaction_timeout(100, record, config.guilds[9])
            tasks = tuple(cog._reaction_tasks)
            await cog.cog_unload()
            self.assertTrue(all(task.done() for task in tasks))
            self.assertEqual(cog._notify_pairs, {})
            self.assertEqual(cog._notify_recipients, {})

        asyncio.run(scenario())

    def test_sr05_delete_control_author_only_duplicate_idempotent_and_no_source_fetch(self):
        async def scenario():
            config = _TestConfig()
            channel = _Channel()
            source = self._source(channel)
            replacement = _Sent(channel, format_fixed(fixed_targets(source.content)[0]))
            channel.sent.append(replacement)
            key, record = _record()
            config.global_data["replacement_records"] = {key: record}
            cog = _s3_cog(config, channel)
            fetched = []
            original_fetch = channel.fetch_message

            async def fetch(message_id):
                fetched.append(message_id)
                return await original_fetch(message_id)

            channel.fetch_message = fetch

            def payload(user_id):
                return SimpleNamespace(
                    user_id=user_id,
                    guild_id=9,
                    channel_id=1,
                    message_id=100,
                    emoji="❌",
                    member=SimpleNamespace(id=user_id, bot=False),
                )

            writes = len([event for event in config.events if event[0] == "set"])
            await cog.on_raw_reaction_add(payload(23))
            self.assertFalse(replacement.deleted)
            self.assertIn(key, config.global_data["replacement_records"])
            self.assertEqual(len([event for event in config.events if event[0] == "set"]), writes)
            await cog.on_raw_reaction_add(payload(22))
            self.assertTrue(replacement.deleted)
            self.assertNotIn(key, config.global_data["replacement_records"])
            await cog.on_raw_reaction_add(payload(22))
            self.assertEqual(fetched, [100])
            self.assertNotIn(10, fetched)

        asyncio.run(scenario())

    def test_legacy_delete_rotate_collision_prefers_rotation(self):
        async def scenario():
            config = _TestConfig()
            channel = _Channel()
            source = self._source(channel)
            replacement = _Sent(channel, format_fixed(fixed_targets(source.content)[0]))
            channel.sent.append(replacement)
            key, record = _record()
            config.global_data["replacement_records"] = {key: record}
            config.guilds[9] = {
                **copy.deepcopy(DEFAULT_GUILD_SETTINGS),
                "delete_msg_emoji": ROTATE_EMOJI,
                "rotate_fix_reaction": True,
            }
            cog = _s3_cog(config, channel)
            calls = []

            async def rotate(payload, received_record, settings):
                calls.append((payload, received_record, settings))

            cog._rotate_record = rotate
            payload = SimpleNamespace(
                user_id=22,
                guild_id=9,
                channel_id=1,
                message_id=100,
                emoji=ROTATE_EMOJI,
                member=SimpleNamespace(id=22, bot=False),
            )
            await cog.on_raw_reaction_add(payload)
            self.assertEqual(len(calls), 1)
            self.assertFalse(replacement.deleted)
            self.assertEqual(config.global_data["replacement_records"][key], record)

            config.guilds[9]["rotate_fix_reaction"] = False
            await cog.on_raw_reaction_add(payload)
            self.assertEqual(len(calls), 1)
            self.assertTrue(replacement.deleted)
            self.assertNotIn(key, config.global_data["replacement_records"])

        asyncio.run(scenario())

    def test_sr06_rotation_source_change_rolls_back_and_rollback_failure_is_inert(self):
        async def scenario():
            config = _TestConfig()
            channel = _Channel()
            source = self._source(channel)
            target = fixed_targets(source.content)[0]
            replacement = _Sent(channel, format_fixed(target))
            channel.sent.append(replacement)
            key, record = _record()
            config.global_data["replacement_records"] = {key: record}
            config.guilds[9] = copy.deepcopy(DEFAULT_GUILD_SETTINGS)
            config.guilds[9]["rotate_fix_reaction"] = True
            cog = _s3_cog(config, channel)
            payload = SimpleNamespace(
                user_id=22,
                guild_id=9,
                channel_id=1,
                message_id=100,
                emoji=ROTATE_EMOJI,
                member=SimpleNamespace(id=22, bot=False),
            )

            source.edited_at = datetime.now(timezone.utc)
            await cog.on_raw_reaction_add(payload)
            self.assertEqual(replacement.edits, [])
            self.assertEqual(config.global_data["replacement_records"][key]["method_id"], 1)

            source.edited_at = None
            replacement.removed_reactions.clear()
            original_edit = replacement.edit
            calls = 0

            async def edit_then_change_source(**kwargs):
                nonlocal calls
                calls += 1
                result = await original_edit(**kwargs)
                if calls == 1:
                    source.edited_at = datetime.now(timezone.utc)
                return result

            replacement.edit = edit_then_change_source
            await cog.on_raw_reaction_add(payload)
            self.assertEqual(replacement.content, format_fixed(target))
            self.assertEqual(config.global_data["replacement_records"][key]["method_id"], 1)
            self.assertEqual(source.edits, [])

            source.edited_at = None

            async def fail_edit(**_kwargs):
                raise RuntimeError("provider and rollback failed")

            replacement.edit = fail_edit
            await cog.on_raw_reaction_add(payload)
            self.assertNotIn(key, config.global_data["replacement_records"])
            self.assertTrue(replacement.deleted)
            self.assertEqual(source.edits, [])

        asyncio.run(scenario())

    def test_sr06_rotation_previews_and_rolls_back_without_global_lock(self):
        async def scenario():
            config = _TestConfig()
            channel = _Channel()
            source = self._source(channel)
            target = fixed_targets(source.content)[0]
            replacement = _Sent(channel, format_fixed(target))
            channel.sent.append(replacement)
            key, record = _record()
            config.global_data["replacement_records"] = {key: record}
            config.guilds[9] = {
                **copy.deepcopy(DEFAULT_GUILD_SETTINGS),
                "rotate_fix_reaction": True,
            }
            cog = _s3_cog(config, channel)
            payload = SimpleNamespace(
                user_id=22,
                guild_id=9,
                channel_id=1,
                message_id=100,
                emoji=ROTATE_EMOJI,
                member=SimpleNamespace(id=22, bot=False),
            )
            entered = asyncio.Event()
            release = asyncio.Event()
            lock_states = []
            calls = 0

            async def confirm(_replacement, _url):
                nonlocal calls
                calls += 1
                lock_states.append(cog._s3_lock.locked())
                entered.set()
                await release.wait()
                return calls == 2

            cog._confirm_embed = confirm
            task = asyncio.create_task(cog.on_raw_reaction_add(payload))
            await entered.wait()
            acquired = asyncio.Event()

            async def probe_lock():
                async with cog._s3_lock:
                    acquired.set()

            probe = asyncio.create_task(probe_lock())
            await acquired.wait()
            release.set()
            await asyncio.gather(task, probe)
            self.assertEqual(lock_states, [False, False])
            self.assertEqual(config.global_data["replacement_records"][key], record)
            self.assertEqual(replacement.content, format_fixed(target))

        asyncio.run(scenario())

    def test_sr06_rotation_races_do_not_persist_stale_authority(self):
        async def scenario(mutation):
            config = _TestConfig()
            channel = _Channel()
            source = self._source(channel)
            target = fixed_targets(source.content)[0]
            replacement = _Sent(channel, format_fixed(target))
            channel.sent.append(replacement)
            key, record = _record()
            config.global_data["replacement_records"] = {key: record}
            config.guilds[9] = {
                **copy.deepcopy(DEFAULT_GUILD_SETTINGS),
                "rotate_fix_reaction": True,
            }
            cog = _s3_cog(config, channel)
            payload = SimpleNamespace(
                user_id=22,
                guild_id=9,
                channel_id=1,
                message_id=100,
                emoji=ROTATE_EMOJI,
                member=SimpleNamespace(id=22, bot=False),
            )
            calls = 0

            async def confirm(_replacement, _url):
                nonlocal calls
                calls += 1
                if calls == 1:
                    mutation(config, source, key, record)
                    return True
                return True

            cog._confirm_embed = confirm
            await cog.on_raw_reaction_add(payload)
            return config, source, replacement, key, record

        def record_change(config, _source, key, record):
            changed = copy.deepcopy(record)
            changed["method_id"] = 2
            config.global_data["replacement_records"][key] = changed

        async def run():
            return (
                await scenario(record_change),
                await scenario(
                    lambda config, source, _key, _record: setattr(
                        source, "content", "https://x.com/changed/status/2"
                    )
                ),
                await scenario(
                    lambda config, _source, _key, _record: config.guilds[9].update(
                        {"translate_target_lang": "ja"}
                    )
                ),
            )

        record_case, source_case, settings_case = asyncio.run(run())
        config, _source, replacement, key, _record_value = record_case
        self.assertEqual(config.global_data["replacement_records"][key]["method_id"], 2)
        self.assertFalse(replacement.deleted)
        self.assertIn("fixvx.com", replacement.content)
        _config, source, replacement, key, record = source_case
        self.assertEqual(source.content, "https://x.com/changed/status/2")
        self.assertEqual(replacement.content, format_fixed(fixed_targets("https://x.com/a/status/1")[0]))
        self.assertEqual(_config.global_data["replacement_records"][key], record)
        _config, _source, replacement, key, record = settings_case
        self.assertEqual(replacement.content, format_fixed(fixed_targets("https://x.com/a/status/1")[0]))
        self.assertEqual(_config.global_data["replacement_records"][key], record)

    def test_sr06_stale_cleanup_aborts_when_authority_changes_before_delete(self):
        async def scenario():
            config = _TestConfig()
            channel = _Channel()
            source = self._source(channel)
            target = fixed_targets(source.content)[0]
            replacement = _Sent(channel, format_fixed(target))
            channel.sent.append(replacement)
            key, record = _record()
            config.global_data["replacement_records"] = {key: record}
            config.guilds[9] = {
                **copy.deepcopy(DEFAULT_GUILD_SETTINGS),
                "rotate_fix_reaction": True,
            }
            cog = _s3_cog(config, channel)
            payload = SimpleNamespace(
                user_id=22,
                guild_id=9,
                channel_id=1,
                message_id=100,
                emoji=ROTATE_EMOJI,
                member=SimpleNamespace(id=22, bot=False),
            )
            calls = 0

            async def confirm(_replacement, _url):
                nonlocal calls
                calls += 1
                if calls == 1:
                    return False
                changed = copy.deepcopy(record)
                changed["method_id"] = 2
                config.global_data["replacement_records"][key] = changed
                alternate = fixed_targets(
                    source.content,
                    provider_choices={"1": 2},
                )[0]
                await replacement.edit(content=format_fixed(alternate), view=None)
                return True

            cog._confirm_embed = confirm
            await cog.on_raw_reaction_add(payload)
            self.assertEqual(config.global_data["replacement_records"][key]["method_id"], 2)
            self.assertFalse(replacement.deleted)
            self.assertIn("fixvx.com", replacement.content)

        asyncio.run(scenario())

    def test_sr06_overlapping_rotations_preserve_newer_authority(self):
        async def scenario():
            config = _TestConfig()
            channel = _Channel()
            source = self._source(channel)
            target = fixed_targets(source.content)[0]
            replacement = _Sent(channel, format_fixed(target))
            channel.sent.append(replacement)
            key, record_one = _record()
            config.global_data["replacement_records"] = {key: record_one}
            settings = {
                **copy.deepcopy(DEFAULT_GUILD_SETTINGS),
                "rotate_fix_reaction": True,
            }
            config.guilds[9] = copy.deepcopy(settings)
            cog = _s3_cog(config, channel)
            payload = SimpleNamespace(
                user_id=22,
                guild_id=9,
                channel_id=1,
                message_id=100,
                emoji=ROTATE_EMOJI,
                member=SimpleNamespace(id=22, bot=False),
            )
            b_rollback_entered = asyncio.Event()
            b_rollback_release = asyncio.Event()
            task_b: asyncio.Task[Any] | None = None
            original_edit = replacement.edit

            async def edit(**kwargs):
                if (
                    asyncio.current_task() is task_b
                    and "fixupx.com" in kwargs.get("content", "")
                ):
                    b_rollback_entered.set()
                    await b_rollback_release.wait()
                return await original_edit(**kwargs)

            replacement.edit = edit

            async def confirm(_replacement, url):
                if asyncio.current_task() is task_b and "fixvx.com" in url:
                    return False
                return True

            cog._confirm_embed = confirm
            task_b = asyncio.create_task(
                cog._rotate_record(payload, copy.deepcopy(record_one), settings)
            )
            await b_rollback_entered.wait()

            task_a = asyncio.create_task(
                cog._rotate_record(payload, copy.deepcopy(record_one), settings)
            )
            await asyncio.sleep(0)
            self.assertFalse(task_a.done())

            b_rollback_release.set()
            await task_b
            await task_a
            self.assertEqual(
                config.global_data["replacement_records"][key]["method_id"], 2
            )
            self.assertFalse(replacement.deleted)
            self.assertIn("fixvx.com", replacement.content)

        asyncio.run(scenario())

    def test_sr06_rotation_flushes_pending_authority(self):
        async def scenario():
            config = _TestConfig()
            channel = _Channel()
            source = self._source(channel)
            target = fixed_targets(source.content)[0]
            replacement = _Sent(channel, format_fixed(target))
            channel.sent.append(replacement)
            key, record = _record()
            config.guilds[9] = copy.deepcopy(DEFAULT_GUILD_SETTINGS)
            config.guilds[9]["rotate_fix_reaction"] = True
            cog = _s3_cog(config, channel)
            cog._pending_records[key] = record
            payload = SimpleNamespace(
                user_id=22,
                guild_id=9,
                channel_id=1,
                message_id=100,
                emoji=ROTATE_EMOJI,
                member=SimpleNamespace(id=22, bot=False),
            )

            await cog.on_raw_reaction_add(payload)
            self.assertEqual((await cog._replacement_records())[key]["method_id"], 2)
            self.assertEqual(cog._pending_records, {})
            await cog.on_raw_reaction_add(payload)
            self.assertEqual((await cog._replacement_records())[key]["method_id"], 29)

        asyncio.run(scenario())

    def test_sr07_notification_throttles_fail_closed_and_failed_dm_retains_reservation(self):
        async def scenario():
            messages = []
            recipient = SimpleNamespace()

            async def send(content, **_kwargs):
                messages.append(content)

            recipient.send = send
            config = _TestConfig()
            config.users[22] = copy.deepcopy(DEFAULT_USER_SETTINGS)
            config.users[22]["notify_on_react"] = True
            channel = _Channel()
            cog = _s3_cog(config, channel, recipient=recipient)
            _, record = _record()
            for reactor_id in range(1000, 1100):
                payload = SimpleNamespace(
                    user_id=reactor_id,
                    message_id=100,
                    member=SimpleNamespace(id=reactor_id, bot=False),
                )
                async with cog._s3_lock:
                    await cog._notify_author(payload, record)
            self.assertEqual(len(messages), 5)
            self.assertTrue(
                all(
                    message
                    == "Someone reacted to one of your fixed embeds: "
                    "https://discord.com/channels/9/1/100"
                    for message in messages
                )
            )

            now = time.monotonic()
            cog._notify_pairs = {(index, index): now + 60 for index in range(10000)}
            cog._notify_recipients.clear()
            async with cog._s3_lock:
                await cog._notify_author(
                    SimpleNamespace(
                        user_id=99999,
                        message_id=100,
                        member=SimpleNamespace(id=99999, bot=False),
                    ),
                    record,
                )
            self.assertEqual(len(cog._notify_pairs), 10000)
            self.assertEqual(len(messages), 5)

            cog._notify_pairs.clear()
            cog._notify_recipients.clear()

            async def fail_send(_content, **_kwargs):
                raise RuntimeError("DM disabled")

            recipient.send = fail_send
            async with cog._s3_lock:
                await cog._notify_author(
                    SimpleNamespace(
                        user_id=77,
                        message_id=100,
                        member=SimpleNamespace(id=77, bot=False),
                    ),
                    record,
                )
            self.assertIn((100, 77), cog._notify_pairs)
            self.assertEqual(len(cog._notify_recipients[22]), 1)

        asyncio.run(scenario())

    def test_sr07_data_deletion_manifest_settings_auth_and_original_mutation_boundary(self):
        async def deletion():
            config = _TestConfig()
            first_key, first = _record(100, author_id=22)
            second_key, second = _record(101, author_id=23)
            config.global_data["replacement_records"] = {
                first_key: first,
                second_key: second,
            }
            config.users[22] = {"notify_on_react": True}
            channel = _Channel()
            cog = _s3_cog(config, channel)
            cog._notify_pairs = {(100, 77): time.monotonic() + 60, (101, 22): time.monotonic() + 60}
            cog._notify_recipients = {22: [time.monotonic()], 23: [time.monotonic()]}
            await cog.red_delete_data_for_user(requester="owner", user_id=22)
            self.assertEqual(config.users[22], {})
            self.assertNotIn(first_key, config.global_data["replacement_records"])
            self.assertIn(second_key, config.global_data["replacement_records"])
            self.assertNotIn((100, 77), cog._notify_pairs)
            self.assertNotIn((101, 22), cog._notify_pairs)
            self.assertNotIn(22, cog._notify_recipients)
            self.assertIn(23, cog._notify_recipients)

        asyncio.run(deletion())
        manifest = json.loads((Path(__file__).parent / "info.json").read_text(encoding="utf-8"))
        statement = manifest["end_user_data_statement"]
        self.assertEqual(__red_end_user_data_statement__, statement)
        for text in (
            "replacement message IDs",
            "source edit timestamps",
            "temporarily in memory",
            "1,000 per guild",
            "10,000 globally",
            "full global cap rejects",
            "user data deletion removes",
            "never contain message content, full URLs, or provider responses",
        ):
            self.assertIn(text, statement)

        admin_commands = (
            "embedfixer_deletecontrols",
            "embedfixer_deleteemoji",
            "embedfixer_rotate",
            "embedfixer_reactiontimeout",
            "embedfixer_originallink",
        )
        for name in admin_commands:
            command = getattr(EmbedFixer, name)
            self.assertGreaterEqual(len(command.checks), 1, name)
            self.assertGreaterEqual(int(command.requires.privilege_level), 3, name)
        self.assertLess(int(EmbedFixer.embedfixer_notify.requires.privilege_level), 3)

        tree = ast.parse(inspect.getsource(EmbedFixer))
        source_edits = []
        source_deletes = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
                continue
            owner = node.func.value.id if isinstance(node.func.value, ast.Name) else None
            if owner in {"message", "source"} and node.func.attr == "edit":
                source_edits.append(node)
            if owner in {"message", "source"} and node.func.attr == "delete":
                source_deletes.append(node)
        self.assertEqual(source_deletes, [])
        self.assertEqual(len(source_edits), 1)
        self.assertEqual(
            [(keyword.arg, ast.literal_eval(keyword.value)) for keyword in source_edits[0].keywords],
            [("suppress", True)],
        )

    def test_delete_emoji_reserves_rotate_in_import_and_command(self):
        with self.assertRaises(ValueError):
            _validated_import(
                {
                    "guild_settings": {"delete_msg_emoji": ROTATE_EMOJI},
                    "fix_methods": [],
                }
            )

        async def command():
            config = _TestConfig()
            channel = _Channel()
            cog = _s3_cog(config, channel)
            replies = []

            async def send(message, **_kwargs):
                replies.append(message)

            ctx = SimpleNamespace(
                guild=channel.guild,
                interaction=None,
                send=send,
                tick=lambda: asyncio.sleep(0),
            )
            await EmbedFixer.embedfixer_deleteemoji.callback(cog, ctx, ROTATE_EMOJI)
            self.assertNotIn(9, config.guilds)
            self.assertTrue(replies)

        asyncio.run(command())

    def test_user_deletion_removes_guild_ignored_entries_without_other_changes(self):
        async def scenario():
            config = _TestConfig()
            config.guilds[9] = {
                **copy.deepcopy(DEFAULT_GUILD_SETTINGS),
                "ignored_users": [22, 23],
                "enabled": False,
            }
            config.guilds[8] = {
                **copy.deepcopy(DEFAULT_GUILD_SETTINGS),
                "ignored_users": [22],
                "fix_mode": "reply",
            }
            channel = _Channel()
            cog = _s3_cog(config, channel)
            await cog.red_delete_data_for_user(requester="owner", user_id=22)
            self.assertEqual(config.guilds[9]["ignored_users"], [23])
            self.assertFalse(config.guilds[9]["enabled"])
            self.assertEqual(config.guilds[8]["ignored_users"], [])
            self.assertEqual(config.guilds[8]["fix_mode"], "reply")

        asyncio.run(scenario())

    def test_context_fix_rejects_already_suppressed_source(self):
        async def scenario():
            config = _TestConfig()
            channel = _Channel()
            source = self._source(channel)
            source.flags.suppress_embeds = True
            cog = _s3_cog(config, channel)
            self.assertIsNone(
                await cog._context_settings(
                    guild=source.guild,
                    author=source.author,
                    channel=channel,
                    source=source,
                    manage_messages=True,
                )
            )

        asyncio.run(scenario())

    def test_delete_reaction_works_when_guild_disabled(self):
        async def scenario():
            config = _TestConfig()
            channel = _Channel()
            source = self._source(channel)
            replacement = _Sent(channel, format_fixed(fixed_targets(source.content)[0]))
            channel.sent.append(replacement)
            key, record = _record()
            config.global_data["replacement_records"] = {key: record}
            config.guilds[9] = copy.deepcopy(DEFAULT_GUILD_SETTINGS)
            config.guilds[9]["enabled"] = False
            cog = _s3_cog(config, channel)
            await cog.on_raw_reaction_add(
                SimpleNamespace(
                    user_id=22,
                    guild_id=9,
                    channel_id=1,
                    message_id=100,
                    emoji="❌",
                    member=SimpleNamespace(id=22, bot=False),
                )
            )
            self.assertTrue(replacement.deleted)
            self.assertEqual(config.global_data["replacement_records"], {})

        asyncio.run(scenario())


class SecurityS4Tests(unittest.TestCase):
    def _source(self, channel):
        source = TransactionTests()._message(channel)
        source.guild = channel.guild
        return source

    def test_media_canonicalizer_rejects_parser_and_allowlist_abuse(self):
        accepted = canonical_media_url(
            "https://PBS.TWIMG.COM/media/%41?format=jpg",
            DomainId.TWITTER,
        )
        self.assertEqual(
            accepted,
            "https://pbs.twimg.com/media/%41?format=jpg",
        )
        blob = "https://bsky.social/xrpc/com.atproto.sync.getBlob?did=did%3Aplc%3Aa&cid=abc"
        self.assertIsNone(canonical_media_url(blob, DomainId.BLUESKY))
        self.assertEqual(
            canonical_media_url(
                blob,
                DomainId.BLUESKY,
                locally_derived=True,
            ),
            blob,
        )
        rejected = (
            "http://pbs.twimg.com/media/a",
            "https://user@pbs.twimg.com/media/a",
            "https://pbs.twimg.com:443/media/a",
            "https://pbs.twimg.com/media/a#x",
            "https://evil.example/media/a",
            "https://pbs.twimg.com/not-media/a",
            "https://pbs.twimg.com\\@evil/media/a",
            "https://pbs.twimg.com/media/a b",
            "https://pbs.twimg.com/media/a\tb",
            "https://pbs.twimg.com/media/a\r\nx",
            "https://pbs.twimg.com/media/a||spoiler-break",
            "https://pbs.twimg.com/media/\u202ea",
            "https://pbs.twimg.com/media/貓",
            "https://pbs.twimg.com@evil.example/media/a",
            "https://[pbs.twimg.com/media/a",
        )
        for raw in rejected:
            self.assertIsNone(
                canonical_media_url(raw, DomainId.TWITTER),
                raw,
            )
        self.assertIsNone(
            canonical_media_url(
                "https://cdn.bsky.app/img/a",
                DomainId.TWITTER,
            )
        )

    def test_twitter_gif_media_allowlist_and_metadata(self):
        gif = "https://video.twimg.com/tweet_video/a.gif"
        self.assertEqual(canonical_media_url(gif, DomainId.TWITTER), gif)
        for rejected in (
            "https://video.twimg.com/tweet_video",
            "https://video.twimg.com/tweet_video_evil/a.gif",
            "https://video.twimg.com.evil/tweet_video/a.gif",
        ):
            self.assertIsNone(canonical_media_url(rejected, DomainId.TWITTER))

        async def scenario():
            api = "https://api.fxtwitter.com/a/status/1"
            cog = EmbedFixer.__new__(EmbedFixer)
            cog._session = _HTTPSession(
                {
                    api: _HTTPResponse(
                        {
                            "tweet": {
                                "media": {
                                    "all": [{"type": "gif", "url": gif}],
                                },
                                "possibly_sensitive": False,
                            }
                        }
                    )
                }
            )
            target = fixed_targets("https://x.com/a/status/1")[0]
            metadata = await cog._twitter_metadata(target)
            self.assertEqual([item.url for item in metadata.media], [gif])
            enriched = cog._enriched_target(
                target,
                metadata,
                _Channel(),
                copy.deepcopy(DEFAULT_GUILD_SETTINGS),
            )
            self.assertIn(gif, enriched.content)

        asyncio.run(scenario())

    def test_dns_resolver_filters_multicast_and_pins_global_ipv4_ipv6(self):
        async def scenario():
            resolver = MetadataResolver()
            loop = asyncio.get_running_loop()
            multicast = [
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("224.0.0.1", 443)),
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.168.1.1", 443)),
                (
                    socket.AF_INET6,
                    socket.SOCK_STREAM,
                    6,
                    "",
                    ("ff02::1", 443, 0, 0),
                ),
            ]
            with patch.object(
                loop,
                "getaddrinfo",
                new=AsyncMock(return_value=multicast),
            ):
                with self.assertRaises(OSError):
                    await resolver.resolve(
                        "api.fxtwitter.com",
                        443,
                        socket.AF_UNSPEC,
                    )
            mixed = [
                *multicast,
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 443)),
                (
                    socket.AF_INET6,
                    socket.SOCK_STREAM,
                    6,
                    "",
                    ("2606:4700:4700::1111", 443, 0, 0),
                ),
            ]
            with patch.object(
                loop,
                "getaddrinfo",
                new=AsyncMock(return_value=mixed),
            ):
                resolved = await resolver.resolve(
                    "www.pixiv.net",
                    443,
                    socket.AF_UNSPEC,
                )
            self.assertEqual(
                {item["host"] for item in resolved},
                {"8.8.8.8", "2606:4700:4700::1111"},
            )
            self.assertTrue(
                all(item["hostname"] == "www.pixiv.net" for item in resolved)
            )
            with self.assertRaises(OSError):
                await resolver.resolve("example.com", 443)

        asyncio.run(scenario())

    def test_provider_fixtures_and_sanitized_enriched_output(self):
        async def scenario():
            twitter_url = "https://api.fxtwitter.com/alice/status/1"
            pixiv_info = "https://www.pixiv.net/ajax/illust/2?lang=jp"
            pixiv_pages = "https://www.pixiv.net/ajax/illust/2/pages"
            bluesky_url = "https://bskx.app/profile/alice.test/post/rkey/json"
            session = _HTTPSession(
                {
                    twitter_url: _HTTPResponse(
                        {
                            "tweet": {
                                "text": "hello\r\n@everyone **bold** https://example.com/x",
                                "possibly_sensitive": False,
                                "media": {
                                    "all": [
                                        {
                                            "type": "photo",
                                            "url": "https://pbs.twimg.com/media/photo",
                                        },
                                        {
                                            "type": "video",
                                            "url": "https://video.twimg.com/ext_tw_video/video",
                                        },
                                        {
                                            "type": "photo",
                                            "url": "https://evil.example/media/no",
                                        },
                                    ]
                                },
                            }
                        }
                    ),
                    pixiv_info: _HTTPResponse(
                        {
                            "body": {
                                "description": "pixiv",
                                "tags": {"tags": [{"tag": "cat"}]},
                                "illustType": 0,
                            }
                        }
                    ),
                    pixiv_pages: _HTTPResponse(
                        {
                            "body": [
                                {
                                    "urls": {
                                        "original": "https://evil.example/original",
                                        "regular": "https://i.pximg.net/img-master/good",
                                    }
                                }
                            ]
                        }
                    ),
                    bluesky_url: _HTTPResponse(
                        {
                            "thread": {
                                "post": {
                                    "record": {"text": "sky"},
                                    "author": {"did": "did:plc:alice"},
                                    "labels": [],
                                    "embed": {
                                        "images": [
                                            {
                                                "fullsize": "https://evil.example/full",
                                                "thumb": "https://cdn.bsky.app/img/thumb",
                                            }
                                        ],
                                        "video": {"cid": "bafycid"},
                                        "external": {
                                            "uri": "https://evil.example/external"
                                        },
                                    },
                                }
                            }
                        }
                    ),
                }
            )
            cog = EmbedFixer.__new__(EmbedFixer)
            cog._session = session
            cog._ensure_s3_runtime()
            twitter = fixed_targets(
                "https://x.com/alice/status/1/photo/1"
            )[0]
            pixiv = fixed_targets("https://pixiv.net/artworks/2")[0]
            bluesky = fixed_targets(
                "https://bsky.app/profile/alice.test/post/rkey"
            )[0]
            twitter_data = await cog._twitter_metadata(twitter)
            pixiv_data = await cog._pixiv_metadata(pixiv)
            bluesky_data = await cog._bluesky_metadata(bluesky)
            self.assertEqual(
                [item.url for item in twitter_data.media],
                [
                    "https://pbs.twimg.com/media/photo",
                    "https://video.twimg.com/ext_tw_video/video",
                    "https://evil.example/media/no",
                ],
            )
            self.assertEqual(
                [item.url for item in pixiv_data.media],
                ["https://i.pximg.net/img-master/good"],
            )
            self.assertEqual(
                [item.url for item in bluesky_data.media],
                [
                    "https://cdn.bsky.app/img/thumb",
                    "https://bsky.social/xrpc/com.atproto.sync.getBlob?"
                    "did=did%3Aplc%3Aalice&cid=bafycid",
                ],
            )
            channel = _Channel()
            channel.id = 5
            settings = copy.deepcopy(DEFAULT_GUILD_SETTINGS)
            settings["show_post_content_channels"] = [5]
            enriched = cog._enriched_target(
                twitter,
                twitter_data,
                channel,
                settings,
            )
            self.assertTrue(enriched.nonrotatable)
            lines = enriched.content.splitlines()
            self.assertEqual(lines[0], format_fixed(twitter))
            self.assertNotIn("\r", lines[1])
            self.assertNotIn("\n", lines[1])
            self.assertNotIn("@everyone", lines[1])
            self.assertIn("<https://example.com/x>", lines[1])
            self.assertEqual(
                lines[-2:],
                [
                    "https://pbs.twimg.com/media/photo",
                    "https://video.twimg.com/ext_tw_video/video",
                ],
            )
            self.assertNotIn("evil.example", enriched.content)
            self.assertLessEqual(len(enriched.content), 2000)
            self.assertTrue(
                all(kwargs == {"allow_redirects": False} for _url, kwargs in session.calls)
            )

        asyncio.run(scenario())

    def test_malformed_provider_fields_stay_unknown_and_emit_no_unsafe_media(self):
        async def scenario():
            twitter_url = "https://api.fxtwitter.com/a/status/1"
            pixiv_info = "https://www.pixiv.net/ajax/illust/2?lang=jp"
            pixiv_pages = "https://www.pixiv.net/ajax/illust/2/pages"
            bluesky_url = "https://bskx.app/profile/a/post/b/json"
            cog = EmbedFixer.__new__(EmbedFixer)
            cog._session = _HTTPSession(
                {
                    twitter_url: _HTTPResponse(
                        {
                            "tweet": {
                                "text": 1,
                                "possibly_sensitive": "false",
                                "media": {
                                    "all": [
                                        {
                                            "type": "photo",
                                            "url": "https://evil.example/a",
                                        },
                                        {"type": "photo", "url": 1},
                                        {"type": "unknown", "url": "https://pbs.twimg.com/media/a"},
                                    ]
                                },
                            }
                        }
                    ),
                    pixiv_info: _HTTPResponse(
                        {
                            "body": {
                                "description": 1,
                                "tags": {"tags": [{"tag": "cat"}, {"bad": "tag"}]},
                            }
                        }
                    ),
                    pixiv_pages: _HTTPResponse(
                        {
                            "body": [
                                {
                                    "urls": {
                                        "original": "https://evil.example/a",
                                        "regular": "https://evil.example/b",
                                    }
                                }
                            ]
                        }
                    ),
                    bluesky_url: _HTTPResponse(
                        {
                            "thread": {
                                "post": {
                                    "record": {"text": 1},
                                    "labels": [{"val": "unsupported"}],
                                    "embed": {
                                        "images": [
                                            {
                                                "fullsize": "https://evil.example/a",
                                                "thumb": "https://evil.example/b",
                                            }
                                        ],
                                        "video": {"cid": "../cid"},
                                    },
                                    "author": {"did": "did:plc:a"},
                                }
                            }
                        }
                    ),
                }
            )
            cog._ensure_s3_runtime()
            targets = (
                fixed_targets("https://x.com/a/status/1")[0],
                fixed_targets("https://pixiv.net/artworks/2")[0],
                fixed_targets("https://bsky.app/profile/a/post/b")[0],
            )
            metadata = (
                await cog._twitter_metadata(targets[0]),
                await cog._pixiv_metadata(targets[1]),
                await cog._bluesky_metadata(targets[2]),
            )
            self.assertTrue(all(item.sensitive is None for item in metadata))
            channel = _Channel()
            for target, item in zip(targets, metadata, strict=True):
                self.assertIs(
                    cog._enriched_target(
                        target,
                        item,
                        channel,
                        copy.deepcopy(DEFAULT_GUILD_SETTINGS),
                    ),
                    target,
                )

        asyncio.run(scenario())

    def test_sensitivity_policy_and_malformed_fields_fail_closed(self):
        cog = EmbedFixer.__new__(EmbedFixer)
        target = fixed_targets("https://x.com/a/status/1")[0]
        spoiler_target = fixed_targets("||https://x.com/a/status/1||")[0]
        media = (MediaCandidate("https://pbs.twimg.com/media/a"),)
        safe_channel = _Channel()
        safe_channel.id = 1
        nsfw_channel = _Channel()
        nsfw_channel.id = 2
        nsfw_channel.nsfw = True
        settings = copy.deepcopy(DEFAULT_GUILD_SETTINGS)
        settings["disable_image_spoilers"] = [2]

        self.assertIs(
            cog._enriched_target(
                target,
                ProviderMetadata(None, media, True),
                safe_channel,
                settings,
            ),
            target,
        )
        true_nsfw = cog._enriched_target(
            target,
            ProviderMetadata(None, media, True),
            nsfw_channel,
            settings,
        )
        self.assertIn("||https://pbs.twimg.com/media/a||", true_nsfw.content)
        self.assertIs(
            cog._enriched_target(
                target,
                ProviderMetadata(None, media, None),
                safe_channel,
                settings,
            ),
            target,
        )
        unknown_spoiler = cog._enriched_target(
            spoiler_target,
            ProviderMetadata(None, media, None),
            safe_channel,
            settings,
        )
        self.assertIn("||https://pbs.twimg.com/media/a||", unknown_spoiler.content)
        false_exception = cog._enriched_target(
            target,
            ProviderMetadata(None, media, False),
            nsfw_channel,
            settings,
        )
        self.assertIn("\nhttps://pbs.twimg.com/media/a", false_exception.content)
        self.assertNotIn("||https://pbs.twimg.com/media/a||", false_exception.content)
        malformed = ProviderMetadata(
            "unsafe",
            (MediaCandidate("https://evil.example/media/a"),),
            None,
        )
        self.assertIs(cog._enriched_target(target, malformed, safe_channel, settings), target)

    def test_http_bounds_redirects_and_exact_endpoint_templates(self):
        async def scenario():
            url = "https://api.fxtwitter.com/a/status/1"
            cog = EmbedFixer.__new__(EmbedFixer)
            cog._ensure_s3_runtime()
            cases = (
                _HTTPResponse({}, status=302),
                _HTTPResponse(
                    body=b"x" * (256 * 1024 + 1),
                    chunk_size=17,
                ),
                _HTTPResponse({"x": [[[[[[[[[[[[None]]]]]]]]]]]]}),
                _HTTPResponse({"x": list(range(51))}),
                _HTTPResponse({"x": "x" * 4097}),
                _HTTPResponse(
                    {
                        f"k{index}": list(range(40))
                        for index in range(50)
                    }
                ),
            )
            for response in cases:
                cog._session = _HTTPSession({url: response})
                self.assertIsNone(await cog._metadata_json(url))
            self.assertTrue(_bounded_json({"x": ["ok"]}))
            self.assertTrue(_metadata_endpoint_allowed(url))
            for rejected in (
                "http://api.fxtwitter.com/a/status/1",
                "https://api.fxtwitter.com/a/status/1?x=1",
                "https://api.fxtwitter.com/a/status/1#x",
                "https://api.fxtwitter.com@evil.example/a/status/1",
                "https://www.pixiv.net/ajax/illust/1?lang=en",
                "https://bskx.app/profile/a/post/b/json?x=1",
            ):
                self.assertFalse(_metadata_endpoint_allowed(rejected), rejected)

        asyncio.run(scenario())

    def test_enrichment_waits_outside_lock_caps_sources_and_stale_state_aborts(self):
        async def cap_sources():
            cog = EmbedFixer.__new__(EmbedFixer)
            cog._ensure_s3_runtime()
            targets = [
                fixed_targets("https://x.com/a/status/1")[0],
                fixed_targets("https://pixiv.net/artworks/2")[0],
                fixed_targets("https://bsky.app/profile/a/post/b")[0],
            ]
            calls = []

            async def metadata(target):
                self.assertFalse(cog._s3_lock.locked())
                calls.append(target.domain.id)
                return None

            cog._metadata_for_target = metadata
            await cog._enrich_targets(
                targets,
                _Channel(),
                copy.deepcopy(DEFAULT_GUILD_SETTINGS),
            )
            self.assertEqual(
                calls,
                [DomainId.TWITTER, DomainId.PIXIV],
            )

        async def stale_source():
            config = _TestConfig()
            channel = _Channel()
            source = self._source(channel)
            cog = _s3_cog(config, channel)

            async def enrich(targets, _destination, _settings):
                self.assertFalse(cog._s3_lock.locked())
                source.content = "https://x.com/changed/status/2"
                return targets

            cog._enrich_targets = enrich
            token = cog._register_author(source.author.id)
            try:
                self.assertFalse(await cog._process_extraction(source, token=token))
            finally:
                cog._discard_author(source.author.id, token)
            self.assertEqual(channel.sent, [])
            self.assertEqual(source.edits, [])

        async def stale_settings_and_unload():
            config = _TestConfig()
            channel = _Channel()
            source = self._source(channel)
            cog = _s3_cog(config, channel)
            session = _HTTPSession()
            cog._session = session

            async def enrich(targets, _destination, _settings):
                self.assertFalse(cog._s3_lock.locked())
                config.guilds[9]["translate_target_lang"] = "en"
                return targets

            cog._enrich_targets = enrich
            token = cog._register_author(source.author.id)
            try:
                self.assertFalse(await cog._process_extraction(source, token=token))
            finally:
                cog._discard_author(source.author.id, token)
            self.assertEqual(channel.sent, [])
            self.assertEqual(source.edits, [])
            await cog.cog_unload()
            self.assertTrue(session.closed)

        async def cancelled_metadata():
            config = _TestConfig()
            channel = _Channel()
            source = self._source(channel)
            cog = _s3_cog(config, channel)

            async def enrich(_targets, _destination, _settings):
                self.assertFalse(cog._s3_lock.locked())
                raise asyncio.CancelledError

            cog._enrich_targets = enrich
            token = cog._register_author(source.author.id)
            try:
                with self.assertRaises(asyncio.CancelledError):
                    await cog._process_extraction(source, token=token)
            finally:
                cog._discard_author(source.author.id, token)
            self.assertEqual(channel.sent, [])
            self.assertEqual(source.edits, [])

        asyncio.run(cap_sources())
        asyncio.run(stale_source())
        asyncio.run(stale_settings_and_unload())
        asyncio.run(cancelled_metadata())

    def test_partial_context_menu_registration_rolls_back_session_and_owned_menu(self):
        async def scenario():
            class Tree:
                def __init__(self):
                    self.commands = {}
                    self.removed = []

                def add_command(self, command):
                    self.commands[command.name] = command
                    if command.name == "Extract Media":
                        raise RuntimeError("registration failed")

                def get_command(self, name, **_kwargs):
                    return self.commands.get(name)

                def remove_command(self, name, **_kwargs):
                    self.removed.append(name)
                    self.commands.pop(name, None)

            tree = Tree()
            session = _HTTPSession()
            cog = EmbedFixer.__new__(EmbedFixer)
            cog.bot = SimpleNamespace(tree=tree)
            cog._context_menu = discord.app_commands.ContextMenu(
                name="Fix Embed",
                callback=cog._context_fix,
            )
            cog._extract_context_menu = discord.app_commands.ContextMenu(
                name="Extract Media",
                callback=cog._context_extract,
            )
            cog._context_menu_registered = False
            cog._extract_context_menu_registered = False
            cog._session = session
            cog._ensure_s3_runtime()

            with self.assertRaisesRegex(RuntimeError, "registration failed"):
                await cog.cog_load()

            self.assertEqual(tree.commands, {})
            self.assertEqual(tree.removed, ["Fix Embed", "Extract Media"])
            self.assertFalse(cog._context_menu_registered)
            self.assertFalse(cog._extract_context_menu_registered)
            self.assertTrue(session.closed)
            self.assertIsNone(cog._session)

            collision = Tree()
            existing = object()
            collision.commands["Extract Media"] = existing
            collision_session = _HTTPSession()
            collision_cog = EmbedFixer.__new__(EmbedFixer)
            collision_cog.bot = SimpleNamespace(tree=collision)
            collision_cog._context_menu = discord.app_commands.ContextMenu(
                name="Fix Embed",
                callback=collision_cog._context_fix,
            )
            collision_cog._extract_context_menu = discord.app_commands.ContextMenu(
                name="Extract Media",
                callback=collision_cog._context_extract,
            )
            collision_cog._context_menu_registered = False
            collision_cog._extract_context_menu_registered = False
            collision_cog._session = collision_session
            collision_cog._ensure_s3_runtime()

            await collision_cog.cog_load()

            self.assertEqual(collision.commands, {"Extract Media": existing})
            self.assertEqual(collision.removed, [])
            self.assertFalse(collision_cog._context_menu_registered)
            self.assertFalse(collision_cog._extract_context_menu_registered)
            self.assertFalse(collision_session.closed)
            await collision_cog.cog_unload()
            self.assertTrue(collision_session.closed)

        asyncio.run(scenario())

    def test_explicit_extraction_rejects_unsupported_metadata_domain(self):
        async def scenario():
            config = _TestConfig()
            channel = _Channel()
            source = self._source(channel)
            source.content = "https://reddit.com/r/a/comments/b/c"
            config.guilds[9] = {
                **copy.deepcopy(DEFAULT_GUILD_SETTINGS),
                "extract_media_channels": [1],
            }
            cog = _s3_cog(config, channel)
            token = cog._register_author(source.author.id)
            try:
                self.assertFalse(
                    await cog._process_extraction(
                        source,
                        token=token,
                        metadata_only=True,
                    )
                )
            finally:
                cog._discard_author(source.author.id, token)
            self.assertEqual(channel.sent, [])
            self.assertEqual(source.edits, [])

            await cog.on_message(source)
            self.assertEqual(len(channel.sent), 1)
            self.assertIn("FixReddit", channel.sent[0].content)
            self.assertEqual(source.edits, [{"suppress": True}])

        asyncio.run(scenario())

    def test_enriched_funnel_records_actual_channel_and_author_delete(self):
        async def scenario():
            config = _TestConfig()
            source_channel = _Channel()
            destination = _Channel()
            destination.id = 2
            destination.guild = source_channel.guild
            source = self._source(source_channel)
            settings = copy.deepcopy(DEFAULT_GUILD_SETTINGS)
            settings["rotate_fix_reaction"] = True
            settings["show_post_content_channels"] = [2]
            settings["funnel_target_channel"] = 2
            config.guilds[9] = copy.deepcopy(settings)
            cog = _s3_cog(config, source_channel)
            cog.bot.get_channel = (
                lambda channel_id: source_channel
                if channel_id == 1
                else destination
                if channel_id == 2
                else None
            )
            target = fixed_targets(source.content)[0]
            enriched = cog._enriched_target(
                target,
                ProviderMetadata(
                    "hello",
                    (MediaCandidate("https://pbs.twimg.com/media/a"),),
                    False,
                ),
                destination,
                settings,
            )
            self.assertTrue(
                await cog._process(
                    source,
                    [enriched],
                    sender=destination.send,
                    guild=source.guild,
                    author=source.author,
                    channel=source_channel,
                    destination=destination,
                    guild_settings=settings,
                )
            )
            self.assertEqual(len(destination.sent), 1)
            self.assertEqual(destination.sent[0].content.splitlines()[0], format_fixed(target))
            self.assertEqual(source.edits, [{"suppress": True}])
            self.assertFalse(source.deleted)
            record = config.global_data["replacement_records"]["100"]
            self.assertEqual(record["channel_id"], 2)
            self.assertIsNone(record["source_message_id"])
            self.assertIsNone(record["source_edited_at"])
            self.assertNotIn(ROTATE_EMOJI, destination.sent[0].reactions)
            payload = SimpleNamespace(
                user_id=22,
                guild_id=9,
                channel_id=2,
                message_id=100,
                emoji="❌",
                member=SimpleNamespace(id=22, bot=False),
            )
            await cog.on_raw_reaction_add(payload)
            self.assertTrue(destination.sent[0].deleted)
            self.assertEqual(config.global_data["replacement_records"], {})
            self.assertFalse(source.deleted)

        asyncio.run(scenario())

    def test_translation_bot_visibility_and_rotation_rollback_use_captured_embed(self):
        self.assertEqual(_normalize_translation("EN", strict=True), "en")
        self.assertEqual(
            _validated_import(
                {
                    "guild_settings": {"translate_target_lang": "JA"},
                    "fix_methods": [],
                }
            )["translate_target_lang"],
            "ja",
        )
        for value in (
            "../en",
            "%65n",
            "en?x",
            "en#x",
            " en",
            "en ",
            "e/n",
            "éé",
            "e",
            "eng",
        ):
            with self.assertRaises(ValueError):
                _normalize_translation(value, strict=True)
        translated = EmbedFixer._targets(
            "https://x.com/a/status/1",
            {**DEFAULT_GUILD_SETTINGS, "translate_target_lang": "EN"},
        )[0]
        self.assertTrue(translated.fixed_url.endswith("/en"))
        vx = EmbedFixer._targets(
            "https://x.com/a/status/1",
            {
                **DEFAULT_GUILD_SETTINGS,
                "translate_target_lang": "en",
                "provider_choices": {"1": 2},
            },
        )[0]
        self.assertFalse(vx.fixed_url.endswith("/en"))

        async def translation_command():
            config = _TestConfig()
            channel = _Channel()
            cog = _s3_cog(config, channel)
            replies = []

            async def send(message, **_kwargs):
                replies.append(message)

            ctx = SimpleNamespace(
                guild=channel.guild,
                interaction=None,
                tick=lambda: asyncio.sleep(0),
                send=send,
            )
            await EmbedFixer.embedfixer_translang.callback(cog, ctx, "EN")
            self.assertEqual(config.guilds[9]["translate_target_lang"], "en")
            await EmbedFixer.embedfixer_translang.callback(cog, ctx, "../en")
            self.assertEqual(config.guilds[9]["translate_target_lang"], "en")
            self.assertTrue(replies)
            await EmbedFixer.embedfixer_translang.callback(cog, ctx, "disable")
            self.assertIsNone(config.guilds[9].get("translate_target_lang"))

        async def visibility():
            config = _TestConfig()
            channel = _Channel()
            source = self._source(channel)
            source.author = SimpleNamespace(bot=True, id=50, roles=[])
            cog = _s3_cog(config, channel)
            calls = []

            async def process(*_args, **_kwargs):
                calls.append(True)
                return True

            cog._process = process
            await cog.on_message(source)
            self.assertEqual(calls, [])
            config.guilds[9]["bot_visibility"] = True
            await cog.on_message(source)
            self.assertEqual(calls, [True])
            source.author.id = 99
            self.assertIsNone(
                await cog._context_settings(
                    guild=source.guild,
                    author=source.author,
                    channel=source.channel,
                    source=source,
                    manage_messages=True,
                )
            )
            await cog.on_message(source)
            source.author.id = 50
            source.webhook_id = 1
            await cog.on_message(source)
            self.assertEqual(calls, [True])

        async def rollback():
            config = _TestConfig()
            channel = _Channel()
            source = self._source(channel)
            settings = copy.deepcopy(DEFAULT_GUILD_SETTINGS)
            settings["rotate_fix_reaction"] = True
            settings["translate_target_lang"] = "ja"
            config.guilds[9] = copy.deepcopy(settings)
            english = EmbedFixer._targets(
                source.content,
                {**DEFAULT_GUILD_SETTINGS, "translate_target_lang": "en"},
            )[0]
            replacement = _Sent(channel, format_fixed(english))
            channel.sent.append(replacement)
            key, record = _record()
            config.global_data["replacement_records"] = {key: record}
            cog = _s3_cog(config, channel)
            original_edit = replacement.edit
            calls = 0

            async def edit_and_change_source(**kwargs):
                nonlocal calls
                calls += 1
                result = await original_edit(**kwargs)
                if calls == 1:
                    source.edited_at = datetime.now(timezone.utc)
                return result

            replacement.edit = edit_and_change_source
            payload = SimpleNamespace(
                user_id=22,
                guild_id=9,
                channel_id=1,
                message_id=100,
                emoji=ROTATE_EMOJI,
                member=SimpleNamespace(id=22, bot=False),
            )
            await cog.on_raw_reaction_add(payload)
            self.assertFalse(replacement.deleted)
            self.assertEqual(replacement.content, format_fixed(english))
            self.assertEqual(
                config.global_data["replacement_records"][key]["method_id"],
                1,
            )

        asyncio.run(translation_command())
        asyncio.run(visibility())
        asyncio.run(rollback())

    def test_auto_extraction_and_owned_second_context_menu_lifecycle(self):
        async def automatic():
            config = _TestConfig()
            channel = _Channel()
            source = self._source(channel)
            config.guilds[9] = copy.deepcopy(DEFAULT_GUILD_SETTINGS)
            config.guilds[9]["extract_media_channels"] = [1]
            cog = _s3_cog(config, channel)
            calls = []

            async def extraction(message, *, token, target_content=None):
                self.assertFalse(cog._s3_lock.locked())
                self.assertIs(message, source)
                self.assertIsNone(target_content)
                self.assertIsNotNone(token)
                calls.append(True)
                return True

            cog._process_extraction = extraction
            await cog.on_message(source)
            self.assertEqual(calls, [True])
            self.assertEqual(channel.sent, [])

        async def lifecycle():
            class Tree:
                def __init__(self):
                    self.commands = {}
                    self.removed = []

                def add_command(self, command):
                    self.commands[command.name] = command

                def get_command(self, name, **_kwargs):
                    return self.commands.get(name)

                def remove_command(self, name, **_kwargs):
                    self.removed.append(name)
                    self.commands.pop(name, None)

            tree = Tree()
            session = _HTTPSession()
            cog = EmbedFixer.__new__(EmbedFixer)
            cog.bot = SimpleNamespace(tree=tree)
            cog._context_menu = discord.app_commands.ContextMenu(
                name="Fix Embed",
                callback=cog._context_fix,
            )
            cog._extract_context_menu = discord.app_commands.ContextMenu(
                name="Extract Media",
                callback=cog._context_extract,
            )
            cog._context_menu_registered = False
            cog._extract_context_menu_registered = False
            cog._session = session
            cog._ensure_s3_runtime()
            await cog.cog_load()
            self.assertEqual(set(tree.commands), {"Fix Embed", "Extract Media"})
            await cog.cog_unload()
            self.assertEqual(set(tree.removed), {"Fix Embed", "Extract Media"})
            self.assertTrue(session.closed)

        asyncio.run(automatic())
        asyncio.run(lifecycle())

    def test_funnel_validation_import_atomicity_and_nsfw_downgrade(self):
        guild = SimpleNamespace(id=9, me=object())
        source = _Channel()
        source.guild = guild
        destination = _text_channel(2, guild)
        guild.get_channel = lambda channel_id: destination if channel_id == 2 else None
        cog = EmbedFixer.__new__(EmbedFixer)
        cog.bot = SimpleNamespace(user=object())
        settings = {
            **DEFAULT_GUILD_SETTINGS,
            "funnel_target_channel": 2,
        }
        self.assertEqual(
            cog._destination_for(
                guild=guild,
                source_channel=source,
                guild_settings=settings,
            ),
            (destination, True),
        )
        self.assertIsNone(
            cog._destination_for(
                guild=None,
                source_channel=source,
                guild_settings=settings,
            )
        )
        missing = {**settings, "funnel_target_channel": 3}
        self.assertIsNone(
            cog._destination_for(
                guild=guild,
                source_channel=source,
                guild_settings=missing,
            )
        )
        destination.guild = SimpleNamespace(id=8)
        self.assertIsNone(
            cog._destination_for(
                guild=guild,
                source_channel=source,
                guild_settings=settings,
            )
        )
        destination.guild = guild
        destination.permissions_for.return_value.send_messages = False
        self.assertIsNone(
            cog._destination_for(
                guild=guild,
                source_channel=source,
                guild_settings=settings,
            )
        )
        destination.permissions_for.return_value.send_messages = True
        source.nsfw = True
        destination.is_nsfw.return_value = False
        self.assertIsNone(
            cog._destination_for(
                guild=guild,
                source_channel=source,
                guild_settings=settings,
            )
        )

        async def routing_and_missing_abort():
            config = _TestConfig()
            message = self._source(source)
            config.guilds[9] = copy.deepcopy(settings)
            config.guilds[9]["fix_mode"] = "reply"
            routing_cog = _s3_cog(config, source)
            calls = []

            async def process(*_args, **kwargs):
                calls.append(kwargs)
                return True

            routing_cog._process = process
            source.nsfw = False
            destination.nsfw = False
            destination.is_nsfw.return_value = False
            guild.get_channel = (
                lambda channel_id: destination if channel_id == 2 else None
            )
            await routing_cog.on_message(message)
            self.assertEqual(len(calls), 1)
            self.assertIs(calls[0]["destination"], destination)
            self.assertEqual(calls[0]["sender"], destination.send)
            self.assertEqual(calls[0]["mode"], "reply")
            calls.clear()
            config.guilds[9]["funnel_target_channel"] = 3
            await routing_cog.on_message(message)
            self.assertEqual(calls, [])
            self.assertEqual(source.sent, [])
            self.assertEqual(message.edits, [])
            self.assertEqual(config.global_data["replacement_records"], {})

        async def imports():
            payload = {
                "guild_settings": {
                    "funnel_target_channel": 2,
                    "translate_target_lang": "EN",
                },
                "fix_methods": [],
            }

            class Attachment:
                size = 128

                async def read(self):
                    return json.dumps(payload).encode()

            class Scope:
                def __init__(self):
                    self.writes = []

                async def set(self, value):
                    self.writes.append(value)

            scope = Scope()
            import_cog = EmbedFixer.__new__(EmbedFixer)
            import_cog.config = SimpleNamespace(guild=lambda _guild: scope)
            import_cog._ensure_s3_runtime()
            messages = []

            async def send(message, **_kwargs):
                messages.append(message)

            ctx = SimpleNamespace(
                guild=guild,
                interaction=None,
                tick=lambda: asyncio.sleep(0),
                send=send,
            )
            source.nsfw = False
            destination.is_nsfw.return_value = False
            guild.get_channel = lambda channel_id: None
            await EmbedFixer.embedfixer_import.callback(
                import_cog,
                ctx,
                Attachment(),
            )
            self.assertEqual(scope.writes, [])
            guild.get_channel = (
                lambda channel_id: destination if channel_id == 2 else None
            )
            await EmbedFixer.embedfixer_import.callback(
                import_cog,
                ctx,
                Attachment(),
            )
            self.assertEqual(len(scope.writes), 1)
            self.assertEqual(scope.writes[0]["translate_target_lang"], "en")
            self.assertEqual(scope.writes[0]["funnel_target_channel"], 2)

        asyncio.run(routing_and_missing_abort())
        asyncio.run(imports())

    def test_s4_surfaces_privacy_and_no_media_download_pipeline(self):
        for name in (
            "embedfixer_mediachannel",
            "embedfixer_showcontent",
            "embedfixer_spoilerexception",
            "embedfixer_funnel",
            "embedfixer_translang",
            "embedfixer_botvisibility",
        ):
            command = getattr(EmbedFixer, name)
            self.assertGreaterEqual(len(command.checks), 1, name)
            self.assertGreaterEqual(int(command.requires.privilege_level), 3, name)
        self.assertFalse(DEFAULT_GUILD_SETTINGS["bot_visibility"])
        self.assertNotIn("content", DEFAULT_GUILD_SETTINGS)
        self.assertNotIn("nonrotatable", DEFAULT_GLOBAL_SETTINGS)
        exported = _export_payload(copy.deepcopy(DEFAULT_GUILD_SETTINGS))
        self.assertNotIn("nonrotatable", exported["guild_settings"])
        self.assertNotIn("content", exported["guild_settings"])
        manifest = json.loads(
            (Path(__file__).parent / "info.json").read_text(encoding="utf-8")
        )
        self.assertEqual(manifest["requirements"], [])
        statement = manifest["end_user_data_statement"]
        for phrase in (
            "bounded provider metadata",
            "processed transiently",
            "never stored or cached",
            "full source and media URLs are never logged",
        ):
            self.assertIn(phrase, statement)
        source = (Path(__file__).parent / "embedfixer.py").read_text(
            encoding="utf-8"
        )
        for forbidden in ("import tempfile", "import zipfile", "ffmpeg", "discord.Embed("):
            self.assertNotIn(forbidden, source)
        provider_source = "\n".join(
            inspect.getsource(method)
            for method in (
                EmbedFixer._twitter_metadata,
                EmbedFixer._pixiv_metadata,
                EmbedFixer._bluesky_metadata,
                EmbedFixer._enrich_targets,
            )
        )
        self.assertNotIn("discord.File", provider_source)
        self.assertNotIn("session.get", provider_source)
        self.assertNotIn("create_task", provider_source)
        self.assertNotIn("asyncio.gather", provider_source)
        self.assertNotIn("source.delete", source)
        self.assertIn("trust_env=False", source)
        self.assertIn("aiohttp.DummyCookieJar()", source)
        tree = ast.parse(source)
        for call in (
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "log"
        ):
            self.assertTrue(call.args and isinstance(call.args[0], ast.Constant))
            rendered_args = " ".join(ast.unparse(arg) for arg in call.args[1:])
            for private_value in ("target", "metadata", "content", ".url"):
                self.assertNotIn(private_value, rendered_args)


class SettingsTests(unittest.TestCase):
    def test_upstream_import_roundtrip_and_legacy_normalization(self):
        payload = {
            "guild_settings": {
                "disabled_fixes": ["x.com", "future.example"],
                "disabled_domains": [],
                "enabled_domains": [],
                "disable_fix_channels": [],
                "enable_fix_channels": [],
                "extract_media_channels": [],
                "disable_image_spoilers": [],
                "show_post_content_channels": [],
                "whitelist_role_ids": [],
                "disable_webhook_reply": False,
                "disable_delete_reaction": False,
                "lang": None,
                "use_vxreddit": True,
                "delete_msg_emoji": "❌",
                "bot_visibility": False,
                "funnel_target_channel": None,
                "translate_target_lang": None,
                "show_original_link_btn": True,
                "delete_original_message_in_threads": False,
                "fix_mode": "reply",
                "remove_delete_reaction_after": None,
                "rotate_fix_reaction": False,
            },
            "fix_methods": [],
        }
        settings = _validated_import(payload)
        twitter_id = int(DomainId.TWITTER)
        reddit_id = int(DomainId.REDDIT)
        self.assertIn(twitter_id, settings["disabled_domains"])
        self.assertEqual(settings["disabled_fixes"], ["future.example"])
        self.assertEqual(settings["provider_choices"][str(reddit_id)], 7)
        self.assertFalse(settings["use_vxreddit"])

        normalized, changed = _normalize_legacy_settings(settings)
        self.assertFalse(changed)
        self.assertEqual(normalized, settings)
        exported = _export_payload(settings)
        self.assertEqual(set(exported), {"guild_settings", "fix_methods"})
        self.assertNotIn("schema_version", exported["guild_settings"])
        self.assertNotIn("enabled", exported["guild_settings"])
        self.assertEqual(_validated_import(exported), settings)

        explicit_enable = _validated_import(
            {
                "guild_settings": {
                    "disabled_fixes": ["x.com"],
                    "enabled_domains": [twitter_id],
                },
                "fix_methods": [],
            }
        )
        self.assertEqual(explicit_enable["enabled_domains"], [twitter_id])
        self.assertNotIn(twitter_id, explicit_enable["disabled_domains"])
        self.assertEqual(explicit_enable["disabled_fixes"], [])
        self.assertEqual(_normalize_legacy_settings(explicit_enable), (explicit_enable, False))

    def test_import_rejects_unknown_fields_provider_mismatch_and_conflicts(self):
        with self.assertRaises(ValueError):
            _validated_import({"guild_settings": {"unknown": True}, "fix_methods": []})
        with self.assertRaises(ValueError):
            _validated_import(
                {
                    "guild_settings": {},
                    "fix_methods": [{"domain_id": int(DomainId.TWITTER), "fix_id": 3}],
                }
            )
        with self.assertRaises(ValueError):
            _validated_import(
                {
                    "guild_settings": {
                        "disabled_domains": [int(DomainId.TWITTER)],
                        "enabled_domains": [int(DomainId.TWITTER)],
                    },
                    "fix_methods": [],
                }
            )
        for value in (123.9, float("nan"), float("inf")):
            with self.assertRaises(ValueError):
                _validated_import(
                    {
                        "guild_settings": {"disable_fix_channels": [value]},
                        "fix_methods": [],
                    }
                )
            with self.assertRaises(ValueError):
                _validated_import(
                    {
                        "guild_settings": {"remove_delete_reaction_after": value},
                        "fix_methods": [],
                    }
                )
        for value in (-1, 86401, True):
            with self.assertRaises(ValueError):
                _validated_import(
                    {
                        "guild_settings": {"remove_delete_reaction_after": value},
                        "fix_methods": [],
                    }
                )
        for value in (None, 0, 86400):
            imported = _validated_import(
                {
                    "guild_settings": {"remove_delete_reaction_after": value},
                    "fix_methods": [],
                }
            )
            self.assertEqual(imported["remove_delete_reaction_after"], value)

    def test_every_admin_child_has_its_own_guild_and_admin_requirements(self):
        for name in (
            "embedfixer_enable",
            "embedfixer_mode",
            "embedfixer_domain",
            "embedfixer_provider",
            "embedfixer_channel",
            "embedfixer_role",
            "embedfixer_ignoreuser",
            "embedfixer_reset",
            "embedfixer_export",
            "embedfixer_import",
        ):
            command = getattr(EmbedFixer, name)
            self.assertGreaterEqual(len(command.checks), 1, name)
            self.assertGreaterEqual(int(command.requires.privilege_level), 3, name)

    def test_user_mode_overrides_guild_mode(self):
        self.assertEqual(
            EmbedFixer._mode({"fix_mode": "resend"}, {"fix_mode": "reply"}),
            "reply",
        )
        self.assertEqual(
            EmbedFixer._mode({"fix_mode": "delete_and_resend"}, {"fix_mode": None}),
            "delete_and_resend",
        )

    def test_import_performs_one_atomic_write_after_validation(self):
        payload = {"guild_settings": {}, "fix_methods": []}

        class Attachment:
            size = 64

            async def read(self):
                return __import__("json").dumps(payload).encode()

        class Scope:
            def __init__(self):
                self.writes = []

            async def set(self, value):
                self.writes.append(value)

        scope = Scope()
        cog = EmbedFixer.__new__(EmbedFixer)
        cog.config = SimpleNamespace(guild=lambda _guild: scope)
        cog._ensure_s3_runtime()
        ctx = SimpleNamespace(
            guild=object(),
            interaction=None,
            tick=lambda: asyncio.sleep(0),
        )
        asyncio.run(
            EmbedFixer.embedfixer_import.callback(cog, ctx, Attachment())
        )
        self.assertEqual(len(scope.writes), 1)
        self.assertEqual(scope.writes[0]["provider_choices"], {})

    def test_context_menu_lifecycle_removes_only_owned_command(self):
        class Tree:
            def __init__(self):
                self.command = None
                self.removed = []

            def add_command(self, command):
                self.command = command

            def get_command(self, _name, **_kwargs):
                return self.command

            def remove_command(self, name, **kwargs):
                self.removed.append((name, kwargs))

        tree = Tree()
        cog = EmbedFixer.__new__(EmbedFixer)
        cog.bot = SimpleNamespace(tree=tree)
        cog._context_menu = discord.app_commands.ContextMenu(
            name="Fix Embed", callback=cog._context_fix
        )
        cog._context_menu_registered = False
        asyncio.run(cog.cog_load())
        self.assertTrue(cog._context_menu_registered)
        asyncio.run(cog.cog_unload())
        self.assertEqual(tree.removed[0][0], "Fix Embed")

        other = object()
        tree.command = other
        cog._context_menu_registered = True
        asyncio.run(cog.cog_unload())
        self.assertEqual(len(tree.removed), 1)


if __name__ == "__main__":
    unittest.main()
