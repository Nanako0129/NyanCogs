"""Red cog for safe provider-link fixes and bounded metadata extraction."""

from __future__ import annotations

import asyncio
import copy
import io
import ipaddress
import json
import logging
import re
import socket
import time
import unicodedata
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from typing import Any, Final
from urllib.parse import parse_qsl, quote, unquote, urlencode, urljoin, urlsplit, urlunsplit

import aiohttp
import discord
from discord import app_commands
from redbot.core import Config, checks, commands

from .fixes import (
    DOMAINS,
    Domain,
    DomainId,
    FixMethod,
    SOURCE_HOSTS,
    Website,
    apply_fix,
    author_profile,
    clean_query,
    source_domain_for,
)


log = logging.getLogger("red.nyancogs.embedfixer")

MAX_MESSAGE_CHARS: Final[int] = 4000
MAX_CANDIDATES: Final[int] = 10
MAX_URL_CHARS: Final[int] = 2048
CONFIRM_TIMEOUT: Final[float] = 10.0
MAX_IMPORT_BYTES: Final[int] = 1024 * 1024
MAX_SETTING_ITEMS: Final[int] = 1000
MAX_SETTING_STRING: Final[int] = 256
MAX_SNOWFLAKE: Final[int] = (1 << 63) - 1
MAX_GUILD_RECORDS: Final[int] = 1000
MAX_GLOBAL_RECORDS: Final[int] = 10000
MAX_NOTIFY_PAIRS: Final[int] = 10000
MAX_NOTIFY_RECIPIENTS: Final[int] = 10000
NOTIFY_PAIR_SECONDS: Final[float] = 60.0
NOTIFY_WINDOW_SECONDS: Final[float] = 600.0
MAX_NOTIFY_PER_WINDOW: Final[int] = 5
ROTATE_EMOJI: Final[str] = "🔄"
DISCORD_MESSAGE_CHARS: Final[int] = 2000
MAX_METADATA_BYTES: Final[int] = 256 * 1024
MAX_JSON_DEPTH: Final[int] = 12
MAX_JSON_NODES: Final[int] = 2000
MAX_JSON_CONTAINER: Final[int] = 50
MAX_JSON_STRING: Final[int] = 4096
MAX_MEDIA_ITEMS: Final[int] = 8
MAX_METADATA_SOURCES: Final[int] = 2
METADATA_REQUEST_TIMEOUT: Final[float] = 5.0
METADATA_TOTAL_TIMEOUT: Final[float] = 8.0
METADATA_HOSTS: Final[frozenset[str]] = frozenset(
    {"api.fxtwitter.com", "www.pixiv.net", "bskx.app"}
)
RESOLVER_HOSTS: Final[frozenset[str]] = (
    METADATA_HOSTS | SOURCE_HOSTS[DomainId.THREADS]
)
METADATA_DOMAINS: Final[frozenset[DomainId]] = frozenset(
    {DomainId.TWITTER, DomainId.PIXIV, DomainId.BLUESKY}
)

_SPOILER_URL_RE = re.compile(r"\|\|(https?://[^\s|]+)\|\|")
_REGULAR_URL_RE = re.compile(r"(?<!\$)(?<!<)(https?://[^\s>]+)(?!>)")
_ESCAPE_LABEL_RE = re.compile(r"([\\\[\]()<>`])")
_TEXT_URL_RE = re.compile(r"https?://[^\s<>]+")
_TRANSLATION_RE = re.compile(r"[A-Za-z]{2}", re.ASCII)
_TWITTER_SOURCE_RE = re.compile(
    r"/([A-Za-z0-9_]{1,15})/status/([0-9]{1,20})(?:/(?:photo(?:/[1-9])?|video/[0-9]+))?/?",
    re.ASCII,
)
_PIXIV_SOURCE_RE = re.compile(
    r"/(?:[A-Za-z]+/)?artworks/([0-9]{1,20})/?",
    re.ASCII,
)
_BLUESKY_SOURCE_RE = re.compile(
    r"/profile/([A-Za-z0-9._:-]{1,253})/post/([A-Za-z0-9._~-]{1,128})/?",
    re.ASCII,
)
_BLUESKY_BLOB_RE = re.compile(r"[A-Za-z0-9._:-]{1,256}", re.ASCII)
_SENTENCE_TRAILING = ".,!?:;"

# Human-facing labels intentionally stay separate from the normative upstream
# Domain/FixMethod names.  The latter are stable config/inventory identifiers.
_SOURCE_LABELS: Final[dict[DomainId, str]] = {DomainId.TWITTER: "Tweet"}
_PROVIDER_LABELS: Final[dict[tuple[DomainId, int], str]] = {
    (DomainId.TWITTER, 1): "FxTwitter",
    (DomainId.TWITTER, 2): "vxTwitter",
    (DomainId.BLUESKY, 14): "FxBluesky",
}


# Red Config defaults mirror the upstream GuildSettings/UserSettings inventory.
# Lists/dicts are copied by Config during registration, so each scope remains
# isolated and additive registration preserves unknown existing fields.
DEFAULT_GLOBAL_SETTINGS: Final[dict[str, Any]] = {
    "schema_version": 1,
    "replacement_records": {},
}
DEFAULT_GUILD_SETTINGS: Final[dict[str, Any]] = {
    "schema_version": 1,
    "enabled": True,
    "disable_webhook_reply": False,
    "disabled_fixes": [],
    "disabled_domains": [],
    "enabled_domains": [],
    "disable_fix_channels": [],
    "enable_fix_channels": [],
    "extract_media_channels": [],
    "disable_image_spoilers": [],
    "show_post_content_channels": [],
    "disable_delete_reaction": False,
    "lang": None,
    "use_vxreddit": False,
    "delete_msg_emoji": "❌",
    "bot_visibility": False,
    "funnel_target_channel": None,
    "whitelist_role_ids": [],
    "translate_target_lang": None,
    "show_original_link_btn": True,
    "delete_original_message_in_threads": False,
    "fix_mode": "delete_and_resend",
    "remove_delete_reaction_after": None,
    "rotate_fix_reaction": False,
    # S1's additive provider selection; later interaction surfaces may use it.
    "provider_choices": {},
    "ignored_users": [],
}
DEFAULT_USER_SETTINGS: Final[dict[str, Any]] = {
    "schema_version": 1,
    "notify_on_react": False,
    "lang": None,
    "fix_mode": None,
    "ignored": False,
}

PORTABLE_GUILD_SETTINGS: Final[tuple[str, ...]] = (
    "disable_webhook_reply",
    "disabled_fixes",
    "disabled_domains",
    "enabled_domains",
    "disable_fix_channels",
    "enable_fix_channels",
    "extract_media_channels",
    "disable_image_spoilers",
    "show_post_content_channels",
    "disable_delete_reaction",
    "lang",
    "use_vxreddit",
    "delete_msg_emoji",
    "bot_visibility",
    "funnel_target_channel",
    "whitelist_role_ids",
    "translate_target_lang",
    "show_original_link_btn",
    "delete_original_message_in_threads",
    "fix_mode",
    "remove_delete_reaction_after",
    "rotate_fix_reaction",
)
FIX_MODES: Final[frozenset[str]] = frozenset({"delete_and_resend", "reply", "resend"})


@dataclass(frozen=True)
class Candidate:
    url: str
    spoiler: bool
    domain: Domain
    website: Website


@dataclass(frozen=True)
class FixedTarget:
    original_url: str
    fixed_url: str
    domain: Domain
    method: FixMethod
    author: tuple[str, str] | None = None
    spoiler: bool = False
    content: str | None = None
    nonrotatable: bool = False


@dataclass(frozen=True)
class MediaCandidate:
    url: str
    locally_derived: bool = False


@dataclass(frozen=True)
class ProviderMetadata:
    text: str | None
    media: tuple[MediaCandidate, ...]
    sensitive: bool | None


@dataclass(frozen=True)
class SourceSnapshot:
    source: tuple[int, int, int, int, str, str | None]
    guild_settings: dict[str, Any]
    user_settings: dict[str, Any]
    destination: tuple[int, int, bool]
    targets: tuple[FixedTarget, ...]


class MetadataResolver(aiohttp.abc.AbstractResolver):
    """Resolve only fixed outbound hosts and discard every non-global address."""

    async def resolve(
        self,
        host: str,
        port: int = 0,
        family: int = socket.AF_INET,
    ) -> list[dict[str, Any]]:
        host = host.casefold()
        if host not in RESOLVER_HOSTS:
            raise OSError("outbound host is not allowed")
        infos = await asyncio.get_running_loop().getaddrinfo(
            host,
            port,
            family=family,
            type=socket.SOCK_STREAM,
        )
        resolved: list[dict[str, Any]] = []
        seen: set[tuple[int, str]] = set()
        for address_family, _socktype, protocol, _canonname, sockaddr in infos:
            raw_address = sockaddr[0]
            try:
                address = ipaddress.ip_address(raw_address)
            except ValueError:
                continue
            key = (address_family, str(address))
            if (
                key in seen
                or not address.is_global
                or address.is_multicast
            ):
                continue
            seen.add(key)
            resolved.append(
                {
                    "hostname": host,
                    "host": str(address),
                    "port": port,
                    "family": address_family,
                    "proto": protocol,
                    "flags": socket.AI_NUMERICHOST,
                }
            )
        if not resolved:
            raise OSError("metadata host has no safe address")
        return resolved

    async def close(self) -> None:
        return None


_RECORD_KEYS: Final[frozenset[str]] = frozenset(
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
    }
)


def _snowflake(value: Any, *, optional: bool = False) -> int | None:
    if value is None and optional:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= MAX_SNOWFLAKE:
        return None
    return value


def _timestamp(value: Any) -> str | None:
    if value is None:
        return None
    if not isinstance(value, datetime) or value.tzinfo is None:
        return None
    return value.astimezone(timezone.utc).isoformat()


def _valid_iso(value: Any, *, optional: bool = False) -> bool:
    if value is None:
        return optional
    if not isinstance(value, str) or len(value) > 64:
        return False
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return False
    return parsed.tzinfo is not None and parsed.astimezone(timezone.utc).isoformat() == value


def _valid_record(message_id: Any, value: Any) -> bool:
    if not isinstance(message_id, str) or not message_id.isascii() or not message_id.isdigit():
        return False
    try:
        replacement_id = int(message_id)
    except ValueError:
        return False
    if _snowflake(replacement_id) is None or not isinstance(value, dict) or set(value) != _RECORD_KEYS:
        return False
    if any(
        _snowflake(value[name]) is None
        for name in ("guild_id", "channel_id", "author_id")
    ):
        return False
    if value["source_message_id"] is not None and _snowflake(value["source_message_id"]) is None:
        return False
    if not _valid_iso(value["source_edited_at"], optional=True) or not _valid_iso(value["created_at"]):
        return False
    if (
        isinstance(value["target_index"], bool)
        or not isinstance(value["target_index"], int)
        or not 0 <= value["target_index"] < MAX_CANDIDATES
    ):
        return False
    if (
        isinstance(value["domain_id"], bool)
        or not isinstance(value["domain_id"], int)
        or value["source_message_id"] is None and value["source_edited_at"] is not None
    ):
        return False
    domain = next((item for item in DOMAINS if int(item.id) == value["domain_id"]), None)
    return (
        domain is not None
        and isinstance(value["method_id"], int)
        and not isinstance(value["method_id"], bool)
        and domain.get_fix_method(value["method_id"]) is not None
    )


def _normalize_translation(value: Any, *, strict: bool = False) -> str | None:
    if value is None:
        return None
    if isinstance(value, str) and _TRANSLATION_RE.fullmatch(value):
        return value.lower()
    if strict:
        raise ValueError("invalid translation language")
    return None


def _translate_target(target: FixedTarget, settings: dict[str, Any]) -> FixedTarget:
    language = _normalize_translation(settings.get("translate_target_lang"))
    if (
        language is None
        or target.domain.id != DomainId.TWITTER
        or target.method.id != 1
    ):
        return target
    parsed = urlsplit(target.fixed_url)
    path = f"{parsed.path.rstrip('/')}/{language}"
    return replace(
        target,
        fixed_url=urlunsplit((parsed.scheme, parsed.netloc, path, parsed.query, "")),
    )


def _bounded_json(value: Any) -> bool:
    pending: list[tuple[Any, int]] = [(value, 1)]
    nodes = 0
    while pending:
        item, depth = pending.pop()
        nodes += 1
        if nodes > MAX_JSON_NODES or depth > MAX_JSON_DEPTH:
            return False
        if isinstance(item, str):
            if len(item) > MAX_JSON_STRING:
                return False
        elif isinstance(item, dict):
            if len(item) > MAX_JSON_CONTAINER:
                return False
            for key, child in item.items():
                if not isinstance(key, str) or len(key) > MAX_JSON_STRING:
                    return False
                pending.append((child, depth + 1))
        elif isinstance(item, list):
            if len(item) > MAX_JSON_CONTAINER:
                return False
            pending.extend((child, depth + 1) for child in item)
        elif item is not None and not isinstance(item, (bool, int, float)):
            return False
    return True


def _metadata_endpoint_allowed(url: str) -> bool:
    try:
        parsed = urlsplit(url)
        if (
            parsed.scheme != "https"
            or parsed.fragment
            or parsed.username is not None
            or parsed.password is not None
            or parsed.port is not None
            or parsed.hostname not in METADATA_HOSTS
            or parsed.netloc != parsed.hostname
        ):
            return False
    except ValueError:
        return False
    if parsed.hostname == "api.fxtwitter.com":
        return (
            parsed.query == ""
            and re.fullmatch(
                r"/[A-Za-z0-9_]{1,15}/status/[0-9]{1,20}",
                parsed.path,
                re.ASCII,
            )
            is not None
        )
    if parsed.hostname == "www.pixiv.net":
        match = re.fullmatch(
            r"/ajax/illust/([0-9]{1,20})(/pages)?",
            parsed.path,
            re.ASCII,
        )
        return match is not None and (
            parsed.query == ("" if match.group(2) else "lang=jp")
        )
    if parsed.hostname != "bskx.app" or parsed.query:
        return False
    parts = parsed.path.split("/")
    if len(parts) != 6 or parts[1] != "profile" or parts[3] != "post" or parts[5] != "json":
        return False
    profile = unquote(parts[2])
    rkey = unquote(parts[4])
    if (
        _BLUESKY_SOURCE_RE.fullmatch(f"/profile/{profile}/post/{rkey}") is None
        or quote(profile, safe="") != parts[2]
        or quote(rkey, safe="") != parts[4]
    ):
        return False
    return url == f"https://bskx.app/profile/{parts[2]}/post/{parts[4]}/json"


def _bluesky_blob_url(did: str, cid: str) -> str | None:
    if not _BLUESKY_BLOB_RE.fullmatch(did) or not _BLUESKY_BLOB_RE.fullmatch(cid):
        return None
    query = urlencode(
        (("did", did), ("cid", cid)),
        quote_via=quote,
        safe="",
    )
    return f"https://bsky.social/xrpc/com.atproto.sync.getBlob?{query}"


def canonical_media_url(
    raw: Any,
    domain_id: DomainId,
    *,
    locally_derived: bool = False,
) -> str | None:
    if (
        not isinstance(raw, str)
        or not raw
        or len(raw) > MAX_URL_CHARS
        or "\\"
        in raw
        or "#"
        in raw
        or any(not 0x21 <= ord(character) <= 0x7E for character in raw)
        or any(character in raw for character in '<>"|')
    ):
        return None
    try:
        parsed = urlsplit(raw)
        host = parsed.hostname
        if (
            parsed.scheme.casefold() != "https"
            or not host
            or host.endswith(".")
            or parsed.username is not None
            or parsed.password is not None
            or parsed.port is not None
            or parsed.netloc.casefold() != host.casefold()
            or parsed.fragment
        ):
            return None
    except ValueError:
        return None
    canonical = urlunsplit(("https", host.casefold(), parsed.path, parsed.query, ""))
    if len(canonical) > MAX_URL_CHARS:
        return None
    try:
        checked = urlsplit(canonical)
        if (
            checked.scheme != "https"
            or checked.hostname != host.casefold()
            or checked.netloc != host.casefold()
            or checked.username is not None
            or checked.password is not None
            or checked.port is not None
            or checked.fragment
            or urlunsplit(
                (checked.scheme, checked.netloc, checked.path, checked.query, "")
            )
            != canonical
        ):
            return None
    except ValueError:
        return None

    def under(prefix: str) -> bool:
        return checked.path.startswith(prefix) and len(checked.path) > len(prefix)

    if domain_id == DomainId.TWITTER:
        allowed = (
            checked.hostname == "pbs.twimg.com"
            and under("/media/")
            or checked.hostname == "video.twimg.com"
            and (
                under("/ext_tw_video/")
                or under("/amplify_video/")
                or under("/tweet_video/")
            )
        )
    elif domain_id == DomainId.PIXIV:
        allowed = checked.hostname == "i.pximg.net" and (
            under("/img-original/") or under("/img-master/")
        )
    elif domain_id == DomainId.BLUESKY:
        if locally_derived:
            try:
                pairs = parse_qsl(
                    checked.query,
                    keep_blank_values=True,
                    strict_parsing=True,
                )
            except ValueError:
                return None
            allowed = (
                checked.hostname == "bsky.social"
                and checked.path == "/xrpc/com.atproto.sync.getBlob"
                and [key for key, _value in pairs] == ["did", "cid"]
                and _bluesky_blob_url(pairs[0][1], pairs[1][1]) == canonical
            )
        else:
            allowed = (
                checked.hostname in {"cdn.bsky.app", "video.bsky.app"}
                and bool(checked.path)
                and checked.path != "/"
            )
    else:
        allowed = False
    return canonical if allowed else None


def _safe_provider_text(value: str) -> str:
    cleaned = "".join(
        " "
        if (
            character == "\r"
            or unicodedata.category(character) in {"Cc", "Cf"}
            or unicodedata.bidirectional(character)
            in {"LRE", "RLE", "LRO", "RLO", "PDF", "LRI", "RLI", "FSI", "PDI"}
        )
        else character
        for character in value
    )
    cleaned = re.sub(r"\s+", " ", cleaned).strip()
    rendered: list[str] = []
    position = 0
    for match in _TEXT_URL_RE.finditer(cleaned):
        rendered.append(
            discord.utils.escape_mentions(
                discord.utils.escape_markdown(cleaned[position : match.start()])
            )
        )
        rendered.append(f"<{match.group(0)}>")
        position = match.end()
    rendered.append(
        discord.utils.escape_mentions(
            discord.utils.escape_markdown(cleaned[position:])
        )
    )
    return "".join(rendered)


def _channel_is_nsfw(channel: Any) -> bool:
    for candidate in (channel, getattr(channel, "parent", None)):
        if candidate is None:
            continue
        checker = getattr(candidate, "is_nsfw", None)
        try:
            if callable(checker) and bool(checker()):
                return True
        except Exception:
            return True
        if bool(getattr(candidate, "nsfw", False)):
            return True
    return False


def _markdown_label(value: str) -> str:
    return _ESCAPE_LABEL_RE.sub(r"\\\1", value.replace("\r", " ").replace("\n", " "))


def _markdown_url(value: str) -> str:
    # The inventory produces ordinary HTTPS URLs. Escaping only delimiters keeps
    # fixed URLs usable when a source path happens to contain parentheses.
    return value.replace("\\", "%5C").replace(")", "%29").replace("(", "%28")


def _trim_sentence_punctuation(url: str) -> str:
    """Drop punctuation commonly typed immediately after a URL in prose."""
    url = url.rstrip(_SENTENCE_TRAILING)
    pairs = {")": "(", "]": "[", "}": "{"}
    while url and url[-1] in pairs and url.count(url[-1]) > url.count(pairs[url[-1]]):
        url = url[:-1]
    return url


def _website_for(url: str, domain: Domain) -> Website | None:
    parsed = urlsplit(clean_query(url))
    candidate = urlunsplit((parsed.scheme, parsed.netloc, parsed.path, parsed.query, ""))
    return next((website for website in domain.websites if website.match(candidate)), None)


def _canonical_threads_url(raw: Any) -> str | None:
    if (
        not isinstance(raw, str)
        or not raw
        or len(raw) > MAX_URL_CHARS
        or "\\" in raw
        or any(character.isspace() or character in '<>"|' for character in raw)
    ):
        return None
    try:
        parsed = urlsplit(raw)
        host = parsed.hostname
        if (
            parsed.scheme.casefold() != "https"
            or host not in SOURCE_HOSTS[DomainId.THREADS]
            or parsed.username is not None
            or parsed.password is not None
            or parsed.port is not None
            or parsed.fragment
            or parsed.netloc.casefold() != host
        ):
            return None
    except ValueError:
        return None
    canonical = urlunsplit(("https", host, parsed.path, parsed.query, ""))
    return canonical if len(canonical) <= MAX_URL_CHARS else None


def _is_threads_share_url(url: str) -> bool:
    try:
        return re.fullmatch(r"/share/[\w-]+/?", urlsplit(url).path) is not None
    except ValueError:
        return False


def extract_candidates(content: str) -> list[Candidate]:
    """Extract at most ten bounded URLs using upstream spoiler/opt-out rules."""
    bounded = (content or "")[:MAX_MESSAGE_CHARS]
    spoiler_matches = [(match.group(1), True) for match in _SPOILER_URL_RE.finditer(bounded)]
    without_spoilers = _SPOILER_URL_RE.sub("", bounded)
    regular_matches = [(match.group(1), False) for match in _REGULAR_URL_RE.finditer(without_spoilers)]
    found: list[Candidate] = []
    for raw, spoiler in spoiler_matches + regular_matches:
        raw = _trim_sentence_punctuation(raw)
        if len(raw) > MAX_URL_CHARS:
            continue
        cleaned = clean_query(raw)
        domain = source_domain_for(cleaned)
        if domain is None:
            continue
        website = _website_for(cleaned, domain)
        if website is None:
            continue
        found.append(Candidate(cleaned, spoiler, domain, website))
        if len(found) == MAX_CANDIDATES:
            break
    return found


def extract_urls(content: str) -> list[tuple[str, bool]]:
    """Upstream-compatible bounded token extraction before domain matching."""
    bounded = (content or "")[:MAX_MESSAGE_CHARS]
    spoilers = [
        (match.group(1), True)
        for match in _SPOILER_URL_RE.finditer(bounded)
        if len(match.group(1)) <= MAX_URL_CHARS
    ]
    regular = [
        (match.group(1), False)
        for match in _REGULAR_URL_RE.finditer(_SPOILER_URL_RE.sub("", bounded))
        if len(match.group(1)) <= MAX_URL_CHARS
    ]
    return (spoilers + regular)[:MAX_CANDIDATES]


def _provider_choice(value: Any, domain: Domain) -> int | None:
    if not isinstance(value, dict):
        return None
    for key in (str(int(domain.id)), domain.id.name, domain.name):
        selected = value.get(key)
        if selected is None:
            continue
        try:
            return int(selected)
        except (TypeError, ValueError):
            return None
    return None


def choose_method(
    candidate: Candidate,
    *,
    provider_choices: Any = None,
) -> FixMethod | None:
    """Choose a configured method while honoring upstream website opt-outs."""
    selected_id = _provider_choice(provider_choices, candidate.domain)
    method = candidate.domain.get_fix_method(selected_id) if selected_id is not None else None
    if method is None:
        method = candidate.domain.default_fix_method
    if method is None or method.id in (candidate.website.skip_method_ids or []):
        return None
    return method


def fixed_targets(
    content: str,
    *,
    provider_choices: Any = None,
    disabled_domains: Any = None,
    enabled_domains: Any = None,
) -> list[FixedTarget]:
    """Return deduplicated provider links; no body/media data is retained."""
    disabled = {int(item) for item in disabled_domains or [] if str(item).isdigit()}
    enabled = {int(item) for item in enabled_domains or [] if str(item).isdigit()}
    results: list[FixedTarget] = []
    seen: set[str] = set()
    for candidate in extract_candidates(content):
        if int(candidate.domain.id) in disabled:
            continue
        if not candidate.domain.enabled_by_default and int(candidate.domain.id) not in enabled:
            continue
        method = choose_method(
            candidate,
            provider_choices=provider_choices,
        )
        if method is None:
            continue
        parsed = urlsplit(candidate.url)
        upstream_url = urlunsplit(
            (parsed.scheme, parsed.netloc[4:] if parsed.netloc.lower().startswith("www.") else parsed.netloc,
             parsed.path, parsed.query, parsed.fragment)
        )
        fixed_url = apply_fix(upstream_url, method, candidate.domain.id)
        if not fixed_url or fixed_url in seen:
            continue
        seen.add(fixed_url)
        results.append(
            FixedTarget(
                original_url=candidate.url,
                fixed_url=fixed_url,
                domain=candidate.domain,
                method=method,
                author=author_profile(candidate.url, candidate.domain),
                spoiler=candidate.spoiler,
            )
        )
    return results


def format_fixed(target: FixedTarget) -> str:
    """Build the exact link-only replacement format."""
    fixed = _markdown_url(target.fixed_url)
    source_label = _SOURCE_LABELS.get(target.domain.id, target.domain.name)
    provider_label = _PROVIDER_LABELS.get((target.domain.id, target.method.id), target.method.name)
    parts = [f"[{_markdown_label(source_label)}]({fixed})"]
    if target.author is not None:
        label, profile = target.author
        parts.append(f"[{_markdown_label(label)}](<{_markdown_url(profile)}>)")
    parts.append(f"[{_markdown_label(provider_label)}]({fixed})")
    rendered = " • ".join(parts)
    return f"||{rendered}||" if target.spoiler else rendered


def _resolve_domain(value: Any) -> Domain | None:
    text = str(value).strip()
    folded = text.casefold().replace("-", "_").replace(" ", "_")
    for domain in DOMAINS:
        if text == str(int(domain.id)) or folded in {domain.id.name.casefold(), domain.name.casefold().replace(" ", "_")}:
            return domain
    return None


def _resolve_method(domain: Domain, value: Any) -> FixMethod | None:
    text = str(value).strip()
    folded = text.casefold().replace("-", "_").replace(" ", "_")
    for method in domain.fix_methods:
        if text == str(method.id) or folded == method.name.casefold().replace(" ", "_"):
            return method
    return None


def _normalize_legacy_settings(settings: dict[str, Any]) -> tuple[dict[str, Any], bool]:
    """Migrate pinned-upstream legacy fields without reviving their runtime semantics."""
    normalized = copy.deepcopy(settings)
    for key, value in DEFAULT_GUILD_SETTINGS.items():
        normalized.setdefault(key, copy.deepcopy(value))
    normalized["translate_target_lang"] = _normalize_translation(
        normalized.get("translate_target_lang")
    )

    host_domains = {
        host.casefold(): int(domain_id)
        for domain_id, hosts in SOURCE_HOSTS.items()
        for host in hosts
    }
    unknown: list[Any] = []
    disabled_domains = _normalize_ids(normalized.get("disabled_domains", []))
    enabled_domains = _normalize_ids(normalized.get("enabled_domains", []))
    legacy = normalized.get("disabled_fixes", [])
    if isinstance(legacy, list):
        for value in legacy[:MAX_SETTING_ITEMS]:
            if not isinstance(value, str):
                unknown.append(value)
                continue
            host = value.strip().casefold().rstrip(".")
            if "://" in host:
                try:
                    host = (urlsplit(host).hostname or "").casefold()
                except ValueError:
                    host = ""
            domain_id = host_domains.get(host)
            if domain_id is None:
                unknown.append(value)
            elif domain_id not in enabled_domains:
                disabled_domains.add(domain_id)
    else:
        unknown = [legacy]
    normalized["disabled_fixes"] = unknown
    normalized["disabled_domains"] = sorted(disabled_domains)

    if normalized.get("use_vxreddit") is True:
        choices = normalized.get("provider_choices")
        choices = dict(choices) if isinstance(choices, dict) else {}
        reddit = next(domain for domain in DOMAINS if domain.id == DomainId.REDDIT)
        if _provider_choice(choices, reddit) is None:
            choices[str(int(DomainId.REDDIT))] = 7
        normalized["provider_choices"] = choices
        normalized["use_vxreddit"] = False

    if unknown and normalized != settings:
        log.warning("EmbedFixer retained %d unknown legacy disabled_fixes value(s)", len(unknown))
    return normalized, normalized != settings


def _strict_int(value: Any) -> int:
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    if isinstance(value, str) and re.fullmatch(r"[+-]?\d+", value):
        return int(value)
    raise ValueError("invalid integer")


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"invalid JSON constant: {value}")


def _validated_id_list(value: Any, *, valid: set[int] | None = None) -> list[int]:
    if not isinstance(value, list) or len(value) > MAX_SETTING_ITEMS:
        raise ValueError("invalid identifier list")
    result: list[int] = []
    for item in value:
        item_id = _strict_int(item)
        if valid is None:
            if not 1 <= item_id <= MAX_SNOWFLAKE:
                raise ValueError("invalid snowflake")
        elif item_id not in valid:
            raise ValueError("unknown identifier")
        if item_id not in result:
            result.append(item_id)
    return result


def _validated_import(payload: Any) -> dict[str, Any]:
    """Validate an upstream export completely before the caller persists it."""
    if not isinstance(payload, dict) or set(payload) != {"guild_settings", "fix_methods"}:
        raise ValueError("invalid export object")
    raw_settings = payload["guild_settings"]
    raw_methods = payload["fix_methods"]
    if not isinstance(raw_settings, dict) or not isinstance(raw_methods, list):
        raise ValueError("invalid export fields")
    if set(raw_settings) - set(PORTABLE_GUILD_SETTINGS) or len(raw_methods) > MAX_SETTING_ITEMS:
        raise ValueError("unknown or oversized settings")

    validated = copy.deepcopy(DEFAULT_GUILD_SETTINGS)
    domain_ids = {int(domain.id) for domain in DOMAINS}
    snowflake_lists = {
        "disable_fix_channels",
        "enable_fix_channels",
        "extract_media_channels",
        "disable_image_spoilers",
        "show_post_content_channels",
        "whitelist_role_ids",
    }
    bool_fields = {
        "disable_webhook_reply",
        "disable_delete_reaction",
        "use_vxreddit",
        "bot_visibility",
        "show_original_link_btn",
        "delete_original_message_in_threads",
        "rotate_fix_reaction",
    }
    optional_strings = {"lang"}

    for name in PORTABLE_GUILD_SETTINGS:
        if name not in raw_settings:
            continue
        value = raw_settings[name]
        if name in {"disabled_domains", "enabled_domains"}:
            value = _validated_id_list(value, valid=domain_ids)
        elif name in snowflake_lists:
            value = _validated_id_list(value)
        elif name == "disabled_fixes":
            if not isinstance(value, list) or len(value) > MAX_SETTING_ITEMS:
                raise ValueError("invalid disabled fixes")
            if any(not isinstance(item, str) or len(item) > MAX_SETTING_STRING for item in value):
                raise ValueError("invalid disabled fix")
        elif name in bool_fields:
            if not isinstance(value, bool):
                raise ValueError("invalid boolean")
        elif name in optional_strings:
            if value is not None and (not isinstance(value, str) or len(value) > MAX_SETTING_STRING):
                raise ValueError("invalid string")
        elif name == "translate_target_lang":
            value = _normalize_translation(value, strict=True)
        elif name == "delete_msg_emoji":
            value = _validated_delete_emoji(value)
        elif name == "funnel_target_channel":
            if value is not None:
                value = _strict_int(value)
                if not 1 <= value <= MAX_SNOWFLAKE:
                    raise ValueError("invalid funnel channel")
        elif name == "fix_mode":
            if value not in FIX_MODES:
                raise ValueError("invalid fix mode")
        elif name == "remove_delete_reaction_after":
            if value is not None and (
                isinstance(value, bool)
                or not isinstance(value, int)
                or not 0 <= value <= 86400
            ):
                raise ValueError("invalid reaction timeout")
        validated[name] = value

    if set(validated["disabled_domains"]).intersection(validated["enabled_domains"]):
        raise ValueError("domain cannot be enabled and disabled")
    if set(validated["disable_fix_channels"]).intersection(validated["enable_fix_channels"]):
        raise ValueError("channel cannot be enabled and disabled")

    choices: dict[str, int] = {}
    for raw_method in raw_methods:
        if not isinstance(raw_method, dict) or set(raw_method) != {"domain_id", "fix_id"}:
            raise ValueError("invalid fix method")
        domain = _resolve_domain(raw_method["domain_id"])
        if domain is None:
            raise ValueError("unknown domain")
        method = _resolve_method(domain, raw_method["fix_id"])
        if method is None:
            raise ValueError("provider does not belong to domain")
        key = str(int(domain.id))
        if key in choices and choices[key] != method.id:
            raise ValueError("conflicting providers")
        choices[key] = method.id
    validated["provider_choices"] = choices
    return _normalize_legacy_settings(validated)[0]


def _export_payload(settings: dict[str, Any]) -> dict[str, Any]:
    normalized = _normalize_legacy_settings(settings)[0]
    methods: list[dict[str, int]] = []
    choices = normalized.get("provider_choices", {})
    for domain in DOMAINS:
        selected = _provider_choice(choices, domain)
        method = domain.get_fix_method(selected) if selected is not None else None
        if method is not None:
            methods.append({"domain_id": int(domain.id), "fix_id": method.id})
    return {
        "guild_settings": {
            key: copy.deepcopy(normalized.get(key, DEFAULT_GUILD_SETTINGS[key]))
            for key in PORTABLE_GUILD_SETTINGS
        },
        "fix_methods": methods,
    }


async def _value(scope: Any, name: str, default: Any) -> Any:
    """Read Config and lightweight fake scopes without broad persistence."""
    if scope is None:
        return default
    try:
        value = getattr(scope, name)
        value = value() if callable(value) else value
        if hasattr(value, "__await__"):
            value = await value
        return default if value is None and default is not None else value
    except (AttributeError, KeyError, TypeError):
        try:
            value = scope.get(name, default)
            if hasattr(value, "__await__"):
                value = await value
            return value
        except (AttributeError, KeyError, TypeError):
            return default


def _channel_permission_ok(channel: Any, guild: Any, bot: Any, *, manage_messages: bool) -> bool:
    permissions_for = getattr(channel, "permissions_for", None)
    if permissions_for is None:
        return False
    member = getattr(guild, "me", None) or getattr(bot, "user", None)
    try:
        permissions = permissions_for(member)
    except Exception:  # permission API failures are a silent no-op
        return False
    required = ["view_channel", "send_messages", "embed_links", "read_message_history"]
    if manage_messages:
        required.append("manage_messages")
    return all(bool(getattr(permissions, name, False)) for name in required)


def _source_permission_ok(channel: Any, guild: Any, bot: Any, *, manage_messages: bool) -> bool:
    permissions_for = getattr(channel, "permissions_for", None)
    member = getattr(guild, "me", None) or getattr(bot, "user", None)
    if not callable(permissions_for) or member is None:
        return False
    try:
        permissions = permissions_for(member)
    except Exception:
        return False
    required = ["view_channel", "read_message_history"]
    required.extend(
        ["manage_messages"] if manage_messages else ["send_messages", "embed_links"]
    )
    return all(bool(getattr(permissions, name, False)) for name in required)


def _normalize_ids(value: Any) -> set[int]:
    """Normalize Red's JSON int/string ID values once at a trust boundary."""
    if isinstance(value, (str, bytes, int)):
        value = [value]
    try:
        iterator = iter(value)
    except TypeError:
        return set()
    normalized: set[int] = set()
    for item in iterator:
        try:
            normalized.add(int(item))
        except (TypeError, ValueError):
            continue
    return normalized


def _validated_delete_emoji(value: Any) -> str:
    if not isinstance(value, str) or not value or len(value) > MAX_SETTING_STRING:
        raise ValueError("invalid emoji")
    if value == ROTATE_EMOJI:
        raise ValueError("delete emoji is reserved for rotation")
    return value


def _is_suppressed(message: Any) -> bool | None:
    if hasattr(message, "suppressed"):
        return bool(message.suppressed)
    flags = getattr(message, "flags", None)
    if flags is not None and hasattr(flags, "suppress_embeds"):
        return bool(flags.suppress_embeds)
    return None


class EmbedFixer(commands.Cog):
    """Automatically post fixed links and suppress only confirmed originals."""

    __author__ = "Nyanako; adapted from seriaati/embed-fixer"
    __version__ = "1.3.0-s4"
    confirm_timeout = CONFIRM_TIMEOUT

    def __init__(self, bot: Any):
        super().__init__()
        self.bot = bot
        self.config = Config.get_conf(self, identifier=0x4E59414E454D4244, force_registration=True)
        self.config.register_global(**DEFAULT_GLOBAL_SETTINGS)
        self.config.register_guild(**DEFAULT_GUILD_SETTINGS)
        self.config.register_user(**DEFAULT_USER_SETTINGS)
        self._context_menu = app_commands.ContextMenu(name="Fix Embed", callback=self._context_fix)
        self._extract_context_menu = app_commands.ContextMenu(
            name="Extract Media",
            callback=self._context_extract,
        )
        self._context_menu_registered = False
        self._extract_context_menu_registered = False
        self._session: aiohttp.ClientSession | None = None
        self._s3_lock = asyncio.Lock()
        self._rotation_lock = asyncio.Lock()
        self._author_inflight: dict[int, set[asyncio.Event]] = {}
        self._pending_records: dict[str, dict[str, Any]] = {}
        self._pending_evictions: set[str] = set()
        self._reaction_tasks: dict[int, asyncio.Task[Any]] = {}
        self._notify_pairs: dict[tuple[int, int], float] = {}
        self._notify_recipients: dict[int, list[float]] = {}

    def _ensure_s3_runtime(self) -> None:
        """Initialize only the runtime state needed by lightweight test doubles."""
        if not hasattr(self, "_s3_lock"):
            self._s3_lock = asyncio.Lock()
        if not hasattr(self, "_rotation_lock"):
            self._rotation_lock = asyncio.Lock()
        if not hasattr(self, "_author_inflight"):
            self._author_inflight = {}
        if not hasattr(self, "_pending_records"):
            self._pending_records = {}
        if not hasattr(self, "_pending_evictions"):
            self._pending_evictions = set()
        if not hasattr(self, "_reaction_tasks"):
            self._reaction_tasks = {}
        if not hasattr(self, "_notify_pairs"):
            self._notify_pairs = {}
        if not hasattr(self, "_notify_recipients"):
            self._notify_recipients = {}
        if not hasattr(self, "_context_menu_registered"):
            self._context_menu_registered = False
        if not hasattr(self, "_extract_context_menu_registered"):
            self._extract_context_menu_registered = False

    def _register_author(self, author_id: Any) -> asyncio.Event | None:
        self._ensure_s3_runtime()
        author_id = _snowflake(author_id)
        if author_id is None:
            return None
        token = asyncio.Event()
        self._author_inflight.setdefault(author_id, set()).add(token)
        return token

    def _discard_author(self, author_id: Any, token: asyncio.Event | None) -> None:
        author_id = _snowflake(author_id)
        if author_id is None or token is None:
            return
        tokens = self._author_inflight.get(author_id)
        if tokens is None:
            return
        tokens.discard(token)
        if not tokens:
            self._author_inflight.pop(author_id, None)

    async def cog_load(self) -> None:
        session = getattr(self, "_session", None)
        if session is None or session.closed:
            connector = aiohttp.TCPConnector(
                resolver=MetadataResolver(),
                family=socket.AF_UNSPEC,
            )
            self._session = aiohttp.ClientSession(
                connector=connector,
                cookie_jar=aiohttp.DummyCookieJar(),
                trust_env=False,
            )
        tree = getattr(self.bot, "tree", None)
        menus = (
            ("_context_menu", "_context_menu_registered"),
            ("_extract_context_menu", "_extract_context_menu_registered"),
        )
        try:
            if tree is not None:
                menu_conflict = False
                for menu_name, state_name in menus:
                    menu = getattr(self, menu_name, None)
                    if menu is None:
                        continue
                    current = tree.get_command(
                        menu.name,
                        type=discord.AppCommandType.message,
                    )
                    if current is menu:
                        setattr(self, state_name, True)
                    elif current is not None:
                        log.warning(
                            "EmbedFixer context menus were not registered because a name is already in use"
                        )
                        menu_conflict = True
                        break
                if not menu_conflict:
                    for menu_name, state_name in menus:
                        menu = getattr(self, menu_name, None)
                        if menu is None or getattr(self, state_name, False):
                            continue
                        setattr(self, state_name, True)
                        tree.add_command(menu)
            await self._restore_reaction_timeouts()
        except Exception:
            await self.cog_unload()
            raise

    async def _restore_reaction_timeouts(self) -> None:
        self._ensure_s3_runtime()
        async with self._s3_lock:
            records = await self._stored_replacement_records()
            restored = 0
            guild_counts: dict[int, int] = {}
            now = datetime.now(timezone.utc)
            for message_id, record in records.items():
                if restored >= MAX_GLOBAL_RECORDS:
                    break
                guild_id = record["guild_id"]
                if guild_counts.get(guild_id, 0) >= MAX_GUILD_RECORDS:
                    continue
                settings = await self._guild_settings_from_id(guild_id)
                timeout = settings.get("remove_delete_reaction_after")
                if (
                    settings.get("disable_delete_reaction", False)
                    or isinstance(timeout, bool)
                    or not isinstance(timeout, int)
                    or not 0 <= timeout <= 86400
                ):
                    continue
                try:
                    created_at = datetime.fromisoformat(record["created_at"])
                except (TypeError, ValueError):
                    continue
                remaining = max(0.0, timeout - (now - created_at).total_seconds())
                self._track_reaction_timeout(
                    int(message_id),
                    record,
                    settings,
                    delay=remaining,
                )
                restored += 1
                guild_counts[guild_id] = guild_counts.get(guild_id, 0) + 1

    async def cog_unload(self) -> None:
        self._ensure_s3_runtime()
        tree = getattr(self.bot, "tree", None)
        menus = (
            ("_context_menu", "_context_menu_registered"),
            ("_extract_context_menu", "_extract_context_menu_registered"),
        )
        for menu_name, state_name in menus:
            menu = getattr(self, menu_name, None)
            if tree is not None and menu is not None and getattr(self, state_name, False):
                current = tree.get_command(menu.name, type=discord.AppCommandType.message)
                if current is menu:
                    tree.remove_command(menu.name, type=discord.AppCommandType.message)
            setattr(self, state_name, False)
        session = getattr(self, "_session", None)
        if session is not None and not session.closed:
            await session.close()
        self._session = None
        tasks = tuple(self._reaction_tasks.values())
        self._reaction_tasks.clear()
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        async with self._s3_lock:
            for tokens in self._author_inflight.values():
                for token in tokens:
                    token.set()
            self._author_inflight.clear()
            self._pending_records.clear()
            self._pending_evictions.clear()
            self._notify_pairs.clear()
            self._notify_recipients.clear()

    async def red_delete_data_for_user(self, *, requester: str, user_id: int) -> None:
        """Clear user settings, replacement authority, and notification throttles."""
        del requester
        self._ensure_s3_runtime()
        user_id = _snowflake(user_id)
        if user_id is None:
            return
        failure: Exception | None = None
        async with self._s3_lock:
            for token in tuple(self._author_inflight.get(user_id, ())):
                token.set()
            records = await self._replacement_records()
            owned_ids = {
                int(message_id)
                for message_id, record in records.items()
                if record["author_id"] == user_id
            }
            self._cancel_reaction_timeouts(owned_ids)
            try:
                await self.config.user_from_id(user_id).clear()
            except Exception as error:
                failure = error
            all_guilds = getattr(self.config, "all_guilds", None)
            guild_data: dict[Any, Any] = {}
            if callable(all_guilds):
                try:
                    loaded = await all_guilds()
                    if isinstance(loaded, dict):
                        guild_data = loaded
                except Exception as error:
                    failure = failure or error
            else:
                for guild in getattr(self.bot, "guilds", ()) or ():
                    guild_id = _snowflake(getattr(guild, "id", None))
                    if guild_id is None:
                        continue
                    try:
                        scope = self._guild_scope_from_id(guild_id)
                        values = await self._scope_values(scope, DEFAULT_GUILD_SETTINGS)
                        guild_data[guild_id] = values
                    except Exception as error:
                        failure = failure or error
            for raw_guild_id, raw_settings in guild_data.items():
                guild_id = _snowflake(raw_guild_id)
                if guild_id is None or not isinstance(raw_settings, dict):
                    continue
                ignored = _normalize_ids(raw_settings.get("ignored_users", []))
                if user_id not in ignored:
                    continue
                updated = copy.deepcopy(raw_settings)
                ignored.discard(user_id)
                updated["ignored_users"] = sorted(ignored)
                try:
                    await self._guild_scope_from_id(guild_id).set(updated)
                except Exception as error:
                    failure = failure or error
            if owned_ids:
                try:
                    await self._set_replacement_records(
                        {
                            message_id: record
                            for message_id, record in records.items()
                            if int(message_id) not in owned_ids
                        }
                    )
                except Exception as error:
                    failure = failure or error
            self._notify_pairs = {
                pair: expires
                for pair, expires in self._notify_pairs.items()
                if pair[0] not in owned_ids and pair[1] != user_id
            }
            self._notify_recipients.pop(user_id, None)
            self._pending_records = {
                message_id: record
                for message_id, record in self._pending_records.items()
                if record["author_id"] != user_id
            }
            for token in tuple(self._author_inflight.get(user_id, ())):
                token.set()
            self._author_inflight.pop(user_id, None)
        if failure is not None:
            raise failure

    @staticmethod
    async def _scope_values(scope: Any, defaults: dict[str, Any]) -> dict[str, Any]:
        all_values = getattr(scope, "all", None)
        if callable(all_values):
            try:
                values = await all_values()
                if isinstance(values, dict):
                    merged = copy.deepcopy(defaults)
                    merged.update(values)
                    return merged
            except (AttributeError, KeyError, TypeError):
                pass
        return {
            key: await _value(scope, key, copy.deepcopy(default))
            for key, default in defaults.items()
        }

    async def _disabled_in_guild(self, guild: Any) -> bool:
        checker = getattr(self.bot, "cog_disabled_in_guild", None)
        if checker is None:
            return False
        try:
            return bool(await checker(self, guild))
        except (AttributeError, TypeError):
            return False

    def _guild_scope_from_id(self, guild_id: int) -> Any:
        factory = getattr(self.config, "guild_from_id", None)
        if callable(factory):
            return factory(guild_id)
        guild = getattr(self.bot, "get_guild", lambda _guild_id: None)(guild_id)
        return self.config.guild(guild or discord.Object(id=guild_id))

    def _user_scope_from_id(self, user_id: int) -> Any:
        factory = getattr(self.config, "user_from_id", None)
        if callable(factory):
            return factory(user_id)
        return self.config.user(discord.Object(id=user_id))

    async def _guild_settings_from_id(self, guild_id: int) -> dict[str, Any]:
        scope = self._guild_scope_from_id(guild_id)
        settings = await self._scope_values(scope, DEFAULT_GUILD_SETTINGS)
        return _normalize_legacy_settings(settings)[0]

    @staticmethod
    def _role_allowed(author: Any, guild_settings: dict[str, Any]) -> bool:
        allowed = _normalize_ids(guild_settings.get("whitelist_role_ids", []))
        roles = _normalize_ids(
            getattr(role, "id", role)
            for role in (getattr(author, "roles", []) or [])
        )
        return not allowed or bool(roles.intersection(allowed))

    async def _context_settings(
        self,
        *,
        guild: Any,
        author: Any,
        channel: Any,
        source: Any = None,
        manage_messages: bool,
        automatic: bool = False,
    ) -> tuple[dict[str, Any], dict[str, Any]] | None:
        if author is None:
            return None
        bot_id = getattr(getattr(self.bot, "user", None), "id", None)
        if source is not None and getattr(author, "id", None) == bot_id:
            return None
        if source is not None and _is_suppressed(source) is True:
            return None
        if guild is None:
            if getattr(author, "bot", False):
                return None
            user = await self._scope_values(self.config.user(author), DEFAULT_USER_SETTINGS)
            if automatic and user.get("ignored"):
                return None
            if not _channel_permission_ok(channel, None, self.bot, manage_messages=False):
                return None
            return copy.deepcopy(DEFAULT_GUILD_SETTINGS), user
        if source is not None and getattr(source, "webhook_id", None) is not None:
            return None
        if await self._disabled_in_guild(guild):
            return None
        if not _source_permission_ok(
            channel,
            guild,
            self.bot,
            manage_messages=manage_messages,
        ):
            return None

        guild_scope = self.config.guild(guild)
        guild_settings, user_settings = await asyncio.gather(
            self._scope_values(guild_scope, DEFAULT_GUILD_SETTINGS),
            self._scope_values(self.config.user(author), DEFAULT_USER_SETTINGS),
        )
        guild_settings, changed = _normalize_legacy_settings(guild_settings)
        if changed:
            await guild_scope.set(guild_settings)
        if not guild_settings.get("enabled", True):
            return None
        if getattr(author, "bot", False) and not guild_settings.get("bot_visibility", False):
            return None

        if automatic and user_settings.get("ignored"):
            return None
        author_id = getattr(author, "id", None)
        if author_id in _normalize_ids(guild_settings.get("ignored_users", [])):
            return None
        if not self._role_allowed(author, guild_settings):
            return None
        channel_ids = _normalize_ids([getattr(channel, "id", None)])
        channel_id = next(iter(channel_ids), None)
        enabled_channels = _normalize_ids(guild_settings.get("enable_fix_channels", []))
        disabled_channels = _normalize_ids(guild_settings.get("disable_fix_channels", []))
        if enabled_channels and channel_id not in enabled_channels:
            return None
        if not enabled_channels and channel_id in disabled_channels:
            return None
        return guild_settings, user_settings

    def _destination_for(
        self,
        *,
        guild: Any,
        source_channel: Any,
        guild_settings: dict[str, Any],
    ) -> tuple[Any, bool] | None:
        configured = guild_settings.get("funnel_target_channel")
        if configured is None:
            destination = source_channel
            funnel = False
        else:
            destination_id = _snowflake(configured)
            guild_id = _snowflake(getattr(guild, "id", None))
            source_guild_id = _snowflake(
                getattr(getattr(source_channel, "guild", None), "id", None)
            )
            getter = getattr(guild, "get_channel", None)
            if (
                destination_id is None
                or guild_id is None
                or source_guild_id != guild_id
                or not callable(getter)
            ):
                return None
            destination = getter(destination_id)
            if (
                not isinstance(destination, discord.TextChannel)
                or getattr(destination, "id", None) != destination_id
                or getattr(getattr(destination, "guild", None), "id", None) != guild_id
                or not callable(getattr(destination, "send", None))
            ):
                return None
            if _channel_is_nsfw(source_channel) and not _channel_is_nsfw(destination):
                return None
            funnel = True
        if not _channel_permission_ok(
            destination,
            guild,
            self.bot,
            manage_messages=False,
        ):
            return None
        return destination, funnel

    @staticmethod
    def _mode(guild_settings: dict[str, Any], user_settings: dict[str, Any]) -> str:
        mode = user_settings.get("fix_mode") or guild_settings.get("fix_mode")
        return mode if mode in FIX_MODES else "resend"

    @staticmethod
    def _targets(content: str, guild_settings: dict[str, Any]) -> list[FixedTarget]:
        targets: list[FixedTarget] = []
        for target in fixed_targets(
            content,
            provider_choices=guild_settings.get("provider_choices", {}),
            disabled_domains=guild_settings.get("disabled_domains", []),
            enabled_domains=guild_settings.get("enabled_domains", []),
        ):
            translated = _translate_target(target, guild_settings)
            if len(format_fixed(translated)) <= DISCORD_MESSAGE_CHARS:
                targets.append(translated)
        return targets

    async def _resolve_threads_share(self, url: str) -> str | None:
        session = getattr(self, "_session", None)
        current = _canonical_threads_url(url)
        if (
            current is None
            or not _is_threads_share_url(current)
            or session is None
            or bool(getattr(session, "closed", False))
        ):
            return None
        try:
            async with asyncio.timeout(METADATA_REQUEST_TIMEOUT):
                redirects = 0
                while True:
                    async with session.get(current, allow_redirects=False) as response:
                        if 300 <= response.status < 400:
                            if redirects == 5:
                                return None
                            location = response.headers.get("Location")
                            if not isinstance(location, str):
                                return None
                            current = _canonical_threads_url(urljoin(current, location))
                            if current is None:
                                return None
                            redirects += 1
                            continue
                        if not 200 <= response.status < 300:
                            return None
                    canonical = clean_query(current)
                    domain = source_domain_for(canonical)
                    if (
                        domain is None
                        or domain.id != DomainId.THREADS
                        or _is_threads_share_url(canonical)
                    ):
                        return None
                    return canonical
        except Exception:
            return None

    async def _metadata_json(self, url: str) -> Any | None:
        session = getattr(self, "_session", None)
        if (
            not _metadata_endpoint_allowed(url)
            or session is None
            or bool(getattr(session, "closed", False))
        ):
            return None
        try:
            async with asyncio.timeout(METADATA_REQUEST_TIMEOUT):
                async with session.get(url, allow_redirects=False) as response:
                    if response.status != 200:
                        return None
                    content_length = response.headers.get("Content-Length")
                    if content_length is not None:
                        try:
                            if int(content_length) > MAX_METADATA_BYTES:
                                return None
                        except (TypeError, ValueError):
                            return None
                    body = bytearray()
                    while len(body) <= MAX_METADATA_BYTES:
                        chunk = await response.content.read(
                            min(64 * 1024, MAX_METADATA_BYTES + 1 - len(body))
                        )
                        if not isinstance(chunk, (bytes, bytearray)):
                            return None
                        if not chunk:
                            break
                        body.extend(chunk)
                    if len(body) > MAX_METADATA_BYTES:
                        return None
            payload = json.loads(
                body.decode("utf-8"),
                parse_constant=_reject_json_constant,
            )
        except (
            TimeoutError,
            aiohttp.ClientError,
            UnicodeDecodeError,
            json.JSONDecodeError,
            OSError,
            TypeError,
            ValueError,
        ):
            return None
        return payload if _bounded_json(payload) else None

    async def _twitter_metadata(self, target: FixedTarget) -> ProviderMetadata | None:
        match = _TWITTER_SOURCE_RE.fullmatch(urlsplit(target.original_url).path)
        if match is None:
            return None
        handle, status_id = match.groups()
        payload = await self._metadata_json(
            f"https://api.fxtwitter.com/{handle}/status/{status_id}"
        )
        tweet = payload.get("tweet") if isinstance(payload, dict) else None
        if not isinstance(tweet, dict):
            return None
        text = tweet.get("text")
        text = text if isinstance(text, str) else None
        media_root = tweet.get("media")
        raw_media = media_root.get("all") if isinstance(media_root, dict) else None
        media: list[MediaCandidate] = []
        if isinstance(raw_media, list):
            for item in raw_media[:MAX_MEDIA_ITEMS]:
                if (
                    isinstance(item, dict)
                    and item.get("type") in {"photo", "video", "gif"}
                    and isinstance(item.get("url"), str)
                ):
                    media.append(MediaCandidate(item["url"]))
        sensitive = tweet.get("possibly_sensitive")
        return ProviderMetadata(
            text=text,
            media=tuple(media),
            sensitive=sensitive if isinstance(sensitive, bool) else None,
        )

    async def _pixiv_metadata(self, target: FixedTarget) -> ProviderMetadata | None:
        match = _PIXIV_SOURCE_RE.fullmatch(urlsplit(target.original_url).path)
        if match is None:
            return None
        illustration_id = match.group(1)
        info = await self._metadata_json(
            f"https://www.pixiv.net/ajax/illust/{illustration_id}?lang=jp"
        )
        body = info.get("body") if isinstance(info, dict) else None
        if not isinstance(body, dict):
            return None
        description = body.get("description")
        text = description if isinstance(description, str) else None
        sensitive: bool | None = None
        tags_root = body.get("tags")
        tags = tags_root.get("tags") if isinstance(tags_root, dict) else None
        if isinstance(tags, list) and all(
            isinstance(item, dict) and isinstance(item.get("tag"), str)
            for item in tags
        ):
            sensitive = any(
                item["tag"] in {"R-18", "R-18G"}
                for item in tags
            )
        illustration_type = body.get("illustType")
        if (
            isinstance(illustration_type, bool)
            or not isinstance(illustration_type, int)
            or illustration_type not in {0, 1, 2}
        ):
            return ProviderMetadata(text=text, media=(), sensitive=sensitive)
        if illustration_type == 2:
            return ProviderMetadata(text=text, media=(), sensitive=sensitive)
        pages = await self._metadata_json(
            f"https://www.pixiv.net/ajax/illust/{illustration_id}/pages"
        )
        raw_pages = pages.get("body") if isinstance(pages, dict) else None
        media: list[MediaCandidate] = []
        if isinstance(raw_pages, list):
            for page in raw_pages[:MAX_MEDIA_ITEMS]:
                urls = page.get("urls") if isinstance(page, dict) else None
                if not isinstance(urls, dict):
                    continue
                for name in ("original", "regular"):
                    raw = urls.get(name)
                    canonical = canonical_media_url(raw, DomainId.PIXIV)
                    if canonical is not None:
                        media.append(MediaCandidate(canonical))
                        break
        return ProviderMetadata(text=text, media=tuple(media), sensitive=sensitive)

    async def _bluesky_metadata(self, target: FixedTarget) -> ProviderMetadata | None:
        match = _BLUESKY_SOURCE_RE.fullmatch(urlsplit(target.original_url).path)
        if match is None:
            return None
        profile, rkey = match.groups()
        payload = await self._metadata_json(
            "https://bskx.app/profile/"
            f"{quote(profile, safe='')}/post/{quote(rkey, safe='')}/json"
        )
        thread = payload.get("thread") if isinstance(payload, dict) else None
        post = thread.get("post") if isinstance(thread, dict) else None
        if not isinstance(post, dict):
            return None
        record = post.get("record")
        text_value = record.get("text") if isinstance(record, dict) else None
        text = text_value if isinstance(text_value, str) else None
        embed = post.get("embed")
        media: list[MediaCandidate] = []
        if isinstance(embed, dict):
            images = embed.get("images")
            if isinstance(images, list):
                for image in images[:MAX_MEDIA_ITEMS]:
                    if not isinstance(image, dict):
                        continue
                    for name in ("fullsize", "thumb"):
                        raw = image.get(name)
                        canonical = canonical_media_url(raw, DomainId.BLUESKY)
                        if canonical is not None:
                            media.append(MediaCandidate(canonical))
                            break
            video = embed.get("video")
            author = post.get("author")
            cid = video.get("cid") if isinstance(video, dict) else None
            did = author.get("did") if isinstance(author, dict) else None
            if isinstance(cid, str) and isinstance(did, str):
                blob = _bluesky_blob_url(did, cid)
                if blob is not None:
                    media.append(MediaCandidate(blob, locally_derived=True))
        labels = post.get("labels")
        if labels == []:
            sensitive: bool | None = False
        elif isinstance(labels, list) and labels:
            values = [
                item.get("val")
                for item in labels
                if isinstance(item, dict) and isinstance(item.get("val"), str)
            ]
            sensitive = (
                True
                if any(
                    value in {"porn", "sexual", "nudity", "graphic-media"}
                    for value in values
                )
                else None
            )
        else:
            sensitive = None
        return ProviderMetadata(text=text, media=tuple(media), sensitive=sensitive)

    async def _metadata_for_target(
        self,
        target: FixedTarget,
    ) -> ProviderMetadata | None:
        if target.domain.id == DomainId.TWITTER:
            return await self._twitter_metadata(target)
        if target.domain.id == DomainId.PIXIV:
            return await self._pixiv_metadata(target)
        if target.domain.id == DomainId.BLUESKY:
            return await self._bluesky_metadata(target)
        return None

    @staticmethod
    def _media_spoiler(
        target: FixedTarget,
        metadata: ProviderMetadata,
        destination: Any,
        guild_settings: dict[str, Any],
    ) -> bool | None:
        destination_id = _snowflake(getattr(destination, "id", None))
        destination_nsfw = _channel_is_nsfw(destination)
        no_auto_spoiler = destination_id in _normalize_ids(
            guild_settings.get("disable_image_spoilers", [])
        )
        if metadata.sensitive is True:
            return True if destination_nsfw else None
        if metadata.sensitive is None:
            if not destination_nsfw:
                return True if target.spoiler else None
            return not no_auto_spoiler
        if target.spoiler:
            return True
        return destination_nsfw and not no_auto_spoiler

    def _enriched_target(
        self,
        target: FixedTarget,
        metadata: ProviderMetadata,
        destination: Any,
        guild_settings: dict[str, Any],
    ) -> FixedTarget:
        spoiler = self._media_spoiler(
            target,
            metadata,
            destination,
            guild_settings,
        )
        if spoiler is None:
            return target
        media: list[str] = []
        seen: set[str] = set()
        for candidate in metadata.media[:MAX_MEDIA_ITEMS]:
            canonical = canonical_media_url(
                candidate.url,
                target.domain.id,
                locally_derived=candidate.locally_derived,
            )
            if canonical is None or canonical in seen:
                continue
            seen.add(canonical)
            media.append(canonical)
        if not media:
            return target

        row = format_fixed(target)
        lines: list[str] = []
        used = len(row)
        for canonical in media:
            line = f"||{canonical}||" if spoiler else canonical
            if used + 1 + len(line) > DISCORD_MESSAGE_CHARS:
                continue
            lines.append(line)
            used += 1 + len(line)
        if not lines:
            return target

        text = ""
        destination_id = _snowflake(getattr(destination, "id", None))
        if (
            isinstance(metadata.text, str)
            and destination_id
            in _normalize_ids(guild_settings.get("show_post_content_channels", []))
        ):
            safe_text = _safe_provider_text(metadata.text)
            limit = min(800, DISCORD_MESSAGE_CHARS - used - 1)
            if limit > 0:
                text = safe_text[:limit].rstrip().rstrip("\\")
                if text.count("<") > text.count(">"):
                    text = text.rsplit("<", 1)[0].rstrip()

        content = "\n".join([row, *([text] if text else []), *lines])
        if len(content) > DISCORD_MESSAGE_CHARS:
            return target
        return replace(target, content=content, nonrotatable=True)

    async def _enrich_targets(
        self,
        targets: list[FixedTarget],
        destination: Any,
        guild_settings: dict[str, Any],
    ) -> list[FixedTarget]:
        enriched = list(targets)
        attempted = 0
        try:
            async with asyncio.timeout(METADATA_TOTAL_TIMEOUT):
                for index, target in enumerate(targets):
                    if target.domain.id not in METADATA_DOMAINS:
                        continue
                    if attempted == MAX_METADATA_SOURCES:
                        break
                    attempted += 1
                    metadata = await self._metadata_for_target(target)
                    if metadata is not None:
                        enriched[index] = self._enriched_target(
                            target,
                            metadata,
                            destination,
                            guild_settings,
                        )
        except TimeoutError:
            pass
        return enriched

    @staticmethod
    def _source_snapshot(message: Any) -> tuple[int, int, int, int, str, str | None] | None:
        source_id = _snowflake(getattr(message, "id", None))
        guild_id = _snowflake(getattr(getattr(message, "guild", None), "id", None))
        channel_id = _snowflake(getattr(getattr(message, "channel", None), "id", None))
        author_id = _snowflake(getattr(getattr(message, "author", None), "id", None))
        content = getattr(message, "content", None)
        edited_at = getattr(message, "edited_at", None)
        edited = _timestamp(edited_at)
        if (
            source_id is None
            or guild_id is None
            or channel_id is None
            or author_id is None
            or not isinstance(content, str)
            or edited_at is not None
            and edited is None
        ):
            return None
        return source_id, guild_id, channel_id, author_id, content, edited

    @staticmethod
    def _destination_snapshot(destination: Any) -> tuple[int, int, bool] | None:
        destination_id = _snowflake(getattr(destination, "id", None))
        guild_id = _snowflake(
            getattr(getattr(destination, "guild", None), "id", None),
            optional=True,
        )
        if destination_id is None:
            return None
        return guild_id or 0, destination_id, _channel_is_nsfw(destination)

    async def _refetch_snapshot(
        self,
        message: Any,
        expected: tuple[int, int, int, int, str, str | None],
    ) -> Any | None:
        fetch = getattr(getattr(message, "channel", None), "fetch_message", None)
        if not callable(fetch):
            return None
        try:
            fresh = await fetch(expected[0])
        except Exception:
            return None
        return fresh if self._source_snapshot(fresh) == expected else None

    async def _process_extraction(
        self,
        message: Any,
        *,
        token: asyncio.Event | None,
        target_content: str | None = None,
        metadata_only: bool = False,
        automatic: bool = False,
    ) -> bool:
        async with self._s3_lock:
            if token is not None and token.is_set():
                return False
            guild = getattr(message, "guild", None)
            author = getattr(message, "author", None)
            channel = getattr(message, "channel", None)
            settings = await self._context_settings(
                guild=guild,
                author=author,
                channel=channel,
                source=message,
                manage_messages=True,
                automatic=automatic,
            )
            if settings is None or guild is None:
                return False
            guild_settings, user_settings = settings
            resolved = self._destination_for(
                guild=guild,
                source_channel=channel,
                guild_settings=guild_settings,
            )
            source_snapshot = self._source_snapshot(message)
            if resolved is None or source_snapshot is None:
                return False
            destination, _funnel = resolved
            destination_snapshot = self._destination_snapshot(destination)
            targets = self._targets(
                target_content if target_content is not None else source_snapshot[4],
                guild_settings,
            )
            if metadata_only:
                targets = [
                    target for target in targets if target.domain.id in METADATA_DOMAINS
                ]
            if destination_snapshot is None or not targets:
                return False
            snapshot = SourceSnapshot(
                source=source_snapshot,
                guild_settings=copy.deepcopy(guild_settings),
                user_settings=copy.deepcopy(user_settings),
                destination=destination_snapshot,
                targets=tuple(targets),
            )

        prepared = await self._enrich_targets(
            targets,
            destination,
            snapshot.guild_settings,
        )

        process_args: dict[str, Any] | None = None
        async with self._s3_lock:
            if token is not None and token.is_set():
                return False
            fresh = await self._refetch_snapshot(message, snapshot.source)
            if fresh is None:
                return False
            fresh_guild = getattr(fresh, "guild", None)
            fresh_author = getattr(fresh, "author", None)
            fresh_channel = getattr(fresh, "channel", None)
            settings = await self._context_settings(
                guild=fresh_guild,
                author=fresh_author,
                channel=fresh_channel,
                source=fresh,
                manage_messages=True,
                automatic=automatic,
            )
            if settings is None:
                return False
            guild_settings, user_settings = settings
            resolved = self._destination_for(
                guild=fresh_guild,
                source_channel=fresh_channel,
                guild_settings=guild_settings,
            )
            if resolved is None:
                return False
            destination, funnel = resolved
            targets_now = self._targets(
                target_content if target_content is not None else snapshot.source[4],
                guild_settings,
            )
            if metadata_only:
                targets_now = [
                    target
                    for target in targets_now
                    if target.domain.id in METADATA_DOMAINS
                ]
            if (
                copy.deepcopy(guild_settings) != snapshot.guild_settings
                or copy.deepcopy(user_settings) != snapshot.user_settings
                or self._destination_snapshot(destination) != snapshot.destination
                or tuple(targets_now) != snapshot.targets
            ):
                return False
            process_args = {
                "message": fresh,
                "targets": prepared,
                "mode": self._mode(guild_settings, user_settings),
                "sender": destination.send if funnel else None,
                "guild": fresh_guild,
                "author": fresh_author,
                "channel": fresh_channel,
                "destination": destination,
                "guild_settings": guild_settings,
                "user_settings": user_settings,
                "token": token,
                "source_snapshot": snapshot.source,
                "automatic": automatic,
            }
        if process_args is None:
            return False
        return await self._process(**process_args)

    async def _process_extraction_without_source(
        self,
        *,
        author: Any,
        guild: Any,
        channel: Any,
        content: str,
        token: asyncio.Event | None,
        automatic: bool = False,
    ) -> bool:
        process_args: dict[str, Any] | None = None
        async with self._s3_lock:
            if token is not None and token.is_set():
                return False
            settings = await self._context_settings(
                guild=guild,
                author=author,
                channel=channel,
                manage_messages=False,
                automatic=automatic,
            )
            if settings is None:
                return False
            guild_settings, user_settings = settings
            resolved = self._destination_for(
                guild=guild,
                source_channel=channel,
                guild_settings=guild_settings,
            )
            if resolved is None:
                return False
            destination, _funnel = resolved
            destination_snapshot = self._destination_snapshot(destination)
            targets = [
                target
                for target in self._targets(content, guild_settings)
                if target.domain.id in METADATA_DOMAINS
            ]
            if destination_snapshot is None or not targets:
                return False
            guild_snapshot = copy.deepcopy(guild_settings)
            user_snapshot = copy.deepcopy(user_settings)

        prepared = await self._enrich_targets(
            targets,
            destination,
            guild_snapshot,
        )

        async with self._s3_lock:
            if token is not None and token.is_set():
                return False
            settings = await self._context_settings(
                guild=guild,
                author=author,
                channel=channel,
                manage_messages=False,
                automatic=automatic,
            )
            if settings is None:
                return False
            guild_settings, user_settings = settings
            resolved = self._destination_for(
                guild=guild,
                source_channel=channel,
                guild_settings=guild_settings,
            )
            if resolved is None:
                return False
            destination, _funnel = resolved
            if (
                guild_settings != guild_snapshot
                or user_settings != user_snapshot
                or self._destination_snapshot(destination) != destination_snapshot
                or [
                    target
                    for target in self._targets(content, guild_settings)
                    if target.domain.id in METADATA_DOMAINS
                ]
                != targets
            ):
                return False
            process_args = {
                "message": None,
                "targets": prepared,
                "mode": self._mode(guild_settings, user_settings),
                "may_suppress": False,
                "sender": destination.send,
                "guild": guild,
                "author": author,
                "channel": channel,
                "destination": destination,
                "guild_settings": guild_settings,
                "user_settings": user_settings,
                "token": token,
                "automatic": automatic,
            }
        if process_args is None:
            return False
        return await self._process(**process_args)

    async def _stored_replacement_records(self) -> dict[str, dict[str, Any]]:
        raw = await _value(getattr(self, "config", None), "replacement_records", {})
        if not isinstance(raw, dict):
            return {}
        return {
            message_id: copy.deepcopy(raw[message_id])
            for message_id in sorted(raw, key=lambda item: int(item) if str(item).isdigit() else 0)
            if _valid_record(message_id, raw[message_id])
        }

    async def _replacement_records(self) -> dict[str, dict[str, Any]]:
        self._ensure_s3_runtime()
        records = await self._stored_replacement_records()
        for message_id in self._pending_evictions:
            records.pop(message_id, None)
        records.update(
            {
                message_id: copy.deepcopy(record)
                for message_id, record in self._pending_records.items()
                if _valid_record(message_id, record)
            }
        )
        return records

    async def _set_replacement_records(self, records: dict[str, dict[str, Any]]) -> None:
        field = getattr(getattr(self, "config", None), "replacement_records", None)
        setter = getattr(field, "set", None)
        if not callable(setter):
            raise RuntimeError("replacement record storage is unavailable")
        ordered = {
            message_id: copy.deepcopy(records[message_id])
            for message_id in sorted(records, key=int)
        }
        await setter(ordered)
        self._pending_records.clear()
        self._pending_evictions.clear()

    async def _persist_replacements(
        self,
        new_records: dict[str, dict[str, Any]],
        token: asyncio.Event | None,
        committed_ids: set[int] | None = None,
    ) -> tuple[bool, list[tuple[int, dict[str, Any]]]]:
        if token is not None and token.is_set():
            return False, []
        records = await self._replacement_records()
        if token is not None and token.is_set():
            return False, []
        if (
            not new_records
            or any(not _valid_record(message_id, record) for message_id, record in new_records.items())
            or set(records).intersection(new_records)
            or len(records) + len(new_records) > MAX_GLOBAL_RECORDS
        ):
            return False, []

        victims: list[tuple[int, dict[str, Any]]] = []
        for guild_id in sorted({record["guild_id"] for record in new_records.values()}):
            own = sorted(
                (
                    (int(message_id), record)
                    for message_id, record in records.items()
                    if record["guild_id"] == guild_id
                ),
                key=lambda item: (item[1]["created_at"], item[0]),
            )
            incoming = sum(record["guild_id"] == guild_id for record in new_records.values())
            victims.extend(own[: max(0, len(own) + incoming - MAX_GUILD_RECORDS)])

        updated = dict(records)
        for message_id, _record in victims:
            updated.pop(str(message_id), None)
            self._pending_records.pop(str(message_id), None)
            self._pending_evictions.add(str(message_id))
        self._cancel_reaction_timeouts({message_id for message_id, _record in victims})
        updated.update(copy.deepcopy(new_records))
        self._pending_records.update(copy.deepcopy(new_records))
        try:
            await self._set_replacement_records(updated)
        except asyncio.CancelledError:
            try:
                current = await self._stored_replacement_records()
                if (
                    committed_ids is not None
                    and all(current.get(key) == value for key, value in new_records.items())
                ):
                    committed_ids.update(int(key) for key in new_records)
                for key, value in tuple(self._pending_records.items()):
                    if current.get(key) == value:
                        self._pending_records.pop(key, None)
                if (
                    all(current.get(key) == value for key, value in new_records.items())
                    and all(str(message_id) not in current for message_id, _record in victims)
                ):
                    self._pending_evictions.clear()
            except Exception:
                log.error("embedfixer could not inspect cancelled record persistence", exc_info=True)
            raise
        except Exception:
            current = await self._stored_replacement_records()
            if not (
                all(current.get(key) == value for key, value in new_records.items())
                and all(str(message_id) not in current for message_id, _record in victims)
            ):
                raise
            for key, value in tuple(self._pending_records.items()):
                if current.get(key) == value:
                    self._pending_records.pop(key, None)
            self._pending_evictions.clear()
        if committed_ids is not None:
            committed_ids.update(int(key) for key in new_records)
        return True, victims

    async def _remove_records(self, message_ids: set[int]) -> bool:
        if not message_ids:
            return True
        self._ensure_s3_runtime()
        records = await self._replacement_records()
        for message_id in message_ids:
            self._pending_records.pop(str(message_id), None)
            self._pending_evictions.add(str(message_id))
        self._cancel_reaction_timeouts(message_ids)
        remaining = {
            message_id: record
            for message_id, record in records.items()
            if int(message_id) not in message_ids
        }
        if len(remaining) == len(records):
            return True
        try:
            await self._set_replacement_records(remaining)
        except Exception:
            current = await self._stored_replacement_records()
            return all(str(message_id) not in current for message_id in message_ids)
        return True

    def _channel_for(
        self,
        guild_id: int | None,
        channel_id: int,
        channel_hint: Any = None,
    ) -> Any | None:
        channel = channel_hint
        if getattr(channel, "id", None) != channel_id:
            getter = getattr(self.bot, "get_channel", None)
            channel = getter(channel_id) if callable(getter) else None
        if getattr(channel, "id", None) != channel_id:
            return None
        if guild_id is not None:
            channel_guild = getattr(getattr(channel, "guild", None), "id", None)
            if channel_guild != guild_id:
                return None
        return channel

    async def _fetch_bot_message(
        self,
        guild_id: int | None,
        channel_id: int,
        message_id: int,
        *,
        source_message_id: int | None = None,
        channel_hint: Any = None,
    ) -> Any | None:
        if (
            _snowflake(channel_id) is None
            or _snowflake(message_id) is None
            or message_id == source_message_id
        ):
            return None
        channel = self._channel_for(guild_id, channel_id, channel_hint)
        fetch = getattr(channel, "fetch_message", None)
        bot_id = _snowflake(getattr(getattr(self.bot, "user", None), "id", None))
        if not callable(fetch) or bot_id is None:
            return None
        try:
            fetched = await fetch(message_id)
        except Exception:
            return None
        if (
            getattr(fetched, "id", None) != message_id
            or getattr(getattr(fetched, "channel", None), "id", None) != channel_id
            or getattr(getattr(fetched, "author", None), "id", None) != bot_id
        ):
            return None
        if guild_id is not None and getattr(getattr(fetched, "guild", None), "id", None) != guild_id:
            return None
        return fetched

    async def _delete_bot_message(
        self,
        guild_id: int | None,
        channel_id: int,
        message_id: int,
        *,
        source_message_id: int | None = None,
        channel_hint: Any = None,
    ) -> bool:
        channel = self._channel_for(guild_id, channel_id, channel_hint)
        fetch = getattr(channel, "fetch_message", None)
        if not callable(fetch) or message_id == source_message_id:
            return False
        try:
            replacement = await fetch(message_id)
        except Exception as error:
            return isinstance(error, discord.NotFound) or getattr(error, "status", None) == 404
        bot_id = _snowflake(getattr(getattr(self.bot, "user", None), "id", None))
        if (
            bot_id is None
            or getattr(replacement, "id", None) != message_id
            or getattr(getattr(replacement, "channel", None), "id", None) != channel_id
            or getattr(getattr(replacement, "author", None), "id", None) != bot_id
            or (guild_id is not None and getattr(getattr(replacement, "guild", None), "id", None) != guild_id)
        ):
            return False
        try:
            await replacement.delete()
        except Exception as error:
            return isinstance(error, discord.NotFound) or getattr(error, "status", None) == 404
        return True

    async def _refetch_unsuppressed(self, message: Any) -> bool | None:
        fetch = getattr(getattr(message, "channel", None), "fetch_message", None)
        if fetch is None:
            return None
        try:
            fresh = await fetch(message.id)
        except Exception:
            return None
        state = _is_suppressed(fresh)
        return False if state is True else True if state is False else None

    async def _cleanup_replacements(self, message: Any | None, sent: list[Any]) -> None:
        # A replacement is deletable only when a refetch positively confirms the
        # original is still unsuppressed. Unknown/refetch-failure retains it.
        if message is not None and await self._refetch_unsuppressed(message) is not True:
            return
        raw_source_id = getattr(message, "id", None)
        source_id = _snowflake(raw_source_id, optional=True)
        if message is not None and source_id is None:
            return
        for replacement in sorted(sent, key=lambda item: getattr(item, "id", 0)):
            channel = getattr(replacement, "channel", None)
            guild_id = _snowflake(getattr(getattr(replacement, "guild", None), "id", None), optional=True)
            channel_id = _snowflake(getattr(channel, "id", None))
            replacement_id = _snowflake(getattr(replacement, "id", None))
            if channel_id is None or replacement_id is None:
                continue
            if await self._delete_bot_message(
                guild_id,
                channel_id,
                replacement_id,
                source_message_id=source_id,
                channel_hint=channel,
            ):
                self._pending_records.pop(str(replacement_id), None)
            else:
                log.debug("embedfixer replacement cleanup was not confirmed")

    async def _cleanup_persisted_replacements(
        self,
        message: Any | None,
        sent: list[Any],
        persisted_ids: set[int],
    ) -> None:
        if message is not None and await self._refetch_unsuppressed(message) is not True:
            return
        source_id = _snowflake(getattr(message, "id", None), optional=True)
        if message is not None and source_id is None:
            return
        deleted: set[int] = set()
        for replacement in sorted(sent, key=lambda item: getattr(item, "id", 0)):
            replacement_id = _snowflake(getattr(replacement, "id", None))
            channel = getattr(replacement, "channel", None)
            channel_id = _snowflake(getattr(channel, "id", None))
            guild_id = _snowflake(
                getattr(getattr(replacement, "guild", None), "id", None),
                optional=True,
            )
            if (
                replacement_id in persisted_ids
                and channel_id is not None
                and await self._delete_bot_message(
                    guild_id,
                    channel_id,
                    replacement_id,
                    source_message_id=source_id,
                    channel_hint=channel,
                )
            ):
                deleted.add(replacement_id)
        if deleted and not await self._remove_records(deleted):
            log.warning("embedfixer retained stale records after confirmed replacement deletion")

    @staticmethod
    def _definitive_rejection(error: Exception) -> bool:
        if isinstance(error, (discord.Forbidden, discord.NotFound)):
            return True
        status = getattr(error, "status", None)
        return isinstance(status, int) and status in {400, 401, 403, 404, 405, 410, 413, 415, 422}

    async def _confirm_embed(
        self,
        sent: Any,
        expected_url: str | tuple[str, ...] | list[str] | set[str],
    ) -> bool:
        raw_urls = (expected_url,) if isinstance(expected_url, str) else tuple(expected_url)
        if not any(isinstance(value, str) and value for value in raw_urls):
            return False
        if self._has_expected_embed(sent, raw_urls):
            return True
        fetch = getattr(getattr(sent, "channel", None), "fetch_message", None)
        if not callable(fetch):
            return False

        channel_id = getattr(getattr(sent, "channel", None), "id", None)
        wait_for = getattr(getattr(self, "bot", None), "wait_for", None)
        waiter: asyncio.Task[Any] | None = None
        if callable(wait_for):
            def exact_update(payload: Any) -> bool:
                return (
                    getattr(payload, "message_id", None) == getattr(sent, "id", None)
                    and getattr(payload, "channel_id", None) == channel_id
                    and self._has_expected_embed(getattr(payload, "data", None), raw_urls)
                )

            waiter = asyncio.create_task(
                wait_for("raw_message_edit", check=exact_update)
            )

        async def fetch_matches() -> bool:
            try:
                latest = await fetch(sent.id)
            except Exception:
                return False
            return self._has_expected_embed(latest, raw_urls)

        try:
            if waiter is not None:
                await asyncio.sleep(0)
            if await fetch_matches():
                return True
            if waiter is None:
                await asyncio.sleep(self.confirm_timeout)
            else:
                try:
                    await asyncio.wait_for(waiter, timeout=self.confirm_timeout)
                    return True
                except Exception:
                    pass
            return await fetch_matches()
        finally:
            if waiter is not None:
                waiter.cancel()
                await asyncio.gather(waiter, return_exceptions=True)

    @staticmethod
    def _has_expected_embed(
        message: Any,
        expected_url: str | tuple[str, ...] | list[str] | set[str],
    ) -> bool:
        raw_urls = (expected_url,) if isinstance(expected_url, str) else tuple(expected_url)
        raw_urls = tuple(value for value in raw_urls if isinstance(value, str) and value)
        embeds = message.get("embeds", ()) if isinstance(message, dict) else getattr(message, "embeds", ())
        actual = {
            embed.get("url") if isinstance(embed, dict) else getattr(embed, "url", None)
            for embed in (embeds or [])
        }
        return bool(raw_urls) and all(value in actual or _markdown_url(value) in actual for value in raw_urls)

    @staticmethod
    def _original_link_view(target: FixedTarget, settings: dict[str, Any]) -> discord.ui.View | None:
        if target.spoiler or not settings.get("show_original_link_btn", True):
            return None
        view = discord.ui.View(timeout=None)
        view.add_item(
            discord.ui.Button(
                label="View",
                style=discord.ButtonStyle.link,
                url=target.original_url,
            )
        )
        return view

    async def _add_controls(
        self,
        replacement: Any,
        target: FixedTarget,
        record: dict[str, Any],
        settings: dict[str, Any],
    ) -> None:
        verified = await self._fetch_bot_message(
            record["guild_id"],
            record["channel_id"],
            replacement.id,
            source_message_id=record["source_message_id"],
            channel_hint=getattr(replacement, "channel", None),
        )
        if verified is None:
            raise RuntimeError("replacement identity could not be verified")
        emoji: str | None = None
        if not settings.get("disable_delete_reaction", False):
            try:
                emoji = _validated_delete_emoji(settings.get("delete_msg_emoji", "❌"))
            except ValueError as error:
                raise RuntimeError("invalid delete emoji") from error
        view = self._original_link_view(target, settings)
        if view is not None:
            await verified.edit(view=view)
        if emoji is not None:
            try:
                await verified.add_reaction(emoji)
            except discord.HTTPException:
                # Discord rejects unknown/custom emoji names at the API.  The
                # confirmed replacement remains usable without this optional
                # delete control; unrelated setup failures stay fatal.
                pass
        if settings.get("rotate_fix_reaction", False) and record["source_message_id"] is not None:
            await verified.add_reaction(ROTATE_EMOJI)

    def _track_reaction_timeout(
        self,
        message_id: int,
        record: dict[str, Any],
        settings: dict[str, Any],
        *,
        delay: float | None = None,
    ) -> None:
        self._ensure_s3_runtime()
        previous = self._reaction_tasks.pop(message_id, None)
        if previous is not None and not previous.done():
            previous.cancel()
        timeout = settings.get("remove_delete_reaction_after")
        if (
            settings.get("disable_delete_reaction", False)
            or isinstance(timeout, bool)
            or not isinstance(timeout, int)
            or not 0 <= timeout <= 86400
        ):
            return
        try:
            emoji = _validated_delete_emoji(settings.get("delete_msg_emoji", "❌"))
        except ValueError:
            return
        sleep_for = timeout if delay is None else min(timeout, max(0.0, delay))

        async def expire() -> None:
            try:
                await asyncio.sleep(sleep_for)
                async with self._s3_lock:
                    records = await self._replacement_records()
                    current = records.get(str(message_id))
                    if current != record:
                        return
                    current_settings = await self._guild_settings_from_id(record["guild_id"])
                    if (
                        current_settings.get("disable_delete_reaction", False)
                        or current_settings.get("delete_msg_emoji") != emoji
                        or current_settings.get("remove_delete_reaction_after") != timeout
                    ):
                        return
                    replacement = await self._fetch_bot_message(
                        record["guild_id"],
                        record["channel_id"],
                        message_id,
                        source_message_id=record["source_message_id"],
                    )
                    if replacement is not None:
                        await replacement.remove_reaction(emoji, self.bot.user)
            except asyncio.CancelledError:
                raise
            except Exception:
                log.debug("embedfixer reaction timeout failed", exc_info=True)

        task = asyncio.create_task(expire())
        self._reaction_tasks[message_id] = task

        def remove_completed(completed: asyncio.Task[Any]) -> None:
            if self._reaction_tasks.get(message_id) is completed:
                self._reaction_tasks.pop(message_id, None)

        task.add_done_callback(remove_completed)

    def _cancel_reaction_timeouts(self, message_ids: set[int]) -> None:
        for message_id in message_ids:
            task = self._reaction_tasks.pop(message_id, None)
            if task is not None and not task.done() and task is not asyncio.current_task():
                task.cancel()

    def _record_batch(
        self,
        message: Any | None,
        replacements: list[Any],
        targets: list[FixedTarget],
        *,
        guild: Any,
        author: Any,
        channel: Any,
        destination: Any,
    ) -> dict[str, dict[str, Any]]:
        guild_id = _snowflake(getattr(guild, "id", None))
        author_id = _snowflake(getattr(author, "id", None))
        source_channel_id = _snowflake(getattr(channel, "id", None))
        destination_id = _snowflake(getattr(destination, "id", None))
        destination_guild_id = _snowflake(
            getattr(getattr(destination, "guild", None), "id", None)
        )
        if (
            guild_id is None
            or author_id is None
            or source_channel_id is None
            or destination_id is None
            or destination_guild_id != guild_id
        ):
            return {}
        source_id = _snowflake(getattr(message, "id", None), optional=True)
        edited_at = getattr(message, "edited_at", None)
        source_edited_at = _timestamp(edited_at)
        if source_id is not None and edited_at is not None and source_edited_at is None:
            return {}
        created_at = datetime.now(timezone.utc).isoformat()
        candidates = (
            extract_candidates(getattr(message, "content", ""))
            if source_id is not None
            else []
        )
        used: set[int] = set()
        records: dict[str, dict[str, Any]] = {}
        for fallback_index, (replacement, target) in enumerate(
            zip(replacements, targets, strict=True)
        ):
            replacement_id = _snowflake(getattr(replacement, "id", None))
            replacement_channel = getattr(replacement, "channel", None)
            replacement_channel_id = _snowflake(
                getattr(replacement_channel, "id", None)
            )
            replacement_guild_id = _snowflake(
                getattr(getattr(replacement_channel, "guild", None), "id", None)
            )
            if (
                replacement_id is None
                or replacement_channel_id is None
                or replacement_channel_id != destination_id
                or replacement_guild_id != guild_id
            ):
                return {}
            rotatable = (
                source_id is not None
                and replacement_channel_id == source_channel_id
                and not target.nonrotatable
            )
            if rotatable:
                candidate_index = next(
                    (
                        index
                        for index, candidate in enumerate(candidates)
                        if index not in used
                        and candidate.url == target.original_url
                        and candidate.domain.id == target.domain.id
                        and candidate.spoiler == target.spoiler
                    ),
                    None,
                )
                if candidate_index is None:
                    return {}
                used.add(candidate_index)
            else:
                candidate_index = fallback_index
            records[str(replacement_id)] = {
                "guild_id": guild_id,
                "channel_id": replacement_channel_id,
                "author_id": author_id,
                "source_message_id": source_id if rotatable else None,
                "source_edited_at": source_edited_at if rotatable else None,
                "target_index": candidate_index,
                "domain_id": int(target.domain.id),
                "method_id": target.method.id,
                "created_at": created_at,
            }
        return records

    async def _process(
        self,
        message: Any | None,
        targets: list[FixedTarget],
        *,
        mode: str = "resend",
        may_suppress: bool = True,
        sender: Any = None,
        guild: Any = None,
        author: Any = None,
        channel: Any = None,
        destination: Any = None,
        guild_settings: dict[str, Any] | None = None,
        user_settings: dict[str, Any] | None = None,
        token: asyncio.Event | None = None,
        source_snapshot: tuple[int, int, int, int, str, str | None] | None = None,
        automatic: bool = False,
        _locked: bool = False,
    ) -> bool:
        self._ensure_s3_runtime()
        del _locked
        guild = guild or getattr(message, "guild", None)
        author = author or getattr(message, "author", None)
        channel = channel or getattr(message, "channel", None)
        destination = destination or channel
        author_id = _snowflake(getattr(author, "id", None))
        owned_token = token is None and author_id is not None
        if owned_token:
            token = self._register_author(author_id)
        async def run() -> bool:
            persistent_context = all(
                value is not None
                for value in (
                    _snowflake(getattr(guild, "id", None)),
                    _snowflake(getattr(author, "id", None)),
                    _snowflake(getattr(channel, "id", None)),
                )
            )
            expected_source = source_snapshot
            if message is not None and expected_source is None:
                expected_source = self._source_snapshot(message)
            if message is not None and persistent_context and expected_source is None:
                return False
            expected_destination = self._destination_snapshot(destination)
            if persistent_context and expected_destination is None:
                return False
            expected_guild_settings = copy.deepcopy(guild_settings) if guild_settings is not None else None
            expected_user_settings = copy.deepcopy(user_settings) if user_settings is not None else None
            active_targets = list(targets[:MAX_CANDIDATES])
            sent: list[Any] = []
            confirmed_count = 0
            persisted_ids: set[int] = set()

            async def cleanup() -> None:
                if message is None and not persistent_context:
                    return
                if persisted_ids:
                    await self._cleanup_persisted_replacements(message, sent, persisted_ids)
                else:
                    await self._cleanup_replacements(message, sent)

            async def revalidate() -> tuple[Any, Any, Any, dict[str, Any], Any] | None:
                if token is not None and (
                    token.is_set()
                    or token not in self._author_inflight.get(author_id, ())
                ):
                    return None
                lookup_source = message
                lookup_guild = (
                    getattr(lookup_source, "guild", None) or guild
                    if message is not None
                    else guild
                )
                lookup_author = (
                    getattr(lookup_source, "author", None) or author
                    if message is not None
                    else author
                )
                lookup_channel = (
                    getattr(lookup_source, "channel", None) or channel
                    if message is not None
                    else channel
                )
                settings = guild_settings or copy.deepcopy(DEFAULT_GUILD_SETTINGS)
                if expected_guild_settings is not None or expected_user_settings is not None:
                    current = await self._context_settings(
                        guild=lookup_guild,
                        author=lookup_author,
                        channel=lookup_channel,
                        source=lookup_source if message is not None else None,
                        manage_messages=message is not None,
                        automatic=automatic,
                    )
                    if current is None:
                        return None
                    current_guild, current_user = current
                    if (
                        expected_guild_settings is not None
                        and current_guild != expected_guild_settings
                    ) or (
                        expected_user_settings is not None
                        and current_user != expected_user_settings
                    ):
                        return None
                    settings = current_guild
                source_for_validation = lookup_source
                if message is not None and expected_source is not None:
                    source_for_validation = await self._refetch_snapshot(message, expected_source)
                    if source_for_validation is None:
                        return None
                if message is not None and _is_suppressed(source_for_validation) is True:
                    return None
                validation_guild = (
                    getattr(source_for_validation, "guild", None) or guild
                    if message is not None
                    else guild
                )
                validation_author = (
                    getattr(source_for_validation, "author", None) or author
                    if message is not None
                    else author
                )
                if not self._role_allowed(validation_author, settings):
                    return None
                validation_channel = (
                    getattr(source_for_validation, "channel", None) or channel
                    if message is not None
                    else channel
                )
                validated_destination = destination
                if expected_destination is not None and expected_user_settings is not None:
                    resolved = self._destination_for(
                        guild=validation_guild,
                        source_channel=validation_channel,
                        guild_settings=settings,
                    )
                    if (
                        resolved is None
                        or self._destination_snapshot(resolved[0]) != expected_destination
                    ):
                        return None
                    validated_destination = resolved[0]
                return (
                    validation_guild,
                    validation_author,
                    validation_channel,
                    settings,
                    validated_destination,
                )

            async def suppress_original() -> bool:
                if not may_suppress or message is None:
                    return True
                if (
                    not persistent_context
                    and expected_source is not None
                    and await self._refetch_snapshot(message, expected_source) is None
                ):
                    await cleanup()
                    return False
                try:
                    # Suppression is the only mutation allowed on the original message.
                    await message.edit(suppress=True)
                except Exception as error:
                    if (
                        self._definitive_rejection(error)
                        and await self._refetch_unsuppressed(message) is True
                    ):
                        await cleanup()
                    return False
                return True

            share_indexes = [
                index
                for index, target in enumerate(active_targets)
                if target.domain.id == DomainId.THREADS
                and _is_threads_share_url(target.original_url)
            ]
            if share_indexes:
                resolved_shares = await asyncio.gather(
                    *(
                        self._resolve_threads_share(active_targets[index].original_url)
                        for index in share_indexes
                    ),
                    return_exceptions=True,
                )
                resolutions = dict(zip(share_indexes, resolved_shares, strict=True))
                expanded_targets: list[FixedTarget] = []
                for index, target in enumerate(active_targets):
                    if index not in resolutions:
                        expanded_targets.append(target)
                        continue
                    canonical = resolutions[index]
                    if not isinstance(canonical, str):
                        return False
                    fixed_url = apply_fix(canonical, target.method, DomainId.THREADS)
                    if fixed_url is None:
                        return False
                    # ponytail: share expansion is nonrotatable; re-resolve during rotation if needed.
                    expanded_targets.append(
                        replace(
                            target,
                            fixed_url=fixed_url,
                            author=author_profile(canonical, target.domain),
                            nonrotatable=True,
                        )
                    )
                seen_fixed_urls: set[str] = set()
                active_targets = []
                for target in expanded_targets:
                    if target.fixed_url not in seen_fixed_urls:
                        seen_fixed_urls.add(target.fixed_url)
                        active_targets.append(target)
                try:
                    async with self._s3_lock:
                        if await revalidate() is None:
                            return False
                except asyncio.CancelledError:
                    raise
                except Exception:
                    return False
            try:
                # Sending and provider preview confirmation intentionally happen without _s3_lock.
                for target in active_targets:
                    send = sender
                    kwargs: dict[str, Any] = {"allowed_mentions": discord.AllowedMentions.none()}
                    if send is None and mode == "reply" and message is not None:
                        send = getattr(message, "reply", None)
                        kwargs["mention_author"] = False
                    if send is None and message is not None:
                        send = message.channel.send
                    if send is None:
                        async with self._s3_lock:
                            await cleanup()
                        return False
                    replacement = await send(
                        target.content if target.content is not None else format_fixed(target),
                        **kwargs,
                    )
                    sent.append(replacement)
                    if not await self._confirm_embed(replacement, target.fixed_url):
                        async with self._s3_lock:
                            await cleanup()
                        return confirmed_count > 0 if not persistent_context and message is None else False
                    confirmed_count += 1
            except asyncio.CancelledError:
                async with self._s3_lock:
                    await cleanup()
                raise
            except Exception:
                async with self._s3_lock:
                    await cleanup()
                return confirmed_count > 0 if not persistent_context and message is None else False

            persisted_records: dict[str, dict[str, Any]] = {}
            async with self._s3_lock:
                try:
                    validation = await revalidate()
                    if validation is None:
                        await cleanup()
                        return False
                    (
                        validation_guild,
                        validation_author,
                        validation_channel,
                        settings,
                        validated_destination,
                    ) = validation

                    records = self._record_batch(
                        message,
                        sent,
                        active_targets,
                        guild=validation_guild,
                        author=validation_author,
                        channel=validation_channel,
                        destination=validated_destination,
                    )
                    if persistent_context:
                        if len(records) != len(sent):
                            await cleanup()
                            return False
                        persisted, _victims = await self._persist_replacements(
                            records,
                            token,
                            persisted_ids,
                        )
                        if not persisted:
                            await cleanup()
                            return False
                        validation = await revalidate()
                        if validation is None:
                            await cleanup()
                            return False
                        settings = validation[3]
                        persisted_records = copy.deepcopy(records)
                except asyncio.CancelledError:
                    await cleanup()
                    raise
                except Exception:
                    await cleanup()
                    return False if message is not None or persistent_context else confirmed_count > 0

            if persistent_context:
                by_id = {
                    int(message_id): record
                    for message_id, record in persisted_records.items()
                }
                try:
                    for replacement, target in sorted(
                        zip(sent, active_targets, strict=True),
                        key=lambda item: item[0].id,
                    ):
                        await self._add_controls(
                            replacement,
                            target,
                            by_id[replacement.id],
                            settings,
                        )
                except asyncio.CancelledError:
                    async with self._s3_lock:
                        await cleanup()
                    raise
                except Exception:
                    async with self._s3_lock:
                        await cleanup()
                    return False if message is not None or persistent_context else confirmed_count > 0

                async with self._s3_lock:
                    try:
                        validation = await revalidate()
                        current_records = await self._replacement_records()
                        if validation is None or any(
                            current_records.get(message_id) != record
                            for message_id, record in persisted_records.items()
                        ):
                            await cleanup()
                            return False
                        settings = validation[3]
                        for replacement in sorted(sent, key=lambda item: item.id):
                            self._track_reaction_timeout(
                                replacement.id,
                                by_id[replacement.id],
                                settings,
                            )
                        if await revalidate() is None:
                            await cleanup()
                            return False
                        return await suppress_original()
                    except asyncio.CancelledError:
                        await cleanup()
                        raise
                    except Exception:
                        await cleanup()
                        return False if message is not None or persistent_context else confirmed_count > 0

            async with self._s3_lock:
                try:
                    if await revalidate() is None:
                        await cleanup()
                        return False
                    return await suppress_original()
                except asyncio.CancelledError:
                    await cleanup()
                    raise
                except Exception:
                    await cleanup()
                    return False if message is not None or persistent_context else confirmed_count > 0
        try:
            return await run()
        finally:
            if owned_token:
                self._discard_author(author_id, token)

    async def _fetch_source(self, record: dict[str, Any]) -> Any | None:
        source_id = record["source_message_id"]
        if source_id is None:
            return None
        channel = self._channel_for(record["guild_id"], record["channel_id"])
        fetch = getattr(channel, "fetch_message", None)
        if not callable(fetch):
            return None
        try:
            source = await fetch(source_id)
        except Exception:
            return None
        author = getattr(source, "author", None)
        if (
            getattr(source, "id", None) != source_id
            or getattr(getattr(source, "channel", None), "id", None) != record["channel_id"]
            or getattr(getattr(source, "guild", None), "id", None) != record["guild_id"]
            or getattr(author, "id", None) != record["author_id"]
            or getattr(author, "bot", False)
            or getattr(source, "webhook_id", None) is not None
            or _timestamp(getattr(source, "edited_at", None)) != record["source_edited_at"]
        ):
            return None
        return source

    @staticmethod
    def _target_for_method(
        candidate: Candidate,
        method: FixMethod,
        settings: dict[str, Any],
    ) -> FixedTarget | None:
        parsed = urlsplit(candidate.url)
        upstream_url = urlunsplit(
            (
                parsed.scheme,
                parsed.netloc[4:] if parsed.netloc.lower().startswith("www.") else parsed.netloc,
                parsed.path,
                parsed.query,
                parsed.fragment,
            )
        )
        fixed_url = apply_fix(upstream_url, method, candidate.domain.id)
        if not fixed_url:
            return None
        return _translate_target(FixedTarget(
            original_url=candidate.url,
            fixed_url=fixed_url,
            domain=candidate.domain,
            method=method,
            author=author_profile(candidate.url, candidate.domain),
            spoiler=candidate.spoiler,
        ), settings)

    def _rotation_targets(
        self,
        source: Any,
        record: dict[str, Any],
        settings: dict[str, Any],
    ) -> tuple[Candidate, FixMethod, FixMethod, FixedTarget, FixedTarget] | None:
        candidates = extract_candidates(getattr(source, "content", ""))
        target_index = record["target_index"]
        if target_index >= len(candidates):
            return None
        candidate = candidates[target_index]
        domain_id = int(candidate.domain.id)
        disabled = _normalize_ids(settings.get("disabled_domains", []))
        enabled = _normalize_ids(settings.get("enabled_domains", []))
        if (
            domain_id != record["domain_id"]
            or domain_id in disabled
            or not candidate.domain.enabled_by_default
            and domain_id not in enabled
        ):
            return None
        skipped = set(candidate.website.skip_method_ids or [])
        methods = [
            method
            for method in candidate.domain.fix_methods
            if method.id not in skipped
        ]
        current = next(
            (method for method in methods if method.id == record["method_id"]),
            None,
        )
        if current is None or len(methods) < 2:
            return None
        next_method = methods[(methods.index(current) + 1) % len(methods)]
        old_target = self._target_for_method(candidate, current, settings)
        new_target = self._target_for_method(candidate, next_method, settings)
        if old_target is None or new_target is None:
            return None
        return candidate, current, next_method, old_target, new_target

    async def _rotate_record(
        self,
        payload: Any,
        record: dict[str, Any],
        settings: dict[str, Any],
    ) -> None:
        self._ensure_s3_runtime()
        async with self._rotation_lock:
            await self._rotate_record_transaction(payload, record, settings)

    async def _rotate_record_transaction(
        self,
        payload: Any,
        record: dict[str, Any],
        settings: dict[str, Any],
    ) -> None:
        if (
            not settings.get("rotate_fix_reaction", False)
            or payload.user_id != record["author_id"]
            or record["source_message_id"] is None
        ):
            return
        replacement = await self._fetch_bot_message(
            record["guild_id"],
            record["channel_id"],
            payload.message_id,
            source_message_id=record["source_message_id"],
        )
        if replacement is None:
            return
        reactor = getattr(payload, "member", None) or discord.Object(id=payload.user_id)
        try:
            source = await self._fetch_source(record)
            source_snapshot = self._source_snapshot(source) if source is not None else None
            rotation = (
                self._rotation_targets(source, record, settings)
                if source is not None
                else None
            )
            if source_snapshot is None or rotation is None:
                return
            _candidate, _current, next_method, old_target, new_target = rotation

            # Snapshot and identity checks are short and locked; editing and
            # provider polling below deliberately stay outside the S3 lock.
            async with self._s3_lock:
                records = await self._replacement_records()
                current_settings = await self._guild_settings_from_id(record["guild_id"])
                current_source = await self._fetch_source(record)
                current_replacement = await self._fetch_bot_message(
                    record["guild_id"],
                    record["channel_id"],
                    payload.message_id,
                    source_message_id=record["source_message_id"],
                )
                current_rotation = (
                    self._rotation_targets(current_source, record, current_settings)
                    if current_source is not None
                    else None
                )
                if (
                    records.get(str(payload.message_id)) != record
                    or current_settings != settings
                    or current_source is None
                    or self._source_snapshot(current_source) != source_snapshot
                    or current_rotation is None
                    or current_rotation[2].id != next_method.id
                    or current_replacement is None
                    or not self._has_expected_embed(
                        current_replacement,
                        current_rotation[3].fixed_url,
                    )
                ):
                    return
                replacement = current_replacement
            old_embed_urls = tuple(
                url
                for embed in (getattr(replacement, "embeds", None) or [])
                if isinstance((url := getattr(embed, "url", None)), str) and url
            )
            if not old_embed_urls:
                return
            old_content = getattr(replacement, "content", format_fixed(old_target))
            old_view = getattr(replacement, "view", None)
            if old_view is None and getattr(replacement, "components", None):
                old_view = discord.ui.View.from_message(replacement, timeout=None)

            committed = False
            try:
                await replacement.edit(
                    content=format_fixed(new_target),
                    view=self._original_link_view(new_target, settings),
                )
                if not await self._confirm_embed(replacement, new_target.fixed_url):
                    raise RuntimeError("rotated provider did not embed")
                async with self._s3_lock:
                    records = await self._replacement_records()
                    current_settings = await self._guild_settings_from_id(record["guild_id"])
                    current_source = await self._fetch_source(record)
                    current_rotation = (
                        self._rotation_targets(current_source, record, current_settings)
                        if current_source is not None
                        else None
                    )
                    current_replacement = await self._fetch_bot_message(
                        record["guild_id"],
                        record["channel_id"],
                        payload.message_id,
                        source_message_id=record["source_message_id"],
                    )
                    if (
                        records.get(str(payload.message_id)) != record
                        or current_settings != settings
                        or current_source is None
                        or self._source_snapshot(current_source) != source_snapshot
                        or current_rotation is None
                        or current_rotation[2].id != next_method.id
                        or current_replacement is None
                        or not self._has_expected_embed(
                            current_replacement,
                            new_target.fixed_url,
                        )
                    ):
                        raise RuntimeError("rotation state changed")
                    updated = copy.deepcopy(records)
                    updated[str(payload.message_id)]["method_id"] = next_method.id
                    try:
                        await self._set_replacement_records(updated)
                    except Exception:
                        current_records = await self._replacement_records()
                        if current_records.get(str(payload.message_id)) != updated[str(payload.message_id)]:
                            raise
                    committed = True
            except Exception:
                async with self._s3_lock:
                    current_records = await self._replacement_records()
                    current_record = current_records.get(str(payload.message_id))
                    if current_record != record:
                        return
                try:
                    await replacement.edit(content=old_content, view=old_view)
                    rollback = await self._confirm_embed(replacement, old_embed_urls)
                except Exception:
                    rollback = False
                cleanup_record: dict[str, Any] | None = None
                async with self._s3_lock:
                    current_records = await self._replacement_records()
                    current_record = current_records.get(str(payload.message_id))
                    if current_record == record:
                        if not rollback:
                            cleanup_record = record
                    else:
                        # A different authority may be in-flight; the stale
                        # transaction must not roll it back or clean it up.
                        cleanup_record = None
                if cleanup_record is not None:
                    async with self._s3_lock:
                        records = await self._replacement_records()
                        if records.get(str(payload.message_id)) != cleanup_record:
                            cleanup_record = None
                        else:
                            cleanup_message = await self._fetch_bot_message(
                                cleanup_record["guild_id"],
                                cleanup_record["channel_id"],
                                payload.message_id,
                                source_message_id=cleanup_record["source_message_id"],
                            )
                            records = await self._replacement_records()
                            if records.get(str(payload.message_id)) != cleanup_record:
                                cleanup_record = None
                            else:
                                deleted = await self._delete_bot_message(
                                    cleanup_record["guild_id"],
                                    cleanup_record["channel_id"],
                                    payload.message_id,
                                    source_message_id=cleanup_record["source_message_id"],
                                    channel_hint=getattr(cleanup_message, "channel", None),
                                )
                                inert = deleted
                                if not deleted and cleanup_message is not None:
                                    inert = True
                                    try:
                                        await cleanup_message.edit(view=None)
                                    except Exception:
                                        inert = False
                                    try:
                                        await cleanup_message.clear_reactions()
                                    except Exception:
                                        inert = False
                                if inert:
                                    records = await self._replacement_records()
                                    if records.get(str(payload.message_id)) == cleanup_record:
                                        await self._remove_records({payload.message_id})
                                else:
                                    log.warning(
                                        "embedfixer retained replacement authority after rotation cleanup failed"
                                    )
            if committed:
                return
        finally:
            try:
                await replacement.remove_reaction(ROTATE_EMOJI, reactor)
            except Exception:
                pass

    def _reserve_notification(self, message_id: int, reactor_id: int, recipient_id: int) -> bool:
        now = time.monotonic()
        self._notify_pairs = {
            pair: expires
            for pair, expires in self._notify_pairs.items()
            if expires > now
        }
        for user_id, sent_at in tuple(self._notify_recipients.items()):
            current = [stamp for stamp in sent_at if stamp > now - NOTIFY_WINDOW_SECONDS]
            if current:
                self._notify_recipients[user_id] = current
            else:
                self._notify_recipients.pop(user_id, None)
        pair = (message_id, reactor_id)
        if pair in self._notify_pairs or len(self._notify_pairs) >= MAX_NOTIFY_PAIRS:
            return False
        history = self._notify_recipients.get(recipient_id)
        if history is None:
            if len(self._notify_recipients) >= MAX_NOTIFY_RECIPIENTS:
                return False
            history = []
        if len(history) >= MAX_NOTIFY_PER_WINDOW:
            return False
        self._notify_pairs[pair] = now + NOTIFY_PAIR_SECONDS
        self._notify_recipients[recipient_id] = [*history, now]
        return True

    async def _prepare_notification(
        self,
        payload: Any,
        record: dict[str, Any],
    ) -> dict[str, Any] | None:
        record = copy.deepcopy(record)
        if not _valid_record(str(payload.message_id), record):
            return None
        member = getattr(payload, "member", None)
        if member is None:
            guild = getattr(self.bot, "get_guild", lambda _guild_id: None)(record["guild_id"])
            member = getattr(guild, "get_member", lambda _user_id: None)(payload.user_id)
        if (
            member is None
            or getattr(member, "bot", False)
            or getattr(member, "id", None) != payload.user_id
            or payload.user_id == record["author_id"]
        ):
            return
        user_settings = await self._scope_values(
            self._user_scope_from_id(record["author_id"]),
            DEFAULT_USER_SETTINGS,
        )
        if not user_settings.get("notify_on_react", False):
            return
        if not self._reserve_notification(
            payload.message_id,
            payload.user_id,
            record["author_id"],
        ):
            return None
        return record

    async def _deliver_notification(self, payload: Any, record: dict[str, Any]) -> None:
        recipient = getattr(self.bot, "get_user", lambda _user_id: None)(record["author_id"])
        if recipient is None:
            fetch_user = getattr(self.bot, "fetch_user", None)
            if callable(fetch_user):
                try:
                    recipient = await fetch_user(record["author_id"])
                except Exception:
                    return
        send = getattr(recipient, "send", None)
        if not callable(send):
            return
        jump_url = (
            f"https://discord.com/channels/{record['guild_id']}/"
            f"{record['channel_id']}/{payload.message_id}"
        )
        try:
            await send(
                f"Someone reacted to one of your fixed embeds: {jump_url}",
                allowed_mentions=discord.AllowedMentions.none(),
            )
        except Exception:
            return

    async def _notify_author(self, payload: Any, record: dict[str, Any]) -> None:
        prepared = await self._prepare_notification(payload, record)
        if prepared is not None:
            await self._deliver_notification(payload, prepared)

    @commands.Cog.listener()
    async def on_raw_reaction_add(self, payload: discord.RawReactionActionEvent) -> None:
        self._ensure_s3_runtime()
        bot_id = getattr(getattr(self.bot, "user", None), "id", None)
        if payload.user_id == bot_id:
            return
        rotate = False
        rotation_record: dict[str, Any] | None = None
        rotation_settings: dict[str, Any] | None = None
        notification_record: dict[str, Any] | None = None
        async with self._s3_lock:
            records = await self._replacement_records()
            record = records.get(str(payload.message_id))
            if (
                record is None
                or payload.guild_id != record["guild_id"]
                or payload.channel_id != record["channel_id"]
            ):
                return
            settings = await self._guild_settings_from_id(record["guild_id"])
            emoji = str(payload.emoji)
            delete_emoji = settings.get("delete_msg_emoji", "❌")
            if emoji == ROTATE_EMOJI and settings.get("rotate_fix_reaction", False):
                rotate = True
                rotation_record = copy.deepcopy(record)
                rotation_settings = copy.deepcopy(settings)
            elif emoji == delete_emoji:
                if (
                    not settings.get("disable_delete_reaction", False)
                    and payload.user_id == record["author_id"]
                    and await self._delete_bot_message(
                        record["guild_id"],
                        record["channel_id"],
                        payload.message_id,
                        source_message_id=record["source_message_id"],
                    )
                ):
                    await self._remove_records({payload.message_id})
                return
            else:
                notification_record = await self._prepare_notification(payload, record)
        if notification_record is not None:
            await self._deliver_notification(payload, notification_record)
        if rotate and rotation_record is not None and rotation_settings is not None:
            await self._rotate_record(payload, rotation_record, rotation_settings)
            return

    @commands.Cog.listener()
    async def on_raw_message_delete(self, payload: discord.RawMessageDeleteEvent) -> None:
        self._ensure_s3_runtime()
        async with self._s3_lock:
            records = await self._replacement_records()
            record = records.get(str(payload.message_id))
            if (
                record is not None
                and payload.guild_id == record["guild_id"]
                and payload.channel_id == record["channel_id"]
            ):
                await self._remove_records({payload.message_id})

    @commands.Cog.listener()
    async def on_raw_bulk_message_delete(self, payload: discord.RawBulkMessageDeleteEvent) -> None:
        self._ensure_s3_runtime()
        async with self._s3_lock:
            records = await self._replacement_records()
            deleted = {
                message_id
                for message_id in payload.message_ids
                if (
                    (record := records.get(str(message_id))) is not None
                    and payload.guild_id == record["guild_id"]
                    and payload.channel_id == record["channel_id"]
                )
            }
            await self._remove_records(deleted)

    async def _plain(self, ctx: commands.Context, text: str, *, ephemeral: bool = False) -> None:
        kwargs: dict[str, Any] = {"allowed_mentions": discord.AllowedMentions.none()}
        if getattr(ctx, "interaction", None) is not None:
            kwargs["ephemeral"] = ephemeral
        await ctx.send(text, **kwargs)

    @commands.hybrid_command(name="fix")
    async def manual_fix(self, ctx: commands.Context, *, link: str) -> None:
        """Manually post repaired embeds for supported links."""
        author = getattr(ctx, "author", None)
        author_id = getattr(author, "id", None)
        token = self._register_author(author_id)
        try:
            async with self._s3_lock:
                if token is not None and token.is_set():
                    return
                interaction = getattr(ctx, "interaction", None)
                guild = getattr(ctx, "guild", None)
                channel = getattr(ctx, "channel", None)
                source = None if interaction is not None else getattr(ctx, "message", None)
                settings = await self._context_settings(
                    guild=guild,
                    author=author,
                    channel=channel,
                    source=source,
                    manage_messages=source is not None,
                )
                if settings is None:
                    await self._plain(ctx, "Embed fixing is not available here.", ephemeral=True)
                    return
                guild_settings, user_settings = settings
                resolved = self._destination_for(
                    guild=guild,
                    source_channel=channel,
                    guild_settings=guild_settings,
                )
                if resolved is None:
                    await self._plain(ctx, "Embed fixing is not available here.", ephemeral=True)
                    return
                destination, funnel = resolved
                source_snapshot = self._source_snapshot(source) if source is not None else None
                targets = self._targets(link[:MAX_MESSAGE_CHARS], guild_settings)
                if not targets:
                    await self._plain(ctx, "No supported links found.", ephemeral=True)
                    return
                mode = self._mode(guild_settings, user_settings)
                sender = destination.send if funnel else None
                deferred = False
                if interaction is not None:
                    if (
                        funnel
                        or mode != "reply"
                        or any(
                            target.domain.id == DomainId.THREADS
                            and _is_threads_share_url(target.original_url)
                            for target in targets
                        )
                    ):
                        await ctx.defer(ephemeral=True)
                        deferred = True
                    if not funnel:
                        sender = ctx.send if mode == "reply" else ctx.channel.send
                elif guild is None:
                    sender = None
            success = await self._process(
                source,
                targets,
                mode=mode,
                may_suppress=source is not None and guild is not None,
                sender=sender,
                guild=guild,
                author=author,
                channel=channel,
                destination=destination,
                guild_settings=guild_settings,
                user_settings=user_settings,
                token=token,
                source_snapshot=source_snapshot,
            )
            if deferred:
                await self._plain(ctx, "Fixed." if success else "The embed could not be fixed.", ephemeral=True)
            elif not success:
                await self._plain(ctx, "The embed could not be fixed.", ephemeral=True)
        finally:
            self._discard_author(author_id, token)

    @commands.hybrid_command(name="extractmedia")
    async def manual_extract_media(self, ctx: commands.Context, *, link: str) -> None:
        """Post a fixed link with bounded provider media when policy permits."""
        author = getattr(ctx, "author", None)
        author_id = getattr(author, "id", None)
        token = self._register_author(author_id)
        try:
            interaction = getattr(ctx, "interaction", None)
            source = None if interaction is not None else getattr(ctx, "message", None)
            if interaction is not None:
                await ctx.defer(ephemeral=True)
            if source is not None and getattr(source, "guild", None) is not None:
                success = await self._process_extraction(
                    source,
                    token=token,
                    target_content=link[:MAX_MESSAGE_CHARS],
                    metadata_only=True,
                )
            else:
                success = await self._process_extraction_without_source(
                    author=author,
                    guild=getattr(ctx, "guild", None),
                    channel=getattr(ctx, "channel", None),
                    content=link[:MAX_MESSAGE_CHARS],
                    token=token,
                )
            if interaction is not None or not success:
                await self._plain(
                    ctx,
                    "Fixed." if success else "The embed could not be fixed.",
                    ephemeral=True,
                )
        finally:
            self._discard_author(author_id, token)

    async def _context_fix(self, interaction: discord.Interaction, message: discord.Message) -> None:
        author = getattr(message, "author", None)
        author_id = getattr(author, "id", None)
        token = self._register_author(author_id)
        try:
            async with self._s3_lock:
                if token is not None and token.is_set():
                    return
                await interaction.response.defer(ephemeral=True, thinking=True)
                guild = getattr(message, "guild", None)
                channel = getattr(message, "channel", None)
                settings = await self._context_settings(
                    guild=guild,
                    author=author,
                    channel=channel,
                    source=message,
                    manage_messages=True,
                )
                if settings is None or guild is None:
                    await interaction.followup.send("This message is not eligible for fixing.", ephemeral=True)
                    return
                guild_settings, user_settings = settings
                resolved = self._destination_for(
                    guild=guild,
                    source_channel=channel,
                    guild_settings=guild_settings,
                )
                if resolved is None:
                    await interaction.followup.send(
                        "This message is not eligible for fixing.",
                        ephemeral=True,
                    )
                    return
                destination, funnel = resolved
                targets = self._targets(getattr(message, "content", ""), guild_settings)
                if not targets:
                    await interaction.followup.send("No supported links found.", ephemeral=True)
                    return
                source_snapshot = self._source_snapshot(message)
            success = await self._process(
                message,
                targets,
                mode=self._mode(guild_settings, user_settings),
                sender=destination.send if funnel else None,
                guild=guild,
                author=author,
                channel=channel,
                destination=destination,
                guild_settings=guild_settings,
                user_settings=user_settings,
                token=token,
                source_snapshot=source_snapshot,
            )
            await interaction.followup.send(
                "Fixed." if success else "The embed could not be fixed.",
                ephemeral=True,
            )
        finally:
            self._discard_author(author_id, token)

    async def _context_extract(
        self,
        interaction: discord.Interaction,
        message: discord.Message,
    ) -> None:
        author = getattr(message, "author", None)
        author_id = getattr(author, "id", None)
        token = self._register_author(author_id)
        try:
            await interaction.response.defer(ephemeral=True, thinking=True)
            success = await self._process_extraction(
                message,
                token=token,
                metadata_only=True,
            )
            await interaction.followup.send(
                "Fixed." if success else "This message is not eligible for extraction.",
                ephemeral=True,
            )
        finally:
            self._discard_author(author_id, token)

    async def _send_settings(self, ctx: commands.Context) -> None:
        async with self._s3_lock:
            user = await self._scope_values(self.config.user(ctx.author), DEFAULT_USER_SETTINGS)
            guild = (
                await self._scope_values(self.config.guild(ctx.guild), DEFAULT_GUILD_SETTINGS)
                if ctx.guild is not None
                else None
            )

        embed = discord.Embed(
            title="EmbedFixer Settings",
            colour=await ctx.embed_colour(),
        )
        if guild is not None:
            embed.add_field(
                name="Cog status",
                value="✅ Enabled" if guild.get("enabled") else "❌ Disabled",
                inline=True,
            )
            embed.add_field(
                name="Guild mode",
                value=f"`{guild.get('fix_mode')}`",
                inline=True,
            )
        user_mode = user.get("fix_mode") or "follow"
        embed.add_field(name="Your mode", value=f"`{user_mode}`", inline=True)
        embed.add_field(
            name="Automatic fixing",
            value="❌ Ignored" if user.get("ignored") else "✅ Enabled",
            inline=True,
        )
        kwargs: dict[str, Any] = {
            "embed": embed,
            "allowed_mentions": discord.AllowedMentions.none(),
        }
        if getattr(ctx, "interaction", None) is not None:
            kwargs["ephemeral"] = True
        await ctx.send(**kwargs)

    @commands.hybrid_group(name="embedfixer", aliases=["ef"], invoke_without_command=True)
    async def embedfixer_group(self, ctx: commands.Context) -> None:
        """Show or change EmbedFixer settings."""
        await self._send_settings(ctx)

    @embedfixer_group.command(name="settings", with_app_command=False)
    async def embedfixer_settings(self, ctx: commands.Context) -> None:
        """Show the current EmbedFixer settings."""
        await self._send_settings(ctx)

    @embedfixer_group.command(name="help", with_app_command=False)
    async def embedfixer_help(self, ctx: commands.Context) -> None:
        """Show every EmbedFixer setting command."""
        await ctx.send_help(ctx.command.parent)

    @embedfixer_group.command(name="ignoreme")
    async def embedfixer_ignoreme(self, ctx: commands.Context, state: bool | None = None) -> None:
        """Opt in or out of automatic fixing for your messages."""
        author_id = getattr(ctx.author, "id", None)
        token = self._register_author(author_id)
        try:
            async with self._s3_lock:
                if token is not None and token.is_set():
                    return
                scope = self.config.user(ctx.author)
                current = bool(await _value(scope, "ignored", False))
                await scope.ignored.set(not current if state is None else state)
                await ctx.tick()
        finally:
            self._discard_author(author_id, token)

    @embedfixer_group.command(name="usermode")
    async def embedfixer_usermode(self, ctx: commands.Context, mode: str) -> None:
        """Choose a personal FixMode or follow the guild setting."""
        mode = mode.casefold()
        author_id = getattr(ctx.author, "id", None)
        token = self._register_author(author_id)
        try:
            async with self._s3_lock:
                if token is not None and token.is_set():
                    return
                scope = self.config.user(ctx.author)
                if mode == "follow":
                    await scope.fix_mode.clear()
                elif mode in FIX_MODES:
                    await scope.fix_mode.set(mode)
                else:
                    await self._plain(ctx, "Mode must be follow, delete_and_resend, reply, or resend.", ephemeral=True)
                    return
                await ctx.tick()
        finally:
            self._discard_author(author_id, token)

    @embedfixer_group.command(name="notify")
    async def embedfixer_notify(self, ctx: commands.Context, state: bool) -> None:
        """Enable or disable generic reaction notifications for your replacements."""
        author_id = getattr(ctx.author, "id", None)
        token = self._register_author(author_id)
        try:
            async with self._s3_lock:
                if token is not None and token.is_set():
                    return
                await self.config.user(ctx.author).notify_on_react.set(state)
                await ctx.tick()
        finally:
            self._discard_author(author_id, token)

    @embedfixer_group.command(name="enable")
    @commands.guild_only()
    @checks.admin_or_permissions(manage_guild=True)
    async def embedfixer_enable(self, ctx: commands.Context, state: bool) -> None:
        """Enable or disable automatic embed fixing in this server."""
        async with self._s3_lock:
            await self.config.guild(ctx.guild).enabled.set(state)
            await ctx.tick()

    @embedfixer_group.command(name="mode")
    @commands.guild_only()
    @checks.admin_or_permissions(manage_guild=True)
    async def embedfixer_mode(self, ctx: commands.Context, mode: str) -> None:
        """Choose how fixed links are sent in this server."""
        mode = mode.casefold()
        if mode not in FIX_MODES:
            await self._plain(ctx, "Mode must be delete_and_resend, reply, or resend.", ephemeral=True)
            return
        async with self._s3_lock:
            await self.config.guild(ctx.guild).fix_mode.set(mode)
            await ctx.tick()

    @embedfixer_group.command(name="deletecontrols")
    @commands.guild_only()
    @checks.admin_or_permissions(manage_guild=True)
    async def embedfixer_deletecontrols(self, ctx: commands.Context, state: bool) -> None:
        """Enable or disable author delete controls."""
        async with self._s3_lock:
            await self.config.guild(ctx.guild).disable_delete_reaction.set(not state)
            await ctx.tick()

    @embedfixer_group.command(name="deleteemoji")
    @commands.guild_only()
    @checks.admin_or_permissions(manage_guild=True)
    async def embedfixer_deleteemoji(self, ctx: commands.Context, emoji: str) -> None:
        """Choose the reaction used for author delete controls."""
        if emoji == ROTATE_EMOJI:
            await self._plain(ctx, "Delete emoji cannot be the rotate emoji.", ephemeral=True)
            return
        if not emoji or len(emoji) > MAX_SETTING_STRING:
            await self._plain(ctx, "Delete emoji must be between 1 and 256 characters.", ephemeral=True)
            return
        async with self._s3_lock:
            await self.config.guild(ctx.guild).delete_msg_emoji.set(emoji)
            await ctx.tick()

    @embedfixer_group.command(name="rotate")
    @commands.guild_only()
    @checks.admin_or_permissions(manage_guild=True)
    async def embedfixer_rotate(self, ctx: commands.Context, state: bool) -> None:
        """Enable or disable provider rotation controls."""
        async with self._s3_lock:
            await self.config.guild(ctx.guild).rotate_fix_reaction.set(state)
            await ctx.tick()

    @embedfixer_group.command(name="reactiontimeout")
    @commands.guild_only()
    @checks.admin_or_permissions(manage_guild=True)
    async def embedfixer_reactiontimeout(self, ctx: commands.Context, value: str) -> None:
        """Set when delete reactions are removed, or turn it off."""
        if value.casefold() == "off":
            timeout = None
        else:
            try:
                timeout = _strict_int(value)
            except ValueError:
                timeout = -1
            if not 0 <= timeout <= 86400:
                await self._plain(ctx, "Timeout must be off or an integer from 0 to 86400.", ephemeral=True)
                return
        async with self._s3_lock:
            await self.config.guild(ctx.guild).remove_delete_reaction_after.set(timeout)
            await ctx.tick()

    @embedfixer_group.command(name="originallink")
    @commands.guild_only()
    @checks.admin_or_permissions(manage_guild=True)
    async def embedfixer_originallink(self, ctx: commands.Context, state: bool) -> None:
        """Show or hide the original-link button."""
        async with self._s3_lock:
            await self.config.guild(ctx.guild).show_original_link_btn.set(state)
            await ctx.tick()

    @embedfixer_group.command(name="domain")
    @commands.guild_only()
    @checks.admin_or_permissions(manage_guild=True)
    async def embedfixer_domain(self, ctx: commands.Context, domain_name: str, state: str) -> None:
        """Enable, disable, or reset fixing for a social platform."""
        domain = _resolve_domain(domain_name)
        state = state.casefold()
        if domain is None or state not in {"default", "enable", "disable"}:
            await self._plain(ctx, "Unknown domain or state.", ephemeral=True)
            return
        async with self._s3_lock:
            scope = self.config.guild(ctx.guild)
            settings = await self._scope_values(scope, DEFAULT_GUILD_SETTINGS)
            enabled = _normalize_ids(settings.get("enabled_domains", []))
            disabled = _normalize_ids(settings.get("disabled_domains", []))
            domain_id = int(domain.id)
            enabled.discard(domain_id)
            disabled.discard(domain_id)
            if state == "enable":
                enabled.add(domain_id)
            elif state == "disable":
                disabled.add(domain_id)
            settings["enabled_domains"] = sorted(enabled)
            settings["disabled_domains"] = sorted(disabled)
            await scope.set(settings)
            await ctx.tick()

    @embedfixer_group.command(name="provider")
    @commands.guild_only()
    @checks.admin_or_permissions(manage_guild=True)
    async def embedfixer_provider(
        self,
        ctx: commands.Context,
        domain_name: str,
        provider: str = "default",
    ) -> None:
        """Choose the fix provider for a social platform."""
        domain = _resolve_domain(domain_name)
        if domain is None:
            await self._plain(ctx, "Unknown domain.", ephemeral=True)
            return
        method = None if provider.casefold() == "default" else _resolve_method(domain, provider)
        if provider.casefold() != "default" and method is None:
            await self._plain(ctx, "That provider does not belong to this domain.", ephemeral=True)
            return
        async with self._s3_lock:
            scope = self.config.guild(ctx.guild)
            choices = await _value(scope, "provider_choices", {})
            choices = dict(choices) if isinstance(choices, dict) else {}
            choices.pop(str(int(domain.id)), None)
            choices.pop(domain.id.name, None)
            choices.pop(domain.name, None)
            if method is not None:
                choices[str(int(domain.id))] = method.id
            await scope.provider_choices.set(choices)
            await ctx.tick()

    @embedfixer_group.command(name="channel")
    @commands.guild_only()
    @checks.admin_or_permissions(manage_guild=True)
    async def embedfixer_channel(
        self,
        ctx: commands.Context,
        state: str,
        channel: discord.TextChannel | None = None,
    ) -> None:
        """Allow, block, or reset embed fixing in a channel."""
        state = state.casefold()
        channel = channel or ctx.channel
        if state not in {"allow", "block", "clear"} or getattr(channel, "id", None) is None:
            await self._plain(ctx, "State must be allow, block, or clear.", ephemeral=True)
            return
        async with self._s3_lock:
            scope = self.config.guild(ctx.guild)
            settings = await self._scope_values(scope, DEFAULT_GUILD_SETTINGS)
            allowed = _normalize_ids(settings.get("enable_fix_channels", []))
            blocked = _normalize_ids(settings.get("disable_fix_channels", []))
            channel_id = int(channel.id)
            allowed.discard(channel_id)
            blocked.discard(channel_id)
            if state == "allow":
                allowed.add(channel_id)
            elif state == "block":
                blocked.add(channel_id)
            settings["enable_fix_channels"] = sorted(allowed)
            settings["disable_fix_channels"] = sorted(blocked)
            await scope.set(settings)
            await ctx.tick()

    async def _update_channel_setting(
        self,
        ctx: commands.Context,
        *,
        setting: str,
        action: str,
        channel: discord.TextChannel | None,
    ) -> None:
        action = action.casefold()
        if action not in {"add", "remove", "clear"}:
            await self._plain(
                ctx,
                "Action must be add, remove, or clear.",
                ephemeral=True,
            )
            return
        if action != "clear":
            getter = getattr(ctx.guild, "get_channel", None)
            if (
                not isinstance(channel, discord.TextChannel)
                or not callable(getter)
                or getter(channel.id) is not channel
                or getattr(getattr(channel, "guild", None), "id", None)
                != getattr(ctx.guild, "id", None)
            ):
                await self._plain(ctx, "Choose a text channel in this guild.", ephemeral=True)
                return
        async with self._s3_lock:
            scope = self.config.guild(ctx.guild)
            values = _normalize_ids(await _value(scope, setting, []))
            if action == "clear":
                values.clear()
            elif action == "add":
                values.add(channel.id)
            else:
                values.discard(channel.id)
            await getattr(scope, setting).set(sorted(values))
            await ctx.tick()

    @embedfixer_group.command(name="mediachannel")
    @commands.guild_only()
    @checks.admin_or_permissions(manage_guild=True)
    async def embedfixer_mediachannel(
        self,
        ctx: commands.Context,
        action: str,
        channel: discord.TextChannel | None = None,
    ) -> None:
        """Add or remove a media extraction channel."""
        await self._update_channel_setting(
            ctx,
            setting="extract_media_channels",
            action=action,
            channel=channel,
        )

    @embedfixer_group.command(name="showcontent")
    @commands.guild_only()
    @checks.admin_or_permissions(manage_guild=True)
    async def embedfixer_showcontent(
        self,
        ctx: commands.Context,
        action: str,
        channel: discord.TextChannel | None = None,
    ) -> None:
        """Add or remove a channel that shows post content."""
        await self._update_channel_setting(
            ctx,
            setting="show_post_content_channels",
            action=action,
            channel=channel,
        )

    @embedfixer_group.command(name="spoilerexception")
    @commands.guild_only()
    @checks.admin_or_permissions(manage_guild=True)
    async def embedfixer_spoilerexception(
        self,
        ctx: commands.Context,
        action: str,
        channel: discord.TextChannel | None = None,
    ) -> None:
        """Add or remove a channel exempt from automatic spoilers."""
        await self._update_channel_setting(
            ctx,
            setting="disable_image_spoilers",
            action=action,
            channel=channel,
        )

    @embedfixer_group.command(name="funnel")
    @commands.guild_only()
    @checks.admin_or_permissions(manage_guild=True)
    async def embedfixer_funnel(
        self,
        ctx: commands.Context,
        action: str,
        channel: discord.TextChannel | None = None,
    ) -> None:
        """Send fixed posts to a target channel, or clear it."""
        action = action.casefold()
        if action not in {"set", "clear"}:
            await self._plain(ctx, "Action must be set or clear.", ephemeral=True)
            return
        if action == "set":
            getter = getattr(ctx.guild, "get_channel", None)
            if (
                not isinstance(channel, discord.TextChannel)
                or not callable(getter)
                or getter(channel.id) is not channel
                or getattr(getattr(channel, "guild", None), "id", None)
                != getattr(ctx.guild, "id", None)
            ):
                await self._plain(ctx, "Choose a text channel in this guild.", ephemeral=True)
                return
        async with self._s3_lock:
            field = self.config.guild(ctx.guild).funnel_target_channel
            if action == "clear":
                await field.clear()
            else:
                await field.set(channel.id)
            await ctx.tick()

    @embedfixer_group.command(name="translang")
    @commands.guild_only()
    @checks.admin_or_permissions(manage_guild=True)
    async def embedfixer_translang(
        self,
        ctx: commands.Context,
        language: str,
    ) -> None:
        """Set the post translation language, or disable translation."""
        if language.casefold() in {"clear", "disable", "none", "off"}:
            normalized = None
        else:
            try:
                normalized = _normalize_translation(language, strict=True)
            except ValueError:
                await self._plain(
                    ctx,
                    "Language must be two ASCII letters or disable.",
                    ephemeral=True,
                )
                return
        async with self._s3_lock:
            field = self.config.guild(ctx.guild).translate_target_lang
            if normalized is None:
                await field.clear()
            else:
                await field.set(normalized)
            await ctx.tick()

    @embedfixer_group.command(name="botvisibility")
    @commands.guild_only()
    @checks.admin_or_permissions(manage_guild=True)
    async def embedfixer_botvisibility(
        self,
        ctx: commands.Context,
        state: bool,
    ) -> None:
        """Allow or deny fixing messages sent by bots."""
        async with self._s3_lock:
            await self.config.guild(ctx.guild).bot_visibility.set(state)
            await ctx.tick()

    @embedfixer_group.command(name="role")
    @commands.guild_only()
    @checks.admin_or_permissions(manage_guild=True)
    async def embedfixer_role(
        self,
        ctx: commands.Context,
        action: str,
        role: discord.Role | None = None,
    ) -> None:
        """Add or remove a role allowed to use automatic fixing."""
        action = action.casefold()
        if action not in {"add", "remove", "clear"} or (action != "clear" and role is None):
            await self._plain(ctx, "Action must be add, remove, or clear.", ephemeral=True)
            return
        async with self._s3_lock:
            scope = self.config.guild(ctx.guild)
            roles = _normalize_ids(await _value(scope, "whitelist_role_ids", []))
            if action == "clear":
                roles.clear()
            elif action == "add":
                roles.add(int(role.id))
            else:
                roles.discard(int(role.id))
            await scope.whitelist_role_ids.set(sorted(roles))
            await ctx.tick()

    @embedfixer_group.command(name="ignoreuser")
    @commands.guild_only()
    @checks.admin_or_permissions(manage_guild=True)
    async def embedfixer_ignoreuser(
        self,
        ctx: commands.Context,
        member: discord.Member,
        state: bool,
    ) -> None:
        """Ignore or restore automatic fixing for a member."""
        async with self._s3_lock:
            scope = self.config.guild(ctx.guild)
            ignored = _normalize_ids(await _value(scope, "ignored_users", []))
            if state:
                ignored.add(member.id)
            else:
                ignored.discard(member.id)
            await scope.ignored_users.set(sorted(ignored))
            await ctx.tick()

    @embedfixer_group.command(name="reset")
    @commands.guild_only()
    @checks.admin_or_permissions(manage_guild=True)
    async def embedfixer_reset(self, ctx: commands.Context) -> None:
        """Reset every server setting to its default."""
        async with self._s3_lock:
            await self.config.guild(ctx.guild).set(copy.deepcopy(DEFAULT_GUILD_SETTINGS))
            await ctx.tick()

    @embedfixer_group.command(name="export")
    @commands.guild_only()
    @checks.admin_or_permissions(manage_guild=True)
    async def embedfixer_export(self, ctx: commands.Context) -> None:
        """Export portable server settings as JSON."""
        async with self._s3_lock:
            settings = await self._scope_values(self.config.guild(ctx.guild), DEFAULT_GUILD_SETTINGS)
            payload = json.dumps(_export_payload(settings), ensure_ascii=False, indent=2).encode("utf-8")
            filename = f"embed_fixer_settings_{ctx.guild.id}.json"
            file = discord.File(io.BytesIO(payload), filename=filename)
            if getattr(ctx, "interaction", None) is not None:
                await ctx.send(file=file, ephemeral=True)
                return
            try:
                await ctx.author.send(file=file)
            except Exception:
                await self._plain(ctx, "I could not DM the settings file.")
                return
            await self._plain(ctx, "Settings sent by DM.")

    @embedfixer_group.command(name="import")
    @commands.guild_only()
    @checks.admin_or_permissions(manage_guild=True)
    async def embedfixer_import(self, ctx: commands.Context, attachment: discord.Attachment) -> None:
        """Import portable server settings from a JSON attachment."""
        if attachment.size > MAX_IMPORT_BYTES:
            await self._plain(ctx, "Invalid settings file.", ephemeral=True)
            return
        async with self._s3_lock:
            try:
                raw = await attachment.read()
                if len(raw) > MAX_IMPORT_BYTES:
                    raise ValueError("oversized import")
                payload = json.loads(raw.decode("utf-8"), parse_constant=_reject_json_constant)
                validated = _validated_import(payload)
                funnel_id = validated.get("funnel_target_channel")
                if funnel_id is not None:
                    getter = getattr(ctx.guild, "get_channel", None)
                    destination = getter(funnel_id) if callable(getter) else None
                    if (
                        not isinstance(destination, discord.TextChannel)
                        or getattr(destination, "id", None) != funnel_id
                        or getattr(getattr(destination, "guild", None), "id", None)
                        != getattr(ctx.guild, "id", None)
                        or not callable(getattr(destination, "send", None))
                    ):
                        raise ValueError("invalid contextual funnel channel")
            except (UnicodeDecodeError, json.JSONDecodeError, ValueError, TypeError, KeyError):
                await self._plain(ctx, "Invalid settings file.", ephemeral=True)
                return
            scope = self.config.guild(ctx.guild)
            current = await self._scope_values(scope, DEFAULT_GUILD_SETTINGS)
            current = _normalize_legacy_settings(current)[0]
            merged = copy.deepcopy(current)
            for name in PORTABLE_GUILD_SETTINGS:
                merged[name] = copy.deepcopy(validated[name])
            merged["provider_choices"] = copy.deepcopy(validated["provider_choices"])
            await scope.set(merged)
            await ctx.tick()

    @commands.Cog.listener()
    async def on_message(self, message: discord.Message) -> None:
        guild = getattr(message, "guild", None)
        if guild is None:
            return
        author = getattr(message, "author", None)
        bot_id = getattr(getattr(self.bot, "user", None), "id", None)
        if (
            author is None
            or getattr(author, "id", None) == bot_id
            or getattr(message, "webhook_id", None) is not None
        ):
            return
        author_id = getattr(author, "id", None)
        token = self._register_author(author_id)
        try:
            extract = False
            async with self._s3_lock:
                if token is not None and token.is_set():
                    return
                get_context = getattr(self.bot, "get_context", None)
                if callable(get_context):
                    context = await get_context(message)
                    if getattr(context, "valid", False):
                        return
                channel = getattr(message, "channel", None)
                settings = await self._context_settings(
                    guild=guild,
                    author=author,
                    channel=channel,
                    source=message,
                    manage_messages=True,
                    automatic=True,
                )
                if settings is None:
                    return
                guild_settings, user_settings = settings
                resolved = self._destination_for(
                    guild=guild,
                    source_channel=channel,
                    guild_settings=guild_settings,
                )
                if resolved is None:
                    return
                destination, funnel = resolved
                source_snapshot = self._source_snapshot(message)
                targets = self._targets(getattr(message, "content", ""), guild_settings)
                extract = (
                    getattr(channel, "id", None)
                    in _normalize_ids(guild_settings.get("extract_media_channels", []))
                )
            if targets and not extract:
                await self._process(
                    message,
                    targets,
                    mode=self._mode(guild_settings, user_settings),
                    sender=destination.send if funnel else None,
                    guild=guild,
                    author=author,
                    channel=channel,
                    destination=destination,
                    guild_settings=guild_settings,
                    user_settings=user_settings,
                    token=token,
                    source_snapshot=source_snapshot,
                    automatic=True,
                )
            if extract:
                await self._process_extraction(message, token=token, automatic=True)
        finally:
            self._discard_author(author_id, token)


__all__ = [
    "Candidate",
    "DEFAULT_GLOBAL_SETTINGS",
    "DEFAULT_GUILD_SETTINGS",
    "DEFAULT_USER_SETTINGS",
    "EmbedFixer",
    "FixedTarget",
    "extract_candidates",
    "extract_urls",
    "fixed_targets",
    "format_fixed",
]
