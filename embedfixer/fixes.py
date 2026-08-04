"""Provider inventory adapted from seriaati/embed-fixer.

The inventory and transformation rules are derived from GPL-3.0 upstream
commit ``42be298c49c3c3910859d1f27943abf9c4e95eb8``:
https://github.com/seriaati/embed-fixer/tree/42be298c49c3c3910859d1f27943abf9c4e95eb8
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Final
from urllib.parse import parse_qsl, unquote, urlencode, urlsplit, urlunsplit


EMBEDEZ_NAME = "EmbedEZ"
EMBEDEZ_REPO_URL = "https://embedez.com"


class DomainId(IntEnum):
    TWITTER = 1
    PIXIV = 2
    TIKTOK = 3
    REDDIT = 4
    INSTAGRAM = 5
    FURAFFINITY = 6
    TWITCH_CLIPS = 7
    IWARA = 8
    BLUESKY = 9
    KEMONO = 10
    FACEBOOK = 11
    BILIBILI = 12
    TUMBLR = 13
    THREADS = 14
    PTT = 15
    DEVIANTART = 16
    BILIBILI_OPUS = 17
    PINTEREST = 18
    YOUTUBE = 19


@dataclass(kw_only=True, frozen=True)
class ReplaceFix:
    old_domain: str
    new_domain: str


@dataclass(kw_only=True, frozen=True)
class AppendURLFix:
    domain: str


@dataclass(kw_only=True, frozen=True)
class FixMethod:
    id: int
    name: str
    fixes: list[ReplaceFix | AppendURLFix]
    repo_url: str | None = None
    default: bool = False
    has_ads: bool = False


@dataclass
class Website:
    pattern: str
    skip_method_ids: list[int] | None = None
    _regex: re.Pattern[str] = field(init=False, repr=False)

    def __post_init__(self) -> None:
        # Compiling once avoids repeatedly compiling attacker-controlled input.
        self._regex = re.compile(self.pattern)

    def match(self, url: str) -> bool:
        return self._regex.fullmatch(url) is not None


@dataclass(kw_only=True)
class Domain:
    id: DomainId
    name: str
    websites: list[Website]
    fix_methods: list[FixMethod]
    enabled_by_default: bool = True

    @property
    def default_fix_method(self) -> FixMethod | None:
        if not self.fix_methods:
            return None
        return next((method for method in self.fix_methods if method.default), self.fix_methods[0])

    def get_fix_method(self, fix_id: int) -> FixMethod | None:
        return next((method for method in self.fix_methods if method.id == fix_id), None)


# The order, IDs, defaults, and source provider names intentionally match the
# upstream inventory.  Do not alphabetize this list: rotation/settings use it.
DOMAINS: Final[list[Domain]] = [
    Domain(
        id=DomainId.TWITTER,
        name="Twitter/X",
        websites=[
            Website(r"https://(www.)?twitter.com/[a-zA-Z0-9_]+/status/\d+(/photo(/[1-9])?|/video/\d+)?/?"),
            Website(r"https://(www.)?x.com/[a-zA-Z0-9_]+/status/\d+(/photo(/[1-9])?|/video/\d+)?/?"),
        ],
        fix_methods=[
            FixMethod(
                id=1,
                name="FxEmbed",
                fixes=[
                    ReplaceFix(old_domain="twitter.com", new_domain="fxtwitter.com"),
                    ReplaceFix(old_domain="x.com", new_domain="fixupx.com"),
                ],
                repo_url="https://github.com/FxEmbed/FxEmbed",
                default=True,
            ),
            FixMethod(
                id=2,
                name="BetterTwitFix",
                fixes=[
                    ReplaceFix(old_domain="twitter.com", new_domain="vxtwitter.com"),
                    ReplaceFix(old_domain="x.com", new_domain="fixvx.com"),
                ],
                repo_url="https://github.com/dylanpdx/BetterTwitFix",
            ),
            FixMethod(
                id=29,
                name=EMBEDEZ_NAME,
                fixes=[
                    ReplaceFix(old_domain="twitter.com", new_domain="xeezz.com"),
                    ReplaceFix(old_domain="x.com", new_domain="xeezz.com"),
                ],
                repo_url=EMBEDEZ_REPO_URL,
                has_ads=True,
            ),
        ],
    ),
    Domain(
        id=DomainId.PIXIV,
        name="Pixiv",
        websites=[Website(r"https://(www.)?pixiv.net(/[a-zA-Z]+)?/artworks/\d+/?")],
        fix_methods=[
            FixMethod(
                id=3,
                name="Phixiv",
                fixes=[ReplaceFix(old_domain="pixiv.net", new_domain="phixiv.net")],
                repo_url="https://github.com/thelaao/phixiv",
                default=True,
            )
        ],
    ),
    Domain(
        id=DomainId.TIKTOK,
        name="TikTok",
        websites=[
            Website(r"https://(www.)?tiktok.com/(t/\w+|@[\w.]+/video/\d+)/?"),
            Website(r"https://vm.tiktok.com/\w+/?"),
            Website(r"https://vt.tiktok.com/\w+/?"),
        ],
        fix_methods=[
            FixMethod(
                id=4,
                name="fxTikTok",
                fixes=[ReplaceFix(old_domain="tiktok.com", new_domain="tnktok.com")],
                repo_url="https://github.com/okdargy/fxTikTok",
                default=True,
            ),
            FixMethod(
                id=27,
                name=EMBEDEZ_NAME,
                fixes=[ReplaceFix(old_domain="tiktok.com", new_domain="tiktokez.com")],
                repo_url=EMBEDEZ_REPO_URL,
                has_ads=True,
            ),
            FixMethod(
                id=31,
                name="KKTikTok",
                fixes=[ReplaceFix(old_domain="tiktok.com", new_domain="kktiktok.com")],
                repo_url="https://kkscript.com/",
                has_ads=True,
            ),
        ],
    ),
    Domain(
        id=DomainId.REDDIT,
        name="Reddit",
        websites=[
            Website(r"https://(www.|old.)?reddit.com/r/[\w]+/comments/[\w]+/[\w]+/?"),
            Website(r"https://(www.|old.)?reddit.com/r/[\w]+/s/[\w]+/?"),
            Website(r"https://(www.|old.)?reddit.com/user/[\w]+/comments/[\w]+/[\w]+/?"),
        ],
        fix_methods=[
            FixMethod(
                id=6,
                name="FixReddit",
                fixes=[ReplaceFix(old_domain="reddit.com", new_domain="fxreddit.seria.moe")],
                repo_url="https://github.com/MinnDevelopment/fxreddit",
                default=True,
            ),
            FixMethod(
                id=7,
                name="vxReddit",
                fixes=[ReplaceFix(old_domain="reddit.com", new_domain="vxreddit.com")],
                repo_url="https://github.com/dylanpdx/vxReddit",
            ),
            FixMethod(
                id=26,
                name=EMBEDEZ_NAME,
                fixes=[ReplaceFix(old_domain="reddit.com", new_domain="redditez.com")],
                repo_url=EMBEDEZ_REPO_URL,
                has_ads=True,
            ),
        ],
    ),
    Domain(
        id=DomainId.INSTAGRAM,
        name="Instagram",
        websites=[
            Website(r"https://(www.)?instagram.com/share/[\w]+/?", skip_method_ids=[8]),
            Website(r"https://(www.)?instagram.com/(p|reels?)/[\w]+/?"),
            Website(r"https://(www.)?instagram.com/share/(p|reels?)/[\w]+/?"),
        ],
        fix_methods=[
            FixMethod(
                id=8,
                name="InstaFix",
                fixes=[ReplaceFix(old_domain="instagram.com", new_domain="eeinstagram.com")],
                repo_url="https://github.com/Wikidepia/InstaFix",
            ),
            FixMethod(
                id=9,
                name=EMBEDEZ_NAME,
                fixes=[ReplaceFix(old_domain="instagram.com", new_domain="g.embedez.com")],
                repo_url=EMBEDEZ_REPO_URL,
                has_ads=True,
            ),
            FixMethod(
                id=23,
                name="KKInstagram",
                fixes=[ReplaceFix(old_domain="instagram.com", new_domain="kkinstagram.com")],
                repo_url="https://kkscript.com/",
                has_ads=True,
            ),
            FixMethod(
                id=34,
                name="vxinstagram",
                fixes=[ReplaceFix(old_domain="instagram.com", new_domain="fxig.seria.moe")],
                repo_url="https://github.com/Lainmode/InstagramEmbed-vxinstagram",
            ),
            FixMethod(
                id=35,
                name="InstaEmbedRouter",
                fixes=[ReplaceFix(old_domain="instagram.com", new_domain="zzinstagram.com")],
                repo_url="https://github.com/Knoppiix/InstaEmbedRouter",
            ),
            FixMethod(
                id=37,
                name="OGInstagram",
                fixes=[ReplaceFix(old_domain="instagram.com", new_domain="oginstagram.com")],
                repo_url="https://github.com/LilasKR/OGInstagram",
                default=True,
            ),
        ],
    ),
    Domain(
        id=DomainId.FURAFFINITY,
        name="FurAffinity",
        websites=[Website(r"https://(www.)?furaffinity.net/view/\d+/?")],
        fix_methods=[
            FixMethod(
                id=10,
                name="xfuraffinity",
                fixes=[ReplaceFix(old_domain="furaffinity.net", new_domain="xfuraffinity.net")],
                repo_url="https://github.com/FirraWoof/xfuraffinity",
                default=True,
            ),
            FixMethod(
                id=28,
                name="fxraffinity",
                fixes=[ReplaceFix(old_domain="furaffinity.net", new_domain="fxraffinity.net")],
                repo_url="https://fxraffinity.net/",
            ),
        ],
    ),
    Domain(
        id=DomainId.TWITCH_CLIPS,
        name="Twitch Clips",
        websites=[
            Website(r"https://m.twitch.tv/clip/[\w]+/?"),
            Website(r"https://clips.twitch.tv/[\w]+/?"),
            Website(r"https://(www.)?twitch.tv/[\w]+/clip/[\w]+/?"),
        ],
        fix_methods=[
            FixMethod(
                id=11,
                name="fxtwitch",
                fixes=[
                    ReplaceFix(old_domain="clips.twitch.tv", new_domain="fxtwitch.seria.moe/clip"),
                    ReplaceFix(old_domain="m.twitch.tv", new_domain="fxtwitch.seria.moe"),
                    ReplaceFix(old_domain="twitch.tv", new_domain="fxtwitch.seria.moe"),
                ],
                repo_url="https://github.com/seriaati/fxtwitch",
                default=True,
            )
        ],
    ),
    Domain(
        id=DomainId.IWARA,
        name="Iwara",
        websites=[Website(r"https://(www.)?iwara.tv/video/[\w]+/[\w]+/?")],
        fix_methods=[
            FixMethod(
                id=12,
                name="fxiwara",
                fixes=[ReplaceFix(old_domain="iwara.tv", new_domain="fxiwara.seria.moe")],
                repo_url="https://github.com/seriaati/fxiwara",
                default=True,
            )
        ],
    ),
    Domain(
        id=DomainId.BLUESKY,
        name="Bluesky",
        websites=[
            Website(
                r"https://(www.)?bsky.app/profile/[A-Za-z0-9._:-]{1,253}/post/[A-Za-z0-9._~-]{1,128}/?"
            )
        ],
        fix_methods=[
            FixMethod(
                id=13,
                name="VixBluesky",
                fixes=[ReplaceFix(old_domain="bsky.app", new_domain="bskx.app")],
                repo_url="https://github.com/Lexedia/VixBluesky",
                default=True,
            ),
            FixMethod(
                id=14,
                name="FxEmbed",
                fixes=[ReplaceFix(old_domain="bsky.app", new_domain="fxbsky.app")],
                repo_url="https://github.com/FxEmbed/FxEmbed",
            ),
        ],
    ),
    Domain(
        id=DomainId.KEMONO,
        name="Kemono",
        websites=[Website(r"https://(www.)?kemono.su/[a-zA-Z0-9_]+/user/[\w]+/post/[\w]+/?")],
        fix_methods=[],
    ),
    Domain(
        id=DomainId.FACEBOOK,
        name="Facebook",
        websites=[
            Website(r"https://(www.)?facebook.com/share/r/[\w]+/?"),
            Website(r"https://(www.)?facebook.com/reel/\d+/?"),
            Website(r"https://(www.)?facebook.com/share/v/[\w]+/?"),
            Website(r"https://(www.)?facebook.com/(.*)", skip_method_ids=[15]),
        ],
        fix_methods=[
            FixMethod(
                id=15,
                name=EMBEDEZ_NAME,
                fixes=[ReplaceFix(old_domain="facebook.com", new_domain="facebookez.com")],
                repo_url=EMBEDEZ_REPO_URL,
                has_ads=True,
            ),
            FixMethod(
                id=16,
                name="fxfacebook",
                fixes=[ReplaceFix(old_domain="facebook.com", new_domain="fxfb.seria.moe")],
                repo_url="https://github.com/seriaati/fxfacebook",
            ),
            FixMethod(
                id=25,
                name="facebed",
                fixes=[ReplaceFix(old_domain="facebook.com", new_domain="facebed.seria.moe")],
                repo_url="https://github.com/4pii4/facebed",
                default=True,
            ),
        ],
    ),
    Domain(
        id=DomainId.BILIBILI,
        name="Bilibili",
        websites=[
            Website(r"https://(www.|m.)?bilibili.com/video/[\w]+/?"),
            Website(r"https://(www.)?b23.tv/[\w]+/?"),
        ],
        fix_methods=[
            FixMethod(
                id=17,
                name="fxbilibili",
                fixes=[
                    ReplaceFix(old_domain="m.bilibili.com", new_domain="fxbilibili.seria.moe"),
                    ReplaceFix(old_domain="bilibili.com", new_domain="fxbilibili.seria.moe"),
                    ReplaceFix(old_domain="b23.tv", new_domain="fxbilibili.seria.moe/b23"),
                ],
                repo_url="https://github.com/seriaati/fxbilibili",
                default=True,
            ),
            FixMethod(
                id=18,
                name=EMBEDEZ_NAME,
                fixes=[ReplaceFix(old_domain="bilibili.com", new_domain="bilibiliez.com")],
                repo_url=EMBEDEZ_REPO_URL,
                has_ads=True,
            ),
            FixMethod(
                id=22,
                name="BiliFix",
                fixes=[
                    ReplaceFix(old_domain="m.bilibili.com", new_domain="vxbilibili.com"),
                    ReplaceFix(old_domain="bilibili.com", new_domain="vxbilibili.com"),
                    ReplaceFix(old_domain="b23.tv", new_domain="vxb23.tv"),
                ],
                repo_url="https://vxbilibili.com",
            ),
        ],
    ),
    Domain(
        id=DomainId.BILIBILI_OPUS,
        name="Bilibili Opus",
        websites=[
            Website(r"https://(www.|m.)?bilibili.com/opus/\d+/?"),
            Website(r"https://t.bilibili.com/\d+/?"),
        ],
        fix_methods=[
            FixMethod(
                id=36,
                name="BiliFix",
                fixes=[ReplaceFix(old_domain="bilibili.com", new_domain="vxbilibili.com")],
                repo_url="https://vxbilibili.com",
                default=True,
            )
        ],
    ),
    Domain(
        id=DomainId.TUMBLR,
        name="Tumblr",
        websites=[Website(r"https://(www\.)?tumblr\.com/[a-zA-Z0-9_-]+/[0-9]+/?([a-zA-Z0-9_-]+/?)?")],
        fix_methods=[
            FixMethod(
                id=19,
                name="fxtumblr",
                fixes=[ReplaceFix(old_domain="tumblr.com", new_domain="tpmblr.com")],
                repo_url="https://github.com/knuxify/fxtumblr",
                default=True,
            )
        ],
    ),
    Domain(
        id=DomainId.THREADS,
        name="Threads",
        websites=[
            Website(r"https://(www.)?threads.(net|com)/@[\w.]+/?"),
            Website(r"https://(www.)?threads.(net|com)/@[\w.]+/post/[\w-]+/?"),
            Website(r"https://(www.)?threads.(net|com)/share/[\w]+/?"),
        ],
        fix_methods=[
            FixMethod(
                id=20,
                name="FixThreads",
                fixes=[
                    ReplaceFix(old_domain="threads.net", new_domain="fixthreads.seria.moe"),
                    ReplaceFix(old_domain="threads.com", new_domain="fixthreads.seria.moe"),
                ],
                repo_url="https://github.com/milanmdev/fixthreads",
                default=True,
            ),
            FixMethod(
                id=21,
                name="vxThreads",
                fixes=[
                    ReplaceFix(old_domain="threads.net", new_domain="vxthreads.net"),
                    ReplaceFix(old_domain="threads.com", new_domain="vxthreads.net"),
                ],
                repo_url="https://github.com/everettsouthwick/vxThreads",
            ),
            FixMethod(
                id=33,
                name="FixEmbed",
                fixes=[AppendURLFix(domain="fixembed.app/embed")],
                repo_url="https://fixembed.app",
            ),
        ],
    ),
    Domain(
        id=DomainId.PTT,
        name="PTT",
        websites=[Website(r"https://(www.)?ptt.cc/bbs/[A-Za-z0-9_]+/M.\d+.A.[A-Z0-9]+.html/?")],
        fix_methods=[
            FixMethod(
                id=24,
                name="fxptt",
                fixes=[ReplaceFix(old_domain="ptt.cc", new_domain="fxptt.seria.moe")],
                repo_url="https://github.com/seriaati/fxptt",
            )
        ],
    ),
    Domain(
        id=DomainId.DEVIANTART,
        name="DeviantArt",
        websites=[Website(r"https://(www.)?deviantart.com/[\w.-]+/art/[\w.-]+-\d+/?")],
        fix_methods=[
            FixMethod(
                id=32,
                name="fxdeviantart",
                fixes=[ReplaceFix(old_domain="deviantart.com", new_domain="fixdeviantart.com")],
                repo_url="https://github.com/Tschrock/fixdeviantart",
                default=True,
            )
        ],
    ),
    Domain(
        id=DomainId.PINTEREST,
        name="Pinterest",
        websites=[Website(r"https://(www.)?pinterest.com/pin/\d+/?")],
        fix_methods=[
            FixMethod(
                id=38,
                name=EMBEDEZ_NAME,
                fixes=[ReplaceFix(old_domain="pinterest.com", new_domain="pinterestez.com")],
                repo_url=EMBEDEZ_REPO_URL,
                has_ads=True,
            )
        ],
    ),
    Domain(
        id=DomainId.YOUTUBE,
        name="YouTube",
        websites=[
            Website(r"https://(www.)?youtube.com/watch\?v=[\w-]+/?"),
            Website(r"https://(www.)?youtu.be/[\w-]+/?"),
        ],
        fix_methods=[
            FixMethod(
                id=39,
                name="Koutube",
                fixes=[
                    ReplaceFix(old_domain="youtube.com", new_domain="koutube.com"),
                    ReplaceFix(old_domain="youtu.be", new_domain="koutu.be"),
                ],
                repo_url="https://github.com/iGerman00/koutube",
                default=True,
            )
        ],
        enabled_by_default=False,
    ),
]


# Source hosts are explicit instead of inferred from regex text.  This keeps
# ``example.twitter.com`` and Unicode lookalikes from passing a permissive regex.
SOURCE_HOSTS: Final[dict[DomainId, frozenset[str]]] = {
    DomainId.TWITTER: frozenset({"twitter.com", "www.twitter.com", "x.com", "www.x.com"}),
    DomainId.PIXIV: frozenset({"pixiv.net", "www.pixiv.net"}),
    DomainId.TIKTOK: frozenset({"tiktok.com", "www.tiktok.com", "vm.tiktok.com", "vt.tiktok.com"}),
    DomainId.REDDIT: frozenset({"reddit.com", "www.reddit.com", "old.reddit.com"}),
    DomainId.INSTAGRAM: frozenset({"instagram.com", "www.instagram.com"}),
    DomainId.FURAFFINITY: frozenset({"furaffinity.net", "www.furaffinity.net"}),
    DomainId.TWITCH_CLIPS: frozenset({"twitch.tv", "www.twitch.tv", "m.twitch.tv", "clips.twitch.tv"}),
    DomainId.IWARA: frozenset({"iwara.tv", "www.iwara.tv"}),
    DomainId.BLUESKY: frozenset({"bsky.app", "www.bsky.app"}),
    DomainId.KEMONO: frozenset({"kemono.su", "www.kemono.su"}),
    DomainId.FACEBOOK: frozenset({"facebook.com", "www.facebook.com"}),
    DomainId.BILIBILI: frozenset({"bilibili.com", "www.bilibili.com", "m.bilibili.com", "b23.tv", "www.b23.tv"}),
    DomainId.BILIBILI_OPUS: frozenset({"bilibili.com", "www.bilibili.com", "m.bilibili.com", "t.bilibili.com"}),
    DomainId.TUMBLR: frozenset({"tumblr.com", "www.tumblr.com"}),
    DomainId.THREADS: frozenset({"threads.net", "www.threads.net", "threads.com", "www.threads.com"}),
    DomainId.PTT: frozenset({"ptt.cc", "www.ptt.cc"}),
    DomainId.DEVIANTART: frozenset({"deviantart.com", "www.deviantart.com"}),
    DomainId.PINTEREST: frozenset({"pinterest.com", "www.pinterest.com"}),
    DomainId.YOUTUBE: frozenset({"youtube.com", "www.youtube.com", "youtu.be", "www.youtu.be"}),
}


def _host(url: str) -> str | None:
    """Return a normalized ASCII host, or ``None`` for unsafe URL syntax."""
    try:
        parsed = urlsplit(url)
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.netloc:
            return None
        if parsed.username is not None or parsed.password is not None or parsed.port is not None:
            return None
        raw_host = parsed.hostname
    except ValueError:
        return None
    if not raw_host or raw_host.endswith("."):
        return None
    try:
        host = raw_host.encode("idna").decode("ascii").lower()
    except UnicodeError:
        return None
    return host


def clean_query(url: str) -> str:
    """Remove tracking parameters while retaining YouTube's content ``v``."""
    try:
        parsed = urlsplit(url)
    except ValueError:
        return url
    host = _host(url)
    keep = host in {"youtube.com", "www.youtube.com"}
    query = urlencode([(key, value) for key, value in parse_qsl(parsed.query, keep_blank_values=True) if keep and key == "v"])
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, query, parsed.fragment))


# Names retained for small integrations/tests that used the upstream utility
# names; both remain pure and bounded in S1.
remove_query_params = clean_query


def domain_in_url(url: str, domain: str) -> bool:
    host = _host(url)
    return host == domain or bool(host and host.endswith(f".{domain}"))


def replace_domain(url: str, old_domain: str, new_domain: str) -> str:
    parsed = urlsplit(url)
    if not domain_in_url(url, old_domain):
        return url
    host, _, path_prefix = new_domain.partition("/")
    path = f"/{path_prefix}/{parsed.path.lstrip('/')}" if path_prefix else parsed.path
    return urlunsplit((parsed.scheme, host, path, parsed.query, parsed.fragment))


def source_domain_for(url: str) -> Domain | None:
    """Find a source domain after strict host and website validation."""
    host = _host(url)
    if host is None:
        return None
    for domain in DOMAINS:
        if host not in SOURCE_HOSTS[domain.id]:
            continue
        parsed = urlsplit(clean_query(url))
        # Website rules operate on the URL without a fragment; upstream
        # matching otherwise treats a fragment as trailing text.
        candidate = urlunsplit(
            (parsed.scheme.casefold(), host, parsed.path, parsed.query, "")
        )
        if any(site.match(candidate) for site in domain.websites):
            return domain
    return None


def apply_fix(original_url: str, fix_method: FixMethod, domain_id: DomainId) -> str | None:
    """Apply one upstream Replace/Append transformation without network I/O."""
    if _host(original_url) not in SOURCE_HOSTS.get(domain_id, frozenset()):
        return None
    for fix in fix_method.fixes:
        if isinstance(fix, AppendURLFix):
            new_url = f"https://{fix.domain}?url={original_url}"
            if domain_id == DomainId.FACEBOOK:
                new_url = new_url.replace("/v/", "/r/")
            return new_url
        parsed = urlsplit(original_url)
        host = _host(original_url)
        if host not in {fix.old_domain} and not (host and host.endswith(f".{fix.old_domain}")):
            continue
        new_netloc, _, new_path = fix.new_domain.partition("/")
        path = f"/{new_path}/{parsed.path.lstrip('/')}" if new_path else parsed.path
        return urlunsplit((parsed.scheme, new_netloc, path, parsed.query, parsed.fragment))
    return None


_SAFE_AUTHOR = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")


def author_profile(url: str, domain: Domain) -> tuple[str, str] | None:
    """Derive an author/profile only from unambiguous local path components."""
    parsed = urlsplit(url)
    parts = [unquote(part) for part in parsed.path.split("/") if part]
    value: str | None = None
    profile_parts: list[str] = []
    if domain.id == DomainId.TWITTER and len(parts) >= 3 and parts[1] == "status":
        value, profile_parts = parts[0], [parts[0]]
    elif domain.id == DomainId.TIKTOK and parts and parts[0].startswith("@"):
        value, profile_parts = parts[0][1:], [parts[0]]
    elif domain.id == DomainId.TWITCH_CLIPS and len(parts) >= 3 and parts[1] == "clip":
        value, profile_parts = parts[0], [parts[0]]
    elif domain.id == DomainId.BLUESKY and len(parts) >= 4 and parts[0] == "profile" and parts[2] == "post":
        value, profile_parts = parts[1], parts[:2]
    elif domain.id == DomainId.TUMBLR and len(parts) >= 2 and parts[1].isdigit():
        value, profile_parts = parts[0], [parts[0]]
    elif domain.id == DomainId.THREADS and parts and parts[0].startswith("@"):
        value, profile_parts = parts[0][1:], [parts[0]]
    elif domain.id == DomainId.DEVIANTART and len(parts) >= 3 and parts[1] == "art":
        value, profile_parts = parts[0], [parts[0]]
    if not value or not _SAFE_AUTHOR.fullmatch(value):
        return None
    profile = urlunsplit((parsed.scheme, parsed.netloc, "/" + "/".join(profile_parts), "", ""))
    return f"@{value}", profile


def method_for(domain: Domain, method_id: int | None = None) -> FixMethod | None:
    return domain.default_fix_method if method_id is None else domain.get_fix_method(method_id)


__all__ = [
    "AppendURLFix",
    "DOMAINS",
    "Domain",
    "DomainId",
    "EMBEDEZ_NAME",
    "FixMethod",
    "ReplaceFix",
    "SOURCE_HOSTS",
    "Website",
    "apply_fix",
    "author_profile",
    "clean_query",
    "domain_in_url",
    "method_for",
    "remove_query_params",
    "replace_domain",
    "source_domain_for",
]
