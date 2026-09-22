"""Flag scam and hostile messages to moderators using a System One model.

The cog watches only channels a guild manager enabled one at a time, batches
recent messages into a short rolling window, asks TypeSafe Jev three judgements
about that window, and posts a report when one crosses its threshold. It never
deletes, edits, reacts to, or punishes anything: the whole output is a message
in a moderator channel.

Windows rather than single messages, for two reasons measured on 97 real
messages from the target guild on 2026-09-20. Hostility is a property of an
exchange, so a single message cannot carry it. And the question block is fixed
overhead per request, so batching cut the amortised cost per message by roughly
half.
"""

from __future__ import annotations

import asyncio
import base64
import ipaddress
import json
import logging
import re
import time
from collections import OrderedDict, defaultdict, deque
from io import BytesIO
from datetime import datetime, timedelta, timezone
from itertools import islice
from typing import Any, Iterable, Mapping, NamedTuple
from urllib.parse import urlsplit

import aiohttp
import discord
from PIL import Image, UnidentifiedImageError
from discord import app_commands
from redbot.core import Config, checks, commands, modlog
from redbot.core.bot import Red
from redbot.core.utils.views import SetApiView
from discord.ext import tasks

TOKEN_SERVICE = "messagewatch_typesafe"
API_URL = "https://api.typesafe.ai/v1/systemone"
# Pinned, not the `jev-latest` alias. The thresholds below were measured
# against this exact version, and TypeSafe's own guidance is to pin a version
# when thresholds are tuned to it, because an alias moves on their schedule and
# the probabilities behind it can change without a change here. Verified
# 2026-09-20: a request with this id returns 200 and reports `jev-1.13.0`.
# Moving it means re-measuring the thresholds, not just editing this line.
MODEL = "jev-1.13.0"

# Discord's own limit is 4000 for most users; anything longer is truncated
# before it leaves, so one pasted log cannot dominate a request.
MAX_MESSAGE_CHARS = 1_000
# How much of a message is echoed into its `scam_index` option label. An option
# has to describe what it selects: with labels that said only "第 6 則訊息" the
# model pointed at the wrong message 6 times out of 6 on one real window, at
# confidence 0.77 to 0.93, so a confidence gate would not have caught it.
# Echoing the first characters of each message fixed all four planted positions
# at 0.98 to 1.00, for about 32% more input tokens.
SCAM_OPTION_LABEL_CHARS = 48
MAX_REQUEST_BYTES = 262_144
MAX_RESPONSE_BYTES = 65_536
REQUEST_TIMEOUT_SECONDS = 30.0

# The pending queue is bounded. A channel can be enabled while no API key is
# stored, and `flush` then returns before consuming anything, so without a cap
# a busy channel would retain every message in process memory indefinitely.
# Past the cap the oldest pending message is dropped rather than the newest,
# because the current exchange is the one worth judging. Must stay above the
# largest `window_size` (25) or a window could never fill.
MAX_PENDING_MESSAGES = 64

# A window that never fills is never judged, and a quiet channel is exactly
# where that bites: a venting channel is a post, two replies and then silence,
# which is the shape the rules feature exists for. Past this many seconds with
# no new message, whatever is queued is judged even though it is short of
# window_size. Below MIN_PARTIAL_WINDOW there is not enough of an exchange to
# judge -- hostility is a property of an exchange, so one message alone cannot
# carry it -- and those are left for the next message to extend.
DEFAULT_IDLE_SECONDS = 600
MIN_PARTIAL_WINDOW = 2
# How often the sweep looks. It only reads in-memory state unless a channel is
# actually due, so the interval is about how late a report can be, not cost.
IDLE_SWEEP_SECONDS = 60

# Discord's own cap on one embed field value.
EMBED_FIELD_LIMIT = 1024

# Images. A scam in this guild is usually a screenshot with text in it, so what
# is worth pulling out of an attachment is the text, verbatim, not a
# description of the picture. A description is open-ended generation that fails
# in ways nobody can check; the characters on the screen are narrow, and they
# feed the scam judgement that already exists rather than needing a rule of
# their own.
#
# This is the first thing the cog sends anywhere other than TypeSafe, and the
# heaviest thing it has ever sent: an image can carry a face, a document, or a
# screenshot of somebody's private conversation. Off unless a manager turns it
# on for one channel.
# Content types only. There used to be a second check requiring the filename's
# extension to match the type, as defence in depth. Measured against 26 real
# attachments from this guild on 2026-09-21, it refused 9 of them: Discord
# re-encodes uploads and reports the new type while keeping the original name,
# so "image/webp" arrives called "image.png" and "image/jpeg" called
# "IMG_2007.png" routinely.
#
# It was also guarding nothing. The filename is never used to decide anything
# -- the bytes are downloaded and PIL decides what they actually are, which is
# the only check that can be true. A guard that cannot be right and refuses a
# third of real input is worse than no guard.
IMAGE_TYPES = frozenset({"image/png", "image/jpeg", "image/webp", "image/gif"})
# Both were set below what Discord actually delivers, which rejected ordinary
# images and said nothing. 8 MB is under Discord's own 10 MB upload limit for
# an account without Nitro, and 40 MP is under any current phone camera --
# 48 MP and 50 MP sensors are the norm, so a photo taken rather than
# screenshotted was refused at ingest every time.
#
# 10 MB matches what a free account can upload. 64 MP covers those sensors
# while still refusing a decompression bomb well before PIL's own ~89 MP
# guard; the pixel cap exists to bound decode work, and every image is
# downscaled to IMAGE_MAX_EDGE before it is sent regardless.
MAX_IMAGE_BYTES = 10_000_000
MAX_IMAGE_PIXELS = 64_000_000
IMAGE_MAX_EDGE = 1536  # Text stays legible far below the 4K ChannelSummary uses.
IMAGE_JPEG_QUALITY = 82
MAX_IMAGES_PER_WINDOW = 4
IMAGE_TEXT_CHARS = 600
IMAGE_TIMEOUT_SECONDS = 45.0
# Keyed by attachment id, which is stable, unlike the signed CDN URL whose
# query string changes on every fetch. Bounded so a busy channel cannot grow it
# without limit; the oldest description goes first.
IMAGE_CACHE_SIZE = 256
IMAGE_TOKEN_SERVICE = "messagewatch_vision"
# Enough to tell an HTML error page from a JSON one from an event stream, and
# short enough that a Responses API body has not reached its `output` yet.
BAD_JSON_LOG_CHARS = 200
IMAGE_PROMPT = (
    "把這張圖片裡的所有文字逐字抄出來，保留原本的換行。"
    "只輸出文字本身，不要描述畫面、不要加標題、不要解釋。"
    "看不清楚的字用 ? 代替。圖片裡沒有文字就回空白。"
)

# Measured 2026-09-20 against jev-1.13.0 through the production key. Synthetic
# cases separated at 0.93+ for scams and 0.95 for hostility, against 0.08 and
# 0.03 for the cases designed to be mistaken for them (a warning *about* a
# phishing mail, and a heated technical argument). 97 real messages from the
# guild produced a maximum of 0.05, 0.15 and 1.53 respectively, so these sit
# far above observed background. False negatives are NOT measured: the real
# sample contained no scam and no argument to catch.
DEFAULT_SCAM_THRESHOLD = 0.90
# The hostility question asks what the person written about would feel, not
# whether the text contains an attack, so its scale is not the old question's
# and the old number does not mean the same thing on it. Measured 2026-09-22
# over twelve cases: friendly teasing 0.33-0.66, hostility 0.61-0.81, and three
# runs moved any one case by at most 0.03. 0.60 sits under every hostile case
# and over four of the five teasing ones.
DEFAULT_HOSTILE_HARM_THRESHOLD = 0.60
# A separate literal question, consumed here rather than written as an
# exception inside the hostility criteria -- which was already tried and does
# not work: `is_hostile` carried 「朋友之間的玩笑互虧不算」 and still scored
# teasing at 0.76-0.80. The same shape as the `is_meta` veto, for the same
# reason (jaggedness #1, literal reading).
#
# It is what separates the two real false positives from everything else. On a
# report of eight messages joking about banning "people who worked over the
# holiday", the old question scored 0.86 and this one scores 0.29-0.31: the
# contempt is aimed at a class of absent people, not at anyone in the room.
HOSTILE_TARGET_PRESENT = 0.70
DEFAULT_HEAT_THRESHOLD = 2.50

# Rules live in the question's `criteria`, never in `state`. Two reasons, both
# from TypeSafe's own list of jev-1.13 failure modes. #5: accuracy falls as the
# state grows with content unrelated to the decision, and a whole ruleset is
# mostly irrelevant to any one window. #6: state is data the model does not
# treat as hostile, and members write the state -- a rule placed there is a rule
# a member could try to write.
MAX_RULES = 20
# 300, not 200. The rule measured hardest on this cog -- the gender-identity
# one, which moved a real case from 0.17 to 0.94 when it was rewritten -- is
# 218 characters, and it works precisely because it names the phrasings it
# covers and says why each counts. Trimming it to fit removes the part that
# made it work. Twenty rules at this length is under 7 KB, against a
# MAX_REQUEST_BYTES of 256 KB, so the cap is about keeping one rule readable
# rather than about the payload.
MAX_RULE_CHARS = 300
MAX_PURPOSE_CHARS = 500
# How much of a rule is echoed into the report's reason line.
RULE_REASON_CHARS = 60

# Buttons are addressed entirely through their own custom_id, so a report stays
# usable after a restart with no view registration to keep in step. Discord caps
# a custom_id at 100 characters: "mw" + the longest action + kind + three
# snowflakes at Discord's own 64-bit ceiling (20 digits) + five separators
# measures 72, which the test builds rather than derives. This comment said 71
# until it was run. CUSTOM_ID_LIMIT asserts the bound at build time rather than
# leaving it to a rejected message nobody sees.
ACTION_PREFIX = "mw"
CUSTOM_ID_LIMIT = 100

# label, style, the permission the clicking member needs, whether it acts on
# Discord at all. The two marks act on nothing: they record what a moderator
# judged, which is the only source of real precision data this cog can ever
# have -- every threshold in it came from synthetic cases.
ACTIONS: dict[str, tuple[str, str, str | None]] = {
    "ok": ("屬實", "secondary", None),
    "no": ("誤判", "secondary", None),
    "del": ("刪除訊息", "danger", "manage_messages"),
    "mute": ("禁言作者", "danger", "moderate_members"),
    "role": ("加上身分組", "danger", "manage_roles"),
}
DEFAULT_ACTIONS = ["ok", "no"]
MAX_TIMEOUT_MINUTES = 40_320  # Discord's own ceiling for a timeout: 28 days.

# Registered in cog_load. Red raises for an unregistered action type, so an
# action taken through a button would go unrecorded while four documents say it
# is recorded. The names are this cog's own, prefixed, so a rename in Red core
# cannot silently change what these cases mean.
CASE_TYPES = [
    {"name": "messagewatch_timeout", "default_setting": True,
     "image": "\N{SPEAKER WITH CANCELLATION STROKE}", "case_str": "MessageWatch 禁言"},
    {"name": "messagewatch_delete", "default_setting": True,
     "image": "\N{WASTEBASKET}", "case_str": "MessageWatch 刪除訊息"},
    {"name": "messagewatch_role", "default_setting": True,
     "image": "\N{NO ENTRY SIGN}", "case_str": "MessageWatch 加上身分組"},
]

DEFAULT_CHANNEL = {
    "rules": [],
    "purpose": "",
    # 0 means "use the guild's report channel". A watched channel can send its
    # reports somewhere else, because a report quotes the channel it came from:
    # a venting channel's findings carry what someone wrote there, and fewer
    # people should see those than see a scam alert.
    "report_channel": 0,
    # Which buttons a report from this channel carries. Marks only by default:
    # every action beyond them changes what this cog does to members, so a
    # manager turns each on for the channel it makes sense in. The ruleset that
    # prompted the feature enforces with a role, not a delete.
    "actions": list(DEFAULT_ACTIONS),
    "action_role": 0,
    # 0.0 means "use the guild's rule_threshold". Rules are per-channel but the
    # threshold was per-guild, and the separation between violating and clean
    # messages differs by ruleset -- measured 2026-09-20: a venting channel's
    # rules put violations at 0.94-0.98 against clean replies at 0.05-0.08, so
    # 0.85 works there, while the server-wide gender-identity rule put
    # violations at 0.49-0.96 against 0.04-0.05, so 0.85 misses half of them.
    "rule_threshold": 0.0,
    # Off unless a manager turns it on here. Sending images is a materially
    # heavier export than sending text, and the disclosure says so.
    "images": False,
}

# Measured 2026-09-20 against jev-1.13.0 with a real channel ruleset (the one
# for a venting channel: no advice, no platitudes, no "I've been there", no
# religion, no guessing at motives, no speaking for others). Nine exemplar
# cases separated at 0.94-0.98 against 0.05-0.08 for replies that are pure
# company, so the threshold sits between them with room on both sides.
DEFAULT_RULE_THRESHOLD = 0.85
# Below this, the report says a rule was broken without claiming which one.
# It does not suppress the report, and the distinction was measured: "他應該不是
# 針對你，可能只是那天壓力大" came back with any_violation 0.94 and the right rule
# at confidence 0.67. The model was sure a rule was broken and unsure which of
# two neighbouring rules it was -- both are about speaking for someone else --
# so suppressing it threw away a true positive to hide an uncertainty that
# belongs in the report instead. Whether a violation happened at all is what
# DEFAULT_RULE_THRESHOLD decides, on a separate calibrated probability.
DEFAULT_RULE_CONFIDENCE = 0.70

# Measured 2026-09-20 against jev-1.13.0 through the production key: USD
# 0.042 per million input tokens, output free. A vendor price change makes
# this silently wrong -- there is no callback that tells this cog the price
# moved -- which is why every render of the estimate it produces says
# "estimate" rather than stating a cost as fact.
DEFAULT_TOKEN_PRICE_PER_MILLION = 0.042

DEFAULT_GLOBAL = {
    "image_api_base": "",
    "image_model": "",
}

DEFAULT_GUILD = {
    # Rules every watched channel is judged against, in front of whatever that
    # channel adds. A server's posted rules apply in all of them, and typing
    # the same eight into eight channels is how a ruleset drifts apart.
    "server_rules": [],
    "report_channel": 0,
    "watched_channels": [],
    "disclosure_version": 0,
    "scam_threshold": DEFAULT_SCAM_THRESHOLD,
    "hostile_harm_threshold": DEFAULT_HOSTILE_HARM_THRESHOLD,
    "heat_threshold": DEFAULT_HEAT_THRESHOLD,
    "window_size": 8,
    "cooldown_seconds": 300,
    "rule_threshold": DEFAULT_RULE_THRESHOLD,
    "rule_confidence": DEFAULT_RULE_CONFIDENCE,
    # Counts only, keyed by which judgement was marked: {"s": {"ok": n, "no": n}}.
    # No message content, no author, no timestamp -- the data statement's "does
    # not store message content" stays true, and this is still the only real
    # precision data this cog can ever accumulate.
    "marks": {},
    "idle_seconds": DEFAULT_IDLE_SECONDS,
    # No default model. Picking one without measuring which reads CJK
    # screenshots best would be a guess dressed as a default, and the cog
    # refuses to send images until both of these are set.

    # Aggregate counters only -- integers, never message text or an author --
    # so the data statement's "does not store message content" stays true for
    # this too. Accumulated in memory and flushed here periodically, not on
    # every judgement; see `_flush_usage`. started_at is 0 until the first
    # flush ever writes one, and is never reset after that.
    "usage": {
        "messages_queued": 0,
        "windows_judged": 0,
        "reports_sent": 0,
        "input_tokens": 0,
        # The vision provider is billed separately and bills for output as
        # well, so its tokens cannot be folded into `input_tokens` above.
        # `image_cache_hits` is what makes `images_read` interpretable: a
        # reposted image is a hit, and hits cost nothing.
        "images_read": 0,
        "image_cache_hits": 0,
        # Counted separately because `images_read` used to count both, which
        # is how 11 consecutive failures were displayed as "讀圖 11 張" while
        # no image had been read at all. Measured on the production host,
        # 2026-09-22: images_read 11, every vision token counter 0, and
        # exactly 11 `vision_bad_json` lines in the log.
        "image_failures": 0,
        "vision_input_tokens": 0,
        "vision_output_tokens": 0,
        "vision_nanodollars": 0,
        "started_at": 0,
    },
    "price_per_million_input_tokens": DEFAULT_TOKEN_PRICE_PER_MILLION,
    # 0 means no dashboard configured. dashboard_message is the id the sweep
    # edits; 0 means none has been posted yet, or the last one was deleted.
    "dashboard_channel": 0,
    "dashboard_message": 0,
}

def fresh_delta() -> dict[str, int]:
    """A zeroed counter set, derived from the stored shape rather than restated.

    The same set of keys was written out three times -- here, in
    `DEFAULT_GUILD["usage"]`, and again in the test fixture -- and `+=` on a
    plain dict raises rather than starting from zero, so adding a counter to
    one of them made `image_failures` a KeyError in every path that touched it.
    Deriving it means a new counter is declared once.

    `started_at` is excluded: it is a timestamp, not something to accumulate,
    and `_flush_usage` skips a guild whose deltas are all zero.
    """
    return {key: 0 for key in DEFAULT_GUILD["usage"] if key != "started_at"}


class VisionUsage(NamedTuple):
    """What one window's image reading cost, for the dashboard.

    Output tokens are counted because the vision provider bills for them.
    TypeSafe does not -- Jev's output is free -- which is why the guild-level
    spend estimate is input-only and this one cannot be.
    """

    images_read: int = 0
    # A call that was paid for and returned nothing usable. `images_read`
    # counts what was actually read, so that a dashboard saying zero is
    # telling the truth rather than describing a feature that is not wired up.
    images_failed: int = 0
    cache_hits: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    # Nanodollars, because the provider reports its own figure and one image
    # costs around 7e-5 dollars: an integer counter keeps the usage dict
    # homogeneous and takes float accumulation out of the question entirely.
    nanodollars: int = 0
    # Why the last image in this window could not be read, for `[p]watch show`.
    # The five failure exits below logged and returned None, so a channel whose
    # vision endpoint was refusing every request looked exactly like a channel
    # where nobody had posted a picture -- the failure shape this cog is built
    # to avoid, in the one feature added without wiring it up.
    failure: str = ""

    def __add__(self, other: "VisionUsage") -> "VisionUsage":
        """Accumulate a window's images: counts add, the reason does not.

        Every numeric field sums. `failure` takes the later non-empty one, so a
        window where the third image failed reports that reason and a window
        where the third failed and the fourth succeeded still does -- one image
        having worked says nothing about the one that did not, and the surface
        this feeds shows a single line per channel.

        The slice is computed rather than written as a literal. It was `[:5]`
        against five numeric fields, so adding a sixth would have silently
        dropped `nanodollars` from every sum: the cost of a window with two
        images would have been the cost of its first.
        """
        numeric = len(self._fields) - 1
        return VisionUsage(
            *(a + b for a, b in zip(self[:numeric], other[:numeric])),
            failure=other.failure or self.failure,
        )


class Setting(NamedTuple):
    """One tunable, with what it means alongside what it accepts.

    The label and the help live here rather than in the command, so the
    dropdown, the settings table and the range check cannot disagree about
    which settings exist or what they do.
    """

    kind: type
    low: Any
    high: Any
    label: str
    help: str


SETTING_RULES: dict[str, Setting] = {
    "scam_threshold": Setting(
        float, 0.0, 1.0, "詐騙門檻",
        "詐騙機率要多高才報告。實測：合成詐騙 0.93–0.97，而「提醒別人小心釣魚信」只有 0.06。",
    ),
    # Deliberately not the old key. The question behind it changed scale, and a
    # guild that had stored 0.80 against the old one would have carried it onto
    # the new one and reported almost nothing -- silently, which is the shape
    # this cog exists to avoid. An unset new key takes the new default; the old
    # stored value is simply no longer read.
    "hostile_harm_threshold": Setting(
        float, 0.0, 1.0, "敵意門檻",
        "被針對的人會不會覺得受傷，要多高才報告。實測：朋友互虧 0.33–0.66，"
        "真正的貶低與排擠 0.61–0.81。只在攻擊對象就在這段對話裡時才會用到。",
    ),
    "heat_threshold": Setting(
        float, 0.0, 3.0, "火藥味門檻",
        "整段對話的衝突程度，滿分 3。97 則真實訊息量到的最高值是 1.53。",
    ),
    "rule_threshold": Setting(
        float, 0.0, 1.0, "違規門檻",
        "違反頻道規則的機率要多高才報告。只有設過 `[p]watch rule` 的頻道會用到。",
    ),
    "rule_confidence": Setting(
        float, 0.0, 1.0, "條文信心下限",
        "低於這個信心時，報告仍會送出，但會說「條文不確定」而不是斷定是第幾條。不是關掉報告的開關。",
    ),
    "window_size": Setting(
        int, 4, 25, "視窗大小",
        "幾則訊息判斷一次。每次判斷後往前推進一半，所以相鄰的兩次會重疊，跨界的對話不會被切開。",
    ),
    "cooldown_seconds": Setting(
        int, 0, 86_400, "冷卻秒數",
        "出過報告後，這個頻道多久內不再報告。冷卻期間的視窗會被直接丟棄、不送去判斷，所以那段時間等於沒在看。",
    ),
    "idle_seconds": Setting(
        int, 0, 86_400, "閒置判斷秒數",
        "安靜這麼久之後，就算湊不滿一個視窗也判斷（至少要 2 則）。設 0 會關掉它，"
        "湊不滿視窗的安靜頻道將永遠不會被判斷。",
    ),
    "price_per_million_input_tokens": Setting(
        float, 0.0, 1000.0, "input token 單價（每百萬美元）",
        "用來估計花費，不是即時報價。實測 jev-1.13.0 是 0.042，但供應商調整價格後"
        "這裡不會自動跟著變，儀表板顯示的花費只是估計值。",
    ),
}

# 2: a channel's rules and its purpose note began leaving Discord with every
# request. The disclosure is about what leaves, so new outbound fields are
# exactly what it exists to re-ask about, and a guild that accepted version 1
# never saw them. Bumping halts every guild until a manager accepts again,
# which is why `[p]watch show` says so in its first field.
DISCLOSURE_VERSION = 4
DISCLOSURE_TEXT = (
    "**What leaves Discord:** in an enabled channel, the text of recent human messages is sent "
    "to TypeSafe continuously, together with the name of the channel, with nobody triggering "
    "it. This is unlike an on-demand command: enabling a channel is a standing export of what "
    "people say in it. Where rules are configured for a channel, those rules and its purpose "
    "note go with every request too. Rules set server-wide apply in every watched channel and "
    "go with every request from all of them.\n"    "**Consider the channel:** a venting or confession channel is where this export costs the "
    "most, because what people write there is what they expect will not be repeated.\n"
    "**Images:** off unless a manager enables it for a channel. When it is on, image "
    "attachments in that channel are downloaded, re-encoded and sent to a separate vision "
    "provider, which is asked only to transcribe the characters in them. That transcription "
    "then travels twice: it is shown in the report, and it is also sent on to TypeSafe with "
    "the message text as part of the same judgement, so text that was only ever inside an "
    "image reaches both providers. An image can carry a face, a document, or a screenshot of "
    "someone else's private conversation, so this is a heavier export than text and is "
    "decided one channel at a time. The vision endpoint is normally https, but the bot "
    "owner may point it at a plain-HTTP address on a private network, in which case the "
    "image bytes and the API key cross that network unencrypted.\n"
    "**What does not:** Discord user IDs, display names and avatars are never sent. Authors are "
    "replaced with labels such as u1 and u2, generated per request and never stored. Embeds and "
    "links are not fetched or resolved. Image attachments are fetched only where a manager has "
    "turned image reading on for that channel, and their transcribed text is held in memory until "
    "the cog is unloaded.\n"
    "**Vendor:** TypeSafe states it does not train on customer input. Its retention terms and the "
    "accuracy of its judgements are unverified by this cog.\n"
    "**What the bot does with a result:** posts a report in the configured moderator channel. "
    "The bot never acts on its own. A report can carry buttons, and only a moderator with the "
    "matching Discord permission can press one: marking the report right or wrong records a "
    "count and nothing else, while deleting a message, timing a member out or adding a role "
    "happen only when a person presses that button, and each is recorded in the modlog with "
    "their name.\n"
    "**Scope:** a channel sends nothing until it is enabled individually, and disabling it stops "
    "the sending immediately."
)

QUESTIONS: dict[str, dict[str, Any]] = {
    "any_scam": {
        "type": "noul",
        "instructions": (
            "在 `recent_messages` 裡，是否有任何一則訊息本身正在對讀者進行詐騙或釣魚？"
        ),
        "criteria": {
            "true": "某則訊息假冒官方通知、索取帳號密碼或證件、保證高報酬的投資或打工、誘導至可疑網址領取獎勵",
            "false": "沒有這樣的訊息，或只是在討論、警告、轉述、分析詐騙，或是正常的招募與分享",
        },
    },
    "scam_index": {
        "type": "choice",
        "instructions": (
            "若 `recent_messages` 裡有詐騙訊息，是哪一則？選項是各則訊息的開頭。若沒有任何一則是詐騙，選 none。"
        ),
        "criteria": {},
    },
    # Asked as what the person written about would feel, not as whether the
    # text contains an attack. The old wording ordered the two backwards:
    # friendly teasing scored 0.76-0.80 while sarcastic contempt scored
    # 0.27-0.41, so no threshold could separate them in either direction.
    #
    # KNOWN AND MEASURED: a laughter marker excuses an attack. Appending two
    # characters to a real one drops it below the threshold -- 「你來幹嘛 沒人
    # 找你吧」 0.68 to 0.53 with XD, 「你真的很會欸」 0.66 to 0.51 with www,
    # 「恭喜啊 花了三個月做這種東西」 0.63 to 0.55 with lol (2026-09-22). So
    # anyone who wants to dodge this signal can, by typing XD.
    #
    # Writing 「句尾的 ww、XD、lol 或表情符號不會讓一句貶低變成玩笑」 into the
    # true criterion does close all three -- the first time an exception clause
    # has worked in this cog. It was measured and not taken, because it also
    # lifts mild teasing onto the line: across two runs the highest teasing
    # reached 0.63 and the lowest evasive attack 0.64, so no threshold
    # separates them. At 0.60 the clause trades those three closed evasions for
    # two more reports on jokes in one run and three in the next -- which side
    # of the line a mild tease lands on is itself unstable. Hostility precision
    # in production is currently 0 of 2, and a moderator who starts skimming
    # this channel costs more than an evasion a human reader can see through.
    # Revisit when `mark_log` has a real distribution rather than a set of
    # fifteen cases, thirteen of them written by hand.
    "is_hostile": {
        "type": "noul",
        "instructions": (
            "在 `recent_messages` 裡，最尖銳的那則訊息，"
            "被說的那個人看到之後最可能的反應是什麼？"
        ),
        "criteria": {
            "true": "覺得被貶低、被羞辱或被排擠，即使對方語氣平靜或包著稱讚",
            "false": "會笑出來、會回嗆回去，或覺得只是被虧了一下",
        },
    },
    # Whether there is anyone to be hurt. Contempt aimed at a class of people
    # who are not here is not this cog's business, and it is most of what the
    # old question was reporting.
    "hostile_target": {
        "type": "noul",
        "instructions": (
            "在 `recent_messages` 裡，最尖銳的那則訊息，"
            "針對的是不是這段對話裡的某個人？"
        ),
        "criteria": {
            "true": "針對的是這段對話裡出現過的某個發言者",
            "false": "針對的是不在這裡的人、某一類人、某種行為、或某件事情本身",
        },
    },
    "hostile_index": {
        "type": "choice",
        "instructions": (
            "若 `recent_messages` 裡有人身攻擊、嘲諷或貶低，最具攻擊性的是哪一則？"
            "選項是各則訊息的開頭。若沒有任何一則是攻擊，選 none。"
        ),
        "criteria": {},
    },
    "heat": {
        "type": "score",
        "instructions": "這段對話的人際衝突程度。只看人與人之間的緊張，不看話題本身嚴不嚴肅。",
        "criteria": [
            "平和：閒聊或協作，沒有分歧",
            "有分歧但就事論事",
            "情緒升高、語氣尖銳、開始針對對方態度",
            "吵架、出現人身攻擊或明顯失控，需要有人介入",
        ],
    },
}

# Every failure in this cog is a silent return, and to a moderator seven of
# them look exactly like a quiet week with nothing to report. The log is where
# the difference is recorded; `[p]watch show` carries the short version.
log = logging.getLogger("red.nyancogs.messagewatch")


def effective_rules(
    channel_settings: Mapping[str, Any], settings: Mapping[str, Any]
) -> list[str]:
    """The server's rules, then this channel's, capped at MAX_RULES.

    Additive rather than either/or: a venting channel's own rules are extra
    demands on top of the server's, not a replacement for them, which is what
    a member reading both posted sets would assume.

    Server first because the order is the order of the model's options, and a
    stable prefix keeps a channel's own rules at predictable numbers in
    `[p]watch rule list` as the server set grows.

    The cap truncates the channel's rules rather than the server's. Losing a
    rule silently is bad either way; the commands refuse to add past the cap,
    so this only fires when a server rule was added after a channel was
    already full.
    """
    combined = [str(rule) for rule in settings.get("server_rules") or ()]
    combined += [str(rule) for rule in channel_settings.get("rules") or ()]
    return combined[:MAX_RULES]


def effective_rule_threshold(channel_settings: Mapping[str, Any], settings: Mapping[str, Any]) -> float:
    """The rule threshold `flush`, `rule threshold` and `rule list` all use.

    0.0 stored on the channel means "inherit the guild value", not "report
    everything" -- `channel_value or guild_value` gets that right and
    `if channel_value is not None` does not, since 0.0 is a valid stored
    value and not a missing one. One function decides this so flush and the
    two commands that report it cannot drift apart on what "effective" means.
    """
    return float(channel_settings["rule_threshold"]) or float(settings["rule_threshold"])


def _bounded_probability(value: Any) -> float | None:
    """A model-reported probability, or None when it is not one.

    Provider output is untrusted: a wrong number here decides whether a report
    is posted about a real person, so anything outside 0 to 1, a boolean, a
    string or a NaN is discarded rather than coerced.
    """
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    try:
        number = float(value)
    except OverflowError:
        # json.loads produces an unbounded int and float() refuses one past the
        # double range. Bounding the value is not bounding the conversion; this
        # exact mistake shipped in ChannelSummary's cost parser first.
        return None
    return number if 0.0 <= number <= 1.0 else None


def _bounded_score(value: Any, levels: int) -> float | None:
    """A model-reported score, or None when it falls outside the defined levels."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    try:
        number = float(value)
    except OverflowError:
        return None
    return number if 0.0 <= number <= float(levels - 1) else None


def _bounded_index(value: Any, size: int) -> int | None:
    """The index the model picked, or None for `none` and anything unexpected."""
    if not isinstance(value, str) or not value.isdigit():
        return None
    try:
        index = int(value)
    except ValueError:
        # `str.isdigit` is not `int`-convertible. Measured on this Python:
        # "²".isdigit() is True and int("²") raises, and int() refuses a digit
        # string longer than sys.get_int_max_str_digits() (4300 by default),
        # which fits well inside MAX_RESPONSE_BYTES. Both are provider-
        # controlled, and neither may escape into the message handler.
        return None
    return index if 0 <= index < size else None


def _bounded_token_count(value: Any) -> int | None:
    """A model-reported token count, or None when it is not a sane one.

    Same guard shape as `_bounded_probability`, for the same reason: this
    number came from the provider and feeds straight into a spend estimate a
    moderator reads, so anything that is not a non-negative real number is
    discarded rather than coerced.
    """
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    try:
        number = float(value)
    except OverflowError:
        return None
    # `number != number` is the NaN check; the infinity check is separate and
    # is the point. json.loads turns a bare `Infinity` into float("inf"), which
    # is neither NaN nor negative, and `int(inf)` raises OverflowError -- from
    # outside judge's JSON error handler, so it would escape a function that
    # documents every failure as returning None and take the message event
    # with it. This is the fourth conversion in this repo to meet the same
    # shape: float(10**400), int("²"), json.loads recursion, and now int(inf).
    # The pattern was copied from `_bounded_probability`, which returns a float
    # and never converts, so copying it without the conversion carried the bug
    # to a new place.
    if number != number or number in (float("inf"), float("-inf")) or number < 0:
        return None
    return int(number)


def _message_options(items: list[Mapping[str, Any]], none_label: str) -> dict[str, str]:
    """One option per message, each labelled with the message it selects."""
    return {
        **{
            str(index): f"{item['alias']}：{item['text'][:SCAM_OPTION_LABEL_CHARS]}"
            for index, item in enumerate(items)
        },
        "none": none_label,
    }


def build_rule_questions(
    window: Iterable[Mapping[str, Any]], rules: list[str]
) -> dict[str, dict[str, Any]]:
    """The four rule questions, or nothing at all when a channel has no rules.

    A channel without rules asks exactly what it asked before this feature
    existed, which is why this returns an empty mapping rather than a disabled
    question: an unused question still costs tokens and still has answers that
    could be misread.

    The rules are the option labels. That is the same lesson the scam question
    learned the hard way -- an option has to describe what it selects -- and it
    is also why the ruleset is not in the state: see MAX_RULES above.
    """
    if not rules:
        return {}
    items = list(window)
    numbered = {str(number): rule for number, rule in enumerate(rules, start=1)}
    joined = "；".join(numbered.values())
    return {
        "any_violation": {
            "type": "noul",
            "instructions": (
                "在 `recent_messages` 裡，是否有訊息違反了 `rules` 所列的任一條規則？"
                "只判斷訊息本身做了什麼，不判斷它談論了什麼。"
            ),
            "criteria": {
                "true": f"某則訊息本身做出了以下任一種行為：{joined}",
                "false": (
                    "沒有訊息做出這些行為；或訊息只是在談論、引用、警告這些行為，"
                    "或是在指出別人違反規則"
                ),
            },
        },
        "meta_index": {
            "type": "choice",
            "instructions": (
                "哪一則訊息是在談論這個頻道適用的規則本身——例如指出別人違規、引用規則、"
                "或討論什麼行為在這裡可不可以？選項是各則訊息的開頭。"
                "注意：解讀或評論某個人，不算談論規則。"
            ),
            "criteria": _message_options(items, "沒有任何一則在談論這個頻道適用的規則"),
        },
        "which_rule": {
            "type": "choice",
            "instructions": "若有訊息違反規則，違反的是哪一條？只看訊息字面上做了什麼。",
            "criteria": {**numbered, "none": "沒有任何一則違反上列規則"},
        },
        "rule_index": {
            "type": "choice",
            "instructions": "若有訊息違反規則，是哪一則？選項是各則訊息的開頭。",
            "criteria": _message_options(items, "沒有任何一則違反規則"),
        },
    }


def build_questions(
    window: Iterable[Mapping[str, Any]], rules: list[str] | None = None
) -> dict[str, dict[str, Any]]:
    """The question block for this exact window.

    Options are built per request for two reasons. The model can only pick an
    option it was offered, so a short window must not be given indexes that are
    not in it. And each option label echoes the start of the message it selects:
    an ordinal alone describes nothing, and with labels that said only
    "第 6 則訊息" the model pointed one message off, reproducibly.
    """
    items = list(window)
    questions = {key: dict(value) for key, value in QUESTIONS.items()}
    questions["scam_index"]["criteria"] = _message_options(items, "沒有任何一則是詐騙")
    questions["hostile_index"]["criteria"] = _message_options(items, "沒有任何一則是攻擊")
    questions.update(build_rule_questions(items, list(rules or ())))
    return questions


def build_state(
    channel_name: str,
    window: Iterable[Mapping[str, Any]],
    purpose: str = "",
    rules: list[str] | None = None,
) -> dict[str, Any]:
    """The request state: text and a per-request label, never a Discord identity.

    The channel's purpose is one sentence of moderator-written context, and it
    earns its place: with the venting channel's own "people here want to be
    heard, not advised" present, replies that are pure company held at 0.05-0.08
    while advice held at 0.94-0.98. The rules are listed by number only, so the
    model can refer to "第 3 條" without the text of every rule sitting in the
    state -- the text lives in the question's criteria, where a member cannot
    write to it.
    """
    state: dict[str, Any] = {
        "channel": channel_name,
        "recent_messages": [
            {
                "i": index,
                "author": item["alias"],
                "text": item["text"],
                # Only when an image was actually read. An absent key says
                # nothing; a present empty one would claim the image had no
                # text, which is a different statement.
                **({"image_text": item["image_text"]} if item.get("image_text") else {}),
            }
            for index, item in enumerate(window)
        ],
    }
    # Both fields are gated on the rules, not on the purpose being set. The
    # purpose exists to sharpen a rule judgement, so with no rules configured it
    # would be an outbound field bought for nothing -- and it would quietly
    # break the guarantee that a channel without rules asks exactly what it
    # asked before this feature existed. `[p]watch rule clear` therefore stops
    # the purpose leaving too, rather than leaving half the export behind.
    if rules:
        if purpose:
            state["channel_purpose"] = purpose
        state["rules"] = [
            f"第 {number} 條" for number in range(1, len(rules) + 1)
        ]
    return state


LAN_NETWORKS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("::1/128"),
)


def _reported_nanodollars(usage: Mapping[str, Any]) -> int:
    """What the provider says this call cost, in nanodollars, or 0.

    Taken from the response rather than computed from a price table. A table
    has to be maintained by hand and is wrong the moment the vendor moves, and
    it was already wrong here: OpenRouter routes `gemma-4-31b-it` across
    fourteen providers at prices from $0.090 to $0.750 per million input
    tokens, so the number to enter depends on where a given request landed.

    Two fields, because they mean different things. `cost` is what OpenRouter
    charged the account, and it is 0 under BYOK, where the upstream provider
    bills directly -- measured on 2026-09-21 against Friendli, `cost: 0` with
    `cost_details.upstream_inference_cost: 6.94e-05`. Reading `cost` alone
    would report every BYOK call as free.
    """
    byok = usage.get("is_byok") is True
    details = usage.get("cost_details")
    raw: Any = None
    if byok and isinstance(details, Mapping):
        raw = details.get("upstream_inference_cost")
    elif not byok:
        raw = usage.get("cost")
    # A numeric type, not something float() happens to parse. `_bounded_token_count`
    # rejects "512" for the same reason: a provider sending a string is
    # sending something this code did not agree to read. bool is an int in
    # Python, and True would price a call at one nanodollar.
    if not isinstance(raw, (int, float)) or isinstance(raw, bool):
        return 0
    try:
        value = float(raw)
    except (TypeError, ValueError, OverflowError):
        return 0
    # Provider output, so bounded like every other field that arrives from
    # one. `not 0.0 <= value` rather than `value < 0.0`: NaN fails the first
    # and passes the second.
    if not 0.0 <= value <= 1_000.0:
        return 0
    return round(value * 1_000_000_000)


def endpoint_is_allowed(value: str) -> bool:
    """Whether the vision endpoint may be stored.

    `https://` to anywhere, or `http://` to a literal address inside
    LAN_NETWORKS. An image leaves Discord over this, so plain HTTP means a
    member's screenshot on the wire in clear -- acceptable on a LAN segment the
    owner controls, which is the same trade ChannelSummary already makes and
    discloses, and not acceptable across the internet.

    A hostname is refused for `http://` even when it resolves inside those
    ranges today. ChannelSummary handles hostnames by resolving them and
    checking every record at request time, because it has to; this setting does
    not, so the smaller rule is available: with no name there is no lookup, and
    with no lookup there is nothing for a later DNS answer to move.
    """
    try:
        parts = urlsplit(value)
        # `urlsplit` defers the port: a bad one raises only when it is read.
        # Reading it here means a malformed endpoint is refused at the command
        # rather than stored, left looking configured, and failing at the first
        # request where nothing surfaces the reason.
        parts.port
    except ValueError:
        return False
    # Before either scheme branch. Credentials in the URL would be readable by
    # any manager through `[p]watch vision`'s display path, which is open on
    # purpose so the people configuring a channel can see the endpoint.
    #
    # Presence, not truthiness: `urlsplit("https://@host")` gives `username`
    # as the empty string, which `or` reads as absent. That form carries no
    # credential, so it is not a leak -- but "no userinfo" is a rule one can
    # state and test, and "no non-empty userinfo" is not the rule the comment
    # above claims. An "@" inside the netloc is always the userinfo separator.
    if "@" in parts.netloc:
        return False
    if parts.scheme == "https":
        return bool(parts.hostname)
    if parts.scheme != "http":
        return False
    host = parts.hostname or ""
    # urlsplit strips the brackets from an IPv6 authority, so this parses both
    # "http://10.0.0.1:80" and "http://[fd00::1]:80".
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return False
    return any(address in network for network in LAN_NETWORKS)


class Attachments(NamedTuple):
    """What ingest kept, and why it dropped anything it did not.

    The reason travels because every refusal here is silent otherwise: these
    checks run above the five exits inside `image_text` that `[p]watch show`
    already reports, so a rejected attachment produced no log line, no note
    and no counter. It was indistinguishable from nobody having posted a
    picture, which is how a filename check that refused a third of real
    uploads survived being reported three times.
    """

    images: list[dict[str, Any]]
    skipped: str = ""


def eligible_attachments(message: Any) -> Attachments:
    """The image attachments worth reading, as plain data the queue can hold.

    Called at ingest, because the queue stores dictionaries and the
    `discord.Message` with its attachments is gone by the time a window is
    judged. The declared size and dimensions come from Discord and are
    attacker-adjacent, so they narrow the set here and the real bytes are
    checked again after download.
    """
    found: list[dict[str, Any]] = []
    skipped = ""
    for attachment in getattr(message, "attachments", ()) or ():
        content_type = getattr(attachment, "content_type", None)
        size = getattr(attachment, "size", None)
        width = getattr(attachment, "width", None)
        height = getattr(attachment, "height", None)
        url = getattr(attachment, "url", None)
        attachment_id = getattr(attachment, "id", None)
        # "image/png; charset=binary" is a legal content type and some clients
        # send one, so the parameters come off before the lookup.
        if isinstance(content_type, str):
            content_type = content_type.split(";", 1)[0].strip().casefold()
        if content_type not in IMAGE_TYPES:
            # Only named when something image-shaped was refused: a PDF or a
            # text file in a chat channel is not a problem to report.
            if isinstance(content_type, str) and content_type.startswith("image/"):
                skipped = skipped or f"image_type_{content_type.split('/', 1)[1][:16]}"
            continue
        if any(
            isinstance(value, bool) or not isinstance(value, int) or value <= 0
            for value in (size, width, height, attachment_id)
        ):
            skipped = skipped or "image_metadata_unusable"
            continue
        if not isinstance(url, str) or not url.startswith("https://"):
            skipped = skipped or "image_url_not_https"
            continue
        if size > MAX_IMAGE_BYTES:
            skipped = skipped or f"image_too_large_{size // 1_000_000}MB"
            continue
        if width * height > MAX_IMAGE_PIXELS:
            skipped = skipped or f"image_too_many_pixels_{width * height // 1_000_000}MP"
            continue
        found.append({"id": int(attachment_id), "url": url})
        if len(found) >= MAX_IMAGES_PER_WINDOW:
            break
    return Attachments(found, skipped)


def transcode_image(raw: bytes, max_edge: int = IMAGE_MAX_EDGE) -> tuple[str, bytes] | None:
    """Decode, downscale and re-encode, or None when it is not a usable image.

    Copied from ChannelSummary rather than shared, deliberately: these are two
    separately installable cogs, and importing across them would make this one
    stop working when the other is not installed.

    Pillow decoding is the validator -- bytes that are not a real image raise
    here. The size is read from the header before any pixel is decoded, because
    Pillow's own bomb guard does not fire until twice MAX_IMAGE_PIXELS and the
    ingest step only saw the dimensions Discord declared. Re-encoding drops
    EXIF, so a phone photo's GPS tags never reach a provider.

    CPU-bound; callers run it off the event loop.
    """
    try:
        with Image.open(BytesIO(raw)) as image:
            width, height = image.size
            if width * height > MAX_IMAGE_PIXELS:
                return None
            image.load()
            has_alpha = image.mode in {"RGBA", "LA", "PA"} or "transparency" in image.info
            image = image.convert("RGBA" if has_alpha else "RGB")
            longest = max(width, height)
            if longest > max_edge:
                scale = max_edge / longest
                image = image.resize(
                    (max(1, round(width * scale)), max(1, round(height * scale))),
                    Image.LANCZOS,
                )
            buffer = BytesIO()
            if has_alpha:
                image.save(buffer, format="PNG", optimize=True)
                return "image/png", buffer.getvalue()
            image.save(buffer, format="JPEG", quality=IMAGE_JPEG_QUALITY, optimize=True)
            return "image/jpeg", buffer.getvalue()
    except (OSError, ValueError, UnidentifiedImageError, Image.DecompressionBombError):
        return None


def build_custom_id(action: str, kind: str, channel_id: int, message_id: int, author_id: int) -> str:
    """Address one button entirely in its own id, so a restart changes nothing.

    Everything the handler needs travels here rather than in memory or in
    storage: the cog keeps no record of a pending report, and a button clicked
    a week after the bot last restarted still works.
    """
    parts = (ACTION_PREFIX, action, kind, str(channel_id), str(message_id), str(author_id))
    custom_id = ":".join(parts)
    if len(custom_id) > CUSTOM_ID_LIMIT:
        # Discord rejects the message rather than the button, so the failure
        # would be an alert that never arrives. discord.py does not check this.
        raise ValueError(f"custom_id over {CUSTOM_ID_LIMIT}: {len(custom_id)}")
    return custom_id


def parse_custom_id(custom_id: str) -> tuple[str, str, int, int, int] | None:
    """The action a click refers to, or None when it is not one of ours.

    Untrusted: a custom_id arrives from Discord and names a message this cog is
    about to delete and a member it is about to punish, so every field is
    validated rather than coerced.
    """
    if not isinstance(custom_id, str):
        return None
    parts = custom_id.split(":")
    if len(parts) != 6 or parts[0] != ACTION_PREFIX:
        return None
    action, kind = parts[1], parts[2]
    if action not in ACTIONS or not kind.isascii() or not kind.isalpha():
        return None
    ids = []
    for raw in parts[3:]:
        if not raw.isascii() or not raw.isdigit() or len(raw) > 20:
            return None
        ids.append(int(raw))
    return (action, kind, *ids)  # type: ignore[return-value]


def reason_kind(reasons: list[str]) -> str:
    """One letter naming what this report is mostly about, for the mark counts.

    The counts exist to build the precision data this cog has never had: every
    threshold in it was set from synthetic cases and a hand-written test set.
    A mark is only useful if it says which judgement was right or wrong.
    """
    for prefix, kind in (("詐騙", "s"), ("違反", "r"), ("疑似違規", "r"), ("敵意", "h")):
        if any(reason.startswith(prefix) for reason in reasons):
            return kind
    return "t"


READ_CHUNK = 65_536


async def read_bounded(response: Any, limit: int) -> bytes | None:
    """The whole response body, or None when it exceeds `limit`.

    `StreamReader.read(n)` returns as soon as any data is available -- at most
    n bytes, not n bytes -- so `read(limit + 1)` handed back whatever the first
    chunk happened to hold and silently dropped the rest.

    Measured against the production host on 2026-09-21: a 124,759-byte PNG
    came back as 38,349 bytes under HTTP 200 with a correct content-length,
    PIL called it truncated, and the cog reported the image as unreadable.
    Every image bigger than one read was refused that way for as long as the
    feature existed, which is why a correctly configured channel read nothing
    and no surface could say why.

    The same call was used for both JSON responses. Those are usually small
    enough to arrive in one chunk, so they mostly worked -- a failure mode
    that shows up only on the larger answers is worse than one that always
    shows.
    """
    buf = bytearray()
    async for chunk in response.content.iter_chunked(READ_CHUNK):
        buf.extend(chunk)
        if len(buf) > limit:
            return None
    return bytes(buf)


def anonymise(window: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Replace author IDs with labels that mean nothing outside this request."""
    aliases: dict[int, str] = {}
    for item in window:
        author_id = item["author_id"]
        if author_id not in aliases:
            aliases[author_id] = f"u{len(aliases) + 1}"
        item["alias"] = aliases[author_id]
    return window


def clean_text(raw: str) -> str:
    """Bound one message and strip the mention markup that carries an ID."""
    text = re.sub(r"<@[!&]?\d+>|<#\d+>", "[mention]", raw)
    text = re.sub(r"<a?:\w+:\d+>", "[emoji]", text)
    text = " ".join(text.split())
    return text[:MAX_MESSAGE_CHARS]


class TimeoutModal(discord.ui.Modal, title="禁言作者"):
    """Duration and reason, typed by the moderator rather than defaulted."""

    minutes = discord.ui.TextInput(
        label="禁言幾分鐘", placeholder="例如 60", max_length=6, required=True
    )
    reason = discord.ui.TextInput(
        label="理由（會記進 modlog）",
        style=discord.TextStyle.paragraph,
        max_length=400,
        required=False,
    )

    def __init__(self, cog: "MessageWatch", member: discord.Member) -> None:
        super().__init__(timeout=600)
        self.cog = cog
        self.member = member

    async def on_submit(self, interaction: discord.Interaction) -> None:
        raw = str(self.minutes.value).strip()
        if not raw.isascii() or not raw.isdigit():
            await interaction.response.send_message("分鐘數要是數字。", ephemeral=True)
            return
        try:
            span = int(raw)
        except ValueError:
            await interaction.response.send_message("分鐘數要是數字。", ephemeral=True)
            return
        if not 1 <= span <= MAX_TIMEOUT_MINUTES:
            await interaction.response.send_message(
                f"分鐘數要介於 1 與 {MAX_TIMEOUT_MINUTES}（Discord 上限 28 天）。", ephemeral=True
            )
            return
        await self.cog.apply_timeout(interaction, self.member, span, str(self.reason.value or ""))


def build_action_view(
    actions: Iterable[str],
    kind: str,
    channel_id: int,
    message_id: int,
    author_id: int,
) -> discord.ui.View | None:
    """The buttons this channel was configured to offer, or None for none.

    `timeout=None` and no registration: the handler reads the custom_id, so a
    report stays usable across restarts without the cog holding any record of
    it. An action that needs a target message is dropped when there is none,
    rather than offered and failing on the click.
    """
    styles = {"secondary": discord.ButtonStyle.secondary, "danger": discord.ButtonStyle.danger}
    view = discord.ui.View(timeout=None)
    added = 0
    for action in actions:
        if action not in ACTIONS:
            continue
        label, style, _ = ACTIONS[action]
        if action not in ("ok", "no") and not message_id:
            continue
        view.add_item(
            discord.ui.Button(
                label=label,
                style=styles[style],
                custom_id=build_custom_id(action, kind, channel_id, message_id, author_id),
            )
        )
        added += 1
    return view if added else None


class MessageWatch(commands.Cog):
    """Report scam and hostile messages in explicitly enabled channels."""

    def __init__(self, bot: Red):
        self.bot = bot
        self.config = Config.get_conf(self, identifier=0x4E59414E4D57415401, force_registration=True)
        self.config.register_guild(**DEFAULT_GUILD)
        # The vision endpoint and model are global, not per guild. The API key
        # they spend belongs to the bot owner and is shared across every guild,
        # so a guild administrator able to set the endpoint could direct that
        # bearer token -- and the images -- to a host of their choosing. Storing
        # the destination at the same scope as the credential removes the class
        # rather than guarding it.
        self.config.register_global(**DEFAULT_GLOBAL)
        # Rules are per channel, not per guild: a venting channel's rules would
        # be absurd in a help channel, and it is the channel's own posted rules
        # that members agreed to.
        self.config.register_channel(**DEFAULT_CHANNEL)
        self._reset_state()

    def _reset_state(self) -> None:
        """Every piece of in-memory state, defined once.

        `__init__` calls it and the tests call it on a bare instance, so a
        new piece of state cannot be added to one and forgotten in the
        other. It used to be inline here, and the code paths that read it
        guarded themselves with hasattr to survive test fixtures built by
        `object.__new__` -- which meant renaming an attribute turned the
        whole of usage accounting into a silent no-op with every test
        still passing. Production code should not be defensive about a
        shape only a test can produce.
        """

        # Per channel: the pending window, and when that channel last reported.
        # Both are process memory on purpose. A restart losing a half-filled
        # window costs one late report; persisting message text would
        # contradict the data statement.
        self._pending: defaultdict[int, deque[dict[str, Any]]] = defaultdict(
            lambda: deque(maxlen=MAX_PENDING_MESSAGES)
        )
        self._last_report: dict[int, float] = {}
        self._locks: defaultdict[int, asyncio.Lock] = defaultdict(asyncio.Lock)
        # What `[p]watch show` reports back: when a channel was last actually
        # judged, and why nothing happened the last time something did not.
        self._last_judged: dict[int, float] = {}
        self._last_error: dict[int, tuple[float, str]] = {}
        # Attachment id -> extracted text. Ordered so the oldest goes first
        # when it is full; the same meme reposted is paid for once.
        self._image_cache: OrderedDict[int, str] = OrderedDict()
        # Usage deltas since the last Config flush, per guild id. In-memory
        # only, on purpose: a Config write per judged window would be a disk
        # write every few messages, so these ride on the 60-second sweep
        # instead. See `_flush_usage`.
        self._usage_delta: defaultdict[int, dict[str, int]] = defaultdict(fresh_delta)
        # Per-guild dashboard state. `_dashboard_error` stops the sweep from
        # retrying a channel that is gone or forbidden every minute forever;
        # it is cleared only by `[p]watch dashboard` posting a new one.
        # `_dashboard_last_render` is the last rendered embed, so the sweep
        # only edits Discord when the numbers actually changed.
        self._dashboard_error: dict[int, tuple[float, str]] = {}
        self._dashboard_last_render: dict[int, dict[str, Any]] = {}

    async def cog_load(self) -> None:
        """Register the case types this cog records under, and start the sweep.

        `modlog.create_case` raises ValueError for a type nobody registered, and
        `_case` catches it, so without this every action would succeed and none
        would be logged -- while the disclosure, the data statement and the
        README all promise that each one is recorded under the moderator's name.
        A false sentence in four places, produced by a silent except.
        """
        for case in CASE_TYPES:
            try:
                await modlog.register_casetype(**case)
            except RuntimeError:
                # Already registered, by Red or by an earlier load of this cog.
                pass
            except Exception as error:
                log.warning(
                    "messagewatch: could not register case type %s (%s)",
                    case["name"],
                    type(error).__name__,
                )
        self._sweep.start()

    def _forget_images(self) -> None:
        """Drop every cached transcription.

        The cache holds text taken out of members' images, keyed by attachment
        id with no author attached -- so a deletion request cannot target one
        person's entries, and the honest response is to drop all of them.
        """
        self._image_cache.clear()

    async def cog_unload(self) -> None:
        """Stop the sweep, so an unloaded cog stops judging.

        The cog had no unload path at all before this. It still cannot cancel a
        `flush` already running inside a discord.py dispatch task -- it does not
        own those -- so an unload can still be followed by one report from a
        request that was already out. What it can stop is this loop, which is
        the only work the cog itself starts.

        The usage flush runs one last time here so a restart loses at most the
        seconds since the last sweep tick, not the whole in-memory tail. The
        transcription cache is dropped instead: it is the only member content
        this cog holds, and an unloaded cog has no reason to keep it.
        """
        self._sweep.cancel()
        self._forget_images()
        await self._flush_usage()

    @tasks.loop(seconds=IDLE_SWEEP_SECONDS)
    async def _sweep(self) -> None:
        """Judge the channels that went quiet before filling a window.

        Without this a channel that never reaches `window_size` is never judged
        at all, which is the silent no-op this cog is most exposed to: a venting
        channel is a post, two replies and then nothing.

        Also where the usage counters and the dashboard message ride: both are
        cheap here regardless, since this already runs every IDLE_SWEEP_SECONDS
        whether or not anything is due.
        """
        await self._flush_usage()
        await self._update_dashboards()
        for channel_id, queue in list(self._pending.items()):
            # A queue that cannot reach MIN_PARTIAL_WINDOW is waiting for
            # another message, not failing. Letting it into `flush` every
            # minute would record `no_api_key` or `no_report_channel` against
            # it before `_take_window` turns it away -- a false problem in the
            # surface built to tell a real one from a quiet channel.
            if len(queue) < MIN_PARTIAL_WINDOW:
                continue
            channel = self.bot.get_channel(channel_id)
            guild = getattr(channel, "guild", None)
            if channel is None or guild is None:
                continue
            idle = int((await self.config.guild(guild).idle_seconds()) or 0)
            if not idle:
                continue
            newest = queue[-1].get("at")
            if not isinstance(newest, (int, float)) or time.monotonic() - newest < idle:
                continue
            await self.flush(channel, partial=True)

    @_sweep.before_loop
    async def _before_sweep(self) -> None:
        """Wait for the cache, or `bot.get_channel` answers None for everything."""
        await self.bot.wait_until_red_ready()

    @_sweep.error
    async def _sweep_error(self, error: BaseException) -> None:
        """A failed sweep must not end the loop silently for the whole process."""
        log.exception("messagewatch: idle sweep failed", exc_info=error)
        self._sweep.restart()

    async def red_delete_data_for_user(self, *, requester: str, user_id: int) -> None:
        """Drop any pending message this user wrote that has not been sent yet.

        The transcription cache is keyed by attachment id and carries no author,
        so it cannot be filtered down to one person -- `_forget_images` drops it
        whole. That is wasteful (every other channel re-reads its images once)
        and correct, which is the right way round for this request.
        """
        for queue in self._pending.values():
            for item in list(queue):
                if item.get("author_id") == user_id:
                    queue.remove(item)
        self._forget_images()

    def _note(self, channel_id: int, reason: str) -> None:
        """Record why this channel produced nothing, for `[p]watch show`."""
        self._last_error[channel_id] = (time.time(), reason)

    async def _flush_usage(self) -> None:
        """Add each guild's accumulated deltas into Config, then zero them.

        Called from the sweep, not from `flush`: a Config write per judged
        window is a disk write every few messages, so this rides on the
        60-second sweep instead and `cog_unload` calls it once more so a
        restart loses at most the tail since the last tick.
        """
        for guild_id, delta in list(self._usage_delta.items()):
            if not any(delta.values()):
                continue
            guild = self.bot.get_guild(guild_id)
            if guild is None:
                # Not cached right now -- leave the delta in place and try
                # again next tick rather than losing it.
                continue
            # Copied before the write, subtracted after it. Red's context
            # manager awaits on entry and on exit, and `flush` or `on_message`
            # can increment this same dict during either await -- popping the
            # entry afterwards would discard whatever arrived in between and
            # undercount silently, which is the worst way for a usage figure
            # to be wrong.
            flushed = dict(delta)
            async with self.config.guild(guild).usage() as usage:
                for key, amount in flushed.items():
                    usage[key] = int(usage.get(key, 0)) + amount
                if not usage.get("started_at"):
                    usage["started_at"] = time.time()
            # Subtract what was written rather than dropping the entry, so an
            # increment that landed during the two awaits above survives to the
            # next tick.
            current = self._usage_delta[guild_id]
            for key, amount in flushed.items():
                current[key] = int(current.get(key, 0)) - amount
            if not any(current.values()):
                self._usage_delta.pop(guild_id, None)

    async def get_api_key(self) -> str | None:
        """The TypeSafe key from Red's shared token store, or None if unusable."""
        tokens = await self.bot.get_shared_api_tokens(TOKEN_SERVICE)
        key = tokens.get("api_key") if isinstance(tokens, Mapping) else None
        return key if isinstance(key, str) and key else None

    async def _attach_image_text(self, window: list[dict[str, Any]]) -> VisionUsage:
        """Read this window's images, bounded, and hang the text on each item.

        Bounded per window rather than per message: one post of twenty
        screenshots would otherwise cost twenty vision calls for a single
        judgement.
        """
        budget = MAX_IMAGES_PER_WINDOW
        total = VisionUsage()
        for item in window:
            for attachment in item.get("images") or ():
                if budget <= 0:
                    return total
                budget -= 1
                text, used = await self.image_text(attachment)
                total = total + used
                if text:
                    item["image_text"] = (item.get("image_text", "") + " " + text).strip()
        return total

    async def image_text(self, attachment: Mapping[str, Any]) -> tuple[str | None, VisionUsage]:
        """The characters in one attachment, or None when they could not be read.

        Every failure returns None for the same reason `judge` does: a
        moderation aid that breaks the message handler is worse than one that
        misses an image. The result is cached by attachment id, so the same
        meme posted ten times is paid for once.
        """
        key = int(attachment["id"])
        cached = self._image_cache.get(key)
        if cached is not None:
            self._image_cache.move_to_end(key)
            # A hit costs nothing, and counting it is what makes "images read"
            # interpretable: the same meme reposted ten times is one call.
            return cached, VisionUsage(cache_hits=1)

        vision = await self.config.all()
        model = str(vision["image_model"]).strip()
        api_base = str(vision["image_api_base"]).strip()
        token = await self.get_image_key()
        if not model or not api_base or not token:
            # The likeliest reason nothing is being read, and previously the
            # quietest: a manager turns a channel on, sees a success message,
            # and the endpoint the owner has to set was never set.
            missing = ("model" if not model else "api_base" if not api_base else "key")
            return None, VisionUsage(failure=f"vision_no_{missing}")

        timeout = aiohttp.ClientTimeout(total=IMAGE_TIMEOUT_SECONDS)
        try:
            async with aiohttp.ClientSession(
                timeout=timeout, trust_env=False, cookie_jar=aiohttp.DummyCookieJar()
            ) as session:
                async with session.get(attachment["url"], allow_redirects=False) as response:
                    if response.status != 200:
                        log.warning("messagewatch: attachment fetch returned %d", response.status)
                        return None, VisionUsage(failure=f"image_fetch_http_{response.status}")
                    raw = await read_bounded(response, MAX_IMAGE_BYTES)
        except (aiohttp.ClientError, asyncio.TimeoutError) as error:
            log.warning("messagewatch: attachment fetch failed (%s)", type(error).__name__)
            return None, VisionUsage(failure=f"image_fetch_{type(error).__name__}")
        if raw is None:
            return None, VisionUsage(failure="image_too_large")

        # Decoding and resizing are CPU-bound and would stall every other
        # channel's ingestion if they ran on the event loop.
        transcoded = await asyncio.to_thread(transcode_image, raw)
        if transcoded is None:
            return None, VisionUsage(failure="image_unreadable")
        content_type, encoded = transcoded
        data_uri = f"data:{content_type};base64,{base64.b64encode(encoded).decode('ascii')}"

        text, tokens_in, tokens_out, nanos, failure = await self._extract_text(
            api_base, token, model, data_uri
        )
        # Spend is recorded either way -- the provider billed for the call --
        # but only a call that came back with text counts as an image read.
        used = VisionUsage(images_read=1 if text is not None else 0,
                           images_failed=0 if text is not None else 1,
                           input_tokens=tokens_in,
                           output_tokens=tokens_out, nanodollars=nanos,
                           failure=failure)
        if text is None:
            return None, used
        text = " ".join(text.split())[:IMAGE_TEXT_CHARS]
        self._image_cache[key] = text
        while len(self._image_cache) > IMAGE_CACHE_SIZE:
            self._image_cache.popitem(last=False)
        return text, used

    async def _extract_text(
        self, api_base: str, token: str, model: str, data_uri: str
    ) -> tuple[str | None, int, int, int, str]:
        """Ask the vision model for the characters, and nothing else.

        Verbatim extraction rather than description: a scam image is a
        screenshot with text in it, the text is the evidence, and asking for a
        description is open-ended generation whose errors nobody can check
        against the picture.
        """
        payload = json.dumps({
            "model": model,
            "input": [{"role": "user", "content": [
                {"type": "input_text", "text": IMAGE_PROMPT},
                {"type": "input_image", "image_url": data_uri},
            ]}],
        }).encode()
        timeout = aiohttp.ClientTimeout(total=IMAGE_TIMEOUT_SECONDS)
        try:
            async with aiohttp.ClientSession(
                timeout=timeout, trust_env=False, cookie_jar=aiohttp.DummyCookieJar()
            ) as session:
                async with session.post(
                    api_base.rstrip("/") + "/api/v1/responses",
                    data=payload,
                    headers={"Authorization": f"Bearer {token}",
                             "Content-Type": "application/json"},
                    allow_redirects=False,
                ) as response:
                    if response.status != 200:
                        log.warning("messagewatch: image model returned %d", response.status)
                        return None, 0, 0, 0, f"vision_http_{response.status}"
                    content_type = response.headers.get("Content-Type", "")
                    body = await read_bounded(response, MAX_RESPONSE_BYTES)
        except (aiohttp.ClientError, asyncio.TimeoutError) as error:
            log.warning("messagewatch: image model unreachable (%s)", type(error).__name__)
            return None, 0, 0, 0, f"vision_{type(error).__name__}"
        if body is None:
            return None, 0, 0, 0, "vision_response_too_large"
        try:
            decoded = json.loads(body)
        except (ValueError, RecursionError):
            # With the content type and the opening bytes, because the message
            # on its own was not diagnosable: eleven of these in a row on the
            # production host said only that something was wrong, and the
            # endpoint, the relay and the provider all remained candidates.
            # An error message is not a measurement.
            #
            # Bounded at BAD_JSON_LOG_CHARS, and the opening rather than a
            # middle slice: a Responses API body starts with its own metadata,
            # so a prefix that short carries the shape without carrying a
            # member's transcribed image text.
            log.warning(
                "messagewatch: image model response was not usable JSON "
                "(content-type %r, %d bytes, starts %r)",
                content_type, len(body), body[:BAD_JSON_LOG_CHARS],
            )
            return None, 0, 0, 0, "vision_bad_json"
        parts: list[str] = []
        for item in (decoded.get("output") or []) if isinstance(decoded, Mapping) else []:
            for chunk in (item.get("content") or []) if isinstance(item, Mapping) else []:
                if isinstance(chunk, Mapping) and chunk.get("type") == "output_text":
                    value = chunk.get("text")
                    if isinstance(value, str):
                        parts.append(value)
        usage = decoded.get("usage") if isinstance(decoded, Mapping) else None
        tokens_in = tokens_out = nanos = 0
        if isinstance(usage, Mapping):
            tokens_in = _bounded_token_count(usage.get("input_tokens")) or 0
            tokens_out = _bounded_token_count(usage.get("output_tokens")) or 0
            nanos = _reported_nanodollars(usage)
        joined = "\n".join(parts).strip()
        # Reported even when the text is unusable: the provider billed for the
        # call either way, and a cost surface that hides the failures
        # understates exactly the spend worth noticing.
        return (joined or None), tokens_in, tokens_out, nanos, ("" if joined else "vision_empty_text")

    async def get_image_key(self) -> str | None:
        """The vision provider's key, from Red's shared token storage."""
        tokens = await self.bot.get_shared_api_tokens(IMAGE_TOKEN_SERVICE)
        key = tokens.get("api_key") if isinstance(tokens, Mapping) else None
        return key if isinstance(key, str) and key else None

    async def judge(
        self,
        window: list[dict[str, Any]],
        channel_name: str,
        key: str,
        purpose: str = "",
        rules: list[str] | None = None,
    ) -> tuple[dict[str, Any] | None, int]:
        """One bounded request, or None when the service could not answer.

        Every failure path returns None rather than raising. A moderation aid
        that breaks the message handler is worse than one that misses a window,
        so the caller carries on and the channel keeps working.

        Returns the answers and the input token count together. An earlier
        version left the count on `self` to keep the return type narrow, but
        `flush` holds a per-channel lock, so two channels judging at once both
        wrote that field and whichever read second recorded the other's tokens
        -- against the wrong window, and where the two channels are in
        different guilds, against the wrong guild's bill.
        """
        tokens = 0
        payload = json.dumps(
            {
                "state": build_state(channel_name, window, purpose, rules),
                "model": MODEL,
                "questions": build_questions(window, rules),
            },
            ensure_ascii=False,
        ).encode()
        if len(payload) > MAX_REQUEST_BYTES:
            log.warning("messagewatch: request over %d bytes, window dropped", MAX_REQUEST_BYTES)
            return None, tokens
        timeout = aiohttp.ClientTimeout(total=REQUEST_TIMEOUT_SECONDS)
        try:
            async with aiohttp.ClientSession(
                timeout=timeout, trust_env=False, cookie_jar=aiohttp.DummyCookieJar()
            ) as session:
                async with session.post(
                    API_URL,
                    data=payload,
                    headers={
                        "Authorization": f"Bearer {key}",
                        "Content-Type": "application/json",
                    },
                    allow_redirects=False,
                ) as response:
                    if response.status != 200:
                        log.warning("messagewatch: provider returned HTTP %d", response.status)
                        return None, tokens
                    raw = await read_bounded(response, MAX_RESPONSE_BYTES)
                    if raw is None:
                        log.warning("messagewatch: provider response over %d bytes", MAX_RESPONSE_BYTES)
                        return None, tokens
        except asyncio.TimeoutError:
            log.warning("messagewatch: provider timed out after %.0fs", REQUEST_TIMEOUT_SECONDS)
            return None, tokens
        except aiohttp.ClientError as error:
            # The class only; the message can carry the URL and its query.
            log.warning("messagewatch: provider transport failure (%s)", type(error).__name__)
            return None, tokens
        try:
            decoded = json.loads(raw)
        except (ValueError, RecursionError):
            # RecursionError, because the byte cap does not bound nesting depth:
            # measured on this interpreter, 60,000 bytes of nested arrays -- well
            # inside MAX_RESPONSE_BYTES -- raises it, and it is not a ValueError,
            # so it would escape this function's promise to return None on every
            # failure and break the message handler instead.
            log.warning("messagewatch: provider response was not usable JSON")
            return None, tokens
        answers = decoded.get("answers") if isinstance(decoded, Mapping) else None
        if not isinstance(answers, Mapping):
            log.warning("messagewatch: provider response carried no answers mapping")
            return None, tokens
        usage = decoded.get("usage") if isinstance(decoded, Mapping) else None
        if isinstance(usage, Mapping):
            tokens = _bounded_token_count(usage.get("input_tokens")) or 0
        return answers, tokens

    @staticmethod
    def _rule_finding(
        answers: Mapping[str, Any], settings: Mapping[str, Any], rules: list[str], size: int
    ) -> tuple[int | None, str | None]:
        """Which rule this window broke, or None -- combined here, not by the model.

        Four separate answers decide one thing, which is the documented way to
        handle a question the model reads too literally to answer in one go.

        The veto exists because members police each other in a channel with
        posted rules: "你這樣算下指導棋喔" scored 0.84 as a violation of the very
        rule it was citing, since jev reads literally and the words were in the
        sentence. Saying so in the criteria did not fix it.

        The veto asks which message is the commentary, not whether commentary
        is present, and the two are not interchangeable. A first attempt asked
        about "the most suspicious message", which made the model resolve one
        question inside another; measured against the real ruleset it let the
        case straight through. Naming the message and comparing the two indexes
        in code is what actually holds.

        The veto is also deliberately about the *rules*, not about commenting
        on people. Asking the broader question collided with the ruleset it was
        meant to protect: a channel forbidding "guessing at someone's motives"
        and "speaking for someone else" has rules that are themselves about
        interpreting a person, so a veto phrased that way swallowed two real
        violations. Measured: 17/19 with the broad wording, 19/19 with this one.
        """
        violation = answers.get("any_violation")
        probability = (
            _bounded_probability(violation.get("noul")) if isinstance(violation, Mapping) else None
        )
        if probability is None or probability < float(settings["rule_threshold"]):
            return None, None

        picked = answers.get("which_rule")
        if not isinstance(picked, Mapping):
            return None, None
        number = _bounded_index(picked.get("choice"), len(rules) + 1)
        if number is None or number < 1:
            return None, None
        confidence = _bounded_probability(picked.get("confidence"))
        sure = confidence is not None and confidence >= float(settings["rule_confidence"])

        where = answers.get("rule_index")
        index = _bounded_index(where.get("choice"), size) if isinstance(where, Mapping) else None
        # A rule report has to name the message. Without one there is nothing a
        # moderator can act on, and no way to tell the violation apart from the
        # message commenting on it.
        if index is None:
            return None, None

        commentary = answers.get("meta_index")
        if not isinstance(commentary, Mapping):
            return None, None
        raw = commentary.get("choice")
        if raw != "none":
            meta_index = _bounded_index(raw, size)
            # Unreadable, so the veto cannot be evaluated. This decides whether
            # to name a person, and "cannot tell" has to mean "do not accuse".
            if meta_index is None or meta_index == index:
                return None, None

        text = rules[number - 1][:RULE_REASON_CHARS]
        if sure:
            return index, f"違反第 {number} 條：{text}"
        # The model is confident a rule was broken and not confident which one.
        # Saying so beats both suppressing the report and asserting a number.
        return index, f"疑似違規，條文不確定，最接近第 {number} 條：{text}"

    @staticmethod
    def findings(
        answers: Mapping[str, Any],
        settings: Mapping[str, Any],
        window_size: int,
        rules: list[str] | None = None,
    ) -> tuple[int | None, list[str], int | None]:
        """Which thresholds this window crossed, and which messages to point at.

        The rule pointer is returned separately because the two judgements can
        name different messages: a scam and a rule violation in one window are
        two findings about two people, and showing one link beside both reasons
        would put a rule's name next to somebody else's message.
        """
        reasons: list[str] = []
        index: int | None = None

        scam_answer = answers.get("any_scam")
        scam = _bounded_probability(scam_answer.get("noul")) if isinstance(scam_answer, Mapping) else None
        # Not `index is None` further down: that conflates "scam did not fire"
        # with "scam fired and its own pointer was unreadable", and the second
        # one must not fall through to hostility. A report carrying a scam
        # finding would otherwise aim its buttons at whoever was rude.
        scam_found = False
        if scam is not None and scam >= float(settings["scam_threshold"]):
            reasons.append(f"詐騙 {scam:.2f}")
            scam_found = True
            picked = answers.get("scam_index")
            if isinstance(picked, Mapping):
                index = _bounded_index(picked.get("choice"), window_size)

        hostile_answer = answers.get("is_hostile")
        hostile = (
            _bounded_probability(hostile_answer.get("noul"))
            if isinstance(hostile_answer, Mapping)
            else None
        )
        target_answer = answers.get("hostile_target")
        target = (
            _bounded_probability(target_answer.get("noul"))
            if isinstance(target_answer, Mapping)
            else None
        )
        # Both, not either. The hostility score says how much the person
        # written about would be hurt; this one says whether that person is in
        # the room. Contempt for a class of absent people scores high on the
        # first and low on the second, and it was most of what this signal
        # reported. An unreadable answer means no finding rather than a guess:
        # this decides whether somebody gets named.
        if (
            hostile is not None
            and hostile >= float(settings["hostile_harm_threshold"])
            and target is not None
            and target >= HOSTILE_TARGET_PRESENT
        ):
            reasons.append(f"敵意 {hostile:.2f}")
            # A hostility report used to name no message, so the delete,
            # timeout and role buttons had nothing to act on and a moderator
            # had to go and find the message themselves. Hostility is a
            # property of an exchange, which is why it is judged over a window
            # -- but a moderator times out a person, not a conversation.
            #
            # Only when there is no scam finding at all: a window that is both
            # keeps the scam target, which is the one with a rule behind it,
            # and keeps no target when that pointer was unreadable. Unreadable
            # means no target rather than a guess, the contract `rule_index`
            # already holds.
            if index is None and not scam_found:
                picked = answers.get("hostile_index")
                if isinstance(picked, Mapping):
                    index = _bounded_index(picked.get("choice"), window_size)

        heat_answer = answers.get("heat")
        levels = len(QUESTIONS["heat"]["criteria"])
        heat = _bounded_score(heat_answer.get("score"), levels) if isinstance(heat_answer, Mapping) else None
        if heat is not None and heat >= float(settings["heat_threshold"]):
            reasons.append(f"火藥味 {heat:.2f}/{levels - 1}")

        rules = list(rules or ())
        rule_index: int | None = None
        if rules:
            found, rule_reason = MessageWatch._rule_finding(
                answers, settings, rules, window_size
            )
            if rule_reason is not None:
                reasons.append(rule_reason)
                # Deliberately not filled in as `index`. A scam finding whose
                # own pointer was unreadable leaves `index` None so the report
                # shows a range; borrowing the rule's pointer there would put
                # the rule-breaker's name under a 詐騙 reason. The rule keeps
                # its own field, and a report with only a rule finding shows
                # the range plus that field.
                rule_index = found

        return index, reasons, rule_index

    @staticmethod
    def report_embed(
        channel: discord.TextChannel | discord.Thread,
        window: list[dict[str, Any]],
        index: int | None,
        reasons: list[str],
        rule_index: int | None = None,
    ) -> discord.Embed:
        """The moderator-facing report. Judgement stays with the moderator."""
        embed = discord.Embed(
            title="MessageWatch",
            description="｜".join(reasons),
            colour=discord.Colour.orange(),
        )
        embed.add_field(
            name="頻道", value=getattr(channel, "mention", f"#{channel.id}"), inline=False
        )
        if index is not None and 0 <= index < len(window):
            flagged = window[index]
            embed.add_field(
                name="指向的訊息",
                value=f"<@{flagged['author_id']}> · [跳至訊息]({flagged['jump_url']})",
                inline=False,
            )
        else:
            # Both ends, not one message. The model crossed a threshold without
            # naming a message, so pointing at a single one would read as an
            # accusation of whoever happens to have written it.
            embed.add_field(
                name="範圍",
                value=(
                    f"[開頭]({window[0]['jump_url']}) → [結尾]({window[-1]['jump_url']})"
                    f"（{len(window)} 則）"
                ),
                inline=False,
            )
        # A scam and a rule violation in one window are findings about two
        # different people. One link beside both reasons would put a rule's
        # name next to somebody else's message.
        if rule_index is not None and rule_index != index and 0 <= rule_index < len(window):
            flagged = window[rule_index]
            embed.add_field(
                name="違規的訊息",
                value=f"<@{flagged['author_id']}> · [跳至訊息]({flagged['jump_url']})",
                inline=False,
            )
        # What the machine thought it saw. The extraction is generated text
        # with nothing calibrated behind it, so a moderator has to be able to
        # check it against the image rather than trust a verdict built on it.
        seen = " / ".join(item["image_text"] for item in window if item.get("image_text"))
        if seen:
            embed.add_field(
                name="圖片中讀到的文字", value=seen[:EMBED_FIELD_LIMIT], inline=False
            )
        embed.set_footer(
            text=f"判斷依據 {len(window)} 則訊息。這是提示，不是裁決；下面的動作只有你按才會發生。"
        )
        return embed

    def _still_idle(self, channel_id: int, idle: int) -> bool:
        """Whether this channel is still quiet. Callers hold its lock."""
        if not idle:
            return False
        queue = self._pending[channel_id]
        if not queue:
            return False
        newest = queue[-1].get("at")
        if not isinstance(newest, (int, float)):
            return False
        return time.monotonic() - newest >= idle

    def _take_window(
        self, channel_id: int, window_size: int, minimum: int | None = None
    ) -> list[dict[str, Any]] | None:
        """Copy one full window and advance the queue by half of it.

        The windows overlap. Consuming the whole batch would mean an exchange
        that straddles a boundary is never judged together, and hostility is a
        property of an exchange, which is the entire reason this cog judges
        windows rather than messages. The stride is half a window, so every
        message is judged in two of them: that doubles the amortised input cost
        per message, and gives a borderline case near a boundary a second
        chance, which is the direction the unmeasured recall gap points.

        Callers hold `self._locks[channel_id]`; nothing here awaits.
        """
        queue = self._pending[channel_id]
        floor = window_size if minimum is None else minimum
        if len(queue) < floor:
            return None
        take = min(len(queue), window_size)
        window = [dict(item) for item in islice(queue, take)]
        # A short window is the tail of a finished conversation, so it is
        # consumed whole: there is no later message for an overlap to join it
        # to, and leaving half behind would have the sweep judge it again.
        stride = take if take < window_size else window_size - window_size // 2
        for _ in range(stride):
            queue.popleft()
        return window

    async def flush(
        self, channel: discord.TextChannel | discord.Thread, *, partial: bool = False
    ) -> None:
        """Judge one full window for this channel and report if it crosses.

        Everything this cog does to one channel happens under that channel's
        lock, the provider request and the send included. That is the whole
        concurrency rule, stated once in code instead of five times in
        comments: a second full window waits here instead of being dropped,
        `[p]watch disable` waits here instead of racing, and there is no second
        piece of shared state to keep in step with this one. Three of the four
        defects found in review round 2 lived in the seam that existed when the
        request ran outside this lock, and a fourth -- a full window left
        unjudged while a request was out -- lived in the state that seam needed.

        The cost is that ingestion for this channel pauses for the length of one
        request. The pause itself drops nothing -- each message arrives in its
        own task and appends when the lock frees -- but the queue is bounded at
        MAX_PENDING_MESSAGES, so a backlog longer than that during one request
        does evict its oldest entries. That cap predates this change and is
        deliberate; the point here is only that "nothing is lost" would be the
        wrong thing to write down. What the pause buys is that `[p]watch
        disable` returning means the export has stopped, which is what the
        disclosure promises.
        """
        async with self._locks[channel.id]:
            guild = channel.guild
            settings = await self.config.guild(guild).all()
            if int(settings["disclosure_version"]) != DISCLOSURE_VERSION:
                # Consent is checked here as well as in `on_message`, because
                # this is the function where text actually leaves. Nothing
                # revokes consent while the process runs today -- the only
                # write sets it to the current version, and a reload that
                # changes the constant builds a new instance with an empty
                # queue -- so the window a reviewer described is not reachable.
                # That reachability argument is exactly what the next person
                # adding a revoke command would have to remember, and this line
                # is what makes remembering unnecessary. Pending text is
                # dropped rather than held, because consent for it is stale.
                self._pending.pop(channel.id, None)
                self._note(channel.id, "disclosure_stale")
                return
            if channel.id not in set(settings["watched_channels"]):
                self._pending.pop(channel.id, None)
                return
            channel_settings = await self.config.channel(channel).all()
            rules = effective_rules(channel_settings, settings)
            report_id = int(channel_settings["report_channel"]) or int(settings["report_channel"])
            if not report_id:
                self._note(channel.id, "no_report_channel")
                return
            report_channel = guild.get_channel(report_id)
            if report_channel is None:
                self._note(channel.id, "report_channel_missing")
                log.warning("messagewatch: report channel %d is gone in guild %d", report_id, guild.id)
                return
            key = await self.get_api_key()
            if key is None:
                self._note(channel.id, "no_api_key")
                return

            if partial and not self._still_idle(channel.id, int(settings["idle_seconds"] or 0)):
                # The sweep measured idleness outside this lock and `on_message`
                # appends under it, so a conversation that resumed in that gap
                # would otherwise be consumed whole as though it had finished --
                # and consumed without overlap, since that is what a finished
                # conversation gets. Rechecking here makes the measurement and
                # the take atomic.
                return
            window = self._take_window(
                channel.id,
                int(settings["window_size"]),
                MIN_PARTIAL_WINDOW if partial else None,
            )
            if window is None:
                return

            cooldown = int(settings["cooldown_seconds"])
            last = self._last_report.get(channel.id)
            # Checked before the request, not after it. One argument spans many
            # windows, and inside the cooldown none of them can be reported, so
            # judging them would be paying the provider for an answer that
            # cannot be delivered.
            if last is not None and time.monotonic() - last < cooldown:
                return

            anonymise(window)
            vision_used = VisionUsage()
            if channel_settings["images"]:
                vision_used = await self._attach_image_text(window)
            answers, judge_tokens = await self.judge(
                window,
                getattr(channel, "name", str(channel.id)),
                key,
                str(channel_settings["purpose"]),
                rules,
            )
            # In memory only -- see `_flush_usage` for why this is not a
            # Config write.
            delta = self._usage_delta[guild.id]
            # The vision calls already happened, above `judge`, so this spend
            # is real whether or not the judgement lands. Recorded before the
            # early return, or a provider failure would hide money that was
            # already paid -- the same shape of gap this surface exists to
            # close.
            delta["images_read"] += vision_used.images_read
            delta["image_failures"] += vision_used.images_failed
            delta["image_cache_hits"] += vision_used.cache_hits
            delta["vision_input_tokens"] += vision_used.input_tokens
            delta["vision_output_tokens"] += vision_used.output_tokens
            delta["vision_nanodollars"] += vision_used.nanodollars
            if answers is None:
                self._note(channel.id, "provider_unavailable")
                return
            self._last_judged[channel.id] = time.time()
            self._last_error.pop(channel.id, None)
            refused = next(
                (str(item.get("skipped_image")) for item in window if item.get("skipped_image")),
                "",
            )
            if refused:
                # Before the vision failure below, so a window carrying both
                # reports the one that happened first. An attachment refused
                # at ingest never reached the vision call at all.
                self._note(channel.id, refused)
            elif vision_used.failure:
                # After the pop, not before it. An image failure is a partial
                # one -- the window was judged on its text and the picture was
                # not read -- so a successful judgement must not clear it, and
                # recording it earlier meant the pop below the judge call wiped
                # it every time. Without this the five image failure exits are
                # invisible: they log, the report still goes out, and nothing a
                # moderator can see says an image was skipped.
                self._note(channel.id, vision_used.failure)
            delta["windows_judged"] += 1
            delta["input_tokens"] += judge_tokens

            # findings() reads settings["rule_threshold"] and keeps that one
            # signature; the per-channel override is folded in here, in the
            # copy it is handed, rather than adding a second parameter that
            # every other caller of findings() would have to also thread.
            effective_settings = {
                **settings, "rule_threshold": effective_rule_threshold(channel_settings, settings)
            }
            index, reasons, rule_index = self.findings(answers, effective_settings, len(window), rules)
            if not reasons:
                return
            pointed = index if index is not None else rule_index
            flagged = window[pointed] if pointed is not None else None
            view = build_action_view(
                channel_settings["actions"],
                reason_kind(reasons),
                channel.id,
                int(flagged["message_id"]) if flagged else 0,
                int(flagged["author_id"]) if flagged else 0,
            )
            try:
                await report_channel.send(
                    embed=self.report_embed(channel, window, index, reasons, rule_index),
                    allowed_mentions=discord.AllowedMentions.none(),
                    view=view,
                )
            except discord.Forbidden:
                # A permission problem does not fix itself in five minutes, and
                # without backing off, every later window opens another provider
                # request for a report that can never be delivered. The cooldown
                # is the backoff that already exists.
                self._last_report[channel.id] = time.monotonic()
                self._note(channel.id, "report_forbidden")
                log.warning(
                    "messagewatch: cannot post to report channel %d in guild %d", report_id, guild.id
                )
                return
            except discord.HTTPException as error:
                self._note(channel.id, "report_failed")
                log.warning("messagewatch: report send failed (%s)", type(error).__name__)
                return
            # Recorded only once a report was delivered: a transport failure
            # must not silence the channel for the whole cooldown with nothing
            # sent.
            self._last_report[channel.id] = time.monotonic()
            self._usage_delta[guild.id]["reports_sent"] += 1

    async def _audit(self, interaction: discord.Interaction, line: str) -> None:
        """Append what was done to the report itself, where a moderator reads it."""
        message = interaction.message
        if message is None or not message.embeds:
            return
        embed = message.embeds[0]
        embed.add_field(name="已處理", value=line, inline=False)
        try:
            await message.edit(embed=embed)
        except discord.HTTPException as error:
            log.warning("messagewatch: could not annotate report (%s)", type(error).__name__)

    async def _case(
        self, guild: discord.Guild, action_type: str, user: Any, moderator: Any, reason: str
    ) -> None:
        """Record the action in Red's modlog, and carry on if it cannot be."""
        try:
            await modlog.create_case(
                self.bot,
                guild,
                datetime.now(timezone.utc),
                action_type,
                user,
                moderator=moderator,
                reason=reason or "MessageWatch",
            )
        except Exception as error:  # modlog raises several unrelated types
            # A recorded action that failed to log is still a recorded action;
            # losing the case must not undo it or break the interaction.
            log.warning("messagewatch: modlog case failed (%s)", type(error).__name__)

    async def apply_timeout(
        self, interaction: discord.Interaction, member: discord.Member, minutes: int, reason: str
    ) -> None:
        """Time a member out, from the modal that asked how long."""
        try:
            await member.timeout(timedelta(minutes=minutes), reason=reason or "MessageWatch")
        except discord.Forbidden:
            await interaction.response.send_message(
                "機器人沒有權限禁言這位成員（可能身分組順序不足）。", ephemeral=True
            )
            return
        except discord.HTTPException as error:
            log.warning("messagewatch: timeout failed (%s)", type(error).__name__)
            await interaction.response.send_message("禁言失敗。", ephemeral=True)
            return
        await interaction.response.send_message(f"已禁言 {minutes} 分鐘。", ephemeral=True)
        await self._case(member.guild, "messagewatch_timeout", member, interaction.user, reason)
        await self._audit(
            interaction, f"{interaction.user.mention} 禁言 {member.mention} {minutes} 分鐘"
        )

    @commands.Cog.listener()
    async def on_interaction(self, interaction: discord.Interaction) -> None:
        """Handle a report button.

        Read straight from the custom_id rather than from a registered view, so
        a button works after a restart and the cog stores nothing about a
        pending report. Everything in that id is untrusted input.
        """
        if interaction.type is not discord.InteractionType.component:
            return
        data = interaction.data if isinstance(interaction.data, Mapping) else {}
        parsed = parse_custom_id(data.get("custom_id", ""))
        if parsed is None:
            return
        action, kind, channel_id, message_id, author_id = parsed
        guild = interaction.guild
        if guild is None:
            return

        # The clicking member's own permissions, not the fact that they can see
        # the moderator channel. Anyone who can read a report could otherwise
        # act on it.
        needed = ACTIONS[action][2]
        if needed is not None:
            member = guild.get_member(interaction.user.id)
            if member is None or not getattr(member.guild_permissions, needed, False):
                await interaction.response.send_message(
                    f"這個動作需要 `{needed}` 權限。", ephemeral=True
                )
                return

        if action in ("ok", "no"):
            await self._record_mark(interaction, guild, kind, action)
            return
        if action == "del":
            await self._delete_target(interaction, guild, channel_id, message_id)
            return
        target = guild.get_member(author_id)
        if target is None:
            await interaction.response.send_message("找不到這位成員，可能已離開。", ephemeral=True)
            return
        if action == "mute":
            await interaction.response.send_modal(TimeoutModal(self, target))
            return
        if action == "role":
            await self._add_role(interaction, guild, target, channel_id)

    async def _record_mark(
        self, interaction: discord.Interaction, guild: discord.Guild, kind: str, action: str
    ) -> None:
        """Count one moderator judgement. Counts only -- no message content."""
        async with self.config.guild(guild).marks() as marks:
            bucket = marks.setdefault(kind, {"ok": 0, "no": 0})
            bucket[action] = int(bucket.get(action, 0)) + 1
            total = dict(bucket)
        label = "屬實" if action == "ok" else "誤判"
        await interaction.response.send_message(
            f"已記錄為{label}。這類判斷目前 屬實 {total['ok']} / 誤判 {total['no']}。",
            ephemeral=True,
        )
        await self._audit(interaction, f"{interaction.user.mention} 標記為{label}")

    async def _delete_target(
        self, interaction: discord.Interaction, guild: discord.Guild, channel_id: int, message_id: int
    ) -> None:
        """Delete the message a report pointed at, on a moderator's press.

        Every failure answers the presser rather than passing silently: someone
        who pressed a button and saw nothing would not know whether it went.
        """
        channel = guild.get_channel_or_thread(channel_id)
        if channel is None:
            await interaction.response.send_message("找不到原頻道。", ephemeral=True)
            return
        try:
            message = await channel.fetch_message(message_id)
            await message.delete()
        except discord.NotFound:
            await interaction.response.send_message("訊息已經不存在了。", ephemeral=True)
            return
        except discord.Forbidden:
            await interaction.response.send_message("機器人沒有刪除該訊息的權限。", ephemeral=True)
            return
        except discord.HTTPException as error:
            log.warning("messagewatch: delete failed (%s)", type(error).__name__)
            await interaction.response.send_message("刪除失敗。", ephemeral=True)
            return
        await interaction.response.send_message("已刪除該訊息。", ephemeral=True)
        await self._case(guild, "messagewatch_delete", message.author, interaction.user, "MessageWatch")
        await self._audit(interaction, f"{interaction.user.mention} 刪除了該訊息")

    async def _add_role(
        self,
        interaction: discord.Interaction,
        guild: discord.Guild,
        member: discord.Member,
        channel_id: int,
    ) -> None:
        """Add the channel's configured role to the flagged member.

        The ruleset that prompted the rules feature enforces with a role rather
        than a delete, which is why this action exists at all.
        """
        # The watched channel's id, carried in the custom_id -- not
        # `interaction.channel_id`, which is wherever the report was posted.
        # With `[p]watch route` those are different channels, and without it the
        # report still sits in the moderator channel, so reading the role from
        # the interaction's channel never found one.
        channel_settings = await self.config.channel_from_id(channel_id).all()
        role_id = int(channel_settings.get("action_role") or 0)
        role = guild.get_role(role_id) if role_id else None
        if role is None:
            await interaction.response.send_message(
                "這個頻道還沒設定要加的身分組（`[p]watch action role`）。", ephemeral=True
            )
            return
        try:
            await member.add_roles(role, reason="MessageWatch")
        except discord.Forbidden:
            await interaction.response.send_message(
                "機器人沒有權限給這個身分組（可能身分組順序不足）。", ephemeral=True
            )
            return
        except discord.HTTPException as error:
            log.warning("messagewatch: add_roles failed (%s)", type(error).__name__)
            await interaction.response.send_message("加身分組失敗。", ephemeral=True)
            return
        await interaction.response.send_message(f"已加上 {role.name}。", ephemeral=True)
        await self._case(guild, "messagewatch_role", member, interaction.user, f"加上 {role.name}")
        await self._audit(interaction, f"{interaction.user.mention} 給 {member.mention} 加上 {role.name}")

    @commands.Cog.listener()
    async def on_message(self, message: discord.Message) -> None:
        """Queue one eligible message, and judge once the window is full.

        Every gate here is cheap and local; the expensive work happens in
        `flush`, which this calls outside the lock.
        """
        guild = getattr(message, "guild", None)
        channel = getattr(message, "channel", None)
        author = getattr(message, "author", None)
        if guild is None or channel is None or author is None:
            return
        if getattr(author, "bot", False) or getattr(message, "webhook_id", None) is not None:
            return
        settings = await self.config.guild(guild).all()
        if settings["disclosure_version"] != DISCLOSURE_VERSION:
            return
        if channel.id not in set(settings["watched_channels"]):
            return
        text = clean_text(getattr(message, "content", "") or "")
        # A bare screenshot is the commonest shape a scam takes here and it
        # carries no text at all, so dropping it on empty text alone made the
        # image feature unreachable for the case it was built for.
        attachments, skipped_image = eligible_attachments(message)
        # A message that is only a refused attachment still queues, carrying no
        # text, so the reason reaches `flush` and from there `[p]watch show`.
        # That costs one empty slot in a window of `window_size`, occasionally.
        # The alternative is the state this feature was in all day: someone
        # posts a screenshot, nothing happens, and every surface reports that
        # the channel is fine.
        if not text and not attachments and not skipped_image:
            return
        async with self._locks[channel.id]:
            # Re-read inside the lock. `[p]watch disable` leaves the watched set
            # and then clears the queue under this same lock, so a handler that
            # passed the check above before the disable must not append after
            # the clear and leave a disabled channel holding message text.
            if channel.id not in set(await self.config.guild(guild).watched_channels()):
                return
            # One read, answering both questions: whether this channel's queue
            # should hold image references at all, and whether an image-only
            # message is worth queueing. An earlier version skipped this read
            # for messages that had text, storing attachments unconditionally
            # so the ordinary path stayed at one settings lookup. That saving
            # produced three separate findings in a row, the last of which was
            # that a channel could queue attachments while image reading was
            # off and have them sent when someone turned it on. The queue now
            # holds an image only where the channel reads images, and the
            # window between the two no longer exists to be reasoned about.
            images = attachments if await self.config.channel(channel).images() else []
            if not text and not images and not skipped_image:
                return
            self._pending[channel.id].append(
                {
                    "author_id": author.id,
                    "message_id": getattr(message, "id", 0),
                    "text": text,
                    "jump_url": getattr(message, "jump_url", ""),
                    "at": time.monotonic(),
                    # Captured here because the queue holds dictionaries and
                    # the Message with its attachments is gone by the time the
                    # window is judged.
                    "images": images,
                    # Rides along to `flush`, which is where a reason can reach
                    # `[p]watch show` without being wiped by the next
                    # successful judgement.
                    "skipped_image": skipped_image,
                }
            )
            # hasattr: several tests build a partial cog that skips __init__.
            self._usage_delta[guild.id]["messages_queued"] += 1
            full = len(self._pending[channel.id]) >= int(settings["window_size"])
        # Outside the lock: flush takes it again for the queue alone, so the
        # provider request never blocks this channel's ingestion.
        if full:
            await self.flush(channel)

    # invoke_without_command, or the callback never runs for a bare `[p]watch`
    # and the help it sends is unreachable. A command group that answers
    # nothing is the same silent no-op this cog exists to avoid, just at the
    # command surface instead of the judging one.
    # hybrid, so every subcommand below is reachable both as `[p]watch ...` and
    # as `/watch ...`. HybridGroup.command and .group produce hybrid children,
    # so this one decorator converts the whole tree. Discord allows groups to
    # nest one level, which `/watch rule add` uses exactly.
    #
    # default_permissions hides the whole tree from members in Discord's own
    # UI. It is a display filter, not the check -- the Red checks below still
    # run, and a guild can override it in Integrations settings.
    @commands.hybrid_group(name="watch", invoke_without_command=True)
    @app_commands.default_permissions(manage_guild=True)
    @commands.guild_only()
    @checks.admin_or_permissions(manage_guild=True)
    async def watch_group(self, ctx: commands.Context) -> None:
        """Configure scam and hostility reporting."""
        if ctx.invoked_subcommand is None:
            await ctx.send_help()

    @watch_group.command(name="key")
    @checks.is_owner()
    async def watch_key(self, ctx: commands.Context) -> None:
        """Store the TypeSafe API key through Red's shared token storage."""
        view = SetApiView(default_service=TOKEN_SERVICE, default_keys={"api_key": ""})
        await ctx.send("Set the `api_key` through Red's shared API token storage.", view=view)

    @watch_group.command(name="report")
    async def watch_report(self, ctx: commands.Context, channel: discord.TextChannel) -> None:
        """Set the moderator channel that receives reports."""
        await self.config.guild(ctx.guild).report_channel.set(channel.id)
        await ctx.send(f"報告會送到 {channel.mention}。")

    @watch_group.command(name="route")
    async def watch_route(
        self,
        ctx: commands.Context,
        channel: discord.TextChannel,
        destination: discord.TextChannel | None = None,
    ) -> None:
        """Send one watched channel's reports somewhere other than the default.

        `[p]watch route #樹洞 #樹洞管理` routes them; `[p]watch route #樹洞`
        with no destination clears the route and falls back to `[p]watch report`.
        """
        if destination is None:
            await self.config.channel(channel).report_channel.set(0)
            await ctx.send(f"{channel.mention} 的報告改回送到伺服器預設的報告頻道。")
            return
        await self.config.channel(channel).report_channel.set(destination.id)
        await ctx.send(f"{channel.mention} 的報告會送到 {destination.mention}。")

    @watch_group.group(name="action", invoke_without_command=True)
    async def watch_action(self, ctx: commands.Context) -> None:
        """Choose which buttons a channel's reports carry."""
        if ctx.invoked_subcommand is None:
            await ctx.send_help()

    @watch_action.command(name="set")
    async def watch_action_set(
        self, ctx: commands.Context, channel: discord.TextChannel, *, names: str = ""
    ) -> None:
        """Set this channel's buttons, e.g. `ok no del`. Empty clears to marks only."""
        wanted = [name for name in names.split() if name]
        unknown = [name for name in wanted if name not in ACTIONS]
        if unknown:
            await ctx.send(f"不認得：{', '.join(unknown)}。可用：{', '.join(ACTIONS)}")
            return
        chosen = wanted or list(DEFAULT_ACTIONS)
        # Order is the button order, and duplicates would render twice.
        seen: list[str] = []
        for name in chosen:
            if name not in seen:
                seen.append(name)
        await self.config.channel(channel).actions.set(seen)
        await ctx.send(f"{channel.mention} 的報告按鈕：{', '.join(seen)}")

    @watch_action.command(name="role")
    async def watch_action_role(
        self, ctx: commands.Context, channel: discord.TextChannel, role: discord.Role | None = None
    ) -> None:
        """Set the role the `role` button adds, or clear it with no role."""
        if role is None:
            await self.config.channel(channel).action_role.set(0)
            await ctx.send(f"已清除 {channel.mention} 的身分組設定。")
            return
        if role >= ctx.guild.me.top_role:
            # Saying so now beats a button that looks configured and fails on
            # the click, which is the same silent no-op in a slower form.
            await ctx.send(
                f"`{role.name}` 的順序高於或等於機器人的最高身分組，機器人無法給它。"
                "請把機器人的身分組移到它上面。"
            )
            return
        await self.config.channel(channel).action_role.set(role.id)
        await ctx.send(
            f"{channel.mention} 的「加上身分組」會給 `{role.name}`。",
            allowed_mentions=discord.AllowedMentions.none(),
        )

    @watch_group.command(name="vision")
    async def watch_vision(self, ctx: commands.Context, key: str = "", *, value: str = "") -> None:
        """Set the vision provider's endpoint or model, or show both.

        Separate from `[p]watch set` because that table is numeric: every entry
        carries a range and is rejected outside it. These two are free strings,
        and squeezing them into a numeric validator would have meant a range
        check that means nothing.

        Bot owner only, and stored globally. The API key these two spend is
        bot-wide and the owner's; an administrator of any guild the bot has
        joined who could set the endpoint would be able to send that bearer
        token, and every image, to a host of their choosing. Reading is left
        open to the administrators who have to configure a channel around it.
        """
        fields = {
            "api_base": ("image_api_base", "視覺模型的 API 根位址，例如 `https://openrouter.ai`"),
            "model": ("image_model", "視覺模型名稱。沒有預設值——哪一個讀中文截圖最準還沒量過。"),
        }
        scope = self.config
        if key not in fields:
            settings = await scope.all()
            lines = [
                f"`{name}` = `{settings[stored] or '（未設定）'}`\n{note}"
                for name, (stored, note) in fields.items()
            ]
            await ctx.send(
                embed=discord.Embed(
                    title="MessageWatch 視覺模型設定",
                    description="\n\n".join(lines)
                    + "\n\n用 `[p]watch vision <api_base|model> <值>` 設定（僅 bot owner）。"
                    + "\nAPI key 由 bot owner 用 `[p]set api messagewatch_vision api_key <key>` 存。",
                    colour=discord.Colour.blurple(),
                ),
                allowed_mentions=discord.AllowedMentions.none(),
            )
            return
        if not await self.bot.is_owner(ctx.author):
            await ctx.send(
                "只有 bot owner 能改視覺模型的端點與模型名稱——它們花的是 bot 全域的 API key。"
            )
            return
        stored, _ = fields[key]
        value = value.strip()
        if key == "api_base" and value and not endpoint_is_allowed(value):
            await ctx.send(
                "`api_base` 必須是 `https://`，或是 `http://` 加上區網的 IP"
                "（RFC1918、IPv6 ULA 或 loopback），例如 `http://192.168.1.2:8318`。"
                "\n`http://` 只接受字面 IP，不接受主機名——主機名要靠 DNS 解析，"
                "而解析結果可以在設定之後改變。"
            )
            return
        if len(value) > 200:
            await ctx.send("太長了，請控制在 200 字元內。")
            return
        await scope.set_raw(stored, value=value)
        await ctx.send(
            f"`{key}` 設為 `{value}`。" if value else f"已清除 `{key}`。",
            allowed_mentions=discord.AllowedMentions.none(),
        )

    @watch_group.command(name="images")
    async def watch_images(
        self, ctx: commands.Context, channel: discord.TextChannel, switch: str = ""
    ) -> None:
        """Turn image reading on or off for one channel, or report its state."""
        scope = self.config.channel(channel)
        wanted = switch.strip().casefold()
        if wanted not in ("on", "off", ""):
            await ctx.send("請用 `on` 或 `off`。")
            return
        if not wanted:
            state = "開啟" if await scope.images() else "關閉"
            await ctx.send(f"{channel.mention} 的圖片判讀目前是 **{state}**。")
            return
        if wanted == "off":
            # Under the channel lock, because `flush` reads `images` and then
            # awaits the download and the vision call while holding it. Without
            # this an in-flight window sends an attachment after the command has
            # already reported that image reading is off -- the same disable
            # contract `[p]watch disable` holds.
            async with self._locks[channel.id]:
                await scope.images.set(False)
            await ctx.send(f"已關閉 {channel.mention} 的圖片判讀。")
            return
        settings = await self.config.all()
        await scope.images.set(True)
        await ctx.send(
            f"已開啟 {channel.mention} 的圖片判讀。該頻道的圖片附件會被下載、縮放後送往視覺模型抽取文字。"
        )
        # Saying so now beats a channel that looks configured and silently
        # reads nothing, which is this project's most common failure.
        missing = [
            name for name, value in (
                ("`image_model`", settings["image_model"]),
                ("`image_api_base`", settings["image_api_base"]),
            ) if not str(value).strip()
        ]
        if not await self.get_image_key():
            missing.append("視覺模型的 API key（`[p]set api messagewatch_vision api_key <key>`，僅 bot owner）")
        if missing:
            await ctx.send(
                "⚠️ 還缺：" + "、".join(missing) + "。在補齊之前，這個頻道的圖片不會被讀取，也不會送出。"
            )

    @watch_group.command(name="marks")
    async def watch_marks(self, ctx: commands.Context) -> None:
        """Show what moderators have marked, which is the only precision data."""
        marks = await self.config.guild(ctx.guild).marks()
        names = {"s": "詐騙", "h": "敵意", "t": "火藥味", "r": "違規"}
        rows = []
        for key, label in names.items():
            bucket = marks.get(key) or {}
            ok, no = int(bucket.get("ok", 0)), int(bucket.get("no", 0))
            if ok or no:
                rate = ok / (ok + no)
                rows.append(f"{label}：屬實 `{ok}` ／ 誤判 `{no}` — 準確率 `{rate:.0%}`")
        embed = discord.Embed(
            title="MessageWatch 標記統計",
            description="\n".join(rows) or "（還沒有任何標記）",
            colour=discord.Colour.blurple(),
        )
        embed.set_footer(
            text="這些數字是精確率，不是召回率。漏掉而沒有報告的案例不會出現在這裡。"
        )
        await ctx.send(embed=embed, allowed_mentions=discord.AllowedMentions.none())

    @watch_group.command(name="disclosure")
    async def watch_disclosure(self, ctx: commands.Context, confirmation: str = "") -> None:
        """Show the data-export disclosure, or accept it with I_ACCEPT."""
        if confirmation != "I_ACCEPT":
            embed = discord.Embed(
                title="MessageWatch · 資料輸出揭露",
                description=DISCLOSURE_TEXT
                + "\n\n接受後才能啟用任何頻道：`[p]watch disclosure I_ACCEPT`",
                colour=discord.Colour.orange(),
            )
            await ctx.send(embed=embed, allowed_mentions=discord.AllowedMentions.none())
            return
        await self.config.guild(ctx.guild).disclosure_version.set(DISCLOSURE_VERSION)
        await ctx.send("已記錄接受。現在可以逐一啟用頻道。")

    @watch_group.command(name="enable")
    async def watch_enable(self, ctx: commands.Context, channel: discord.TextChannel) -> None:
        """Start watching one channel. Every channel is opted in separately."""
        scope = self.config.guild(ctx.guild)
        if await scope.disclosure_version() != DISCLOSURE_VERSION:
            await ctx.send("請先閱讀並接受 `[p]watch disclosure`。")
            return
        routed = await self.config.channel(channel).report_channel()
        if not routed and not await scope.report_channel():
            await ctx.send(
                "請先用 `[p]watch report` 指定伺服器預設的報告頻道，"
                "或用 `[p]watch route` 單獨指定這個頻道的報告去處。"
            )
            return
        async with scope.watched_channels() as watched:
            if channel.id in watched:
                await ctx.send(f"{channel.mention} 已經在監看中。")
                return
            watched.append(channel.id)
        await ctx.send(f"開始監看 {channel.mention}。該頻道的訊息會送往 TypeSafe 判斷。")
        if await self.get_api_key() is None:
            # The key is owner-scoped and this command is not, so a manager can
            # enable a channel that then silently judges nothing.
            await ctx.send("⚠️ 尚未設定 API key，在 bot owner 執行 `[p]watch key` 之前不會產生任何判斷。")

    @watch_group.command(name="disable")
    async def watch_disable(self, ctx: commands.Context, channel: discord.TextChannel) -> None:
        """Stop watching one channel and drop anything pending for it."""
        # Waits for the channel lock, so if a judgement is in flight this
        # command returns only once it has finished. That wait is the reason
        # the disclosure's "disabling stops the sending immediately" is true:
        # when this replies, nothing for this channel is still on its way out.
        # `typing()` is there so a moderator sees the wait rather than silence.
        async with ctx.typing():
            async with self._locks[channel.id]:
                async with self.config.guild(ctx.guild).watched_channels() as watched:
                    if channel.id not in watched:
                        message = f"{channel.mention} 本來就沒有在監看。"
                    else:
                        watched.remove(channel.id)
                        self._pending.pop(channel.id, None)
                        self._last_report.pop(channel.id, None)
                        self._last_judged.pop(channel.id, None)
                        self._last_error.pop(channel.id, None)
                        message = f"停止監看 {channel.mention}，未送出的暫存也已清除。"
        await ctx.send(message)

    @watch_group.group(name="rule", invoke_without_command=True)
    async def watch_rule(self, ctx: commands.Context) -> None:
        """Manage the rules a watched channel is judged against."""
        if ctx.invoked_subcommand is None:
            await ctx.send_help()

    @watch_group.group(name="serverrule", invoke_without_command=True)
    async def watch_serverrule(self, ctx: commands.Context) -> None:
        """Rules every watched channel is judged against.

        A separate group rather than an optional channel argument on
        `[p]watch rule`: the rule text is free-form, so a first word that
        looks like a channel mention would silently change which set it
        landed in, and the two sets are not interchangeable.
        """
        await ctx.send_help()

    @watch_serverrule.command(name="add")
    async def watch_serverrule_add(self, ctx: commands.Context, *, text: str) -> None:
        """Add one rule that applies in every watched channel."""
        text = " ".join(text.split())
        if not text:
            await ctx.send("規則內容不能是空的。")
            return
        if len(text) > MAX_RULE_CHARS:
            await ctx.send(f"單條規則請控制在 {MAX_RULE_CHARS} 字以內（目前 {len(text)} 字）。")
            return
        async with self.config.guild(ctx.guild).server_rules() as rules:
            if len(rules) >= MAX_RULES:
                await ctx.send(f"最多 {MAX_RULES} 條伺服器規則，請先刪除不需要的。")
                return
            rules.append(text)
            number = len(rules)
        await ctx.send(
            f"伺服器規則第 {number} 條：{text}\n"
            f"套用於所有被監看的頻道，排在各頻道自己的規則前面。",
            allowed_mentions=discord.AllowedMentions.none(),
        )

    @watch_serverrule.command(name="list")
    async def watch_serverrule_list(self, ctx: commands.Context) -> None:
        """Show the server-wide rules."""
        rules = list(await self.config.guild(ctx.guild).server_rules())
        body = (
            "\n".join(f"{number}. {rule}" for number, rule in enumerate(rules, start=1))
            or "尚未設定。加了之後，每個被監看的頻道都會用它判斷。"
        )
        await ctx.send(
            embed=discord.Embed(
                title="伺服器規則", description=body[:EMBED_FIELD_LIMIT],
                colour=discord.Colour.blurple(),
            ),
            allowed_mentions=discord.AllowedMentions.none(),
        )

    @watch_serverrule.command(name="remove")
    async def watch_serverrule_remove(self, ctx: commands.Context, number: int) -> None:
        """Remove one server rule by the number `[p]watch serverrule list` shows."""
        async with self.config.guild(ctx.guild).server_rules() as rules:
            if not 1 <= number <= len(rules):
                await ctx.send(f"沒有第 {number} 條。用 `[p]watch serverrule list` 看編號。")
                return
            removed = rules.pop(number - 1)
        await ctx.send(
            f"已刪除伺服器規則第 {number} 條：{removed}",
            allowed_mentions=discord.AllowedMentions.none(),
        )

    @watch_serverrule.command(name="clear")
    async def watch_serverrule_clear(self, ctx: commands.Context) -> None:
        """Drop every server rule. Channel rules are untouched."""
        await self.config.guild(ctx.guild).server_rules.set([])
        await ctx.send("已清除所有伺服器規則。各頻道自己的規則不受影響。")

    @watch_rule.command(name="add")
    async def watch_rule_add(
        self, ctx: commands.Context, channel: discord.TextChannel, *, text: str
    ) -> None:
        """Add one rule to one channel. One rule per command, deliberately."""
        text = " ".join(text.split())
        if not text:
            await ctx.send("規則內容不能是空的。")
            return
        if len(text) > MAX_RULE_CHARS:
            await ctx.send(f"單條規則請控制在 {MAX_RULE_CHARS} 字以內（目前 {len(text)} 字）。")
            return
        async with self.config.channel(channel).rules() as rules:
            if len(rules) >= MAX_RULES:
                await ctx.send(f"一個頻道最多 {MAX_RULES} 條規則，請先刪除不需要的。")
                return
            rules.append(text)
            number = len(rules)
        # A rule is moderator-written text echoed back verbatim, so a rule
        # containing @everyone would otherwise ping the guild from here.
        await ctx.send(
            f"{channel.mention} 第 {number} 條：{text}",
            allowed_mentions=discord.AllowedMentions.none(),
        )

    @watch_rule.command(name="list")
    async def watch_rule_list(
        self, ctx: commands.Context, channel: discord.TextChannel
    ) -> None:
        """Show a channel's rules, exactly as the model is given them.

        Server rules included and marked, in the order the model receives
        them. Listing only the channel's own would print numbers that do not
        match the ones a report cites, which is the number a moderator
        actually looks up.
        """
        settings = await self.config.channel(channel).all()
        guild_settings = await self.config.guild(ctx.guild).all()
        server_count = len(guild_settings.get("server_rules") or ())
        rules = effective_rules(settings, guild_settings)
        lines = [
            f"{number}. {rule}" + ("　`伺服器`" if number <= server_count else "")
            for number, rule in enumerate(rules, start=1)
        ]
        embed = discord.Embed(
            title=f"#{channel.name} 的判斷規則",
            description="\n".join(lines) or "（尚未設定，這個頻道只做詐騙與敵意判斷）",
            colour=discord.Colour.blurple(),
        )
        dropped = server_count + len(settings["rules"]) - len(rules)
        if dropped:
            embed.add_field(
                name="⚠️ 超出上限",
                value=f"共 {server_count + len(settings['rules'])} 條，超過 {MAX_RULES} 條上限，"
                      f"這個頻道最後 {dropped} 條不會被送出。",
                inline=False,
            )
        if settings["purpose"]:
            embed.add_field(name="頻道用途", value=settings["purpose"], inline=False)
        channel_threshold = float(settings["rule_threshold"])
        effective = effective_rule_threshold(settings, guild_settings)
        source = "沿用伺服器設定" if not channel_threshold else "此頻道獨立設定"
        embed.add_field(name="違規門檻", value=f"`{effective}`（{source}）", inline=False)
        await ctx.send(embed=embed, allowed_mentions=discord.AllowedMentions.none())

    @watch_rule.command(name="threshold")
    async def watch_rule_threshold(
        self, ctx: commands.Context, channel: discord.TextChannel, value: str = ""
    ) -> None:
        """Set this channel's own rule-violation threshold, or show it.

        `0` clears the override back to inheriting the guild's rule_threshold.
        Rules are per-channel but the threshold was per-guild, and how well
        one number separates violating from clean messages differs by
        ruleset -- see DEFAULT_CHANNEL's comment for the measured numbers.
        """
        if not value:
            settings = await self.config.channel(channel).all()
            guild_settings = await self.config.guild(ctx.guild).all()
            channel_threshold = float(settings["rule_threshold"])
            effective = effective_rule_threshold(settings, guild_settings)
            source = "沿用伺服器設定" if not channel_threshold else "此頻道獨立設定"
            await ctx.send(
                f"{channel.mention} 的違規門檻是 `{effective}`（{source}）。",
                allowed_mentions=discord.AllowedMentions.none(),
            )
            return
        try:
            parsed = float(value)
        except ValueError:
            await ctx.send("違規門檻需要是數字。")
            return
        # Same NaN trap as watch_set: `not low <= parsed <= high` rejects NaN,
        # while `parsed < low or parsed > high` would let it through and make
        # every probability comparison against it false.
        if not 0.0 <= parsed <= 1.0:
            await ctx.send("違規門檻必須介於 `0.0` 與 `1.0`。")
            return
        await self.config.channel(channel).rule_threshold.set(parsed)
        if parsed == 0.0:
            await ctx.send(
                f"{channel.mention} 的違規門檻改回沿用伺服器設定。",
                allowed_mentions=discord.AllowedMentions.none(),
            )
            return
        await ctx.send(
            f"{channel.mention} 的違規門檻設為 `{parsed}`。",
            allowed_mentions=discord.AllowedMentions.none(),
        )

    @watch_rule.command(name="remove")
    async def watch_rule_remove(
        self, ctx: commands.Context, channel: discord.TextChannel, number: int
    ) -> None:
        """Remove one rule by the number `[p]watch rule list` shows.

        That list numbers the combined set, server rules first, so the number
        a moderator reads is not an index into this channel's own list. Before
        the offset below, deleting displayed number 1 with one server rule
        configured removed the channel's first rule instead -- the wrong rule,
        with a success message naming the right one.
        """
        server_count = len(await self.config.guild(ctx.guild).server_rules())
        if 1 <= number <= server_count:
            await ctx.send(
                f"第 {number} 條是伺服器規則，不屬於這個頻道。"
                f"要刪的話用 `[p]watch serverrule remove {number}`，"
                f"但它會從**所有**被監看的頻道消失。"
            )
            return
        async with self.config.channel(channel).rules() as rules:
            index = number - server_count
            if not 1 <= index <= len(rules):
                total = server_count + len(rules)
                await ctx.send(
                    f"沒有第 {number} 條。目前共 {total} 條"
                    f"（伺服器 {server_count} 條 + 這個頻道 {len(rules)} 條）。"
                )
                return
            removed = rules.pop(index - 1)
        # The numbers are positions, so removing one renumbers the rest. Saying
        # so beats a moderator deleting the wrong rule next time.
        await ctx.send(
            f"已刪除第 {number} 條：{removed}\n後面的規則會往前遞補編號。",
            allowed_mentions=discord.AllowedMentions.none(),
        )

    @watch_rule.command(name="clear")
    async def watch_rule_clear(
        self, ctx: commands.Context, channel: discord.TextChannel
    ) -> None:
        """Remove every rule for one channel."""
        await self.config.channel(channel).rules.set([])
        await ctx.send(f"已清除 {channel.mention} 的所有規則，該頻道回到只做詐騙與敵意判斷。")

    @watch_rule.command(name="purpose")
    async def watch_rule_purpose(
        self, ctx: commands.Context, channel: discord.TextChannel, *, text: str = ""
    ) -> None:
        """Set one sentence saying what this channel is for."""
        text = " ".join(text.split())
        if len(text) > MAX_PURPOSE_CHARS:
            await ctx.send(f"請控制在 {MAX_PURPOSE_CHARS} 字以內（目前 {len(text)} 字）。")
            return
        await self.config.channel(channel).purpose.set(text)
        await ctx.send(f"已設定 {channel.mention} 的用途說明。" if text else "已清除用途說明。")

    @watch_group.command(name="set")
    # Built from SETTING_RULES rather than written out, so the dropdown cannot
    # drift from what the command accepts. Discord caps choices at 25.
    @app_commands.choices(
        key=[
            # Shown as the label, sent as the key. Built from SETTING_RULES so
            # the dropdown cannot drift from what the command accepts.
            app_commands.Choice(name=f"{rule.label}（{name}）", value=name)
            for name, rule in sorted(SETTING_RULES.items())
        ]
    )
    async def watch_set(
        self, ctx: commands.Context, key: str = "", value: str = ""
    ) -> None:
        """Change one setting, or show every setting with what it means."""
        if key not in SETTING_RULES:
            # A bare invocation and a typo get the same answer: the table. A
            # list of key names tells a moderator what is spelled correctly and
            # nothing about what any of them does.
            await ctx.send(embed=await self.settings_embed(ctx.guild, unknown=key))
            return
        if not value:
            rule = SETTING_RULES[key]
            current = await self.config.guild(ctx.guild).get_raw(key)
            await ctx.send(
                f"**{rule.label}**（`{key}`）目前是 `{current}`，可設定 `{rule.low}` 到 `{rule.high}`。\n"
                f"{rule.help}",
                allowed_mentions=discord.AllowedMentions.none(),
            )
            return
        rule = SETTING_RULES[key]
        kind, low, high = rule.kind, rule.low, rule.high
        try:
            parsed = kind(value)
        except ValueError:
            await ctx.send(f"`{key}` 需要 {kind.__name__}。")
            return
        if not low <= parsed <= high:
            await ctx.send(f"`{key}` 必須介於 {low} 與 {high}。")
            return
        await self.config.guild(ctx.guild).set_raw(key, value=parsed)
        await ctx.send(f"`{key}` 設為 `{parsed}`。")

    async def settings_embed(
        self, guild: discord.Guild, unknown: str = ""
    ) -> discord.Embed:
        """Every setting with its meaning, range and current value."""
        settings = await self.config.guild(guild).all()
        embed = discord.Embed(
            title="MessageWatch 可調設定",
            description=(f"沒有 `{unknown}` 這個設定。\n" if unknown else "")
            + "用 `[p]watch set <key> <value>` 修改，只給 key 會顯示該項說明。",
            colour=discord.Colour.blurple(),
        )
        for key, rule in SETTING_RULES.items():
            embed.add_field(
                name=f"{rule.label}　`{key}`",
                value=f"目前 `{settings[key]}`　範圍 `{rule.low}`–`{rule.high}`\n{rule.help}",
                inline=False,
            )
        embed.set_footer(text="門檻的預設值來自 2026-09-20 對 jev-1.13.0 的實測，不是猜的。")
        return embed

    async def _channel_status_rows(self, watched_channels: Iterable[int]) -> str:
        """Per-channel status lines, trimmed to fit one embed field.

        Shared between `[p]watch show` and the dashboard, which is a live
        sibling of it rather than a second tool: same row shape, same
        EMBED_FIELD_LIMIT trim, so the two surfaces cannot silently drift
        apart on what a "channel status" line means.
        """
        rows = []
        for item in watched_channels:
            parts = [f"<#{item}>", f"待判 `{len(self._pending.get(item, ()))}`"]
            routed = int(await self.config.channel_from_id(item).report_channel())
            if routed:
                parts.append(f"→ <#{routed}>")
            judged = self._last_judged.get(item)
            # `_last_judged` is in memory, so a reload empties it while the
            # persisted window count survives. Saying "never" there put two
            # contradictory facts on one embed -- "judged 21 windows" above a
            # column of "never judged" -- with nothing to tell a reader which
            # was wrong. Neither was; the sentence was.
            parts.append(f"上次判斷 <t:{int(judged)}:R>" if judged else "本次載入後尚未判斷")
            noted = self._last_error.get(item)
            if noted is not None:
                parts.append(f"⚠️ `{noted[1]}` <t:{int(noted[0])}:R>")
            rows.append(" · ".join(parts))
        hidden = 0
        # Discord rejects an embed field value over EMBED_FIELD_LIMIT, and the
        # guild that needs this surface most is the one watching enough channels
        # to overflow it. Room is reserved for the line that says so.
        while rows and len("\n".join(rows)) > EMBED_FIELD_LIMIT - 40:
            rows.pop()
            hidden += 1
        if hidden:
            rows.append(f"…另 {hidden} 個頻道未顯示")
        return "\n".join(rows) or "（無）"

    @watch_group.command(name="show")
    async def watch_show(self, ctx: commands.Context) -> None:
        """Show the effective settings for this guild."""
        settings = await self.config.guild(ctx.guild).all()
        # Not just the id list: without the last judgement time and the last
        # reason, a channel that has been silently failing for a week looks
        # exactly like one with nothing to report.
        watched = await self._channel_status_rows(settings["watched_channels"])
        report = f"<#{settings['report_channel']}>" if settings["report_channel"] else "（未設定）"
        embed = discord.Embed(title="MessageWatch 設定", colour=discord.Colour.blurple())
        accepted = int(settings["disclosure_version"])
        # A bumped disclosure halts every channel, and a list that still says
        # "監看中" while nothing is judged is the silent no-op this cog exists
        # to avoid producing.
        if accepted != DISCLOSURE_VERSION:
            state = (
                f"⚠️ **已暫停**：目前接受的是 `v{accepted}`，最新為 `v{DISCLOSURE_VERSION}`。"
                f"在管理員重新執行 `[p]watch disclosure` 並接受之前，所有頻道都不會送出或判斷任何訊息。"
            )
        else:
            state = f"揭露=`v{accepted}` · 報告頻道={report}"
        embed.add_field(name="狀態", value=state, inline=False)
        embed.add_field(name="監看中的頻道", value=watched, inline=False)
        embed.add_field(
            name="門檻",
            value=(
                f"詐騙=`{settings['scam_threshold']}` · 敵意=`{settings['hostile_harm_threshold']}` · "
                f"火藥味=`{settings['heat_threshold']}`\n"
                f"違規=`{settings['rule_threshold']}` · 條文信心下限=`{settings['rule_confidence']}`"
            ),
            inline=False,
        )
        embed.add_field(
            name="花費估計",
            value=f"每百萬 input token `{settings['price_per_million_input_tokens']}` 美元（估計值，見 `[p]watch dashboard`）",
            inline=False,
        )
        embed.add_field(
            name="視窗",
            value=(
                f"每 `{settings['window_size']}` 則判一次 · 冷卻 `{settings['cooldown_seconds']}` 秒\n"
                + (
                    f"安靜 `{settings['idle_seconds']}` 秒後判斷手上的"
                    f"（不足一個視窗也判，但至少要 {MIN_PARTIAL_WINDOW} 則）"
                    if int(settings["idle_seconds"])
                    else "閒置判斷 `關閉`：湊不滿一個視窗的頻道不會被判斷"
                )
            ),
            inline=False,
        )
        await ctx.send(embed=embed, allowed_mentions=discord.AllowedMentions.none())

    async def dashboard_embed(self, guild: discord.Guild) -> discord.Embed:
        """The live usage dashboard: throughput, spend estimate, per-channel status.

        Deliberately a sibling of `[p]watch show`, not a second tool: the same
        per-channel row shape and the same `EMBED_FIELD_LIMIT` trim, both from
        `_channel_status_rows`, so a moderator reading either recognises the
        other. The colour is set from state -- orange the instant any watched
        channel carries a recorded problem -- so the dashboard's whole point,
        being readable at a glance, does not require reading it.
        """
        settings = await self.config.guild(guild).all()
        usage = settings["usage"]
        watched = list(settings["watched_channels"])
        messages = int(usage.get("messages_queued", 0))
        windows = int(usage.get("windows_judged", 0))
        reports = int(usage.get("reports_sent", 0))
        tokens = int(usage.get("input_tokens", 0))
        started = usage.get("started_at") or 0
        price = float(settings["price_per_million_input_tokens"])
        spend = tokens / 1_000_000 * price
        rate = f"{reports / windows:.0%}" if windows else "N/A"

        # The vision provider is a second bill: a different endpoint, a
        # different price, and output tokens that are not free the way Jev's
        # are. Folding it into the figure above would have made one number that
        # is wrong for both.
        images = int(usage.get("images_read", 0))
        failures = int(usage.get("image_failures", 0))
        hits = int(usage.get("image_cache_hits", 0))
        v_in = int(usage.get("vision_input_tokens", 0))
        v_out = int(usage.get("vision_output_tokens", 0))
        v_nanos = int(usage.get("vision_nanodollars", 0))
        v_spend = v_nanos / 1_000_000_000

        healthy = not any(item in self._last_error for item in watched)
        colour = discord.Colour.blurple() if healthy else discord.Colour.orange()

        embed = discord.Embed(title="MessageWatch 儀表板", colour=colour)
        embed.add_field(
            name="統計期間",
            value=f"<t:{int(started)}:R> 至今" if started else "尚未開始累計",
            inline=False,
        )
        embed.add_field(
            name="用量",
            value=(
                f"排入佇列 `{messages}` 則 · 判斷 `{windows}` 次視窗 · 送出報告 `{reports}` 則"
                f"（報告率 `{rate}`）"
            ),
            inline=False,
        )
        lines = [
            f"**TypeSafe**　input `{tokens:,}` · `${spend:.4f}`"
        ]
        # Always printed, including at zero. Hiding the row made "no images
        # have been read" indistinguishable from "this cog does not read
        # images", which is the reading the first person to see it took.
        if images or hits or failures:
            read = f"讀圖 `{images}` 張"
            if hits:
                read += f"（另有 `{hits}` 張命中快取，不計費）"
            # Printed next to the successes rather than only in `watch show`,
            # because this row is where a failure looked like a success: with
            # failures counted as reads, eleven that returned nothing rendered
            # as 讀圖 11 張. A run that is failing has to say so where the
            # number is read.
            if failures:
                read += f" · 失敗 `{failures}` 次（`[p]watch show` 有原因）"
            if v_nanos:
                cost = f"`${v_spend:.4f}`（供應商回報值）"
            else:
                # Saying "$0.0000" here would be a measurement nobody took.
                cost = "供應商未回報成本"
            # Not "failed calls are excluded": a `vision_empty_text` failure
            # parsed fine and its tokens and cost were read, so it is in these
            # numbers while being counted as a failure. What is missing is the
            # usage of calls whose body never parsed -- and it is unknowable,
            # not merely unread: the only out-of-band figures OpenRouter
            # exposes are `X-Generation-Id, X-Provider-Name, request-id,
            # cf-ray`, an id, a name and two trace ids, measured on 2026-09-22
            # by dumping every response header of a real call.
            missing = "（含所有回報了用量的呼叫；讀不到用量的失敗不在其中）" if failures else ""
            lines.append(
                f"**視覺模型**　{read} · in `{v_in:,}` / out `{v_out:,}` · {cost}{missing}"
            )
            if v_nanos:
                lines.append(f"**合計**　`${spend + v_spend:.4f}` 美元")
        else:
            enabled = [
                item for item in watched
                if await self.config.channel_from_id(item).images()
            ]
            where = (
                f"已於 {len(enabled)} 個頻道開啟，尚未讀到圖片"
                if enabled
                else "未在任何頻道開啟（`[p]watch images #頻道 on`）"
            )
            lines.append(f"**視覺模型**　{where} · `$0.0000`")
        embed.add_field(
            name="花費（估計值，見下方註記）",
            value="\n".join(lines),
            inline=False,
        )
        embed.add_field(
            name="監看中的頻道",
            value=await self._channel_status_rows(watched),
            inline=False,
        )

        marks = settings["marks"]
        names = {"s": "詐騙", "h": "敵意", "t": "火藥味", "r": "違規"}
        mark_lines = [
            f"{label} 屬實 `{int((marks.get(key) or {}).get('ok', 0))}` "
            f"／ 誤判 `{int((marks.get(key) or {}).get('no', 0))}`"
            for key, label in names.items()
            if (marks.get(key) or {}).get("ok") or (marks.get(key) or {}).get("no")
        ]
        embed.add_field(
            name="標記統計", value="\n".join(mark_lines) or "（還沒有任何標記）", inline=False
        )

        embed.set_footer(
            text=(
                f"花費是估計值：每百萬 input token ${price} 美元是量到的價格，供應商調價後這裡不會自動更新。"
                "標記統計量到的是精確率，不是召回率——漏掉而沒有報告的案例不會出現在這裡。"
                "API key 是整個機器人共用的，這裡的花費是這個伺服器佔全部帳單的一部分，不是獨立帳單。"
            )
        )
        return embed

    async def _update_dashboards(self) -> None:
        """Edit each guild's dashboard message when its rendered numbers changed.

        Runs from the sweep, so a dashboard is never more than one sweep
        interval stale. Compared against the last rendered embed rather than
        against individual counters, so this edits Discord only when something
        a viewer would actually see has changed.
        """
        all_guilds = await self.config.all_guilds()
        for guild_id, settings in all_guilds.items():
            channel_id = int(settings.get("dashboard_channel") or 0)
            if not channel_id:
                continue
            if guild_id in self._dashboard_error:
                # A permission problem or a missing channel does not fix
                # itself in a minute; wait for `[p]watch dashboard` instead of
                # retrying every tick.
                continue
            guild = self.bot.get_guild(guild_id)
            if guild is None:
                continue
            channel = guild.get_channel(channel_id)
            if channel is None:
                self._dashboard_error[guild_id] = (time.time(), "dashboard_channel_missing")
                continue

            embed = await self.dashboard_embed(guild)
            signature = embed.to_dict()
            if self._dashboard_last_render.get(guild_id) == signature:
                continue

            message_id = int(settings.get("dashboard_message") or 0)
            message = None
            if message_id:
                try:
                    message = await channel.fetch_message(message_id)
                except discord.NotFound:
                    # Deleted -- fall through and post a new one rather than
                    # raising, exactly like a fresh `[p]watch dashboard`.
                    message = None
                except discord.HTTPException as error:
                    log.warning("messagewatch: dashboard fetch failed (%s)", type(error).__name__)
                    self._dashboard_error[guild_id] = (time.time(), "dashboard_fetch_failed")
                    continue
            try:
                if message is not None:
                    await message.edit(embed=embed)
                else:
                    message = await channel.send(
                        embed=embed, allowed_mentions=discord.AllowedMentions.none()
                    )
                    await self.config.guild(guild).dashboard_message.set(message.id)
            except discord.Forbidden:
                self._dashboard_error[guild_id] = (time.time(), "dashboard_forbidden")
                continue
            except discord.HTTPException as error:
                log.warning("messagewatch: dashboard update failed (%s)", type(error).__name__)
                self._dashboard_error[guild_id] = (time.time(), "dashboard_update_failed")
                continue
            self._dashboard_last_render[guild_id] = signature

    @watch_group.command(name="dashboard")
    async def watch_dashboard(
        self, ctx: commands.Context, channel: discord.TextChannel | None = None
    ) -> None:
        """Post a live usage dashboard in one channel, or stop with no channel."""
        if channel is None:
            await self.config.guild(ctx.guild).dashboard_channel.set(0)
            await self.config.guild(ctx.guild).dashboard_message.set(0)
            self._dashboard_error.pop(ctx.guild.id, None)
            self._dashboard_last_render.pop(ctx.guild.id, None)
            await ctx.send("已取消儀表板。")
            return
        embed = await self.dashboard_embed(ctx.guild)
        try:
            message = await channel.send(embed=embed, allowed_mentions=discord.AllowedMentions.none())
        except discord.Forbidden:
            await ctx.send(f"機器人沒有在 {channel.mention} 發言的權限。")
            return
        except discord.HTTPException as error:
            log.warning("messagewatch: dashboard post failed (%s)", type(error).__name__)
            await ctx.send("儀表板訊息發送失敗。")
            return
        await self.config.guild(ctx.guild).dashboard_channel.set(channel.id)
        await self.config.guild(ctx.guild).dashboard_message.set(message.id)
        self._dashboard_error.pop(ctx.guild.id, None)
        self._dashboard_last_render[ctx.guild.id] = embed.to_dict()
        await ctx.send(f"已在 {channel.mention} 建立儀表板，之後每分鐘更新一次。")
