**English** | [繁體中文](messagewatch-design.zh-TW.md)

# MessageWatch: design decisions

This records why MessageWatch is shaped the way it is. It is not usage
documentation — that is in the [README](../README.md) — but the trade-offs made
while building it, and what forced each one.

The question design and measurements behind the model side are in
[Jev integration](jev-integration.md).

---

## 1. What it does, and what it deliberately does not

MessageWatch reads recent messages in an enabled channel, judges whether the
exchange needs a person to look at it, and posts a report in a moderator
channel.

It never acts on its own. No automatic deletion, timeout, or reminder. A report
can carry buttons, and every button needs someone to press it. The two mark
buttons record a count and ask for no permission beyond reaching the moderator
channel; the three that change something — deleting a message, timing a member
out, adding a role — each require the person pressing to hold the matching
Discord permission themselves.

This is not caution for its own sake. The same repository used to contain a
punishment path that looked complete and did nothing: the old `phishingchecker`
called `modlog.case_create`, which does not exist in Red 3.5 (only `create_case`
does), and neither its ban branch nor its kick branch ever actually called
`ban()` or `kick()`. An automated punishment bot fails by quietly acting on
someone. A reporting bot fails by quietly reporting nothing — a failure a
person can notice.

## 2. The unit of judgement is a window, not a message

Hostility, heat, "someone is being lectured at when they wanted to be heard" —
these are properties of an exchange. A single message cannot carry them. So
the cog accumulates a window (`window_size`, 8 by default) before sending
anything.

- A full window is taken with half of it left behind (take 8, keep 4).
  Without the overlap, a conversation cut across the boundary is never seen
  whole.
- A short window, the kind the idle sweep takes, is consumed entirely. There
  is no later message for an overlap to join it to, and leaving half behind only
  makes the next sweep re-judge the same tail.
- A lone message is never judged; `MIN_PARTIAL_WINDOW = 2` is the floor.

## 3. Channels that never fill a window

The first version only judged at 8 messages. That meant a quiet channel — one
confession, two replies, then nothing — was never judged at all. That is
the exact kind of channel this cog was written to watch.

The answer is a `tasks.loop(seconds=60)` idle sweep: once a queue holds at least
`MIN_PARTIAL_WINDOW` (2) messages and the newest one is older than the guild's
`idle_seconds` (600 by default), it is sent with `partial=True`.

So the real behaviour is:

| Situation | When it is judged |
|---|---|
| 8 messages or more | Immediately |
| 2–7 messages, then silence | Once the silence reaches 10 minutes, at the next sweep (up to 60 seconds later) |
| Exactly 1 message, ever | Never — see §2, one message is not an exchange |

A queue below `MIN_PARTIAL_WINDOW` is skipped in the sweep rather than allowed
into `flush` and turned away by `_take_window`. Otherwise it would record
`no_api_key` or `no_report_channel` against that channel every minute — noise
on a diagnostic surface meant to separate real problems from quiet channels.

The sweep is also where usage counters are written to disk and the dashboard
message is refreshed. It already runs every 60 seconds; both ride along without
extra timer overhead.

## 4. Almost everything is per-channel

Enablement, rules, the channel's purpose note, the violation threshold, where
reports are routed, which buttons a report carries, which role the role button
adds, whether images are read — all per-channel.

This shape was forced by one channel. The venting channel's rules forbid
inspirational platitudes, unsolicited advice, "I've been through this too",
speculation about motives, and smoothing things over on someone's behalf. Every
one of those scores near zero to a scam or hostility detector, and its
disposition is not deletion or a timeout but adding a role that hides the channel
from the person. The same ruleset in a general channel would be absurd, and so
would the same buttons.

Threshold inheritance is `channel_value or guild_value`: a per-channel `0.0`
means *inherit*, not *threshold of zero*.

## 5. The disclosure contract and its version

`DISCLOSURE_VERSION` is currently 4. When the version a guild accepted does not
match the current one, the cog stops sending anything at all for that guild
until a manager accepts again.

It is bumped every time what leaves Discord changes: adding rules and the purpose
note (members cannot write those, but they are still text leaving the platform),
adding buttons and dispositions, adding image reading. The cost of that rule has
to be handled with it — after a bump every guild silently stops, so
`[p]watch show` must state plainly that it is stopped because the disclosure
version is stale. A cog that quietly does nothing is the failure this project
guards against hardest.

The contract text is stated in four places — `DISCLOSURE_TEXT`, the
`end_user_data_statement` in `info.json`, the README, and the report embed's
footer. All four move together, and a test pins the field set of
`DEFAULT_CHANNEL` against a phrase map, so adding any stored field without naming
it in the disclosure turns the suite red.

## 6. Concurrency: one lock, held end to end

`flush()` holds `self._locks[channel.id]` for its entire body. An earlier version
took the lock only while lifting the window, which left a gap between taking the
messages and sending the report — and `[p]watch disable` could land in that gap
while the messages it had just disabled went out anyway.

Holding the lock across the whole body closes that race. There is
still a re-read of `watched_channels` before sending, inside the lock; the
disable command takes the same lock, so the two cannot interleave.

## 7. Provider output is never trusted

Everything that comes back from a provider goes through `_bounded_probability`,
`_bounded_score`, `_bounded_index` or `_bounded_token_count`. This is not
theoretical caution — the same class of defect appeared four times in this
cog, in a different shape each time:

- `float(10**400)` → `OverflowError`
- `int("²")` → `ValueError` (yes, `"²".isdigit()` is `True`)
- Deeply nested JSON → `RecursionError` from `json.loads`
- `int(float("inf"))` → `OverflowError`

Range checks are always written `if not low <= parsed <= high`, never
`if parsed < low or parsed > high`. The second form lets NaN through — both
comparisons are false — and a NaN threshold makes `probability < threshold`
false for everything, which is to say it passes everything.

## 8. Disposition stays in human hands

Report buttons are a persistent view. The `custom_id` encodes
`mw:<action>:<kind>:<channel>:<message>:<author>`, 69 characters at worst.
discord.py does not enforce the 100-character limit (measured); only the
Discord API rejects it, so the bound has to be kept by hand. `cog_load`
re-registers the view with `bot.add_view`, so buttons on old reports still work
after a restart.

The three state-changing actions carry a required permission in the `ACTIONS`
table; the two marks carry `None`. Where one is required, the check lives in the
callback and reads the `guild_permissions` of the person who pressed the button
(`manage_messages` / `moderate_members` / `manage_roles`), not "can see the
moderator channel". Each action is written to the Red modlog under that
moderator's name.

## 9. What is stored

Stored: guild settings, the report channel ID, the set of enabled channel IDs,
per-channel rules and purpose note, the button list, the role ID, thresholds, and
per-rule counts of how moderators marked reports. Counts only.

Not stored: message content, model responses, any judgement.

So false-positive data accumulates — and what accumulates is precision only.
**Recall is still unmeasured.** A missed case needs a real missed case, and the
buttons cannot see those. Every threshold in use came from measurements on
synthetic cases. None of the recent work changed that, and it is written here so
it does not get forgotten.

## 10. The image aux

Jev does not read images. The commonest scam shape here is a message that is
a screenshot and nothing else, so a multimodal model is bolted on to do one
thing: transcribe the characters in the image, verbatim.

Not "describe this image". A description is open-ended generation whose errors
nobody can check against the picture; a verbatim transcription can be checked,
and it is shown in the report so a moderator can do that. The transcription then
feeds the scam judgement that already exists rather than getting a rule of its
own — which means it travels twice, to the vision provider and on to TypeSafe,
and the disclosure says so.

- Downscaled to a 1536 px long edge and re-encoded before sending, which
  discards EXIF including GPS.
- At most 4 images per window; 8 MB and 40 megapixels per image.
- Cached by attachment id, at most 256 entries, in memory only. `cog_unload` and
  a data deletion request both drop the whole cache (it has no author field, so
  it cannot be filtered to one person, and dropping all of it is the honest
  answer).
- **There is no default model.** Which multimodal model reads CJK screenshots
  best has not been measured, and picking one without data would just be guessing,
  so this path sends nothing until it is configured.

The endpoint and model live in global config and only the bot owner can write
them: the API key they spend is bot-wide and the owner's, so an administrator of
any guild the bot has joined who could aim the endpoint would be able to send
that bearer token, and every image, to a host of their own. `[p]watch vision` is
separate from `[p]watch set` because that table is numeric — every entry carries
a range — while these two are free strings, and forcing them in would have meant
a range check that means nothing. `api_base` must be `https://`: the image
leaves Discord over it.

## 11. Cost visibility

Usage — input tokens and windows judged — accumulates in memory, is written to
disk by the idle sweep every 60 seconds, and once more in `cog_unload`, so a
restart loses at most the tail since the last tick. `[p]watch dashboard` pins an
embed in any channel that refreshes on the same tick.

## 12. What is not solved here

- **Recall** (see §9).
- No vision model has been measured.
- Once `flush` is inside a discord.py dispatch task, `cog_unload` cannot cancel
  it — those tasks do not belong to the cog — so an unloaded cog can still emit
  one more report.
