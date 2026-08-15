# NyanCogs

Cogs for [Red Discord Bot](https://github.com/Cog-Creators/Red-DiscordBot).

## ChannelSummary

ChannelSummary creates attributed Discord channel summaries through an OpenAI-
compatible LLM Agent. It supports recent-message, explicit-start, and duration
ranges. The Agent can search additional history only in the invocation channel
and can use native OpenAI or OpenRouter web search when the selected profile
supports it.

Install and load it with Red's Downloader:

```text
[p]cog install NyanCogs channelsummary
[p]load channelsummary
```

The bot owner then creates one or more global provider profiles. Profiles store
only endpoint, dialect, token-service name, and model allowlist metadata; API
keys remain in Red's shared API token storage.

```text
[p]summary provider add openai openai_responses https://api.openai.com channelsummary_openai gpt-5.6
[p]summary provider key openai

[p]summary provider add openrouter openrouter_responses https://openrouter.ai channelsummary_openrouter openai/gpt-5.6
[p]summary provider key openrouter
```

HTTP is restricted to RFC1918, IPv6 ULA, or loopback destinations. API keys
and selected Discord data traverse the LAN unencrypted; use HTTP only on a
trusted LAN. Prefer HTTPS whenever it is available.

Guild members with guild-level Manage Messages use `/summary settings` to pick
a profile and model, adjust limits through the Select and Modal panel, review
the data-export disclosure, and enable the Cog. The equivalent text setting
surface is `[p]summaryset set <key> <value>`; use
`[p]summary help` for every key, range, provider command, and privacy detail.

| Command | Purpose |
|---|---|
| `/summary auto [count]` | Summarize recent messages and search backward for the natural topic start |
| `/summary from <message>` | Summarize from an inclusive same-channel message ID or link |
| `/summary time <duration>` | Summarize a range such as `30m`, `2h`, or `1d` |
| `/summary settings` | Open the Manage Messages Select and Modal configuration panel |
| `[p]summaryset show` | Show all effective guild settings |
| `[p]summaryset set <key> <value>` | Change any documented text setting |
| `[p]summaryset reset <key\|all>` | Reset one setting or the full guild configuration |
| `[p]summaryset enable I_ACCEPT` / `[p]summaryset disable` | Enable after disclosure acceptance, or disable summaries |
| `[p]summaryset checkpoint <show\|reset>` | Inspect or clear this channel's successful-summary checkpoint |

While a summary runs, the bot updates one temporary channel status through
message collection, Agent context completion, and Embed rendering, then removes
it. The progress text never exposes hidden reasoning or raw tool payloads.

All users who can view and read the current channel may run a summary after a
guild enables it. The bot needs View Channel, Read Message History, Send
Messages, and Embed Links. A per-user cooldown, atomic guild request quota,
bounded guild/provider concurrency, and a persistent per-channel new-message
checkpoint limit API cost and repeated output. Defaults require 20 new human
messages after a successful summary before that channel can run another.

Summary Embeds preserve validated `<@user_id>` speaker attribution but use
`AllowedMentions.none()`, so they do not notify anyone. Discord jump links are
constructed locally from supplied messages. Web links are rendered only from
provider citation annotations. Model-authored links, mass/role/channel
mentions, and fabricated message IDs are not trusted.

Selected message text, stable user and message IDs, timestamps, reply and embed
metadata, and Agent-generated web queries may leave Discord. When images are
enabled, the selected provider fetches and reads eligible image content (PNG,
JPEG, or WebP) through signed Discord CDN URLs. Image metadata, references, and
signed URLs may be resent on every stateless provider turn, up to 10 turns. Provider
and search-backend retention policies apply. Images are limited to 20 MiB and
25 MP each, 50 MiB and 100 MP total, and the first 20 eligible attachments in
chronological order. ChannelSummary does not persist messages, prompts,
searches, provider responses, or summaries. With an HTTP provider, API keys
and selected Discord data traverse the LAN unencrypted; signed URLs do too.
Use HTTP only on a trusted LAN. Its complete statement is in
[`channelsummary/info.json`](channelsummary/info.json).

## EmbedFixer

EmbedFixer replaces supported social links with provider-fixed links sent by the
bot itself. It never impersonates the message author, never deletes the original
post, and never constructs a `discord.Embed`. After Discord confirms the
provider preview, the cog suppresses only the embeds on the original message.

When the author profile can be derived safely from the source URL, the
replacement row follows this format:

```text
[Source platform](fixed URL) • [@author](author profile) • [Provider](fixed URL)
```

Both the source-platform and provider labels link to the same fixed URL. Labels
are selected from the matched platform and provider rather than being hard-coded
to Twitter or FxTwitter. If the source URL does not contain a derivable author
profile, such as a Pixiv artwork URL, the middle author link is omitted.

### Requirements and installation

- Red Discord Bot 3.5.24 or later
- Python 3.11 or later
- No additional Python packages beyond Red's dependencies

Install the cog with Red's Downloader:

```text
[p]repo add NyanCogs https://github.com/Nanako0129/NyanCogs
[p]cog install NyanCogs embedfixer
[p]load embedfixer
```

Replace `[p]` with the bot's command prefix.

### Permissions

The bot needs the following permissions:

| Location | Permissions |
|---|---|
| Original message channel | View Channel, Read Message History, Manage Messages |
| Replacement or funnel channel | View Channel, Send Messages, Embed Links, Read Message History |
| Default reaction controls | Add Reactions; Use External Emojis when a custom external emoji is configured |

When the original and replacement use the same channel, the permissions from
both rows are required. `Manage Webhooks` is not used.

Server setting commands require Administrator or Manage Server. Regular members
may use `/fix`, `/extractmedia`, the message context menus, and their own
`ignoreme`, `usermode`, and `notify` settings when allowed by the guild's channel,
role, domain, and user rules.

### Commands

| Command | Purpose |
|---|---|
| `[p]fix <link>` / `/fix` | Post ordinary fixed provider links |
| `[p]extractmedia <link>` / `/extractmedia` | Add bounded media URLs for supported metadata providers |
| Message → Apps → Fix Embed | Fix links in an existing message |
| Message → Apps → Extract Media | Extract supported media metadata from an existing message |
| `[p]embedfixer` / `[p]ef` | Show the effective mode and basic state |
| `[p]embedfixer ignoreme` | Opt your messages in or out of automatic fixing |
| `[p]embedfixer usermode` | Follow or override the guild delivery mode |
| `[p]embedfixer notify` | Toggle generic reaction notifications |

Use `[p]help embedfixer` for the complete administrator command list. It includes
enablement, delivery mode, channel and role rules, domain/provider selection,
delete and rotate controls, funnel routing, media extraction channels, optional
post content, spoiler policy, FxTwitter translation, other-bot visibility,
ignored users, reset, import, and export.

The legacy mode name `delete_and_resend` is retained for upstream setting
compatibility. In this cog it does not delete the original message; it has the
same direct bot-send behavior as `resend`. Only `reply` changes where the bot
message is attached.

### Behavior and limits

| Area | Behavior |
|---|---|
| Original message | Never deleted; only its embeds may be suppressed after replacement confirmation |
| Sender identity | Always the bot; no webhook, copied avatar, or copied username |
| Ordinary output | Link-only Markdown row; Discord creates the provider preview |
| Metadata extraction | Twitter/X, Pixiv, and Bluesky only |
| Media handling | Emits allowlisted HTTPS media URLs; never downloads, transcodes, or uploads media bytes |
| Translation | Exactly two ASCII letters and FxTwitter only |
| Funnel routing | Same-guild text channels only; NSFW content cannot be routed to a non-NSFW channel |
| Failures | Unsafe or malformed metadata falls back to the ordinary fixed link; the original is not deleted |
| Ownership controls | Only the original author can delete or rotate eligible bot replacements |

Automatic extraction channels still apply ordinary link fixing to other
supported platforms without fetching metadata. Explicit Extract Media operations
reject platforms outside Twitter/X, Pixiv, and Bluesky.

Kemono media extraction, webhook impersonation, source-message deletion,
provider media downloads, and the upstream database/web dashboard are
intentionally not included.

### Privacy

The cog stores guild/user settings and bounded scalar replacement-ownership
records in Red Config. Records contain IDs, provider/domain identifiers, and
timestamps, but not message content, full URLs, or provider responses.

Provider metadata, optional sanitized post text, and media URLs are processed
transiently for extraction and are not stored, cached, or logged by the cog.
Red's user-data deletion hook removes that user's settings, ownership records,
and notification throttles. The complete data statement is in
[`embedfixer/info.json`](embedfixer/info.json).

### Attribution and license

The provider inventory and transformation rules are adapted from
[`seriaati/embed-fixer`](https://github.com/seriaati/embed-fixer) at upstream
commit
[`42be298c49c3c3910859d1f27943abf9c4e95eb8`](https://github.com/seriaati/embed-fixer/tree/42be298c49c3c3910859d1f27943abf9c4e95eb8).
This Red Cog preserves the upstream GPL-3.0 licensing and is distributed under
this repository's [GPL-3.0 license](LICENSE).
