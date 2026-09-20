**English** | [繁體中文](messagewatch-design.zh-TW.md)

# MessageWatch: design decisions

This document records why MessageWatch is shaped the way it is. Usage and command syntax live in the [README](../README.md). For empirical measurements, question schema, and provider benchmarks, see [Jev integration](jev-integration.md).

---

## 1. What it does, and what it deliberately does not

MessageWatch monitors recent messages in explicitly enabled channels, evaluates whether an exchange warrants moderator attention, and dispatches structured reports to a configured moderation channel.

The cog never initiates punitive or corrective actions autonomously—no automated message deletions, timeouts, or member warnings. Every action requires human confirmation via interactive report buttons:

- **Audit marks (`ok`, `no`)**: Record moderator feedback for precision accounting. These require no elevated permissions beyond visibility of the moderation channel.
- **State-altering actions (`del`, `mute`, `role`)**: Delete the target message, apply a temporary timeout, or assign a moderation role. Each button requires the moderator clicking it to hold the corresponding Discord permission directly (`manage_messages`, `moderate_members`, or `manage_roles`).

This boundary addresses a concrete defect found in earlier moderation implementations. A legacy cog in this repository, `phishingchecker`, contained moderation branches that gave the false impression of handling enforcement. In practice, its ban and kick branches attempted to call `modlog.case_create`—an API absent in Red 3.5, where only `create_case` exists—and never invoked `ban()` or `kick()`. 

An automated punishment system fails by silently penalizing innocent members. A reporting system fails by silently omitting a report—a failure mode human operators can identify and diagnose.

## 2. The unit of judgement is a window, not a message

Hostility, interpersonal friction, and condescension are properties of an exchange, not of a single message. Isolated messages cannot establish these dynamics. MessageWatch therefore evaluates rolling windows rather than individual messages, using a default `window_size` of 8.

- **Full windows slide by half (`take = 8`, `stride = 4`)**: When a channel queue reaches `window_size`, 8 messages are evaluated while 4 messages remain in the queue. Without this 50% overlap, conversations that cross a window boundary would be truncated and evaluated without context.
- **Partial windows flush completely**: When an idle sweep consumes a partial window, all queued messages are cleared. Because no immediate subsequent messages exist, preserving an overlap would cause the next sweep to repeatedly re-evaluate the same conversational tail.
- **Single messages are ignored**: Evaluation requires at least `MIN_PARTIAL_WINDOW = 2` messages. A lone message does not constitute an exchange.

## 3. Channels that never fill a window

If evaluation required a full window of 8 messages, low-traffic channels—such as a venting channel where a member posts a single message followed by two replies—would never reach the threshold. These quiet spaces are often the primary channels requiring oversight.

To handle low-activity queues, an idle sweep runs every 60 seconds via `tasks.loop(seconds=60)` (`IDLE_SWEEP_SECONDS = 60`). The sweep checks whether a pending queue contains at least `MIN_PARTIAL_WINDOW` (2) messages and the timestamp of the newest message exceeds the guild's `idle_seconds` setting (default: 600 seconds). If both conditions hold, the queue is flushed with `partial=True`.

| Message Queue State | Evaluation Timing |
|---|---|
| 8 or more messages | Immediate evaluation |
| 2–7 messages, followed by silence | Evaluated once silence reaches `idle_seconds` (10 minutes), on the next 60-second sweep |
| Exactly 1 message | Never evaluated alone; waits for at least `MIN_PARTIAL_WINDOW = 2` |

Queues with fewer than `MIN_PARTIAL_WINDOW` messages are bypassed via `continue` in `_sweep` rather than forwarded to `flush()`. Forwarding undersized queues would trigger `_take_window` rejections and log `no_api_key` or `no_report_channel` errors every minute on idle channels, creating false diagnostics on surfaces intended to flag genuine operational failures.

The idle sweep also handles disk persistence for token spend counters (`_flush_usage`) and refreshes the monitoring dashboard (`_update_dashboards`). Bundling these tasks into the existing 60-second loop avoids auxiliary timer overhead.

## 4. Almost everything is per-channel

Channel enablement, custom rules, channel purpose definitions, violation thresholds (`rule_threshold`), report routing destinations (`report_channel`), report button layouts (`actions`), and role assignment targets (`action_role`) are all configured per channel.

This per-channel isolation was prompted by the requirements of confession and venting channels (e.g., `#樹洞`). Rules in such channels typically prohibit unsolicited advice, empty platitudes, personal anecdotes ("I went through this too"), motive speculation, and unprompted peacemaking. To generic scam or hostility detectors, these supportive or conversational statements register scores near 0.0. Furthermore, the appropriate remedy is neither deletion nor a timeout, but assigning an isolation role that hides the channel from the user. Applying these specialized rules or button actions to a general discussion channel would be counterproductive.

Threshold inheritance follows the pattern `channel_value or guild_value`. A channel setting stored as `0.0` indicates inheritance from the guild-wide configuration, not a literal zero threshold.

## 5. The disclosure contract and its version

`DISCLOSURE_VERSION` is currently set to 3 in `messagewatch.py`. If the version accepted by a guild manager does not match this constant, the cog suspends all outbound processing for that guild until a manager re-accepts via `[p]watch disclosure I_ACCEPT`. Version 3 covers initial baseline exports, channel rules with purpose notes, and interactive report actions. Version 4 exists on an open pull request that adds image reading and is not merged; this document describes the merged code.

Outbound changes trigger version bumps:
- v1: Baseline human message text and channel names.
- v2: Channel rules and moderator purpose notes.
- v3: Interactive report action buttons with modlog audit records.

When the version increments, all guilds halt outbound requests until re-acknowledged. To prevent silent failures, `[p]watch show` prominently reports when processing is suspended due to an outdated disclosure version.

The disclosure statement is synchronized across four locations: `DISCLOSURE_TEXT` in `messagewatch.py`, `end_user_data_statement` in `info.json`, the repository [README](../README.md), and report embed footers. Automated tests validate the configuration schema of `DEFAULT_CHANNEL` against a phrase map in `test_messagewatch.py`, failing the build if a newly persisted field is omitted from the disclosure text.

## 6. Concurrency: one lock, held end to end

The evaluation routine `flush()` acquires `self._locks[channel.id]` across its entire body, including external provider network calls. 

In an earlier prototype, the lock was held only while popping messages from the pending queue. This left a concurrency gap between message extraction and report dispatch. A moderator executing `[p]watch disable` within that window could disable the channel, yet extracted messages would still transmit to external APIs and generate reports.

Holding the lock across the entire method closes this race condition. Message intake pauses briefly during active provider requests; incoming messages append to `self._pending[channel.id]` once the lock releases. In addition, `flush()` re-checks `watched_channels` inside the lock before transmission. Because `[p]watch disable` acquires the same lock, it cannot interleave with that re-check: a channel disabled before the re-check sends nothing. It does not cancel a request already in flight. `flush` holds the lock across the provider call, so the disable command waits for that call to finish, and the report it produces is still delivered.

## 7. Provider output is never trusted

All responses received from external inference providers are validated and constrained via helper utilities: `_bounded_probability`, `_bounded_score`, `_bounded_index`, and `_bounded_token_count`.

These guards were introduced in response to four distinct data-parsing failures encountered during development:

- `float(10**400)` raised `OverflowError` from unboundedly large integers parsed by `json.loads`.
- `int("²")` raised `ValueError` because `"²".isdigit()` returns `True` despite failing integer conversion.
- Excessively nested JSON structures raised `RecursionError` in `json.loads`.
- `int(float("inf"))` raised `OverflowError` because `json.loads` converts literal `Infinity` tokens to float infinity.

Range checks are strictly written using inclusive bounds: `if not low <= parsed <= high`, never `if parsed < low or parsed > high`. The latter pattern evaluates to `False` when comparing against `NaN`, permitting invalid values to bypass filtering and causing downstream checks like `probability < threshold` to fail silently.

## 8. Disposition stays in human hands

Interactive report buttons are implemented as a persistent view. Each button encodes its operational context in a structured `custom_id`:

```text
mw:<action>:<kind>:<channel>:<message>:<author>
```

With three 20-digit snowflakes and the longest action (`role`), this measures 72 characters, below `CUSTOM_ID_LIMIT = 100`, which `build_custom_id` asserts at build time. Two smaller figures were in circulation before that was measured — 69 in an earlier draft of this document and 71 in the source comment — and both were written from inspection rather than from running the builder. While `discord.py` does not validate this 100-character ceiling client-side, the Discord API enforces it strictly. Handlers are re-registered on startup via `bot.add_view` inside `cog_load`, allowing buttons on pre-existing reports to remain functional across bot restarts.

The `ACTIONS` registry pairs each action identifier with its required Discord permission:

| Action Identifier | Button Label | Button Style | Required Discord Permission |
|---|---|---|---|
| `ok` | 屬實 | `secondary` | None (audit mark only) |
| `no` | 誤判 | `secondary` | None (audit mark only) |
| `del` | 刪除訊息 | `danger` | `manage_messages` |
| `mute` | 禁言作者 | `danger` | `moderate_members` |
| `role` | 加上身分組 | `danger` | `manage_roles` |

Button callbacks check `guild_permissions` directly on the interacting member, verifying that the user possesses the requisite administrative authority rather than merely having access to the moderation channel. State changes are recorded in Red's `modlog` credited to the acting moderator.

## 9. What is stored

### Persisted data
- Guild configurations and moderation report channel IDs.
- Sets of explicitly enabled channel IDs.
- Per-channel rules, purpose notes, report route targets, button configurations, and action role IDs.
- Classification thresholds (`scam_threshold`, `hostile_threshold`, `heat_threshold`, `rule_threshold`, `rule_confidence`).
- Aggregate moderator mark counts (`ok` and `no` totals grouped by category).

### Excluded data
- Raw message content.
- Model response payloads.
- Individual inference judgements.

Moderator audit buttons allow precision data to accumulate over time. However, **recall remains unmeasured**. Detecting false negatives requires identifying violations that never generated a report, which button feedback cannot capture. Operational defaults derive from synthetic test benchmarks rather than production recall metrics.

## 10. The image aux

Jev processes text representations only. Because Discord scams frequently arrive as standalone image screenshots without accompanying text, MessageWatch includes an auxiliary multimodal image pipeline with a strictly bounded contract: literal character transcription.

The model is restricted to verbatim OCR transcription. It does not generate descriptive scene summaries. Free-form descriptions represent uncalibrated text that moderators cannot readily audit against original attachments; literal transcriptions can be verified directly on the report embed. Extracted text is fed into the existing scam classification question rather than a dedicated rule, meaning extracted text travels first to the vision endpoint and subsequently to TypeSafe.

Operational parameters:
- Images are downscaled to a maximum long edge of 1536 px and re-encoded before transmission, discarding EXIF metadata including GPS coordinates.
- Limits are capped at 4 images per window, with individual image limits of 8 MB and 40 megapixels.
- Attachments are cached in memory by attachment ID up to 256 entries. The cache contains no user identifiers; consequently, `cog_unload` and GDPR data deletion requests flush the entire cache.
- **No default vision model is configured.** Because transcription accuracy across CJK screenshots remains unmeasured, the pipeline remains inactive until explicitly configured by an operator.

Vision endpoints and model names are stored in global configuration, editable only by the bot owner via `[p]watch vision`. Because vision calls consume the bot owner's global API credentials, restricting this setting prevents server administrators from redirecting API keys or image data to unauthorized hosts. `api_base` must use an `https://` scheme.

## 11. Cost visibility

Resource utilization—including input token tallies and total evaluated windows—accumulates in process memory. Counters are written to disk every 60 seconds during the idle sweep and flushed once more during `cog_unload`. An ungraceful restart loses at most the final 60-second window. Operators can pin an auto-updating status embed in any channel via `[p]watch dashboard`.

## 12. What is not solved here

- **Recall remains unmeasured**: The system tracks precision through moderator feedback, but cannot quantify missed violations.
- **Vision model benchmarks are absent**: Multi-model accuracy on CJK screenshots has not been benchmarked.
- **Dispatch task cancellation on unload**: In-flight `flush()` calls managed by `discord.py` dispatch tasks cannot be terminated during `cog_unload`, meaning an unloaded cog may emit one concluding report.
