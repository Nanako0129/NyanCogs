**English** | [繁體中文](jev-integration.zh-TW.md)

# Building MessageWatch on Jev

This document details how MessageWatch integrates [TypeSafe](https://docs.typesafe.ai) Jev (a System One model) and records the empirical measurements behind each threshold and design choice.

For the cog's overall architecture and Discord-side mechanisms, refer to [design decisions](messagewatch-design.md).

All probabilities and confidence values recorded below were **measured directly against `jev-1.13.0`**. Unmeasured dimensions are stated explicitly.

---

## 1. Why a System One model rather than a generative one

MessageWatch requires calibrated numerical scores for direct mathematical comparison, not unstructured explanatory prose.

When a generative model outputs text such as "this message appears somewhat fraudulent," an application must either introduce brittle regex parsing layers or delegate control to uncalibrated prose. In contrast, Jev outputs typed values accompanied by probabilities:
- `noul`: Returns the probability that a specified condition holds.
- `choice`: Returns the selected option alongside a confidence score.
- `score`: Returns a continuous weighted position across ordered discrete levels.

All decision logic—thresholding, veto rules, and multi-factor composition—remains in Python. Adjusting a threshold requires neither re-running inference nor altering prompt formulations.

The model identifier is pinned in source code as `MODEL = "jev-1.13.0"`, avoiding floating aliases like `jev-latest`. Because thresholds are calibrated to specific model weights, allowing the model version to shift would silently invalidate the calibration.

## 2. What one request carries

Every evaluation payload structures input into three explicit fields:

```json
{
  "state": { "channel": "...", "messages": [ ... ] },
  "model": "jev-1.13.0",
  "questions": {
    "<question name>": {
      "type": "noul | choice | score",
      "instructions": "what this one question is judging",
      "criteria": "how its possible answers differ"
    }
  }
}
```

`state` is the anonymised message array plus the channel name, and it is shared
by every question in the request. `instructions` and `criteria` sit inside each
question, not beside `state`, which is what lets independent judgements run over
one payload.

Discord user IDs, server nicknames, and avatar hashes are never transmitted. Author identities are mapped to ephemeral labels (`u1`, `u2`), generated per request and discarded immediately. The same user receives different pseudonyms across consecutive requests, preventing cross-window tracking outside the bot.

A typical evaluation window (8 channel rules plus 5 messages) consumes approximately 1,500 input tokens. At $0.042 per million input tokens (`DEFAULT_TOKEN_PRICE_PER_MILLION = 0.042`), each request costs roughly $0.00006, with output tokens free.

## 3. One primitive per kind of judgement

| Judgement Task | Primitive | Operational Rationale |
|---|---|---|
| Scam detection (`any_scam`) | `noul` | Evaluates whether a binary condition holds; returns calibrated probability |
| Hostility detection (`is_hostile`) | `noul` | Independent binary evaluation; scam and hostility can co-occur, requiring separate queries |
| Interpersonal friction (`heat`) | `score` | Continuous scale across ordered levels (0 to 3), rather than a binary flag |
| Target rule identification (`which_rule`) | `choice` | Selects from defined candidate rules; requires confidence score |
| Target message identification (`scam_index`, `rule_index`) | `choice` | Identifies specific violating message index within the window |
| Rule meta commentary (`is_meta` / `meta_index`) | `noul` / `choice` | Veto filter against false positives; see §6 |

Independent questions across the same `state` are dispatched in a single batch request. They execute concurrently, have no visibility into sibling answers, and are filtered downstream in Python.

## 4. Rules go in `criteria`, not in `state`

Placing channel rules in `criteria` rather than `state` avoids two documented TypeSafe failure modes:

- **Jaggedness #5 (Extraneous state degrades accuracy)**: Accuracy declines when `state` contains large volumes of irrelevant information. For any individual 8-message window, the vast majority of server rules are irrelevant.
- **Jaggedness #6 (State is treated as unverified data)**: The model treats `state` as raw data rather than authoritative instructions. Placing rules in `state` allows user messages to overwrite or simulate rules. In `criteria`, rules cannot be altered by message contents.

Empirical verification:
- **Generic 8-rule ruleset across 4 test cases (advertising, personal attack, doxxing, clean)**: Achieved 4/4 accuracy on both rule and message attribution. Violations scored 0.92–0.97; clean exchanges scored 0.04.
- **Venting channel rules across 9 representative cases**: Achieved 9/9 accuracy. Violations scored 0.94–0.98; permitted replies scored 0.05–0.08.

## 5. Option labels must be the rule text

In initial tests, `choice` options were designated using ordinal labels ("Rule 1", "Rule 2", etc.). The model produced incorrect classifications across 6 consecutive runs.

This failure stems from TypeSafe jaggedness #4 (indirection failure): ordinal labels possess no intrinsic semantic meaning, requiring the model to resolve numbers against external rule text. Replacing ordinal keys with verbatim rule text eliminated classification errors across the same test suite.

A parallel defect emerged in PR #29 for scam detection: pointing to the target message via ordinal numbers ("Message 6") produced repeated misidentifications at confidence levels between 0.77 and 0.93. Echoing the initial text of each candidate message (`SCAM_OPTION_LABEL_CHARS = 48`) resolved all planted test positions with confidence between 0.98 and 1.00.

Rule: When pointing at targets in choice primitives, label options with verbatim content rather than index identifiers.

## 6. `meta_index`: a veto question

In channels where rules are posted, members regularly remind others of guidelines. Saying "That's lecturing, you know" points out an infraction rather than committing one. Yet in baseline testing, the model assigned this statement a 0.84 violation probability under Rule 2.

Adding negative instructions into `criteria` and `instructions` ("pointing out someone else's violation is not itself a violation") failed to resolve the misclassification. This reflects jaggedness #1 (literal keyword matching): the keyword "lecturing" appeared in the sentence, triggering rule matching regardless of context.

The effective solution separates meta-discussion into an independent question that the code then vetoes on.

Two shapes of that question exist, and earlier drafts of this document described only the first. The measurements were taken against a `noul` named `is_meta`, asking whether a message discussed the channel's rules at all:

- Meta-discussion cases: 0.56, 0.92, 0.92.
- Genuine rule violations: 0.06, 0.08.
- Validation across 5 critical edge cases: 5/5.

What ships is a `choice` named `meta_index`, asking *which* message discusses the rules, with `"沒有任何一則在談論這個頻道的規則"` as its no-match option. The veto fires only when that index equals the one `rule_index` flagged, so a member pointing out someone else's infraction no longer suppresses a genuine violation elsewhere in the same window — which the whole-window `noul` veto did.

The figures above therefore measure the earlier shape. The per-message form has not been re-measured against the 19-case set.

Prompt phrasing is highly sensitive:

| `is_meta` Prompt Formulation | Benchmark Accuracy (19 Cases) | Failure Mode |
|---|---|---|
| Initial prompt generalised during refactoring | 18/19 | 1 misclassification |
| Overly broad formulation | 17/19 | Suppressed 2 genuine violations |
| Narrowed formulation ("talks about this channel's rules") | 19/19 | 0 errors |

Generalising a calibrated question reverts it to an uncalibrated state.

## 7. Probability is not enough — a confidence floor too

During edge-case validation, an empathetic reply ("me too" / 「我也是」) yielded a violation probability of 0.61, but the corresponding `choice` confidence was only 0.43. The model accurately signaled classification uncertainty.

To prevent reporting low-confidence findings, rule evaluations enforce dual criteria:
1. `any_violation` probability $\ge$ `rule_threshold` (default: 0.85).
2. `which_rule` confidence $\ge$ `rule_confidence` (default: 0.70).

When probability satisfies `rule_threshold` but confidence falls below `rule_confidence`, the report is not suppressed; instead, it explicitly states that a violation occurred while marking the specific rule as uncertain ("疑似違規，條文不確定").

This confidence floor cannot be applied to scam detection. In PR #29, scam targeting errors occurred with high confidence (0.77–0.93) due to ordinal indirection failures. Confidence gating addresses semantic uncertainty, not structural labeling defects.

## 8. Thresholds are per-channel because the measurements say so

Empirical separation across distinct channel environments:

| Channel Environment | Violating Test Cases | Clean Test Cases |
|---|---|---|
| Venting channel (concrete custom rules) | 0.94–0.98 | 0.05–0.08 |
| General channel (server-wide rule 8) | 0.49–0.96 | 0.04–0.05 |

The venting channel exhibits clean separation, operating with substantial margin under the default 0.85 threshold. In contrast, violations of server rule 8 scored as low as 0.49, meaning a global 0.85 threshold failed to detect a substantial cohort of real infractions.

This discrepancy reflects rule specificity rather than model degradation. The venting channel enumerates concrete prohibited behaviors, whereas server rule 8 relies on abstract policy generalizations. Consequently, thresholds are configured per channel via `[p]watch rule threshold`.

Furthermore, rule criteria formulation directly alters classification performance. Rewriting rule 8's criterion using spoken explanations provided by the maintainer raised a real test case from 0.17 to 0.94, while benign control cases remained unchanged. Criterion clarity influences detection accuracy more than numerical threshold adjustments.

## 9. Two things that were measured and then stopped worrying about

- **Pre-filtered context outperforms raw message dumps**: Supplying 25 raw chat messages yielded a target detection probability of 0.25. Pre-filtering relevant messages with a preliminary query prior to evaluation increased detection probability to 0.59 while reducing token consumption (consistent with jaggedness #5).
- **Precondition detection does not hallucinate**: To verify whether querying for preconditions induces false positives, 3 negative test cases (including 2 deliberate lure prompts) were evaluated. All measured between 0.03 and 0.04, confirming that the detector does not fabricate preconditions.

## 10. Current defaults

| Configuration Key | Default Value | Derivation Source |
|---|---|---|
| `scam_threshold` | 0.90 | Empirical benchmark |
| `hostile_threshold` | 0.80 | Empirical benchmark |
| `heat_threshold` | 2.50 | Empirical benchmark (scale 0–3; real guild background peaked at 1.53) |
| `rule_threshold` | 0.85 | §8 empirical separation |
| `rule_confidence` | 0.70 | §7 empirical separation |
| `window_size` | 8 | Windowing architecture |
| `idle_seconds` | 600 | Idle sweep timing |

## 11. What is not measured

**Recall.** Every figure documented above evaluates precision: given a known input case, does the model categorize it accurately. Quantifying recall requires capturing production violations that the system failed to flag, which synthetic test suites and moderator report buttons cannot observe. Moderator audit buttons accumulate precision feedback only.

This omission is a methodological boundary of the synthetic benchmark framework rather than a transient task item.
