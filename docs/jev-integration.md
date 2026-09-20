**English** | [繁體中文](jev-integration.zh-TW.md)

# Building MessageWatch on Jev

This records how MessageWatch uses [TypeSafe](https://docs.typesafe.ai) Jev, a
System One model, and the numbers behind each decision.

The cog's own architecture is in [design decisions](messagewatch-design.md).

Every probability below was **measured against `jev-1.13.0`**, not estimated.
Where something was not measured, it says so.

---

## 1. Why a System One model rather than a generative one

This cog does not want a paragraph. It wants a number it can compare.

A generative model answering "this one looks a bit like a scam" leaves the code
with two options: write another parsing layer, or hand the decision to an
uncalibrated piece of prose. Jev returns a typed answer with a probability —
`noul` gives the probability that a condition holds, `choice` gives the selected
option plus a confidence, `score` gives a weighted position on ordered levels.
Thresholds, vetoes, and composition all stay in Python; the code controls the
workflow.

The practical consequence: changing a threshold requires neither a new inference
run nor a prompt edit.

The model name is pinned in source as `jev-1.13.0`, not `jev-latest`. Every
threshold was measured against that version, and letting the version drift means
letting the thresholds quietly stop meaning anything.

## 2. What one request carries

```
state        = the anonymised message array (text, position, u1/u2 labels, channel name)
instructions = what this question is judging
criteria     = how its possible answers differ
```

Discord user IDs, display names, and avatars are never sent. Authors become
`u1`, `u2` and so on, generated fresh per request and never stored. The same
person is therefore not the same `u1` across two requests — deliberately; that
correlation should not leave the bot in the first place.

One window — 8 rules plus 5 messages — runs about 1,500 input tokens, roughly
$0.00006 at $0.042/Mtok, with output free.

## 3. One primitive per kind of judgement

| Judgement | Primitive | Why |
|---|---|---|
| Is there a scam here | `noul` | A condition either holds or not; return the probability it does |
| Is there hostility here | `noul` | Same — and both can hold at once, so two questions rather than one multiple choice |
| How heated is it | `score` | An ordered degree, not a yes/no |
| Which rule was broken | `choice` | Select from a defined set, and its confidence is needed |
| Is this talk *about* the rules | `noul` | A veto; see §6 |

Independent questions over the same state are asked in one request. They run
in parallel, cannot see one another's answers, and the code decides which ones to
consume.

## 4. Rules go in `criteria`, not in `state`

TypeSafe's own documented jaggedness forced this:

- **#5 — irrelevant detail in a large state degrades accuracy.** For any given
  window, nearly every rule is irrelevant.
- **#6 — state is data; the model does not treat it as adversarial by default.**
  Member messages *are* the state. Put the rules there too and a member can
  rewrite the rules by typing in the channel. In `criteria`, they cannot.

Measured on a generic 8-rule ruleset across 4 cases (advertising, personal
attack, doxxing, clean): 4/4 correct on both the rule and the message, with
violations at 0.92–0.97 and the clean case at 0.04.

Measured on the venting channel's real rules across 9 typical cases: 9/9,
violations 0.94–0.98, permitted messages 0.05–0.08.

## 5. Option labels must be the rule text

The `choice` options were first labelled "Rule 1", "Rule 2" and so on. The
model got it wrong six times in a row.

The cause is jaggedness #4 (indirection): an ordinal label carries no meaning of
its own, so the model has to resolve it against the rule text somewhere else, and
that resolution is not reliable. Labelling each option with the rule's own text
fixed the same set of cases immediately.

This is the same lesson as PR #29's scam detection, which used ordinals to point
at the *n*-th message in the window, also got it wrong repeatedly, and was also
fixed by echoing the message text instead.

When pointing at anything, label it with its content, not its number.

## 6. `is_meta`: a veto question

In a channel where the rules are posted, members correct each other. "That's
lecturing, you know" is pointing out a violation, not committing one — and the
model scored it 0.84, as a violation of rule 2.

Writing "pointing out someone else's violation is not itself a violation" into
both `criteria` and `instructions` still failed. This is jaggedness #1
(literal reading): the string "lecturing" appears in the sentence, so it matches
the shape.

What worked is what the documentation suggests: split it into an independent
literal question and veto in code. A `noul` question, `is_meta`, asks whether
the message is talking about the channel's rules themselves; above threshold, the
whole window is vetoed.

- Meta cases: 0.56 / 0.92 / 0.92
- Real violations: 0.06 / 0.08

Cleanly separated. Re-running the 5 critical cases with it: 5/5.

The wording is sensitive, and it fails in both directions:

| How `is_meta` was worded | Result over 19 cases |
|---|---|
| The measured version, "generalised" while rewriting | 18/19 |
| Too broad | 17/19 (swallowed two real violations) |
| Narrowed to "talks about this channel's rules" | 19/19 |

Generalising a measured question turns it back into an unmeasured one.

## 7. Probability is not enough — a confidence floor too

Edge case, "me too": violation probability 0.61, but the `choice` confidence
only 0.43. The model correctly expressed that it was unsure.

So a rule finding requires both: probability ≥ `rule_threshold` (0.85 by
default) and `which_rule` confidence ≥ `rule_confidence` (0.70).

This cannot be transplanted onto scam detection. In PR #29, the wrong
messages were identified at confidence 0.77–0.93 — a confidence floor would not
have caught any of them, because that was the labelling problem in §5. The two
failure modes differ, and so the patches are not interchangeable.

## 8. Thresholds are per-channel because the measurements say so

| Channel | Violating cases | Clean cases |
|---|---|---|
| Venting channel (custom rules) | 0.94–0.98 | 0.05–0.08 |
| General channel (server rule 8) | 0.49–0.96 | 0.04–0.05 |

The venting channel separates cleanly and 0.85 has room to spare. Rule 8's
violations run as low as 0.49, and the same 0.85 would miss a batch of them.

The gap is not the model getting worse. It is how concretely the rule is
written — the venting channel's rules enumerate forbidden behaviours one by
one, while rule 8 is a single generalisation. So the threshold became
per-channel (`[p]watch rule threshold`) rather than a hunt for one correct global
value.

The other half of the answer is to write the rule properly. Rewriting rule 8's
criterion from the maintainer's own spoken explanation moved a real case from
0.17 to 0.94, while the cases that should be protected did not move at all.
Criteria quality matters more than the threshold number.

## 9. Two things that were measured and then stopped worrying about

Filtered context beats raw context and costs less. Dropping 25 raw messages
in whole gave the target judgement 0.25; selecting the relevant ones with one
question first gave 0.59, at fewer tokens. Consistent with jaggedness #5.

The precondition detector does not invent preconditions. The worry was that
asking "is there a precondition here" would make one appear. Three negative cases,
two of them deliberate lures, measured 0.03–0.04. It did not invent one.

## 10. Current defaults

| Setting | Default | Source |
|---|---|---|
| `scam_threshold` | 0.90 | Measured |
| `hostile_threshold` | 0.80 | Measured |
| `heat_threshold` | 2.50 | Measured |
| `rule_threshold` | 0.85 | §8 |
| `rule_confidence` | 0.70 | §7 |
| `window_size` | 8 | — |
| `idle_seconds` | 600 | — |

## 11. What is not measured

**Recall.** Every number above is on the precision side: given a case, does the
model judge it correctly. A missed case needs a real missed case, and all the
test cases are synthetic. The right/wrong buttons on reports accumulate precision
data too.

This is not a to-do item. It is what this methodology currently cannot see, which
is why it is written here rather than in a TODO.
