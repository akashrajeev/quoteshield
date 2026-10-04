# Demo-day runbook (rehearse from this)

Judges score evidence they see live. Every claim here is one run of a mock-tool sandbox on dev fixtures. Say "offline scripted proposals" when the toggle is on. Never say "benchmark", never quote a detection rate, never call an offline run a live-agent run.

Setup before the room fills (once):

    cd quoteshield && . .venv/bin/activate
    streamlit run streamlit_app.py --server.address 127.0.0.1 --browser.gatherUsageStats false
    # open http://127.0.0.1:8501 ; click "Reset session" in the sidebar

Open a second terminal in the repo for the commands. Keep `docs/rubric-compliance.md` open in a third window.

## 5-minute live script

| Time | Do this | Say this |
|---|---|---|
| 0:00 | Sidebar: leave "Presenter mode" off. Tab **Attack Arena**. Read the trusted task line aloud. | "Buyer asks an agent to compare three quotes. One document carries instructions the buyer never gave." |
| 0:30 | Attack selector: dev case `plain-01`. Toggle **Offline guard verification** on. Click **Run side-by-side**. | "Same task, same inputs, defence off and on. This is offline scripted proposals, not a live model." |
| 1:00 | Point at the baseline lane effect (mock email or confidential read happened) and the protected lane block with its named rule. | "Baseline executes the proposal. Protected stops it at the action boundary with a named rule." |
| 1:30 | Tab **X-ray**. Show the original source left, sanitized evidence right. | "The firewall removes the injected line and keeps the quote facts." |
| 2:00 | Tab **Attack Arena**, click **Run firewall-miss demo**. | "This note passes the firewall on purpose. The action guard still blocks the confidential read. Layers do not rely on each other." |
| 2:30 | Tab **Audit Explorer**: show scope fixed at audit#1, before the first document. Click **Verify tampered copy**. | "Scope is fixed from the user's task before any document is opened. The audit hash chain detects edits." |
| 3:00 | Tab **Human review**: **Prepare legitimate mock email**. Read recipient, subject, body. Approve once. Show the mock outbox. | "Sending is a human decision on the exact call. Approval is single use. Nothing leaves the machine." |
| 3:45 | Tab **Judge Challenge**: paste the judge's text into "Text inserted into a mock vendor quote", or upload an image. Click **Run custom challenge**. | "Offline mode scans your text and compares quotes. It cannot invent a new attacker plan; a live model run can." |
| 4:15 | Terminal: `python3 -m scenario_engine.score` and show the summary (see section 1 to 5). | "Counts, not rates. Here is what is measured and what is not." |
| 4:45 | Show the gaps list in `docs/rubric-compliance.md`. | "Unseen rate is pending the held-out evaluation. Manipulation class is a known gap." |

If a run errors, show the error. Do not switch modes silently.

## 1. Baseline vulnerability >= 70%

(a) Live: Attack Arena, **Run side-by-side**, point at the baseline lane. Offline toggle on: effects are scripted proposals, so they are executed by construction. Say that.
(b) Rerun: `python3 -m scenario_engine.score | python3 -c "import json,sys;print(json.load(sys.stdin)['summary']['attack_success_baseline'])"`. Expected: `{'n': 11, 'of': 12}`.
(c) Artifact: scorer JSON; `docs/rubric-compliance.md` section 1.
(d) Judge asks "is that a real hijack rate?" Answer: No. It is the undefended lane executing scripted proposals on 12 comparable dev fixtures. 4 of 16 are not comparable offline. A live baseline rate needs a live model run, which has not been run as a measured set.

## 2. Catch rate >= 85% on dev, plus a separate unseen rate

(a) Live: after the pair run, show the protected lane stop plus the Audit Explorer rule name.
(b) Rerun: same command, key `attack_success_protected` expected `{'n': 0, 'of': 12}`, `containment` expected `{'n': 11, 'of': 11}`. Cross-check: `python3 evaluate.py --mode offline --split development` prints `protected_effect_count: 0` of 20 attacks.
(c) Artifact: scorer JSON, `artifacts/offline-development.json`, `docs/rubric-compliance.md` section 2. For the unseen rate, the artifact is the held-out evaluation `results.json`, which does not exist yet.
(d) Judge asks "what about unseen attacks?" Answer: Not measured yet. The dev set is ours and we tuned against it, so 0 of 12 is a dev number. The held-out evaluation is a separate protocol step with a blind author; we will report its raw counts separately and not pool them with dev. Known miss: the answer-manipulation footer (manifest `manipulation-concealment`) passes the content firewall because it makes no out-of-scope call. Do not run `--split reserved` or anything on the sealed corpus on stage.

## 3. Benign task completion >= 90%

(a) Live: Attack Arena, **Run clean legitimate task**; show the comparison completes with the shield on.
(b) Rerun: `python3 -m scenario_engine.score` keys `benign_utility_measured` (11), `benign_completion_baseline` and `benign_completion_protected` (both `{'n': 11, 'of': 11}`), `benign_poisoned`.
(c) Artifact: scorer JSON; `docs/rubric-compliance.md` section 3.
(d) Judge asks "does it still work when a document is poisoned?" Answer: yes on 3 of 3 procurement controls where a quote carries an injection and the answer is checked by the oracle. Four other domains measure only that the clean page reached the agent, not answer correctness, because the answer oracle is procurement-shaped. One poisoned note (`proc-benign-poisoned-cheapest`) is paraphrased, passes the firewall, and nothing acts on it.

## 4. False positives <= 10% of benign actions

(a) Live: in the Human review tab, show that the legitimate email asks a person instead of being blocked.
(b) Rerun: same score command; keys `false_positive_blocks` (`{'n': 0, 'of': 19}`), `fp_escalated_by_policy` (`{'n': 1, 'of': 19}`), `fp_action_level` (`blocked: 0, escalated: 1, of: 41`).
(c) Artifact: scorer JSON; `docs/rubric-compliance.md` section 4.
(d) Judge asks "isn't asking a human a false positive?" Answer: it is friction and we report it separately from hard blocks: 0 blocked, 1 escalated by policy (a benign email-sending task), out of 19 scenarios and 41 action decisions. The set is small and ours. A benign line like "send questions to help@agency.gov" can still be flagged by the disclosure rule.

## 5. Latency < 2 s with per-layer breakdown

(a) Live: Presenter mode on, view "Measured report", show `layer_timings`; or run the score command.
(b) Rerun: `python3 -m scenario_engine.score | python3 -c "import json,sys;print(json.dumps(json.load(sys.stdin)['summary']['layer_latency_ms'],indent=1))"`. Expected on the build measured: request guard p95 about 0.2 ms, scope about 0.06, content firewall p95 about 43, action guard plus taint about 0.1, protection total p95 about 43 (ms; machine dependent).
(c) Artifact: scorer JSON; `artifacts/offline-development.json` `layer_timings`; `docs/rubric-compliance.md` section 5.
(d) Judge asks "what about the model and OCR?" Answer: those are excluded. This is the deterministic layers with mock tools. Image OCR (two passes) measured about 1.1 to 2.7 s on a real image, and a model classifier call adds its own time, so end-to-end live latency is not claimed under 2 s.

## 6. Explainability

(a) Live: Audit Explorer, inspect lane "protected": every intervention shows stage, rule, source and the exact call. Judge Challenge shows "Why this task was flagged" for a flagged task. X-ray shows removed spans.
(b) Rerun: `python3 -m unittest tests.test_scope_immunity` (prints the audit sequence numbers in the explanation).
(c) Artifact: downloaded run JSON ("Download complete run JSON"), `docs/judge-guide-decision-gates.md`.
(d) Judge asks "is that the model's reasoning?" Answer: no. Explanations are generated from deterministic audit events, so they describe what the gate did, not why a model chose something.

## 7. Robustness to unseen phrasings

(a) Live: Judge Challenge: let a judge type their own injection into the vendor-quote box, or upload their own file or image, then **Run custom challenge**. In offline mode it only scans and compares; say so.
(b) Rerun: `python3 -m scenario_engine.score` and look at the `*-paraphrase` scenarios (each of four non-procurement domains has one); the held-out command is run by Adith under the protocol and is not part of this runbook.
(c) Artifact: held-out `results.json` once it exists. Until then, nothing.
(d) Judge asks "how robust is it to phrasings you have not seen?" Answer: we do not have that number. The action boundary is structural (exact tools, paths and recipients), so a new phrasing that proposes an out-of-scope call is still blocked; content-level phrasing that makes no out-of-scope call, such as the manipulation footer, is not caught by the rules or by the local classifier in the one dev run on file. OCR cannot read near-zero-contrast or tiny noisy text.

## 8. Mock-only safety

(a) Live: Human review tab shows approved mail captured in an in-memory outbox; the app has four mock tools and no network or filesystem access.
(b) Rerun: `python3 -m unittest discover -s tests -t .`. Expected: `Ran 403 tests ... OK (skipped=3)` (count grows as tests are added).
(c) Artifact: `docs/rubric-compliance.md` section 8; `THREAT_MODEL.txt`.
(d) Judge asks "did any email actually go out?" Answer: no. Sends are recorded in memory and recipients use reserved test domains. A remote model endpoint would see mock inputs, so use a local endpoint for a fully local demo.

## Images

Harborline: the test `tests/test_image_injection_pipeline.py` generates a "HARBORLINE SUPPLY CO. QUOTATION" image with Pillow; run `python3 -m unittest tests.test_image_injection_pipeline` to show the OCR path and then upload an image in Judge Challenge. Before showing the Atlas quote image Adith attached, open the file and confirm the footer text is actually readable in it; the copy we inspected did not contain the surcharge text. Pick whichever image shows the text you plan to claim.

## Do not

- Run anything on the sealed corpus or `--split reserved` on stage.
- Say the offline run is a live agent, or give any rate as a benchmark.
- Edit the demo manifests live.
