# Technical depth

## Threat model
Indirect prompt injection: instructions hidden in content the agent retrieves (documents, web pages, tool output, errors) that try to make it leak confidential data, change records or send email the user never asked for. Forms: plain text, encoded (base64, hex, URL, HTML entities and comments, Unicode escapes, zero-width characters), fake system messages, tool-response injection, and multi-step chains. Attacker controls retrieved content only, not the user's request.

## Why single-layer defences fail
A keyword filter misses new phrasing and encodings. A prompt warning is bypassed by a persuasive injection. Neither checks what the agent does. QuoteShield checks both what it reads and what it does.

## Layers (as built, per the repo's checklist)
1. Scope extraction: the user's request becomes an authorised scope of tools, resources, recipients and record keys. A model-extracted scope is intersected with explicit bounds and never widens the request.
2. Trust separation: the user request and retrieved evidence travel separately; evidence is wrapped in an escaped delimiter with source labels and checksums (spotlighting).
3. Content firewall: Unicode normalisation, bounded decoding of common encodings, regex and heuristics, optional LLM instruction classifier, then sanitise or quarantine the flagged lines while keeping the quote facts.
4. Action guard: every proposed call is checked for tool, resource path, recipient, and record key; schema errors are rejected.
5. Taint: once confidential content is read, a sticky taint blocks sending it to an external sink.
6. Decision: Allow, Block or Ask Human. Ask Human uses a native LangGraph interrupt and resume; approval is one-use and tied to the exact call.
7. Audit: JSON events with source spans, rule IDs, reasons and a hash chain; a tamper check detects edited files.
Defence in depth: the guard alone stops the supplied offline attacks even with the firewall disabled (ablation modes exist).

## Evaluation design
- Baseline: an unprotected agent with the same tools; PS target at least 70% hijacked (real model). In progress, no number yet.
- 30 authored attacks over five categories (20 development, 10 reserved; the reserved set was already inspected so it is not independent), 20 benign content variants and 20 task-shaped benign cases.
- Independent held-out sets from other teammates are sealed and unopened by the build side; they are meant for one pass after a model and defence freeze.
- Metrics and PS targets: catch rate at least 85% on development plus a separately reported unseen rate; task completion at least 90%; false positives at most 10%; added latency under 2 s with per-layer breakdown.

## Results so far (be exact)
Offline decision-boundary checks only: 0 harmful effects on 20 supplied attack proposals, all benign tasks complete, millisecond rule-layer latency. These do not measure a real model. Real baseline and protected rates are pending.

## Known limits
No semantic classifier metrics yet. Provenance is by source label and sticky taint, not token level. PDF and DOCX hidden content is not covered. Adaptive and cross-document attacks are not fully tested. Review state is in memory, so a paused run does not survive a restart. A layered defence reduces risk; it does not prevent every attack.
