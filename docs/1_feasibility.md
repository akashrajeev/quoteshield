# Technical and financial feasibility

Status key: BUILT and VERIFIED claims come from the repo's own checklist and status files (commit c7f15013). TARGET means not yet measured.

## What it is
QuoteShield wraps a tool-using LangGraph procurement agent with two layers. A content firewall inspects retrieved text before the model sees it. An action guard checks every proposed tool call (read_file, search_web, send_email, write_record) against a scope extracted from the user's request, and returns Allow, Block or Ask Human. A hash-chained JSON audit log records every decision.

## Technical feasibility
- Runs on a normal CPU laptop with Python. Dependencies: langgraph, httpx, streamlit, python-dotenv. No GPU, Docker or paid service needed for the offline demo.
- All four tools are mock and in-memory, so nothing real is read, sent or written.
- Verified locally: 82 regression tests pass; offline checks show zero harmful mock effects on the 20 development attack proposals and all benign tasks completing. Layer overhead without model calls, from the offline development report (artifacts/offline-development.json): protection_total p50 1.022 ms, p95 1.303 ms; firewall p50 0.919 ms, p95 1.193 ms. LLM calls are excluded from these numbers.
- Important limit: those offline checks feed pre-written attack calls into the guard. They test the decision boundary. They are not evidence about how a real model behaves.

## Integration shape
The guard sits between the agent's tool proposal and the tool executor, so it can wrap another agent loop that exposes proposed tool calls. The content firewall wraps the retrieval step. Production integration into a real agent framework is not built or tested.

## Financial feasibility
- The offline demo has no API charge. Real-model runs use an OpenAI-compatible endpoint; the repo presets point to Gemini, Groq, OpenRouter and NVIDIA, with free-tier use as the plan. Free-tier limits and terms change, so check each provider's current page before relying on them.
- Where model cost appears: the LLM scope extractor runs once per protected request. The optional LLM instruction classifier runs once per inspected string field in each tool output, so its cost grows with the number of tool calls and the amount of retrieved text, not once per request. The rule-based layers make no model calls. We will report measured token counts from real runs rather than estimate.
- Ideas to reduce cost (proposed, not implemented): route only content the cheap rules cannot clear to the classifier, use a small model for scope extraction, cache the extracted scope per task, cache classifier results for repeated content.

## Latency
PS target: under 2 seconds added per request. TARGET, not yet measured. The rule layers measured about a millisecond offline (see numbers above); the two LLM layers will dominate and depend on provider speed. Per-layer timing is recorded in the runs so the breakdown can be reported.

## Not established
Real-LLM hijack, catch, completion and false-positive rates; provider cost per 1,000 requests; production deployment; multi-process resume of a paused human-review step (state is in memory).

## Evidence still pending
Genuine baseline hijack rate (in progress), protected rates and full-system latency from the main build.
