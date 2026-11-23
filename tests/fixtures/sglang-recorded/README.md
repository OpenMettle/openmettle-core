# Recorded SGLang responses

Raw HTTP responses recorded on 23 Nov 2026 from one real SGLang deployment that serves a
single model. The deployment runs a patched fork; its exact commit was not verified. Each
request used a small synthetic prompt. `tests/provider_inference/recorded_sglang.rs` replays
them through the production decoder. Background and findings: issue #9.

## Files

For each case `NN-name`:

- `.request.json` is the request body the capture tool sent (`01-models` was a plain `GET`).
- `.headers` is the response status line and headers, stored with LF. The replay sends CRLF.
- `.body` is the exact response body followed by one LF added for repository hygiene. The
  replay removes that LF.

## Cases

| Case | Request | Recorded response |
| --- | --- | --- |
| `01-models` | `GET /v1/models` | 200 model list. Not replayed: core has no model-list client. |
| `02-chat-plain` | Chat, `max_tokens` 64, thinking off | 200 JSON, `ok`, finish `stop` |
| `03-chat-stream-usage` | Chat streamed with `include_usage`, thinking off | SSE, `12345`, usage chunk |
| `04-chat-stream-reasoning` | Chat streamed with `include_usage`, thinking on (default) | SSE with `reasoning_content`, `43` |
| `05-chat-stream-tools` | Chat streamed, two tools, thinking off | SSE, two parallel calls, `"\n"` on the content lane |
| `06-chat-tools-nonstream` | Chat, two tools, thinking off | 200 JSON, two parallel calls |
| `07-chat-stream-length` | Chat streamed, `max_tokens` 12 | SSE, finish `length`, then usage |
| `08-chat-stream-abort` | Chat streamed, `max_tokens` 600 | The capture client stopped after 1.5 s; no finish, usage or `[DONE]` |
| `09-responses-plain` | Responses, string input | 500 `Internal Server Error` |
| `10-responses-stream` | Responses streamed | 500 `Internal Server Error` |
| `11-chat-bad-model` | Chat for `no-such-model`, `max_tokens` 8 | 200 JSON from the loaded model, echoing `no-such-model`, finish `length` |
| `14-responses-list` | Responses, message-list input | 500 `Internal Server Error` |

## Changes from the recording

- The served model name is a site value. It is replaced with `recorded-sglang-model` in
  every body and request, and each `content-length` is recomputed to match.
- Header CRLF line endings are stored as LF. No header was dropped: the remaining
  `date`, `server: uvicorn`, `vary` and framing headers do not identify the site.
- The capture tool de-chunked streamed bodies, so the original chunk boundaries are lost.
  The replay re-chunks each stream once per SSE event and once per byte.
- Health checks, metrics, curl timings and the port-forward log were not committed.

## Not captured

`reasoning_effort`, `max_completion_tokens`, two consecutive system messages,
`continuous_usage_stats`, in-stream error chunks, 400/429/503 bodies, tokens generated after
a client disconnect, and any successful Responses API output. Core's own requests differ
from these: it sends its catalog model name, system guidance and `max_completion_tokens`.
The fixtures show how this server answers; they do not show how it answers core's request.
