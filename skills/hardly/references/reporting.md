# One-pass report

> Purpose: How the one-pass `hardly_session_report` evidence index works: sections, severity, detail levels and `explain`.

`hardly session report <har>` (MCP: `hardly_session_report`) runs the existing detectors once and
returns an **evidence index**: a flat list of findings that say *what was seen
and where*, never what to do about it. It contains no detection logic of its own;
it selects, ranks and caps what the detectors return.

## Finding shape

```json
{"section": "access", "kind": "gate", "severity": "blocker",
 "label": "bot_wall gate (cloudflare) -> stop", "entry_ids": [1],
 "names": ["header:server", "state:blocked"],
 "lookup": {"technology": "cloudflare", "suggest_search": "cloudflare challenge page behaviour and cookies"}}
```

- `severity` is always `info | notice | blocker`. A gate whose policy action is
  `stop` is a `blocker`; other gates and "needs attention" items are `notice`.
- `entry_ids` point at `hardly_entry_get` / `hardly_entry_around`. `names` are header,
  cookie, field or key *names* and shapes only - never values.
- `lookup` appears where a technology or product was identified. The phrase is
  generic (product name plus a topic), never site-specific; use it as a web
  search seed to learn how that technology behaves.

## Sections

| Section | Reuses |
|---------|--------|
| `access` | gates, walls (protection products), redirect chains |
| `auth` | credentials, auth patterns, challenges |
| `stack` | stack fingerprint, grids, tables, data attributes |
| `data` | export links, endpoints, response-shape key names |
| `forms` | forms, search-navigation candidates |
| `run` | placeholder for replay results (see `hardly_send_entry_ablation`) |

A detector that raises is isolated: its section reports `errors` and the rest of
the report is unaffected.

## Detail levels

| `detail` | Contents |
|----------|----------|
| `summary` (default) | About 1 KB: counts per section, which sections have findings, up to 5 blockers |
| `standard` | Findings, capped per section (`truncated` says how many were left out) |
| `full` | More findings plus a `drill` pointer naming the tool that expands each one |

## Evidence only, prose on request

Detectors return evidence by default. Canned prose (stack `implications` and
`sdk_notes`, gate `policy`, wall/bot-protection `recommendation`, challenge,
credential, redirect and grid `next`, crawl `next`, signed-request `replay_hint`)
is returned only with `explain=true` (`--explain` on the CLI). `session report --explain`
adds per-finding `explain` strings and a top-level `explain` block.

## CLI and files

```
hardly session report capture.har                      # summary JSON
hardly session report capture.har --detail standard --categories access,auth
hardly session report capture.har --detail full --format md --explain
hardly write export capture.har --format report -o capture.report.json   # .json = JSON, else Markdown
hardly write export capture.har --format report -o out/                  # directory -> out/capture.report.md
```

`hardly_session_report(session_id, host=None, categories=None, detail="summary", explain=False)`
returns the report over MCP and writes nothing; `hardly_write_export(session_id='S', format='report',
output_path='out/capture.report.md', detail='standard')` saves it (`.json` paths get JSON, anything else
Markdown, a directory gets `<har stem>.report.md`; an existing file is refused unless
`overwrite=true`). `categories` selects sections (`access`, `auth`, `stack`, `data`, `forms`).
