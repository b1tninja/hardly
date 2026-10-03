# API stability

> Purpose: The v1 compatibility policy: what is public, what counts as a breaking change, how deprecation works and how snapshots enforce it.

hardly's value to a caller (an agent, a script, a downstream SDK) is that a name or call keeps meaning
the same thing. This page defines the **public surface** precisely, the **semver rules** that
protect it, and the tests that enforce it. How the names were chosen: [api-decisions.md](api-decisions.md).

## Status before and after 1.0

hardly has never been published. Versions below 1.0.0 are development builds: names, parameters
and formats may still change, but only deliberately (the snapshots below make an accidental change
fail CI). **From the first published release (1.0.0) everything on the public surface is permanent**
and changes only as described here.

## The public surface

| Surface | What is covered |
|---|---|
| MCP tools | Tool names (`hardly_*`); parameter names, types, order and defaults; the effect marker (`send_`, `write_`, `browser_` or none) |
| MCP results | Result keys that are **documented** (named in a tool description, [tools.md](tools.md) or another doc), their meaning and JSON type; the `sections` echo of merged tools |
| Error codes | The `code` field of error results: `unknown_session`, `output_exists`, `output_error`, `index_outdated`, `har_not_found`, `har_missing`, `har_ephemeral_gone`, `har_unavailable`, `file_not_found`, `invalid_argument`, `missing_argument`, `unknown_section`, `unknown_format` (and other `unknown_<field>` codes), `confirm_required`, `optional_dependency_missing` |
| Safety behaviour | `send_*` and `browser_capture_discover` send nothing without `confirm=true` and return a plan; `write_*` never replace a file without `overwrite=true`; secrets never appear in output |
| MCP prompts and resources | Prompt names, `hardly://cheatsheet`, `hardly://docs/<slug>` URIs |
| CLI | Command paths and flags in [cli.md](cli.md) (`tests/cli_surface.json`); exit codes 0 (ok), 1 (error result), 2 (usage or input error); JSON on stdout |
| Python API | What `hardly` exports: `open_session`, `Session` (`session_id`, `conn`, `info`, `har_path`, `saved_to`, `closed`, `close()`, context manager), `session_id_for`, and the error classes `SessionError`, `UnknownSession`, `OutputExists`, `OutputError`, `IndexOutdated`, `HarNotFound` with their `code` and `to_dict()` |
| Saved index file | A SQLite file written by `session open -o` / `hardly_write_session_copy(session_id, output_path, format='index')`; see below |
| Environment variables | The `HARDLY_*` variables documented in [capture.md](capture.md), [integrating.md](integrating.md) and [troubleshooting.md](troubleshooting.md) |

### Not public (may change in any release)

- Modules `hardly.core.*`, `hardly.index.*`, `hardly.capture*`, `hardly.server` (except that it hosts
  the tools above), `hardly.session` functions other than those re-exported by `hardly`,
  `hardly.cli` internals (`cmd_*`, `build_parser`), `hardly.local_site`, `hardly.soak_live`.
  Each carries this in its docstring; AGENTS.md repeats it. Anything starting with an underscore.
- Undocumented result keys, key order, and the exact wording of descriptions, hints, `explain=true`
  prose and error messages (match on `code`, not on `error`).
- What detectors find: a better detector may add findings, kinds, technologies and sections, or
  fix a wrong one. The *shape* of a finding is public; its presence for a given capture is not.
- Numeric defaults behind an omitted `limit` and other caps, within the documented hard maxima.
- The SQLite schema inside an index file (only `meta.index_version` is read by other tools).

## Semver

Versions are `MAJOR.MINOR.PATCH`.

| Change | Release |
|---|---|
| Add a tool, a CLI command, an optional parameter (at the end, default keeps behaviour), a result key, a section, an enum value, an error code, a detector finding | minor |
| Bug fix, faster, more accurate detection, better wording, docs | patch |
| Rename or remove a tool, parameter, CLI command or flag, result key or error code | **major** |
| Change a type, a default, a required/optional status, parameter order, or the meaning of a documented key or flag | **major** |
| Make a read-only tool write or send; relax `confirm` or `overwrite` gating | **major** (never done) |
| Raise `INDEX_VERSION` | minor, see below |
| Drop a Python version, change the exit codes | major |

Adding a *required* parameter is breaking; adding a new value that callers must handle in an
existing field is breaking unless documented as open-ended.

## Deprecation

A public name is never removed in a minor release. The process:

1. In a minor release mark it deprecated: say so in the tool docstring and `tools.md`, add a
   `deprecated` field to its result (`{"deprecated": {"since": "1.4.0", "use": "hardly_session_overview",
   "removal": "2.0.0"}}`), print a warning on stderr for CLI commands and emit `DeprecationWarning`
   for Python names. Behaviour is unchanged.
2. Keep it for at least one minor release; list it under **Deprecated** in `CHANGELOG.md`.
3. Remove it in the next major release, listed under **Removed**.

## Saved index files

`INDEX_VERSION` (in `hardly/index/ingest.py`) is stored in the index `meta` table. Rules:

- An index is a cache of the HAR, not an archive. A build opens only indexes of its own
  `INDEX_VERSION`; any other returns `index_outdated` with the exact call that rebuilds it from the
  HAR. It never opens a stale index and never answers from one silently.
- `INDEX_VERSION` must be raised whenever ingest stores something new or changes what a stored
  value means. Raising it is a minor release (no data is lost: re-open the HAR).
- The HAR remains the source of truth; hardly never needs to read an old index to work.

## How the snapshots enforce this

| Snapshot | Pins | Regenerate |
|---|---|---|
| `tests/api_surface.json` | Every tool: name, ordered parameters (name, type, default, required), effect marker | `python scripts/dump_api_surface.py` |
| `tests/cli_surface.json` | Every command path, positional and flag (kind, default, choices), and the tool it mirrors | `python scripts/dump_cli_surface.py` |

`tests/test_api_surface.py` and `tests/test_cli_surface.py` fail on any difference with the message
"v1 ... names are permanent". `tests/test_docs_tool_names.py` checks that every tool name, tool call
and CLI example in the docs exists. A deliberate change means: edit the code, regenerate the
snapshot(s) and the generated docs (`python scripts/gen_tool_docs.py`), add a `CHANGELOG.md`
entry (Added / Deprecated / Removed) and let review see the snapshot diff. Additions show up as
added lines; a removed or changed line is a breaking change and needs a major version.
