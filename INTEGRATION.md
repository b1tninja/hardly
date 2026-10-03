
## hardly_stub carry-forward (core/stub.py)

No signature changes for server.py / cli.py. `client_stub` result gains an
`inputs` list (names of `run(**inputs)` keywords); `correlate_tokens` hits gain
`from_name_hint` / `to_name_hint`.

Docs paragraph for docs/sdk-workflow.md:

> `hardly stub` now emits a runnable client. Values issued by an earlier
> response are extracted at run time: all hidden form fields are carried
> forward (`_hidden_fields`, covers ASP.NET VIEWSTATE/EVENTVALIDATION and
> antiforgery fields), cookies are echoed into headers (`_cookie`, URL-decoded,
> e.g. XSRF-TOKEN -> X-XSRF-TOKEN), and JSON keys (including double-encoded
> bodies) are read with `_json_path`. Previous bodies are kept in
> `self.resp[entry_id]`. User-supplied values (passwords, search terms) remain
> `PLACEHOLDER_*` defaults, overridable as `run(txtpassword="...")`.
