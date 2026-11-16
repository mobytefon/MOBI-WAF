# Full HTTP request of a WAF event

On [Security events](security-events.md), a WAF event shows the request as the WAF saw it under **Full HTTP request**: the request line, every header, then the body. **Copy** puts all of it on the clipboard.

## What is kept

Coraza logs the request body with each event (audit log part C). Before an event is stored, the log parser:

- redacts the value of every form, multipart or JSON field whose name looks like a credential (`password`, `token`, `apiKey`, `session`…), as it already does for headers such as `Authorization` and `Cookie` and for query parameters;
- leaves uploaded files out, writing their size instead, e.g. `[1.0 MiB of file data not stored]`; the part headers (field name, file name, content type) stay;
- keeps a binary body (NUL bytes, other control characters, bytes that are not UTF-8), such as that of a binary RPC protocol, as text. The page shows control characters as escapes (`\x00`) and says the body is binary. Coraza logs each byte that is not UTF-8 as U+FFFD, shown as `�`, so those bytes' values are lost. Credentials in a binary body cannot be told apart, so they are not redacted;
- keeps at most the first **32 KiB** of the cleaned body. A note under the request says when the body was cut, and how large it was.

Bodies are kept from the release that added this; older events show only the headers. When the client sent a body that was not logged, the page says so. That happens when keeping bodies is off, or when the WAF stopped the request before it read the body (a phase 1 rule).

**Keep request bodies with WAF events** in the WAF settings (Request bodies) turns this off for every host. It is on by default. It is stored as `log_request_body` in the global WAF settings (`GET`/`PUT /api/v1/settings/waf`); unset means on.

## Show the value

Each matched rule says what it matched and in which variable, for example "Matched `user (` in `ARGS:json.Body.Items.0.Body.Value`". **Show the value** shows that variable's value with the matched text marked.

Coraza logs only the start of a value: about 280 bytes together with the rule's text. So when the parser stores an event, it looks the variable up in the whole request and keeps up to 4 KiB of the value around the match. This happens before the body is cut. The marked text shows even when it lies past those 280 bytes or past the 32 KiB of body kept. `…` marks where the value goes on. The variables looked up are:

- JSON (`ARGS:json.…`), form and multipart arguments;
- query arguments;
- request headers;
- the URI, the query string and the body.

The value of a variable whose name looks like a credential is never kept.

When a rule matched `REQUEST_BODY` inside an uploaded file the stored body leaves out, only the matched text and a few hundred characters around it are kept, at most 768 characters. The file itself is still not stored. Control characters such as NUL show as escapes (`\x00`).

A rule matches a value after its transformations (decoding, lowercase, whitespace removed…). When the matched text is not in the value as it is, the page searches for it again ignoring case and whitespace. When even that fails, the page shows the value without a mark and says why. For events stored before this release, the value is what Coraza logged; when the match lies past it, the page says so.

## Storage

All of this is stored in the event's audit record (`waf_events.raw_data` in ClickHouse, under `ingressi_capture` for the matched values). There is no database migration. Bodies make the records larger: at most 32 KiB of body and 20 matched values of at most 4 KiB per event.
