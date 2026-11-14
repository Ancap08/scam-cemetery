# Decisions

v0.1 choices, each with the reason it was made. Limits that follow from those choices are at the bottom.

- **python-telegram-bot (v21, long polling).** One process, no webhook, and no inbound port to open on the VPS.
- **httpx.** Async, and `MockTransport` lets the tests fake every vendor without another library.
- **Three sources run together under one timeout each.** A slow Safe Browsing call must not delay the VirusTotal and URLhaus lines.
- **Missing API key skips that source and says so.** A half-configured `.env` should still answer, not crash on startup.
- **Grok is the judge, behind a `Judge` interface.** The verdict sentence is the part worth a model. The interface is where an open-source model, then OpenAI, will slot in later. Those backups are not built.
- **Rules judge if xAI fails, is unconfigured, or returns GO over a malicious hit.** The bot still owes a verdict when the model is down, and a positive hit should not be talked out of.
- **xAI via `POST https://api.x.ai/v1/chat/completions`, model `grok-4.7`.** That is the OpenAI-compatible base URL the project asked for. `XAI_MODEL` overrides the id when xAI renames it. Chat completions is the legacy endpoint; newer xAI features land on the Responses API first.
- **Safe Browsing v4 `threatMatches.find`.** It is the lookup API: we send the URL, they say whether it is on a list. Empty body means clean.
- **VirusTotal v3 URL report, not a new scan.** Lookup stays inside the timeout. A URL they have never seen is "unknown", which the rules treat as CAUTION.
- **VirusTotal malicious means any engine (`malicious >= 1`).** Simple and conservative. It will sometimes false-positive.
- **URLhaus `POST /v1/url/` with the `Auth-Key` header.** That is the documented single-URL lookup. Being listed is malicious even if the URL is offline; `no_results` is clean because the feed only contains malware URLs.
- **Allowlist, and silence for everyone else.** A private checker should not explain itself to strangers or confirm the bot is alive.
- **Private chats only.** The same silence applies in groups, so a pasted link in a group is not answered out loud.
- **Secrets only from the environment.** `.env.example` has blanks, `.env` is gitignored. Source failures log the HTTP status and, for URLhaus, `query_status`, never the API key or the request URL (Safe Browsing puts its key in the query string).
- **SQLite, one table, 90-day cleanup, `archive` exempts a row.** The history is small. `/archive` is the only way to set the flag. There is no un-archive command.
- **At most three URLs per message.** One paste should not fan out into dozens of vendor calls.
- **Defang support is `hxxp`/`hxxps`, `[.]`, `(.)`, `{.}`, `[dot]`, `(dot)`, and `[:]`.** Those are the forms people actually paste. Userinfo (`user:password@host`) is stripped so a credential in a URL is not stored.
- **The container runs as uid 1000 and stores the database on a named volume.** A named volume picks up that ownership, so `docker compose up` can write the sqlite file without a host-side `chown`. The image publishes no ports.
- **Official `python:3.12-slim` image, compose on Ubuntu 24.04.** The VPS does not need its own Python; the image has 3.12.
- **Ruff and pytest in GitHub Actions on every push and pull request.** The tests never call the network.

## Known limits

- No live call to Telegram, xAI, or the three vendors is part of CI. The request shapes are tested against mocks.
- A brand-new URL that VirusTotal has not scanned comes back CAUTION even when Safe Browsing and URLhaus are clean. That is noisy on purpose.
- Bare IP addresses, `localhost`, and internationalized domains are not extracted. `http://1.2.3.4/...` is, because it has a scheme.
- Filenames such as `notes.txt` are not treated as links. A real site whose suffix is in that small denylist (`txt`, `pdf`, `py`, ...) and that was pasted with no scheme is also skipped.
- Redirects are not followed by this bot. The vendors may follow them on their side.
- Grok is instructed to follow the same verdict table as the rules. It can still be wrong; the only hard override is "GO while something was malicious".
- There is no rate limiter beyond the allowlist and the three-URL cap.
- No license file yet.
