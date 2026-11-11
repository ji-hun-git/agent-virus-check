# Dangerous operations by language

"Sink" is where attacker-controlled data becomes dangerous. For each one: what to look for, the safe form, and the bypasses reviewers miss.

## Cross-language

| Bug | Look for | Safe form | Often missed |
|---|---|---|---|
| SQL injection (CWE-89) | string-built queries, `format`/f-strings/template literals in SQL, raw query APIs | parameters / prepared statements, ORM query builders | `ORDER BY`/column names (allowlist them), `LIKE` wildcards, second-order injection from stored data |
| Command injection (CWE-78) | shell strings with user data | argument arrays without a shell, allowlisted programs | arguments starting with `-` (use `--`), `git`/`ssh` options, Windows `cmd /c` quoting |
| Path traversal (CWE-22) | file paths built from input, archive extraction | resolve then check the result is inside the base folder | `..` after URL decoding, absolute paths, symlinks, Windows drive letters and `\\?\` |
| SSRF (CWE-918) | server-side fetches of user URLs (webhooks, previews, importers) | allowlist hosts; resolve and pin the IP; block private, loopback, link-local and metadata ranges | redirects, IPv6 and decimal IP forms, DNS rebinding between check and use |
| Deserialization (CWE-502) | binary or typed deserializers on untrusted input | JSON with schema validation | model files and caches that are pickles; signed-but-not-verified payloads |
| XSS (CWE-79) | raw HTML insertion, disabled auto-escaping | framework escaping, sanitizer with an allowlist, CSP | `href="javascript:..."`, Markdown renderers, SVG uploads, template attributes |
| Authorization (CWE-862/639) | handlers that load objects by ID | check ownership or tenant on every object access, in one layer | bulk endpoints, export jobs, GraphQL nested resolvers, mass assignment of `role`/`owner` fields |
| Secrets (CWE-798/532) | keys in code, config, logs, error pages, client bundles | secret manager or environment, redaction in logs | `.env` files committed then deleted (still in history), source maps, CI logs |
| ReDoS (CWE-1333) | nested quantifiers on input (`(a+)+`, `(.*a){n}`) | linear-time engines (RE2), input length limits | validation regexes in middleware run on every request |

## Python

- `eval`, `exec`, `compile`, `__import__` on input; `pickle`, `marshal`, `shelve`, `joblib`, `torch.load` without `weights_only=True`; `yaml.load` without `SafeLoader`.
- `subprocess` with `shell=True`, `os.system`, `os.popen`; `tarfile.extractall` without the `filter="data"` argument (Python 3.12+); `zipfile` extraction without checks.
- Jinja2 `Environment(autoescape=False)` and `Template(user_string)` (SSTI); Django `mark_safe`, `|safe`, `extra()`/`raw()`; Flask `send_file` with user paths.
- `requests` with `verify=False`; `hashlib.md5/sha1` for passwords; `random` for tokens (use `secrets`).

## JavaScript and TypeScript

- `eval`, `new Function`, `vm.runIn*Context` (not a sandbox), `child_process.exec` with interpolation, `setTimeout(string)`.
- Prototype pollution: recursive merges and `obj[key] = value` with keys like `__proto__`, `constructor`, `prototype`.
- `innerHTML`, `dangerouslySetInnerHTML`, `v-html`, `document.write`; React `href` with user URLs.
- Express: missing `helmet`/CSRF where cookies authenticate; `res.redirect(req.query.next)`; `express.static` on user-controlled roots.
- JWT: `jwt.decode` used instead of `verify`, accepting `alg: none` or both HS and RS keys.
- `JSON.parse` of huge bodies without limits; regex DoS in validators.

## Go

- `exec.Command("sh", "-c", ...)` with input; `filepath.Join` with absolute or `..` components; `html/template` vs `text/template` mixups.
- Unchecked `io.ReadAll` on request bodies; goroutine leaks per request; `math/rand` for secrets.

## Java and Kotlin

- `ObjectInputStream`, XStream, Jackson default typing; XML parsers without disabling external entities (XXE); `Runtime.exec` with concatenated strings.
- Spring: SpEL with input, mass assignment through `@ModelAttribute`, actuator endpoints exposed.

## C#

- `BinaryFormatter`, `NetDataContractSerializer`, `TypeNameHandling` in Json.NET; `Process.Start` with shell; `XmlDocument` with DTD processing; Razor `Html.Raw`.

## C and C++

- Bounds (`memcpy`, `strcpy`, `sprintf`), integer overflow in size math, use-after-free, format strings, unchecked return values; unsafe Rust blocks that rely on invariants callers can break.

## Infrastructure and configuration

- Dockerfiles running as root with secrets in layers; public cloud buckets; CI workflows using `pull_request_target` with checkout of the PR head, or `${{ github.event.* }}` inside `run:` (script injection); overly broad tokens (`permissions: write-all`).
- Kubernetes: privileged pods, hostPath mounts, missing network policies; Terraform with `0.0.0.0/0` on admin ports.
