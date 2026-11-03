# GrepHunt

SAST core: one finding record, YAML scanner descriptors, isolated runs, and a console on port 4000.

## Layout

`grephunt` is the application. A finding is not a folder of scan results. It is the record every module writes.

```
grephunt/finding_model/     what a finding is: location, severity, two identity keys
grephunt/scan_pipeline/     raw output to findings: events, excludes, SARIF, correlation
grephunt/scanner_catalog/   what to run: one YAML per scanner, locks/ for pinned installs
grephunt/scanner_hooks/     generic.py runs a YAML-only scanner; Semgrep, Trivy, Bearer have their own hooks
grephunt/execution/         where to run: Docker or a local binary
grephunt/report_output/     who reads findings: console, JSON, merged SARIF
grephunt/web_console/       FastAPI: folder path or zip, progress over SSE
grephunt/database/          SQLite by default, tenant_id on every table
web/                        React console
rules/                      project Semgrep rules
samples/vuln_flask          six planted bugs
samples/clean_flask         a file the rules must ignore
tests/golden/               SARIF fixtures that do not need Docker
```

A new scanner is a YAML file in `scanner_catalog/`. A Python hook is only needed when the YAML fields below cannot describe the tool.

## Adding a scanner

| Field | Meaning |
|---|---|
| `image`, `version` | Pinned image tag. `latest` and `latest-*` are rejected. |
| `container_binary` | Entrypoint in the image, when it differs from `binary` on a local machine. |
| `args` | Argument template: `{src}`, `{output}`, `{out_dir}`, `{cache:NAME}`, `{catalog}`. An unknown placeholder is an error. |
| `output_source` | `file` (the tool writes `{output}`) or `stdout` (GrepHunt saves stdout, whatever the exit code). |
| `output_format` | `sarif`, or a converter from `scan_pipeline/converters.py`. A converter needs `raw_output_filename`. |
| `applies_to` | File name globs. The tool is skipped when nothing in the project matches. |
| `cache_volumes` | Host directories under `data/caches/`. `read_only: true` mounts them read-only for the scan. |
| `prepare` | A run before the scan that fills a cache, with network if it needs it. A marker records it; `ttl_hours` sets when it runs again. If a refresh fails, the old data is used. |

The scan itself should run with `network: false`. Databases and installs belong in `prepare`.

## Console

```bash
pip install -r requirements.txt
cd web && npm install && npm run build && cd ..
python -m grephunt serve
```

Open http://127.0.0.1:4000. For UI development, run the API and Vite separately:

```bash
python -m grephunt serve
cd web && npm run dev
```

The dev UI on http://127.0.0.1:5173 proxies `/api` to port 4000.

Give a folder on this machine, or upload a zip. Project code is mounted read-only and is never executed.

## Container images

A container image can be scanned from a tar file: `docker save -o app.tar myapp:1.0`, or an OCI image layout packed as tar. Upload the `.tar` in the console instead of a zip, or run:

```bash
python -m grephunt scan --image app.tar
```

The tar is not unpacked by GrepHunt. It is checked (`manifest.json`, or `oci-layout` with `index.json`) and mounted read-only into the scanner containers. Trivy, Grype, Syft, and OSV-Scanner read images; the other scanners skip an image scan. Default excludes (tests, build, dist) are not applied to images. The upload limit for images is 4096 MB, set by `GREPHUNT_MAX_IMAGE_MB`.

A descriptor opts in with `image_args`, a template where `{src}` is the tar and `{image_ref}` is `docker-archive:<tar>` or `oci-archive:<tar>`.

## CLI

```bash
python -m grephunt scan samples/vuln_flask --config rules/python-basic.yml -s semgrep
python -m grephunt scan samples/vuln_flask -s trivy
python -m grephunt scan samples/vuln_flask -s bearer
python -m grephunt scan samples/vuln_flask --local
```

Without `-s`, the CLI runs every scanner in the catalog. The web console selects Semgrep and Trivy by default; Bearer is opt-in there.

Reports land in `reports/<project>/findings.json`, `scan.json`, and `merged.sarif`.

## Code scanners

| Scanner | Languages | How it runs |
|---|---|---|
| Semgrep | many | official image; registry rules need the network |
| Bearer | Go, Java, JS/TS, PHP, Python, Ruby | official image; pinned rule pack, offline |
| Bandit | Python | pinned `python` image, Bandit installed from a hash-checked lock file |
| gosec | Go | official image, offline (`GOPROXY=off`) |
| DevSkim | many | pinned .NET SDK image, DevSkim CLI installed from NuGet |

gosec does not download Go modules. Packages whose dependencies are missing still get the AST rules; the SSA and taint rules skip them.

DevSkim reports error, warning, and note in SARIF. Its own scale (Critical, Important, Moderate, BestPractice, ManualReview) is in `DevSkimSeverity`, and `severity_map` in `devskim.yaml` maps it.

## Snyk

Snyk Code and Snyk Open Source run through the official Snyk CLI. They are cloud scanners: Snyk Code uploads the project's source to Snyk, and Snyk Open Source sends the dependency list. They are off by default, marked "cloud" in the console, and the CLI runs them only when named (`-s snyk-code`).

Connecting an account:

1. On the New scan page, press **Connect Snyk**. A popup opens.
2. GrepHunt starts `snyk auth --auth-type=oauth` on this machine (the first time it downloads the pinned Snyk CLI, about 190 MB, and checks its SHA-256 from `scanner_catalog/config/snyk-cli.yaml`). The CLI's own sign-in address on app.snyk.io is loaded into the popup.
3. Sign in on Snyk's page and allow access. GrepHunt never sees the password.
4. Snyk sends the browser back to the CLI on `127.0.0.1:8080` (or the next free callback port), and the CLI stores the token in `data/caches/grephunt-snyk-home/`. The button turns into **Disconnect Snyk**.

The browser must run on the same machine as GrepHunt, because the callback goes to 127.0.0.1. Before each scan the CLI on this machine refreshes the token; the scan container receives it in `INTERNAL_OAUTH_TOKEN_STORAGE`. The token in `data/` gives access to the Snyk account: keep `data/` private.

Snyk exit code 3 (no supported files) marks the task as skipped. For an image tar, Snyk Open Source runs `snyk container test`.

## Secret scanners

| Scanner | Output | Notes |
|---|---|---|
| Gitleaks | SARIF, `--redact` | last release March 2026 |
| Betterleaks | SARIF, `--redact` | successor of Gitleaks by its author; same report format |
| TruffleHog | JSON lines, converted | `--no-verification`; also scans image tars |
| Kingfisher | SARIF | `--no-validate` |
| Secretlint | JSON, converted | recommended preset; files hidden by `.gitignore` are scanned too |

None of them tries a found key against the provider's API: checking a client's live credentials is a decision for a person, not a default.

A secret finding says where a credential is, not what it is. For every tool, the SARIF parser masks secret values in the snippet, message, and title of secret findings (first four characters kept), so they are not stored, shown, or sent to an AI provider. The TruffleHog and Secretlint converters never copy the raw value or the file content.

## Dependency scanners

| Scanner | Database | Network during the scan |
|---|---|---|
| Trivy | Trivy DB, refreshed before each scan | no |
| Grype | Grype DB, `grype db update` at most once a day | no |
| OSV-Scanner | OSV archives per ecosystem, downloaded by the scan | yes, only the archive download; no package list is sent |
| Syft | none | no; writes the project SBOM as `syft.cdx.json` and reports no findings |

Grype, OSV-Scanner, and Trivy findings for the same package, version, and CVE merge into one finding with all three tools listed.

`ok_exit_codes` in a descriptor fails the task on any other exit code, even when the tool wrote a report. OSV-Scanner writes an empty report when it cannot load a database, so without this a broken scan would look clean.

## Bandit

Bandit has no versioned image. `bandit.yaml` uses a pinned `python` image, and its `prepare` step installs Bandit from `scanner_catalog/locks/bandit.txt` with `--require-hashes` into `data/caches/grephunt-bandit/<version>/`. Every later scan reuses that install without the network. To update Bandit, regenerate the lock file (the command is at its top) and change `version`, `container_binary`, and `PYTHONPATH` in `bandit.yaml`.

## Bearer

Bearer CLI adds data-flow rules for Go, Java, JavaScript/TypeScript, PHP, Python, and Ruby. Projects without these languages are skipped.

- The rule pack is pinned in `bearer.yaml` (`rules_version`). Before the first scan GrepHunt downloads it from the `Bearer/bearer-rules` releases on GitHub into `data/caches/grephunt-bearer-rules/<version>/`. Later scans reuse it.
- The scan runs with `--network none`. The rule pack is mounted read-only, and Bearer does not look up the latest rules on GitHub.
- Bearer SARIF has no CWE, severity, or code snippet, so Bearer writes its JSON report and the hook converts it to `bearer.sarif`.
- To update Bearer, change `image`, `version`, and `rules_version` together and run `pytest -m integration`.
- The image is published for amd64 only. On Apple Silicon Docker runs it under emulation, which is slower.
- Bearer CLI is licensed under the Elastic License 2.0.

## Tests

```bash
pip install pytest httpx
pytest -m "not integration"
pytest -m integration
```

Integration tests pull the images from `scanner_catalog/*.yaml` and need a running Docker daemon.
