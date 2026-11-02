# GrepHunt

SAST core: one finding record, YAML scanner descriptors, isolated runs, and a console on port 4000.

## Layout

`grephunt` is the application. A finding is not a folder of scan results. It is the record every module writes.

```
grephunt/finding_model/     what a finding is: location, severity, two identity keys
grephunt/scan_pipeline/     raw output to findings: events, excludes, SARIF, correlation
grephunt/scanner_catalog/   what to run: semgrep.yaml, trivy.yaml
grephunt/scanner_hooks/     tool-specific behavior: Semgrep rules, Trivy CVE database
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

A new scanner is a YAML file in `scanner_catalog/`. A Python hook is only needed when the tool prepares state or parses non-standard output.

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

## CLI

```bash
python -m grephunt scan samples/vuln_flask --config rules/python-basic.yml -s semgrep
python -m grephunt scan samples/vuln_flask -s trivy
python -m grephunt scan samples/vuln_flask --local
```

Reports land in `reports/<project>/findings.json`, `scan.json`, and `merged.sarif`.

## Tests

```bash
pip install pytest httpx
pytest -m "not integration"
pytest -m integration
```

Integration tests pull `semgrep/semgrep:1.180.0` and `aquasec/trivy:0.76.0` and need a running Docker daemon.
