# REST API authorization lab

Recovered learning materials from the course. The local source matches the supplied `BOLA.zip` archive; these files are credited as course-provided code, not presented as independently authored student software. No separate upstream license or author identity was found in the recovered lab. Existing attribution is retained; no new license is asserted for the supplied material.

## Topics

- MediNotes medical-portal API
- PayFlow payment API
- CloudVault multi-tenant API

The application uses Node.js, Express, HTML templates, browser JavaScript and CSS. The API specification files in `DOCS/` can be inspected in an OpenAPI viewer. Original course text is retained in its original language.

## Run locally

With Node.js 18 or later and npm installed, from this repository:

```text
npm ci --ignore-scripts
npm start
```

Open `http://localhost:3847/`. Stop the server with Ctrl+C. The server is deliberately bound to `127.0.0.1` because these are intentionally vulnerable local training examples. Do not deploy this application as a public service.

All original lab-gate passwords have been replaced in the publication copy. The synthetic default is `portfolio-demo-only`; the named environment variables in `.env.example` can override it. `.env.example` is a reference, not automatically loaded by the application. Assign variables in your local shell before starting the server to use custom values. Seeded tokens and API keys have been replaced with `DEMO_ONLY_*` values. These are synthetic local fixtures, not credentials for any real service.

## Recovery changes and validation

- Dependency folders, operating-system metadata, process IDs and local environment values are excluded.
- Original password/token/key literals are replaced consistently in code and handouts.
- The server binds only to the local machine. The old restart command that killed other processes was removed.
- `provenance.json` records original source hashes and which files changed for publication.
- Every published JavaScript file passed `node --check`; JSON manifests parsed successfully. No live target was tested while assembling this repository.

The recovered files establish available course materials. They do not establish completed exercises, successful exploitation or remediation. This compilation does not recreate missing student submissions.
