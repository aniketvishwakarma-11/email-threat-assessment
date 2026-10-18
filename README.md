# Email Threat Assessment

A small Django application for explainable email and PDF threat assessment.

## Features

- Classifies pasted email text with a local scikit-learn model.
- Extracts text from PDF uploads with `pypdf`.
- Detects suspicious and malicious indicators with transparent local rules.
- Produces a report with verdict, risk score, severity, confidence, evidence, and a recommendation.
- Supports optional Gemini review for documents that have no local indicator match.
- Uses an explicit `unknown` result when analysis is unavailable instead of silently returning `safe` or `Ham`.

## Setup

```text
python -m venv .venv
.venv\Scripts\activate
python -m pip install -r requirements.txt
python manage.py check
python manage.py runserver
```

The application is intentionally kept compatible with the existing root-level module layout. The home page is available at `http://127.0.0.1:8000/`.

## Configuration

Development defaults are provided for local use. Set these environment variables for a shared or deployed environment:

| Variable | Default | Purpose |
| --- | --- | --- |
| `DJANGO_SECRET_KEY` | Development placeholder | Django signing secret |
| `DJANGO_DEBUG` | `false` | Enable Django debug mode |
| `DJANGO_ENV` | `development` | Use `production` to require hardened settings |
| `DJANGO_ALLOWED_HOSTS` | `localhost,127.0.0.1` | Comma-separated host names |
| `MAX_UPLOAD_SIZE` | `10485760` | Maximum PDF upload size in bytes |
| `MAX_PDF_PAGES` | `50` | Maximum pages parsed per PDF |
| `THREAT_AI_ENABLED` | `false` | Enable optional Gemini review |
| `GEMINI_API_KEY` | Empty | Gemini API key when AI review is enabled |

Gemini is disabled by default. Local rules still run without the optional SDK or API key. An AI-only `safe` response remains advisory and is reported as `unknown` so an external model cannot silently turn an inconclusive document into a trusted one.

## Threat reports

Each report contains:

- `verdict`: `safe`, `suspicious`, `malicious`, or `unknown`
- `risk_score`: bounded from 0 to 100
- `severity`: `low`, `medium`, `high`, or `critical`
- `confidence`: `low`, `medium`, or `high`
- matched reasons and bounded evidence
- a recommended next action
- the analysis source and whether a fallback was used

The score is deterministic for the same input. Strong local indicators such as payload execution, PowerShell, and antivirus bypass instructions take priority over weak indicators.

## Checks

Run the Django system check and the application tests with:

```text
python manage.py check
python manage.py test tests
```

The project currently keeps its tests in the repository-root `tests.py`, so the explicit `tests` label is used with Django's test runner.
