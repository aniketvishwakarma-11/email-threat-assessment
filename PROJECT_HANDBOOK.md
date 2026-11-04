# Project Handbook — Email Threat Assessment

> **Contributor:** Aniket (GitHub: `aniketvishwakarma-11`)
> **Branch:** `dev/aniket`
> **Baseline commit:** `c983617` ("uploaded")
> **Last verified:** 2026-11-02
> **Current status:** implementation complete, `python manage.py check` clean, 14/14 tests passing. The UI and analysis changes are present in the working tree and are **not yet committed**.

This document is the single A–Z reference for the project. It explains what existed before, what Aniket changed and why, how the system works now, how to run and test it, what results to expect, and what rules future contributors or AI coding agents must preserve.

---

## 0. How to read this document

| Reader | Start here |
| --- | --- |
| New developer or reviewer | Sections 1–6, then 10 and 14 |
| Committee / demo audience | Sections 1, 4.8, 11, 12 |
| Security reviewer | Sections 5.4–5.6, 6, 8, 13 |
| AI coding agent | Sections 2, 5, 6, 10, 14 |
| Maintainer preparing a release | Sections 8, 9, 10, 13, 16 |

Companion documents:

- `README.md` — short setup and feature overview.
- `IMPLEMENTATION_GUIDE.md` — deeper technical implementation notes.
- `PROJECT_HANDBOOK.md` — this file: context, history, decisions, impact, and operating rules.

---

## 1. Executive summary

The original repository was a small Django demo that classified email text as `Spam` or `Ham` with a scikit-learn model, and checked PDF text with keyword rules plus an optional Gemini call. It had no interface template, no tests, hardcoded secrets, could not start cleanly, and **failed open**: empty or unreadable content was reported as harmless.

Aniket turned it into an explainable threat-assessment tool:

- Every result now includes a verdict, 0–100 risk score, severity, confidence, evidence, recommendations, score breakdown, and analysis pipeline.
- Inconclusive input returns `unknown`, never a false `safe` or `Ham`.
- Email classification combines transparent local rules with the local ML model.
- PDF uploads are validated by extension, size, magic bytes, and page count before parsing.
- AI review is optional, disabled by default, and can never silently mark an inconclusive document as safe.
- The UI shows a side-by-side "legacy vs improved" comparison, highlighted evidence, a risk gauge, contribution bars, a pipeline stepper, and one-click demo samples.
- The repository now has 14 Django tests covering analysis, uploads, rendering, and the demo UI.

The result is a system that is demonstrable, defensible, and safe to hand to another developer.

---

## 2. Repository map

The project intentionally keeps the original **root-level Django layout**. The Django project package is `SpamDetection/`, but the application code lives at the repository root.

| Path | Role | Notes |
| --- | --- | --- |
| `manage.py` | Django entry point | Uses `SpamDetection.settings`. |
| `SpamDetection/settings.py` | Project settings | Environment-driven configuration, template directory, upload/AI limits. |
| `SpamDetection/urls.py` | URL configuration | Routes `/` to `views.Home`. |
| `views.py` | Analysis engine and view | All detection, scoring, report building, PDF extraction, and request handling. |
| `forms.py` | Email input form | Required text, 100,000-character limit. |
| `templates/home.html` | Main page | Email and PDF panels, demo buttons, report includes, highlighting JavaScript. |
| `templates/_report.html` | Shared report component | Comparison strip, gauge, breakdown, reasons, preview, pipeline. Used for both email and PDF. |
| `tests.py` | Test suite | 14 Django tests, no network calls. |
| `emails.csv` | Training dataset | Local spam/ham corpus used by the Naive Bayes model. |
| `requirements.txt` | Dependencies | Django, pandas, scikit-learn, pypdf, openpyxl, google-genai. |
| `.env.example` | Configuration template | Documents supported environment variables (not auto-loaded). |
| `.gitignore` | Ignore rules | Covers virtual environments, caches, `.env`, model artifacts, test output. |
| `README.md` | Quick start | Setup, demo walkthrough, configuration table. |
| `IMPLEMENTATION_GUIDE.md` | Technical guide | Detailed implementation notes and test descriptions. |
| `PROJECT_HANDBOOK.md` | This document | A–Z context, changes, impact, operating rules. |
| `urls.py`, `models.py`, `admin.py`, `apps.py` at root | Legacy compatibility | Kept from the original layout; the active URL configuration is `SpamDetection/urls.py`. |
| `db.sqlite3`, `pyvenv.cfg`, `__pycache__/*.pyc` | Tracked artifacts | Inherited from the original repository; see section 13. |

---

## 3. What existed before (baseline `c983617`)

### 3.1 Startup and structure

- The project used the root-level app layout but failed to start cleanly because of an import of a `detector` package that did not exist.
- There was no `templates/home.html`, even though the view tried to render `home.html`.
- The Django secret key and a Gemini API key were hardcoded in `SpamDetection/settings.py`.
- There was no environment-based configuration for debug mode, allowed hosts, upload size, or AI review.

### 3.2 Email analysis

- A `CountVectorizer` + `MultinomialNB` pipeline was trained **at module import time**, so every process start paid the training cost and any dataset problem could break startup.
- `predict_message()` returned only `Spam` or `Ham`.
- Empty or unrecognized input fell through to `Ham` (fail-open).
- There was no explanation of which words or rules influenced the result, and no risk score.

### 3.3 PDF analysis

- Text was extracted and matched against keyword lists.
- An optional Gemini call returned one of `safe`, `suspicious`, or `malicious`.
- No matched evidence was reported to the user.
- Empty or unreadable PDFs were treated as safe.
- Uploads were not checked for size, page count, or PDF file signature.

### 3.4 Security and operations

- Secrets were committed to source control.
- No CSRF-aware templates existed because there was no template.
- No upload limits meant large or malformed files could exhaust resources.
- Document contents could reach logs in failure paths.
- AI was effectively always available if a key was present, with no explicit enable switch.

### 3.5 Quality gaps

- No tests.
- No explanation layer, so a reviewer could not audit a verdict.
- No distinction between "analyzed and found harmless" and "could not analyze".
- No demo assets or sample inputs for a presentation.

---

## 4. What Aniket changed

### 4.1 Startup, layout, and configuration

| Area | Before | After |
| --- | --- | --- |
| Model training | At import time | Lazy, on first classification attempt |
| Startup | Broken by a missing import | Starts with the original root-level layout |
| Secrets | Hardcoded | Environment variables; production refuses to start without a secret |
| Debug / hosts | Hardcoded defaults | `DJANGO_DEBUG`, `DJANGO_ENV`, `DJANGO_ALLOWED_HOSTS` |
| Templates | Missing `home.html` | `templates/home.html` plus shared `templates/_report.html` |
| URL routing | Not wired to the new page | `/` routes to `views.Home` |
| Email input | Unbounded | Required, 100,000-character maximum |
| Upload limits | None | 10 MB and 50 pages by default, configurable |

Key locations: `SpamDetection/settings.py`, `SpamDetection/urls.py`, `forms.py`, `views.py`.

### 4.2 Security and privacy

- PDF validation now occurs in layers before parsing:
  1. `.pdf` extension check.
  2. Size check against `MAX_UPLOAD_SIZE`.
  3. `%PDF-` magic-byte check.
  4. Page-count check against `MAX_PDF_PAGES` inside extraction.
- Document contents are never written to logs; only failure events are logged.
- Gemini review is gated behind `THREAT_AI_ENABLED=true` **and** a non-empty `GEMINI_API_KEY`.
- The AI prompt treats document text as untrusted data and instructs the model to ignore embedded instructions, reducing prompt-injection risk.
- The UI never renders user content with `|safe` or `innerHTML`. Evidence highlighting uses DOM text nodes (`textContent`, `createElement`, `mark`), and report data is embedded with Django's `json_script`.
- Both forms include `{% csrf_token %}`.
- An AI-only "safe" response is downgraded to `unknown`, so an external model cannot silently turn an inconclusive document into a trusted one.

### 4.3 Email analysis

The email path in `views.py` now:

- Normalizes text and handles empty input explicitly as `unknown`.
- Matches a transparent malicious and suspicious indicator table.
- Adds the local ML model result as a reason (and +20 points when it predicts spam).
- Deduplicates repeated indicators by code.
- Builds a numeric risk score and a verdict using deterministic thresholds.
- Preserves the original simple API (`predict_message()`) for compatibility.

### 4.4 PDF analysis

- Extracts text with `pypdf`, with a `PyPDF2` fallback for older environments.
- Bounds extraction by page count and returns empty text safely.
- Applies the same indicator engine (without URL matching, because a URL inside a PDF is not evidence by itself).
- Uses local rules first; malicious or suspicious matches are decisive.
- Calls Gemini only when local rules find nothing and AI review is enabled.
- Maps AI `safe` to `unknown` with an advisory reason, and AI `suspicious`/`malicious` to weighted scores of 55/90.
- Returns `unknown` with a clear reason when no AI review is available.
- Preserves `pdf_threat_detection()` for compatibility.

### 4.5 Explainability data contract

`_build_report()` in `views.py` converts raw analysis into a stable dictionary that every consumer uses:

- `verdict`, `risk_score`, `severity`, `confidence`
- `reasons` with code, label, evidence, weight, and malicious flag
- `score_breakdown` with per-reason points and percentages
- `raw_score`, `score_note`
- `recommendation`
- `analysis_source` and human-readable `analysis_source_label`
- `fallback`
- Email-only: `model_prediction`

### 4.6 User interface

`templates/home.html` and `templates/_report.html` now provide:

- **Email panel** with textarea, CSRF token, validation errors, and a submit button.
- **PDF panel** with file picker, `application/pdf` hints, multipart upload, and validation messages.
- **Demo buttons** that prefill phishing, phishing-with-link, malicious, and benign samples.
- **Legacy comparison strip**: what the old single-label system would have said versus the new verdict.
- **Risk gauge** with the numeric score.
- **Score breakdown** showing which indicators contributed points.
- **Detection reasons** with evidence and weights.
- **Evidence highlighting** in a bounded text preview.
- **Analysis pipeline stepper** showing each stage and whether it ran, was skipped, or warned.
- **"Why unknown?" callout** explaining inconclusive results.
- Responsive single-column layout on narrow screens.

### 4.7 Tests and documentation

- `tests.py` grew from nothing to 14 tests.
- `README.md` gained the explainable-report description, demo walkthrough, and configuration reference.
- `IMPLEMENTATION_GUIDE.md` documents the architecture, UI, testing, and verification commands.

### 4.8 Before/after behavior, concretely

| Input | Old behavior | New behavior |
| --- | --- | --- |
| Empty email | `Ham` | `unknown`, low confidence, reason "No email text was provided" |
| "Run PowerShell to download payload.exe and disable antivirus." | `Ham` (model-only) | `malicious`, 100/100, critical, reasons with weights |
| "URGENT: Your account is suspended..." | `Spam` with no explanation | `suspicious`, 68/100, high, four reasons |
| Benign PDF with no indicators, AI off | `Safe` | `unknown`, fallback notice, reason "AI review unavailable" |
| Malformed `.pdf` upload | Parsed or crashed | Rejected before extraction with a clear message |
| Paste containing `<script>` | Could be rendered unsafely in a naive template | Escaped and highlighted as text only |

---

## 5. How the system works now

### 5.1 Request flow

```text
Browser
  -> SpamDetection/urls.py
  -> views.Home
       -> email_check POST -> MessageForm -> analyze_email()
       -> pdf_check POST   -> validation -> extract_pdf_text() -> analyze_pdf_text()
  -> _build_report()
  -> templates/home.html
  -> templates/_report.html (email and/or PDF)
```

`Home` still populates the legacy context variables `result` and `pdf_result`, so older callers or templates that expect them do not break.

### 5.2 Email pipeline

1. **Input validation** — reject empty text at the analysis layer with `unknown`.
2. **Local rules** — match malicious and suspicious phrases and URLs.
3. **ML classifier** — Naive Bayes prediction (`spam` or `ham`), if the model and dataset are available.
4. **Score and verdict** — sum weights, add the model bonus, apply verdict rules and the malicious floor, cap at 100.
5. **Recommendation** — map the verdict to actionable guidance.

These stages are surfaced to the UI by `_email_pipeline()`.

### 5.3 PDF pipeline

1. **Upload validation** — extension, size, and PDF signature.
2. **Text extraction** — bounded by page count; failures return empty text.
3. **Local rules** — malicious/suspicious indicator matching.
4. **Optional AI review** — only when local rules find nothing and AI is enabled.
5. **Score and verdict** — apply weights, floor, and cap.
6. **Recommendation** — map the verdict to guidance.

These stages are surfaced by `_pdf_pipeline(report, extracted)`.

### 5.4 Scoring and verdict rules

- **Base score:** sum of the weights of unique matched indicators.
- **Model bonus:** +20 when the email model predicts spam.
- **Deduplication:** only the first matching phrase per indicator code is counted. For example, `password` and `credentials` share the `credential_request` code, so only the first match adds points.
- **Malicious override:** any malicious indicator makes the verdict `malicious`.
- **Malicious floor:** a malicious verdict has a minimum score of 80, even if the added weights are lower.
- **Cap:** the displayed score is always between 0 and 100, and the UI explains when contributions exceed 100.
- **Suspicious:** triggered by a spam model result or a score of at least 20 when no malicious indicator matched.
- **Safe:** only when the email model predicts ham and no risky rule matched.
- **Unknown:** empty input, inconclusive PDF analysis, unavailable classifier, or an AI-only safe response.
- **Severity:** `critical` at 80+, `high` at 50–79, `medium` at 20–49, `low` below 20.

### 5.5 Indicator catalog

Malicious indicators (each matched phrase adds its weight and forces `malicious`):

| Category | Example phrases | Weight |
| --- | --- | --- |
| Payload execution | `payload.exe`, `shellcode`, `execute payload`, `download payload` | 40 |
| Command execution | `cmd /c`, `powershell` | 40 |
| Command execution (weaker) | `run script`, `execute script` | 35 |
| Security bypass | `disable antivirus` | 40 |
| Security bypass (weaker) | `bypass security` | 35 |
| Exploit | `exploit` | 35 |
| Malware family | `ransomware` | 40 |
| Malware family (weaker) | `malware`, `trojan` | 35 |

Suspicious indicators:

| Category | Example phrases | Weight |
| --- | --- | --- |
| Credential request | `credentials`, `bank details` | 22 |
| Account verification | `verify your account` | 20 |
| Financial request | `bank account`, `login immediately` | 20 |
| Web link | any `http://`, `https://`, or `www.` URL (email only) | 20 |
| Credential request | `password`, `otp` | 18 |
| Account threat | `suspended`, `account closure` | 18 |
| Financial request | `payment` | 18 |
| Call to action | `click here` | 15 |
| Urgency | `urgent` | 12 |

Canonical definitions: `MALICIOUS_INDICATORS` and `SUSPICIOUS_INDICATORS` in `views.py`. Because matching is substring-based after lowercasing and whitespace normalization, short phrases can match inside longer words; keep that in mind when adding new rules.

### 5.6 Confidence

- **High:** a malicious indicator matched, or an email model result and at least one rule match agree.
- **Medium:** the model produced a result without rule matches; or an AI review produced a PDF verdict.
- **Low:** the result is `unknown` or analysis was inconclusive.

### 5.7 Legacy labels (comparison only)

The UI intentionally shows what the previous system would have returned:

- **Email legacy label:** `Spam` if the model predicted spam, otherwise `Ham`.
- **PDF legacy label:** capitalized verdict; `unknown` with no extracted text is shown as `Suspicious`, and other unknown results are shown as `Safe`.

These labels are **not** the application's recommendation. They exist to demonstrate why the explainable verdict is safer.

---

## 6. Report contract

Every analysis returns a dictionary with these fields:

| Field | Type | Meaning |
| --- | --- | --- |
| `source` | string | `email` or `pdf` |
| `verdict` | string | `safe`, `suspicious`, `malicious`, `unknown` |
| `risk_score` | integer | 0–100, capped |
| `severity` | string | `low`, `medium`, `high`, `critical` |
| `confidence` | string | `low`, `medium`, `high` |
| `reasons` | list | Matched indicators and advisory notes |
| `recommendation` | string | Recommended next action |
| `analysis_source` | string | Machine key such as `combined`, `rules`, `gemini`, `local_rules` |
| `analysis_source_label` | string | Human-readable source |
| `fallback` | boolean | True when analysis was inconclusive or used a fallback |
| `score_breakdown` | list | `label`, `points`, `percent`, `malicious` per contribution |
| `score_note` | string or null | Explains a cap or verdict minimum |
| `raw_score` | integer | Uncapped total contribution |
| `model_prediction` | string or null | Email only: `spam`, `ham`, or null |

Each reason contains `code`, `label`, and `evidence`; rule reasons also contain `weight` and `malicious`.

Example (malicious demo email, abbreviated evidence strings):

```json
{
  "source": "email",
  "verdict": "malicious",
  "risk_score": 100,
  "severity": "critical",
  "confidence": "high",
  "reasons": [
    {"code": "payload_execution", "label": "Payload execution reference", "evidence": "payload.exe", "weight": 40, "malicious": true},
    {"code": "command_execution", "label": "PowerShell execution reference", "evidence": "powershell", "weight": 40, "malicious": true},
    {"code": "security_bypass", "label": "Instruction to disable antivirus", "evidence": "disable antivirus", "weight": 40, "malicious": true},
    {"code": "model_ham", "label": "The local email model found no spam classification", "evidence": "local classifier", "weight": 0, "malicious": false}
  ],
  "recommendation": "Do not execute, open, reply to, or distribute this content. Report it for security review.",
  "analysis_source": "combined",
  "analysis_source_label": "Local rules + ML model",
  "fallback": false,
  "score_breakdown": [
    {"label": "Payload execution reference", "points": 40, "percent": 33, "malicious": true},
    {"label": "PowerShell execution reference", "points": 40, "percent": 33, "malicious": true},
    {"label": "Instruction to disable antivirus", "points": 40, "percent": 33, "malicious": true}
  ],
  "score_note": "Indicator contributions exceed 100; the displayed score is capped.",
  "raw_score": 120,
  "model_prediction": "ham"
}
```

The same input always produces the same result (given the same dataset and library versions). The model split uses `random_state=42`.

---

## 7. User interface guide

The home page is a single screen with two panels and a report area below.

### Email panel

- Required textarea with a 100,000-character limit.
- CSRF token and Django validation errors.
- Submit button named `email_check`.
- Four sample buttons: Phishing, Phishing + link, Malicious, Benign.

### PDF panel

- File input accepting `application/pdf,.pdf`.
- Multipart form and CSRF token.
- Submit button named `pdf_check`.
- Validation messages for missing, wrong-type, oversized, or invalid files.
- A hint explaining that an unreviewed clean PDF returns `unknown`.

### Report component

For each submitted item, `_report.html` renders:

1. Header and legacy-vs-improved comparison.
2. Risk gauge and severity/score/confidence badges.
3. Recommendation.
4. "Why unknown?" callout when applicable.
5. Score breakdown bars.
6. Detection reasons with evidence and weights.
7. Bounded evidence preview with safe highlighting.
8. Analysis pipeline stepper.
9. Truncation notice for long inputs.

### Front-end safety

- Report data is embedded with `json_script`.
- Highlighting walks text nodes and creates `<mark>` elements; it never assigns user text to `innerHTML`.
- The page uses Django auto-escaping for all template variables.

---

## 8. Security and privacy model

| Concern | Mitigation |
| --- | --- |
| Committed secrets | Environment variables; production startup check; `.env` ignored by git |
| Fail-open verdicts | Explicit `unknown` with low confidence |
| Malicious uploads | Extension, size, magic-byte, and page-count checks before parsing |
| PDF parser resource exhaustion | Page limit and bounded extraction |
| Prompt injection | Document text framed as untrusted data; output restricted to one of three words |
| AI over-trust | AI-only `safe` becomes `unknown` with an advisory reason |
| Stored XSS | Auto-escaping, `json_script`, DOM text nodes, no `innerHTML` |
| CSRF | Token on both forms |
| Sensitive logging | Document contents are not logged |
| Oversized previews | Email preview capped at 20,000 characters; PDF excerpt at 2,000; AI prompt at 3,000 |

Operational limits:

- This is an advisory tool, not an antivirus sandbox. PDF parsing and text extraction do not make an attachment safe to open.
- The old Gemini API key remains in the repository's git history. It must be **rotated/revoked** before the branch is published.
- There is no authentication, rate limiting, or audit log; do not expose the app directly to the public internet without adding them.
- Rules are lexical and English-oriented; they can produce false positives and false negatives.

---

## 9. Configuration reference

Configuration is read from environment variables. The project does **not** auto-load `.env`; use shell environment variables or a process manager.

| Variable | Default | Purpose |
| --- | --- | --- |
| `DJANGO_SECRET_KEY` | Generated in development; required when `DJANGO_ENV=production` | Django signing secret |
| `DJANGO_DEBUG` | `false` | Enable debug mode locally |
| `DJANGO_ENV` | `development` | Set `production` to enforce the secret requirement |
| `DJANGO_ALLOWED_HOSTS` | `localhost,127.0.0.1` | Comma-separated allowed hosts |
| `MAX_UPLOAD_SIZE` | `10485760` (10 MB) | Maximum PDF upload size in bytes |
| `MAX_PDF_PAGES` | `50` | Maximum pages parsed per PDF |
| `THREAT_AI_ENABLED` | `false` | Enable optional Gemini review |
| `GEMINI_API_KEY` | Empty | Gemini API key when AI review is enabled |

Example for local development (Git Bash):

```bash
export DJANGO_DEBUG=true
python manage.py runserver
```

PowerShell:

```powershell
$env:DJANGO_DEBUG="true"
python manage.py runserver
```

Example for a shared environment:

```bash
export DJANGO_ENV=production
export DJANGO_SECRET_KEY="$(python -c 'import secrets; print(secrets.token_urlsafe(50))')"
export DJANGO_ALLOWED_HOSTS="threat.example.com"
python manage.py runserver 0.0.0.0:8000
```

---

## 10. Testing and verification

Commands:

```bash
cd D:\Projects\email-threat-assessment
python manage.py check
python manage.py test tests
```

Verified result on 2026-11-02:

```text
System check identified no issues (0 silenced).
Found 14 test(s).
OK
```

Coverage map:

| Test | What it proves |
| --- | --- |
| `test_malicious_pdf_indicators_produce_explainable_critical_report` | Malicious PDF rules produce a critical, explained report |
| `test_suspicious_email_contains_reasons_and_recommendation` | Suspicious email includes reasons and guidance |
| `test_empty_email_is_unknown_instead_of_ham` | No fail-open on empty input |
| `test_unreviewed_benign_pdf_is_not_marked_safe_without_ai` | Clean PDF without AI is `unknown`, not `safe` |
| `test_malicious_rule_has_priority_over_suspicious_rule` | Malicious rules override weaker signals |
| `test_malicious_score_breakdown_reconciles_to_final_score` | Breakdown points reconcile with the score |
| `test_malicious_score_breakdown_reports_cap` | Scores above 100 are capped and explained |
| `test_home_page_renders` | The home page loads |
| `test_email_report_includes_legacy_comparison_and_score_breakdown` | UI data reaches the rendered report |
| `test_email_form_returns_report` | The email request path works |
| `test_invalid_pdf_is_rejected_before_extraction` | Magic-byte validation blocks fake PDFs |
| `test_valid_pdf_upload_returns_threat_report` | The PDF request path works with extraction mocked |
| `test_benign_pdf_compares_legacy_safe_with_unknown` | Legacy-vs-improved comparison is correct |
| `test_pdf_upload_limit_is_enforced` | Size limits are enforced |

Tests never call Gemini and do not require a network connection. Django's test runner adds `testserver` to `ALLOWED_HOSTS` automatically, so the rendering tests work with the production-style defaults.

---

## 11. Demo script with exact expected outputs

### Setup

```bash
cd D:\Projects\email-threat-assessment
.venv\Scripts\activate
pip install -r requirements.txt
export DJANGO_DEBUG=true
python manage.py runserver
```

Open `http://127.0.0.1:8000/`.

### Email samples (one click each)

| Button | Expected verdict | Score | Severity | Confidence | Legacy label |
| --- | --- | --- | --- | --- | --- |
| Phishing | suspicious | 68 | high | high | Spam |
| Phishing + link | suspicious | 35 | medium | high | Ham |
| Malicious | malicious | 100 | critical | high | Ham |
| Benign | safe | 0 | low | medium | Ham |

Reason contributions:

- **Phishing:** urgent +12, password +18, suspended +18, model spam +20.
- **Phishing + link:** click here +15, web link +20.
- **Malicious:** payload.exe +40, PowerShell +40, disable antivirus +40; raw 120, displayed 100, cap note shown.
- **Benign:** model ham only, 0 points.

The **Malicious** sample is the strongest demonstration: the legacy model says `Ham`, while the new engine returns `malicious` with a critical score and a capped-contribution explanation.

These values assume `emails.csv` is present and scikit-learn is installed. Without the model, rule scores remain but model-based bonuses and legacy labels change.

### PDF checks

| Upload | Expected result |
| --- | --- |
| Text PDF: "Quarterly project status report. No action required." with AI off | `unknown`, 0/100, low confidence, legacy `Safe`, fallback notice, reason "AI review unavailable" |
| Text PDF containing "Run PowerShell to download payload.exe and disable antivirus." | `malicious`, 100/100 (raw 120), critical, legacy `Malicious` |
| Scanned/image-only PDF with no extractable text | `unknown`, 0/100, legacy `Suspicious` |
| Text file renamed to `.pdf` | "The uploaded file does not appear to be a valid PDF." |
| Non-PDF extension | "Upload only PDF files." |
| PDF larger than 10 MB | "The PDF exceeds the maximum upload size." |

To create a text PDF locally, write the text in any editor and use "Print to PDF"; no special tooling is required.

### UI checklist

1. Sample buttons fill the textarea.
2. Report shows the comparison strip, gauge, breakdown, reasons, highlights, and pipeline.
3. The malicious sample shows a capped score note and a red/critical gauge.
4. The clean PDF shows the "Why unknown?" callout.
5. Narrowing the window stacks panels into one column.
6. No browser console errors appear.

---

## 12. Impact of the changes

### For end users

- Results are explainable: every point and every verdict has a visible reason.
- Inconclusive cases are labeled honestly instead of being called harmless.
- Recommendations tell the user what to do next.
- Inputs are bounded and validated, reducing accidental misuse.

### For the committee / demo

- The before/after comparison makes the value of the contribution obvious in one screen.
- One-click samples remove typing and make the demo repeatable.
- The gauge and breakdown turn an abstract classifier into an auditable assessment.
- The malicious sample specifically shows a case the old model got wrong.

### For maintainers

- Detection rules are centralized and easy to extend.
- The report dictionary is a stable contract shared by the engine, UI, and tests.
- The system degrades gracefully when optional dependencies or AI access are missing.
- Tests run offline and deterministically.

### For open source

- No secrets in new code; configuration is documented.
- The original module layout and public helper functions remain compatible.
- A reviewer can understand the change from the handbook, README, implementation guide, and tests.
- The branch is a self-contained improvement with a clear narrative.

---

## 13. Limitations and future work

Known limitations:

- Rules are lexical, substring-based, and English-oriented; obfuscation, encoding tricks, and non-English content can evade them.
- The ML model is a small Naive Bayes classifier trained from a bundled dataset; it is not a production-grade detector.
- Scanned PDFs are not OCR'd; they return `unknown`.
- PDF analysis is text-based; embedded scripts, JavaScript, and exploits are not deeply inspected.
- There is no persistence, audit trail, user accounts, or rate limiting.
- Scoring weights are hand-tuned, not statistically calibrated.
- AI review is optional and its "safe" output is never trusted as final.
- `IMPLEMENTATION_GUIDE.pdf` is untracked and has not been regenerated from the current Markdown source.

Repository hygiene items before publishing:

- Rotate/revoke the Gemini API key exposed in the original git history.
- Remove tracked `db.sqlite3`, `pyvenv.cfg`, and `__pycache__/*.pyc` artifacts.
- Commit the UI and analysis changes on `dev/aniket`.
- Consider regenerating or removing the stale PDF guide.
- Add CI to run `manage.py check` and the test suite.

Possible future enhancements:

- Configurable rule sets with severity calibration and tests per rule.
- OCR support for scanned documents.
- File-hash reputation or external threat-intelligence lookups.
- Structured JSON API endpoint for integration.
- Authentication, rate limiting, and audit logging for shared deployments.
- More languages and internationalized indicator sets.

---

## 14. Guidance for AI agents and contributors

### Invariants: do not break these

1. **Root-level layout.** Application modules stay at the repository root; the Django project package is `SpamDetection/`. Do not move `views.py` or `forms.py` without updating imports, tests, and documentation.
2. **No import-time training.** Model training must remain lazy; tests and startup must not depend on dataset availability.
3. **No fail-open verdicts.** Inconclusive input must return `unknown`, never `safe`, `Ham`, or an empty success.
4. **Stable report contract.** Keep the fields listed in section 6; the templates, tests, and helper pipelines depend on them.
5. **Reason metadata.** Rule reasons must carry `weight` and `malicious`; `_build_report` uses them for breakdown and scoring.
6. **Malicious priority.** A malicious indicator must continue to override suspicious signals and force the score to at least 80.
7. **Escaping.** Never render user content with `|safe` or `innerHTML`. Use Django escaping, `json_script`, and DOM text nodes.
8. **Offline tests.** The suite must pass without network access or a Gemini key.
9. **Bounded inputs.** Keep preview, prompt, upload, and page limits in place.
10. **Documentation.** Update this handbook, `README.md`, and `IMPLEMENTATION_GUIDE.md` when behavior or test counts change.

### Where to make common changes

| Goal | Location |
| --- | --- |
| Add or tune an indicator | `MALICIOUS_INDICATORS` / `SUSPICIOUS_INDICATORS` in `views.py`; add a test |
| Change score thresholds | `_risk_level()` and verdict logic in `analyze_email()` / `analyze_pdf_text()`; update tests and this handbook |
| Add a report field | `_build_report()` and, if used by the UI, `templates/_report.html`; update section 6 |
| Change page layout or report UI | `templates/home.html`, `templates/_report.html`; keep escaping rules |
| Change validation limits | `SpamDetection/settings.py`, `forms.py`, upload checks in `Home` |
| Change AI behavior | `_gemini_classification()` and the AI branch of `analyze_pdf_text()` |
| Change legacy compatibility labels | `_legacy_email_label()` / `_legacy_pdf_label()`; keep them clearly labeled as comparison-only |

### Definition of done

- `python manage.py check` passes.
- `python manage.py test tests` passes with all tests.
- New behavior has at least one test.
- No secrets, document contents, or user text are logged.
- User-controlled content remains escaped.
- Documentation and any test-count references are updated.
- `git diff --check` reports no whitespace errors.

---

## 15. Glossary

| Term | Meaning |
| --- | --- |
| **Verdict** | Final classification: safe, suspicious, malicious, or unknown. |
| **Unknown** | Analysis was inconclusive; not a claim of safety. |
| **Risk score** | 0–100 additive indicator score, capped and explained. |
| **Severity** | Score band: low, medium, high, critical. |
| **Confidence** | How strongly the evidence supports the verdict. |
| **Reason** | A matched indicator or advisory note with evidence. |
| **Score breakdown** | Per-reason point contributions shown in the UI. |
| **Fallback** | The system could not fully analyze the input. |
| **Legacy label** | What the original Spam/Ham or Safe model would have returned. |
| **Indicator** | A phrase or pattern with an associated weight and category. |
| **Naive Bayes** | The local probabilistic text classifier used for spam/ham. |
| **CountVectorizer** | Converts text into word-count features for the model. |
| **pypdf** | Library used to extract text from PDF files. |
| **Prompt injection** | Malicious instructions embedded in content sent to an AI model. |
| **CSRF** | Cross-Site Request Forgery; mitigated with Django tokens. |
| **XSS** | Cross-Site Scripting; mitigated with escaping and DOM text nodes. |

---

## 16. Change history and current state

| Commit | Description |
| --- | --- |
| `c983617` | Original repository snapshot ("uploaded") |
| `bc8a3f3` | Explainable threat assessment reports, safe configuration, validation, tests |
| `fdc8093` | Detailed implementation guide |

Current branch and working tree:

- Branch: `dev/aniket`
- The UI pack (`views.py`, `templates/home.html`, `templates/_report.html`, `tests.py`, `README.md`, `IMPLEMENTATION_GUIDE.md`) is modified/untracked and has not been committed.
- `PROJECT_HANDBOOK.md` (this file) is new and uncommitted.
- The branch is ahead of `origin/dev/aniket` by the local documentation commit.
- `IMPLEMENTATION_GUIDE.pdf` is untracked and not regenerated from the current Markdown source.

Before publishing:

1. Rotate the exposed Gemini API key.
2. Commit the UI and handbook changes.
3. Decide whether to remove or regenerate the PDF guide.
4. Clean tracked build artifacts.
5. Push `dev/aniket` and open a pull request with a summary that links this handbook.

---

## Appendix A — Quick command reference

```bash
# Setup
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt

# Verify
python manage.py check
python manage.py test tests

# Run locally
export DJANGO_DEBUG=true          # Git Bash
python manage.py runserver

# Inspect expected demo values without the browser
python - <<'EOF'
import os, django
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "SpamDetection.settings")
django.setup()
import views
text = "URGENT: Your account is suspended. Verify your credentials immediately and provide your password."
print(views.analyze_email(text)["verdict"], views.analyze_email(text)["risk_score"])
EOF
```

## Appendix B — Key function map (`views.py`)

| Function | Responsibility |
| --- | --- |
| `load_email_dataset()` | Load and normalize the bundled CSV/XLSX dataset. |
| `_ensure_email_model()` | Lazily train the vectorizer and Naive Bayes model once. |
| `_model_prediction()` | Return `spam`, `ham`, or `None`. |
| `predict_message()` | Legacy public classifier API. |
| `_matched_indicators()` | Match rules and optional URL evidence. |
| `_risk_level()` | Convert a score into a severity band. |
| `_recommendation()` | Map a verdict to user guidance. |
| `_build_report()` | Build the stable explainable report contract. |
| `analyze_email()` | Full email analysis and verdict logic. |
| `extract_pdf_text()` | Bounded PDF text extraction. |
| `rule_based_pdf_check()` | Legacy PDF rule verdict. |
| `_gemini_classification()` | Optional, gated AI review. |
| `analyze_pdf_text()` | Full PDF analysis and verdict logic. |
| `pdf_threat_detection()` | Legacy public PDF API. |
| `_legacy_email_label()` / `_legacy_pdf_label()` | Old-system labels for the comparison UI. |
| `_email_pipeline()` / `_pdf_pipeline()` | Stage-by-stage UI traces. |
| `Home()` | Request handling, validation, rendering. |
