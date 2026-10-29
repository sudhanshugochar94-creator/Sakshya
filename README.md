# Sakshya - evidence-first scrutiny support for AICTE (SIH26261)

*Sakshya (साक्ष्य) means evidence. Formerly PramaanSetu. Team EvidenceX.*

AI-assisted application validation, document authentication and regulatory compliance verification.
**Agents propose, rules verify, humans decide.** The system never approves, rejects or accuses.

Implements the *Final Solution Document v3.0* (22 Oct 2026) and the SIH 2026 submission deck. See `/system` in the app (or
`GET /api/v1/system/status`) for an honest implemented / mocked / designed status of every capability.

## Run

```bash
# 1. backend (FastAPI + SQLite)
cd backend
pip install -r requirements.txt
uvicorn main:app --port 8000

# 2. frontend (Next.js)
cd ..
npm install
echo "NEXT_PUBLIC_API_URL=http://localhost:8000" > .env.local
npm run dev            # http://localhost:3000
```
Open **Overview -> Load synthetic demo dossiers**, then follow the demo narrative below.
Optional OCR for scanned pages: install the Tesseract binary and `pip install pytesseract`.

## Deploying

The Next.js frontend can be deployed directly to Vercel: import this repository, keep the
project root as the repository root, and use the detected Next.js build settings. Add
`NEXT_PUBLIC_API_URL` in the Vercel project environment variables, set to the public origin
of the Sakshya API (for example, `https://api.example.com`, without `/api/v1`). Redeploy
after setting or changing it. The frontend defaults to `http://localhost:8000` only during
local development and reports a configuration error in production if this variable is missing.

Vercel hosts the frontend only. The FastAPI backend in `backend/` must be deployed separately
to a Python host, with a persistent volume for `SAKSHYA_DATA_DIR` because SQLite, original
uploads, and derived files are stored on disk. Configure `SAKSHYA_ALLOWED_ORIGINS` on that
backend with the comma-separated frontend origins, such as
`https://your-project.vercel.app,https://www.example.com`. Do not deploy the backend on an
ephemeral filesystem for real data; its current SQLite storage is not a shared/serverless database.
For a Python service configured with `backend/` as its working directory, install with
`pip install -r requirements.txt` and start with
`python -m uvicorn main:app --host 0.0.0.0 --port $PORT`.

**Prototype warning:** role headers are not production authentication. Do not expose the backend
to real case data until real authentication, authorization, and data-protection controls are in place.

Optional LLM wording for explanations (off by default; data-handling rules permitting):
```bash
export SAKSHYA_LLM=anthropic ANTHROPIC_API_KEY=...   # SAKSHYA_LLM_MODEL overrides the model
```
The data directory is `SAKSHYA_DATA_DIR` (the old `PRAMAAN_DATA_DIR` is still read).

```bash
cd backend && python -m pytest -q          # 20 integration tests
python scripts/run_eval.py                 # metrics on the documented synthetic test set
python scripts/build_packs.py              # regenerate starter rule packs (JSON is then the source of truth)
```

## Architecture (matches the solution document)
| Layer | Where |
|---|---|
| Supervisor: per-case plan, parallel tasks, bounded retries, idempotency keys, human gates | `backend/app/supervisor.py` |
| Document Intelligence: text layer / optional OCR, classification (`unknown` allowed), fields with page + bbox + confidence | `app/docintel.py` |
| Executable Handbook: versioned, effective-dated JSON rule packs, embedded golden tests, maker-checker activation | `app/rules/`, `app/rulepacks.py` |
| Deterministic rule engine incl. irregular-date rules, cross-document and record reconciliation | `app/rules/engine.py` |
| Integrity & Forensics: SHA-256, PDF metadata/xref, signature validation (pyHanko), exact + near duplicates, optional ELA | `app/forensics.py` |
| Source Checker + adapter registry, six statuses, provenance label | `app/source_checker.py` |
| Infrastructure: vector floor-plan geometry (shoelace), calibration, GPS/EXIF, quality, reused images, 3-level recommendation | `app/infra.py` |
| No-evidence-no-flag validator, routing queues, Verification Passport | `app/findings.py` |
| Hash-chained audit ledger | `app/audit.py` |
| Alerts: merge, escalate, mock email/SMS gateway, timeliness | `app/alerts.py` |
| Officer Scrutiny Workbench + dashboards | `app/*` pages (Next.js) |
| **New in 1.1** Document-wise Proof Cards + case roll-up (`verified` only when the source confirmed) | `app/proofcards.py`, `components/ProofCards.tsx` |
| **New in 1.1** Plain-language explanation layer (template by default; optional LLM; verdict never from the model) | `app/explain.py` |
| **New in 1.1** Printable case report | `app/applications/[id]/report` |

## Human gates (nothing adverse happens automatically)
Rule-pack activation (maker-checker) · ambiguous extraction · serious integrity indicator · official communication
(deficiency notice approval) · final decision (competent authority only, rationale mandatory).

## Honesty policy
* Synthetic documents carry a visible `DEMO DATA` marker; the "AICTE record adapter" is a labelled synthetic fixture.
* No access to AICTE, DigiLocker, MCA21, EPFO, bank or state systems is claimed.
* Clause references come from the solution document and are flagged *to be confirmed* against the authorised APH.
  Numeric thresholds (faculty ratio, built-up norms) are deliberately **draft rules** until a regulatory expert approves them.
* Forensic output is a preliminary indicator, never proof. A hash proves integrity of bytes, not truth of contents.
* Designed but not implemented: vision-model facility recognition, video continuity analysis, Rule Compiler,
  issuer/QR/bank/professional-registry verification, real SSO, real email/SMS.

## Demo narrative (section 16 of the document)
1. Applicant: *Applications* -> demo case -> **Pre-submission check** (advisory, no official record) -> fix guidance.
2. Replace a document (history kept, new SHA-256) -> **Final submission** -> pre/final diff.
3. Officer: *Evaluate rules* -> open a finding -> original page opens at the exact region -> **Verification Passport**.
4. Integrity indicators (metadata, duplicate), advisory floor-plan area, mock source statuses with provenance labels.
5. Correct a field (original preserved) -> targeted re-check -> confirm / dismiss with reason.
6. Draft deficiency notice -> officer approval gate. *Audit ledger* shows every step; chain verifies.
