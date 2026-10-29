"""Sakshya API. Authenticated, role-checked, validated and audited. No endpoint approves or rejects
an application except the competent-authority decision endpoint, which records a human rationale."""
import hashlib, io, json, mimetypes, re, uuid
from datetime import date
from pathlib import Path
from typing import Optional, List, Any

import pymupdf
from fastapi import FastAPI, Depends, HTTPException, UploadFile, File, Form, Header, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, Response
from pydantic import BaseModel, Field

from . import db, audit, rulepacks, supervisor, alerts, forensics, source_checker, proofcards, explain as explain_mod
from .config import UPLOAD_DIR, DERIVED_DIR, MAX_UPLOAD_BYTES, ALLOWED_EXT, TOOL_VERSION, CORS_ORIGINS
from .findings import passport as build_passport

app = FastAPI(title="Sakshya API", version="1.1.0",
              description="AI-assisted decision support for AICTE application scrutiny. Agents propose, rules verify, humans decide.")
app.add_middleware(CORSMiddleware, allow_origins=CORS_ORIGINS, allow_methods=["*"], allow_headers=["*"])

ROLES = {"applicant", "scrutiny_officer", "specialist_reviewer", "rule_author", "regulatory_expert", "competent_authority", "administrator"}
OFFICER = {"scrutiny_officer", "specialist_reviewer", "regulatory_expert", "competent_authority", "administrator"}

@app.on_event("startup")
def _startup():
    db.init_db(); rulepacks.seed_packs()

# ------------------------------------------------------------------ auth (token/SSO mapped to roles; header-based in prototype)
class Actor(BaseModel):
    name: str; role: str; specialty: Optional[str] = None

def actor(x_role: str = Header("scrutiny_officer"), x_actor: str = Header("officer.demo"), x_specialty: Optional[str] = Header(None)) -> Actor:
    if x_role not in ROLES: raise HTTPException(401, f"unknown role '{x_role}'")
    return Actor(name=x_actor, role=x_role, specialty=x_specialty)

def need(a: Actor, *roles):
    if a.role not in roles and a.role != "administrator":
        raise HTTPException(403, f"role '{a.role}' is not permitted for this action (needs one of {sorted(roles)})")

def app_or_404(app_id):
    a = supervisor.get_app(app_id)
    if not a: raise HTTPException(404, "application not found")
    return a

def mask(v: str, keep=4):
    return v if v is None or len(v) <= keep else "*" * (len(v) - keep) + v[-keep:]

SENSITIVE = re.compile(r"\b(\d{12}|[A-Z]{5}\d{4}[A-Z])\b")  # Aadhaar-like / PAN-like
def mask_text(s):
    return SENSITIVE.sub(lambda m: mask(m.group(0)), s) if isinstance(s, str) else s

# ------------------------------------------------------------------ models
class AppIn(BaseModel):
    institution_name: str
    category: str
    applicant_ref: Optional[str] = None
    declared: dict = Field(default_factory=dict)
    is_demo: bool = False

class ReviewIn(BaseModel):
    action: str  # confirm | dismiss | request_clarification | escalate | correct_field | mark_source_pending | mark_source_completed
    reason: str = ""
    field_id: Optional[str] = None
    new_value: Optional[str] = None
    escalate_to: Optional[str] = None

class InfraIn(BaseModel):
    floorplan: Optional[dict] = None       # {page, calibration:{meters_per_pt | pt_length+real_length_m}, declared_area_sqm}
    location: Optional[dict] = None        # {latitude, longitude, tolerance_km}
    application_period: Optional[List[str]] = None

class DecisionIn(BaseModel):
    decision: str   # recorded exactly as entered by the competent authority
    rationale: str

class PackIn(BaseModel):
    pack: dict
    changelog: str = ""

# ------------------------------------------------------------------ applications
CATEGORIES = {"eoa_self_disclosure", "eoa_increase_intake", "eoa_change_of_site", "eoa_change_name_address"}

@app.post("/api/v1/applications")
def create_application(body: AppIn, a: Actor = Depends(actor)):
    if body.category not in CATEGORIES: raise HTTPException(422, f"category must be one of {sorted(CATEGORIES)}")
    aid = "APP-" + date.today().strftime("%y%m%d") + "-" + uuid.uuid4().hex[:5].upper()
    db.run("INSERT INTO applications VALUES(?,?,?,?,?,?,?,?,?,?)", (aid, body.institution_name, body.category, "draft", body.applicant_ref or a.name,
           db.jd(body.declared), audit.now(), None, db.jd([]), int(body.is_demo)))
    audit.append("application_created", a.name, a.role, aid, refs={"category": body.category, "demo": body.is_demo})
    return {"id": aid, "status": "draft", "checklist": rulepacks.checklist_for(body.category)}

@app.get("/api/v1/applications")
def list_applications(category: Optional[str] = None, status: Optional[str] = None, q: Optional[str] = None,
                      page: int = 1, page_size: int = Query(20, le=100), a: Actor = Depends(actor)):
    where, args = ["1=1"], []
    if a.role == "applicant": where.append("applicant_ref=?"); args.append(a.name)
    if category: where.append("category=?"); args.append(category)
    if status: where.append("status=?"); args.append(status)
    if q: where.append("(institution_name LIKE ? OR id LIKE ?)"); args += [f"%{q}%", f"%{q}%"]
    total = db.one(f"SELECT COUNT(*) n FROM applications WHERE {' AND '.join(where)}", args)["n"]
    rows = db.many(f"SELECT * FROM applications WHERE {' AND '.join(where)} ORDER BY created_at DESC LIMIT ? OFFSET ?", args + [page_size, (page - 1) * page_size])
    for r in rows:
        r["declared"] = db.jl(r["declared"], {})
        c = db.one("SELECT SUM(status='deficiency') d, SUM(status='needs_review') n, COUNT(*) t FROM findings WHERE application_id=? AND active=1", (r["id"],))
        r["counts"] = {"deficiency": c["d"] or 0, "needs_review": c["n"] or 0, "findings": c["t"] or 0}
    return {"total": total, "page": page, "items": rows}

@app.get("/api/v1/applications/{app_id}")
def get_application(app_id: str, a: Actor = Depends(actor)):
    ap = app_or_404(app_id)
    ap["checklist"] = rulepacks.checklist_for(ap["category"])
    ap["documents"] = list_documents(app_id, a)
    ap["open_gates"] = db.many("SELECT * FROM gates WHERE application_id=? AND status='open'", (app_id,))
    return ap

# ------------------------------------------------------------------ documents
@app.post("/api/v1/applications/{app_id}/documents")
async def upload_document(app_id: str, file: UploadFile = File(...), replaces: Optional[str] = Form(None), a: Actor = Depends(actor)):
    ap = app_or_404(app_id)
    ext = Path(file.filename or "").suffix.lower()
    if ext not in ALLOWED_EXT: raise HTTPException(415, f"file type '{ext}' not allowed ({sorted(ALLOWED_EXT)})")
    data = await file.read()
    if len(data) > MAX_UPLOAD_BYTES: raise HTTPException(413, "file too large")
    if not data: raise HTTPException(422, "empty file")
    if ext == ".pdf" and not data.startswith(b"%PDF"): raise HTTPException(422, "file is not a valid PDF (bad header)")
    sha = hashlib.sha256(data).hexdigest()
    doc_id = "DOC-" + uuid.uuid4().hex[:8].upper()
    path = UPLOAD_DIR / f"{doc_id}{ext}"; path.write_bytes(data); path.chmod(0o444)   # originals immutable
    group, version = doc_id, 1
    if replaces:
        old = db.one("SELECT * FROM documents WHERE id=? AND application_id=?", (replaces, app_id))
        if not old: raise HTTPException(404, "document to replace not found")
        group, version = old["group_id"], old["version"] + 1
        db.run("UPDATE documents SET superseded_by=? WHERE id=?", (doc_id, replaces))
    mime = mimetypes.guess_type(path.name)[0] or "application/octet-stream"
    db.run("INSERT INTO documents VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", (doc_id, app_id, group, version, file.filename, sha, len(data), mime, str(path),
           "unknown", 0.0, audit.now(), a.name, None, None, db.jd({}), db.jd({})))
    audit.append("document_uploaded" if not replaces else "document_replaced", a.name, a.role, app_id, doc_id,
                 refs={"sha256": sha, "filename": file.filename, "version": version, "replaces": replaces})
    return {"id": doc_id, "sha256": sha, "version": version, "group_id": group}

@app.get("/api/v1/applications/{app_id}/documents")
def list_documents(app_id: str, a: Actor = Depends(actor)):
    app_or_404(app_id)
    rows = db.many("SELECT id,group_id,version,filename,sha256,size,mime,doc_type,doc_type_conf,uploaded_at,uploaded_by,superseded_by,page_count FROM documents WHERE application_id=? ORDER BY uploaded_at", (app_id,))
    return rows

@app.patch("/api/v1/documents/{doc_id}/type")
def set_doc_type(doc_id: str, doc_type: str, reason: str = "", a: Actor = Depends(actor)):
    need(a, "scrutiny_officer", "specialist_reviewer")
    d = db.one("SELECT * FROM documents WHERE id=?", (doc_id,))
    if not d: raise HTTPException(404, "document not found")
    db.run("UPDATE documents SET doc_type=?, doc_type_conf=1.0 WHERE id=?", (doc_type, doc_id))
    audit.append("document_type_corrected", a.name, a.role, d["application_id"], doc_id, refs={"original": d["doc_type"], "corrected": doc_type, "reason": reason})
    return {"ok": True, "original": d["doc_type"], "corrected": doc_type}

@app.get("/api/v1/documents/{doc_id}/fields")
def get_fields(doc_id: str, a: Actor = Depends(actor)):
    rows = db.many("SELECT * FROM fields WHERE document_id=? ORDER BY page, name", (doc_id,))
    for r in rows:
        r["bbox"] = db.jl(r["bbox"])
        if r["name"] in ("registration_number", "certificate_number") and a.role not in OFFICER: r["raw_value"] = mask(r["raw_value"])
    return rows

@app.get("/api/v1/documents/{doc_id}/file")
def get_file(doc_id: str, a: Actor = Depends(actor)):
    d = db.one("SELECT * FROM documents WHERE id=?", (doc_id,))
    if not d: raise HTTPException(404, "document not found")
    audit.append("document_accessed", a.name, a.role, d["application_id"], doc_id)
    return FileResponse(d["path"], media_type=d["mime"], filename=d["filename"])

@app.get("/api/v1/documents/{doc_id}/page/{page}.png")
def render_page(doc_id: str, page: int, boxes: bool = True, dpi: int = 110, a: Actor = Depends(actor)):
    """Original page rendering with OCR/field boxes drawn as a derived visualisation (source file untouched)."""
    d = db.one("SELECT * FROM documents WHERE id=?", (doc_id,))
    if not d or not d["path"].lower().endswith(".pdf"): raise HTTPException(404, "no PDF page")
    pdf = pymupdf.open(d["path"])
    if not 1 <= page <= pdf.page_count: raise HTTPException(404, "page out of range")
    pg = pdf[page - 1]
    if boxes:
        for f in db.many("SELECT name,bbox FROM fields WHERE document_id=? AND page=?", (doc_id, page)):
            bb = db.jl(f["bbox"])
            if bb:
                W, H = pg.rect.width, pg.rect.height
                pg.draw_rect(pymupdf.Rect(bb[0] * W, bb[1] * H, bb[2] * W, bb[3] * H), color=(0.1, 0.4, 0.9), width=1)
    return Response(pg.get_pixmap(dpi=dpi).tobytes("png"), media_type="image/png", headers={"X-Derived-From-Sha256": d["sha256"]})

@app.get("/api/v1/artifacts/{name}")
def derived_artifact(name: str, a: Actor = Depends(actor)):
    p = (DERIVED_DIR / Path(name).name)
    if not p.exists(): raise HTTPException(404, "artifact not found")
    return FileResponse(p, media_type="image/png")

# ------------------------------------------------------------------ evaluation runs
@app.post("/api/v1/applications/{app_id}/presubmission-check")
def presubmission(app_id: str, a: Actor = Depends(actor)):
    """Advisory check for the applicant: creates no official record and no deficiency."""
    app_or_404(app_id)
    out = supervisor.run_case(app_id, "presubmission", a.name, a.role)
    return {"summary": out["summary"], "findings": [{k: v for k, v in f.items() if k not in ("inputs", "outputs")} for f in out["findings"] if f["visibility"] == "applicant"],
            "notice": "Advisory only. Forensic and integrity indicators are visible to officers and reviewers only."}

@app.post("/api/v1/applications/{app_id}/evaluate-rules")
def evaluate_rules(app_id: str, run_ela: bool = False, a: Actor = Depends(actor)):
    need(a, "scrutiny_officer", "specialist_reviewer", "regulatory_expert")
    app_or_404(app_id)
    return supervisor.run_case(app_id, "full", a.name, a.role, run_ela=run_ela)["summary"]

def _snapshot(app_id, kind):
    r = db.one("SELECT * FROM snapshots WHERE application_id=? AND kind=? ORDER BY created_at DESC, rowid DESC LIMIT 1", (app_id, kind))
    return (r["id"], db.jl(r["data"])) if r else (None, None)

@app.post("/api/v1/applications/{app_id}/submit")
def submit(app_id: str, a: Actor = Depends(actor)):
    ap = app_or_404(app_id)
    if ap["status"] not in ("draft", "deficiency_notice_issued"): raise HTTPException(409, f"cannot submit from status '{ap['status']}'")
    pre_id, pre = _snapshot(app_id, "presubmission")
    db.run("UPDATE applications SET status='submitted', submitted_at=? WHERE id=?", (audit.now(), app_id))
    audit.append("final_submission", a.name, a.role, app_id, refs={"last_presubmission_snapshot": pre_id})
    out = supervisor.run_case(app_id, "full", a.name, a.role)
    diff = compute_diff(app_id, pre)
    final_snap = {"documents": diff["final_documents"], "fields": diff["final_fields"]}
    db.run("INSERT INTO snapshots VALUES(?,?,?,?,?)", ("SNAP-" + uuid.uuid4().hex[:8].upper(), app_id, "final", audit.now(), db.jd(final_snap)))
    if diff["has_changes"] and pre:
        alerts.raise_alert(app_id, "final_submission_differs_from_presubmission",
                           f"Final submission differs from last clean pre-submission state ({len(diff['added'])} added, {len(diff['removed'])} removed, {len(diff['replaced'])} replaced, {len(diff['changed_fields'])} field changes). A change alone is not proof of tampering.",
                           "diff", "medium", None, ("scrutiny_officer",))
    return {"status": "submitted", "summary": out["summary"], "diff": {k: v for k, v in diff.items() if not k.startswith("final_")}}

def compute_diff(app_id, pre):
    docs = supervisor.current_docs(app_id)
    final_docs = [{"id": d["id"], "group_id": d["group_id"], "type": d["doc_type"], "sha256": d["sha256"], "filename": d["filename"], "version": d["version"]} for d in docs]
    final_fields = {d["id"]: {f["name"]: (f["corrected_value"] or f["raw_value"]) for f in supervisor.doc_fields(d["id"])} for d in docs}
    if not pre:
        return {"baseline": None, "added": [], "removed": [], "replaced": [], "unchanged": [], "changed_fields": [], "has_changes": False,
                "note": "No pre-submission baseline exists.", "final_documents": final_docs, "final_fields": final_fields}
    pre_g = {d["group_id"]: d for d in pre["documents"]}; fin_g = {d["group_id"]: d for d in final_docs}
    added = [d for g, d in fin_g.items() if g not in pre_g]
    removed = [d for g, d in pre_g.items() if g not in fin_g]
    replaced = [{"before": pre_g[g], "after": d} for g, d in fin_g.items() if g in pre_g and pre_g[g]["sha256"] != d["sha256"]]
    unchanged = [d for g, d in fin_g.items() if g in pre_g and pre_g[g]["sha256"] == d["sha256"]]
    changed = []
    for g, d in fin_g.items():
        if g in pre_g:
            before, after = pre["fields"].get(pre_g[g]["id"], {}), final_fields.get(d["id"], {})
            for k in sorted(set(before) | set(after)):
                if before.get(k) != after.get(k): changed.append({"document": d["filename"], "field": k, "before": before.get(k), "after": after.get(k)})
    return {"baseline": pre["summary"]["snapshot_id"], "added": added, "removed": removed, "replaced": replaced, "unchanged": unchanged,
            "changed_fields": changed, "has_changes": bool(added or removed or replaced or changed),
            "note": "Changes are shown for review. A change alone is not proof of tampering.", "final_documents": final_docs, "final_fields": final_fields}

@app.get("/api/v1/applications/{app_id}/diff")
def get_diff(app_id: str, a: Actor = Depends(actor)):
    need(a, *OFFICER)
    _, pre = _snapshot(app_id, "presubmission")
    d = compute_diff(app_id, pre)
    return {k: v for k, v in d.items() if not k.startswith("final_")}

# ------------------------------------------------------------------ findings & review
def _finding_out(r, a: Actor):
    f = db.jl(r["data"]); f["review"] = db.jl(r["review"]); f["active"] = bool(r["active"])
    if a.role == "applicant":
        if r["visibility"] != "applicant": return None
        f.pop("outputs", None); f.pop("inputs", None)
    f["message"] = mask_text(f["message"])
    return f

@app.get("/api/v1/applications/{app_id}/findings")
def list_findings(app_id: str, status: Optional[str] = None, queue: Optional[str] = None, include_inactive: bool = False, a: Actor = Depends(actor)):
    app_or_404(app_id)
    where, args = ["application_id=?"], [app_id]
    if not include_inactive: where.append("active=1")
    if status: where.append("status=?"); args.append(status)
    if queue: where.append("queue=?"); args.append(queue)
    rows = db.many(f"SELECT * FROM findings WHERE {' AND '.join(where)} ORDER BY created_at", args)
    out = [x for x in (_finding_out(r, a) for r in rows) if x]
    return {"total": len(out), "items": out}

def _get_finding(fid):
    r = db.one("SELECT * FROM findings WHERE id=?", (fid,))
    if not r: raise HTTPException(404, "finding not found")
    return r

@app.get("/api/v1/findings/{fid}")
def get_finding(fid: str, a: Actor = Depends(actor)):
    r = _get_finding(fid); f = _finding_out(r, a)
    if f is None: raise HTTPException(403, "finding not visible to this role")
    return f

@app.get("/api/v1/applications/{app_id}/proof-cards")
def proof_cards(app_id: str, a: Actor = Depends(actor)):
    """Document-wise Proof Cards + overall roll-up. Role-filtered exactly like /findings (applicants see only applicant-visible findings)."""
    app_or_404(app_id)
    rows = db.many("SELECT * FROM findings WHERE application_id=? AND active=1 ORDER BY created_at", (app_id,))
    fs = [x for x in (_finding_out(r, a) for r in rows) if x]
    out = proofcards.build(app_id, supervisor.current_docs(app_id), fs)
    if a.role == "applicant":
        for c in out["cards"]: c.pop("source_provenance", None); c.pop("source_name", None)
    return out

@app.get("/api/v1/findings/{fid}/explain")
def explain_finding(fid: str, a: Actor = Depends(actor)):
    """Plain-language wording of a validated finding. Never changes the finding; the provider is always reported."""
    r = _get_finding(fid); f = _finding_out(r, a)
    if f is None: raise HTTPException(403, "finding not visible to this role")
    out = explain_mod.explain(f)
    audit.append("explanation_generated", a.name, a.role, r["application_id"], refs={"finding_id": fid, "provider": out["provider"]})
    return {"finding_id": fid, "status": f["status"], **out}

@app.get("/api/v1/findings/{fid}/passport")
def get_passport(fid: str, a: Actor = Depends(actor)):
    need(a, *OFFICER)
    r = _get_finding(fid); f = _finding_out(r, a); ap = supervisor.get_app(r["application_id"])
    audit.append("passport_viewed", a.name, a.role, r["application_id"], refs={"finding_id": fid})
    return build_passport(f, ap, {})

QUEUE_ROLES = {"document_integrity_reviewer": {"specialist_reviewer", "scrutiny_officer"}, "infrastructure_reviewer": {"specialist_reviewer", "scrutiny_officer"},
               "legal_document_reviewer": {"specialist_reviewer", "scrutiny_officer"}, "regulatory_expert": {"regulatory_expert"},
               "manual_source_confirmation": {"scrutiny_officer", "specialist_reviewer"}, "scrutiny_officer": {"scrutiny_officer", "specialist_reviewer"}}
ACTIONS = {"confirm", "dismiss", "request_clarification", "escalate", "correct_field", "mark_source_pending", "mark_source_completed"}

@app.post("/api/v1/findings/{fid}/review")
def review_finding(fid: str, body: ReviewIn, a: Actor = Depends(actor)):
    need(a, "scrutiny_officer", "specialist_reviewer", "regulatory_expert")
    if body.action not in ACTIONS: raise HTTPException(422, f"action must be one of {sorted(ACTIONS)}")
    r = _get_finding(fid); f = db.jl(r["data"]); app_id = r["application_id"]
    if body.action in ("dismiss", "escalate", "request_clarification") and not body.reason.strip():
        raise HTTPException(422, "a reason is required for this action")
    extra = {}
    if body.action == "correct_field":
        if not body.field_id or body.new_value is None: raise HTTPException(422, "field_id and new_value required")
        fld = db.one("SELECT * FROM fields WHERE id=?", (body.field_id,))
        if not fld: raise HTTPException(404, "field not found")
        db.run("UPDATE fields SET corrected_value=?, corrected_by=?, corrected_at=? WHERE id=?", (body.new_value, a.name, audit.now(), body.field_id))
        audit.append("field_corrected", a.name, a.role, app_id, fld["document_id"], refs={"field_id": body.field_id, "field": fld["name"],
                     "original_value": fld["raw_value"], "corrected_value": body.new_value, "note": "Original value preserved"})
        # targeted re-check: only rules touching that field's document type
        doc = db.one("SELECT doc_type FROM documents WHERE id=?", (fld["document_id"],))
        ap = supervisor.get_app(app_id)
        ids = {rl["rule_id"] for p in rulepacks.active_packs(ap["category"]) for rl in p["rules"]
               if doc["doc_type"] in __import__("app.rules.engine", fromlist=["x"]).rule_input_doc_types(rl) or rl["check"]["type"] in ("date_irregularities", "cross_doc_match", "record_match")}
        res = supervisor.run_case(app_id, "targeted", a.name, a.role, only_rules=ids)
        extra = {"targeted_recheck": {"rules_rerun": len(ids), "by_status": res["summary"]["by_status"]}}
    rv = {"outcome": body.action, "reason": body.reason, "by": a.name, "role": a.role, "at": audit.now(), "original_status": f["status"]}
    if body.escalate_to: rv["escalate_to"] = body.escalate_to
    r2 = db.one("SELECT review FROM findings WHERE id=?", (fid,))
    hist = (db.jl(r2["review"], {}) or {}).get("history", [])
    rv["history"] = hist + [{k: rv[k] for k in ("outcome", "reason", "by", "at")}]
    db.run("UPDATE findings SET review=?, updated_at=? WHERE id=?", (db.jd(rv), audit.now(), fid))
    audit.append("finding_reviewed", a.name, a.role, app_id, refs={"finding_id": fid, "action": body.action, "reason": body.reason}, rule_pack_version=f.get("pack_version"))
    if body.action in ("confirm", "dismiss", "escalate", "request_clarification", "mark_source_completed", "correct_field"):
        for g in db.many("SELECT id FROM gates WHERE finding_id=? AND status='open'", (fid,)):
            db.run("UPDATE gates SET status='resolved', resolved_at=?, resolved_by=?, outcome=? WHERE id=?", (audit.now(), a.name, body.action, g["id"]))
            audit.append("gate_resolved", a.name, a.role, app_id, refs={"gate_id": g["id"], "outcome": body.action})
    if not db.one("SELECT 1 x FROM gates WHERE application_id=? AND status='open'", (app_id,)):
        db.run("UPDATE applications SET status='under_scrutiny' WHERE id=? AND status='awaiting_review'", (app_id,))
    return {"ok": True, "review": rv, **extra}

@app.get("/api/v1/findings")
def global_findings(family: Optional[str] = None, status: Optional[str] = None, queue: Optional[str] = None, limit: int = 200, a: Actor = Depends(actor)):
    """Cross-case review queues for officers and reviewers."""
    need(a, *OFFICER)
    where, args = ["f.active=1"], []
    if family: where.append("json_extract(f.data,'$.family')=?"); args.append(family)
    if status: where.append("f.status=?"); args.append(status)
    if queue: where.append("f.queue=?"); args.append(queue)
    rows = db.many(f"SELECT f.*, a.institution_name, a.category, a.is_demo FROM findings f JOIN applications a ON a.id=f.application_id WHERE {' AND '.join(where)} ORDER BY f.updated_at DESC LIMIT ?", args + [limit])
    out = []
    for r in rows:
        f = _finding_out(r, a)
        if f: f.update(institution_name=r["institution_name"], category=r["category"], is_demo=bool(r["is_demo"])); out.append(f)
    return {"total": len(out), "items": out}

@app.get("/api/v1/source-checks")
def global_source_checks(a: Actor = Depends(actor)):
    need(a, *OFFICER)
    rows = db.many("SELECT s.*, d.filename, a.institution_name, a.is_demo FROM source_checks s JOIN documents d ON d.id=s.document_id JOIN applications a ON a.id=s.application_id ORDER BY s.created_at DESC")
    return [{**db.jl(r["data"]), "id": r["id"], "application_id": r["application_id"], "filename": r["filename"], "institution_name": r["institution_name"], "is_demo": bool(r["is_demo"])} for r in rows]

@app.get("/api/v1/notices")
def global_notices(a: Actor = Depends(actor)):
    need(a, *OFFICER)
    rows = db.many("SELECT n.*, a.institution_name FROM notices n JOIN applications a ON a.id=n.application_id ORDER BY n.created_at DESC")
    for r in rows: r["body"] = db.jl(r["body"])
    return rows

@app.get("/api/v1/gates")
def list_gates(status: str = "open", a: Actor = Depends(actor)):
    need(a, *OFFICER)
    return db.many("SELECT * FROM gates WHERE status=? ORDER BY opened_at DESC", (status,))

# ------------------------------------------------------------------ source checks
@app.get("/api/v1/applications/{app_id}/source-checks")
def source_checks(app_id: str, a: Actor = Depends(actor)):
    need(a, *OFFICER)
    rows = db.many("SELECT * FROM source_checks WHERE application_id=?", (app_id,))
    return [{**db.jl(r["data"]), "id": r["id"]} for r in rows]

@app.post("/api/v1/applications/{app_id}/source-checks/{doc_id}/retry")
def retry_source(app_id: str, doc_id: str, a: Actor = Depends(actor)):
    need(a, *OFFICER)
    ap = app_or_404(app_id); d = next((x for x in supervisor.current_docs(app_id) if x["id"] == doc_id), None)
    if not d: raise HTTPException(404, "document not found")
    res = supervisor.source_check_doc(ap, d)
    audit.append("source_check_retried", a.name, a.role, app_id, doc_id, refs={"status": res["status"], "provenance": res["provenance"]})
    return res

@app.get("/api/v1/integrations/health")
def integrations_health(a: Actor = Depends(actor)):
    reg = source_checker.adapter_registry()
    inst = source_checker.FIXTURES["institutions"]
    return {"adapters": reg, "aicte_record_adapter": {"provenance": "synthetic", "label": source_checker.FIXTURES["_label"],
            "simulated_states": {i["aicte_id"]: i["adapter_state"] for i in inst}},
            "claims": "No access to AICTE, DigiLocker, MCA21, EPFO, bank or state systems is claimed. Only the local signature validator is live."}

# ------------------------------------------------------------------ infrastructure
@app.put("/api/v1/applications/{app_id}/infrastructure")
def set_infra(app_id: str, body: InfraIn, a: Actor = Depends(actor)):
    need(a, "scrutiny_officer", "specialist_reviewer")
    app_or_404(app_id)
    db.run("INSERT OR REPLACE INTO infra_inputs VALUES(?,?,?,?,?)", ("INF-" + app_id, app_id, db.jd(body.dict(exclude_none=True)), audit.now(), a.name))
    audit.append("infrastructure_inputs_set", a.name, a.role, app_id, refs=body.dict(exclude_none=True))
    return {"ok": True}

@app.post("/api/v1/infrastructure/geometry")
def geometry_preview(doc_id: str, page: int = 1, meters_per_pt: Optional[float] = None, declared_area_sqm: Optional[float] = None, a: Actor = Depends(actor)):
    from . import infra
    need(a, "scrutiny_officer", "specialist_reviewer")
    d = db.one("SELECT * FROM documents WHERE id=?", (doc_id,))
    if not d: raise HTTPException(404, "document not found")
    return infra.analyze_floorplan(d["path"], page, {"meters_per_pt": meters_per_pt} if meters_per_pt else None, declared_area_sqm, doc_id=doc_id)

# ------------------------------------------------------------------ deficiency notices (human gate: official communication)
@app.post("/api/v1/applications/{app_id}/deficiency-draft")
def deficiency_draft(app_id: str, a: Actor = Depends(actor)):
    need(a, "scrutiny_officer")
    ap = app_or_404(app_id)
    rows = db.many("SELECT * FROM findings WHERE application_id=? AND active=1 AND status='deficiency'", (app_id,))
    items = []
    for r in rows:
        f = db.jl(r["data"]); rv = db.jl(r["review"], {}) or {}
        if rv.get("outcome") == "dismiss": continue
        items.append({"finding_id": f["id"], "clause": f.get("aph_clause"), "clause_confirmed": f.get("clause_confirmed"), "issue": f["message"],
                      "evidence": [{"file": e.get("filename"), "page": e.get("page")} for e in f["evidence"]], "officer_confirmed": rv.get("outcome") == "confirm"})
    if not items: raise HTTPException(409, "no deficiency findings to cite - a notice cannot be drafted without evidence-linked findings")
    ver = (db.one("SELECT MAX(version) v FROM notices WHERE application_id=?", (app_id,))["v"] or 0) + 1
    nid = "NOT-" + uuid.uuid4().hex[:6].upper()
    body = {"institution": ap["institution_name"], "category": ap["category"], "deficiencies": items,
            "draft_notice": "DRAFT - NOT ISSUED. The following items were identified during scrutiny and cite the clauses shown (clause references are to be confirmed against the current authorised APH before issue).",
            "response_requirement": "Applicant to respond by the due date set by the authorised officer."}
    db.run("INSERT INTO notices VALUES(?,?,?,?,?,?,?,?,?,?)", (nid, app_id, ver, "draft", db.jd(body), a.name, None, audit.now(), None, None))
    audit.append("deficiency_draft_created", a.name, a.role, app_id, refs={"notice_id": nid, "version": ver, "items": len(items)})
    g = "G-" + uuid.uuid4().hex[:8].upper()
    db.run("INSERT INTO gates VALUES(?,?,?,?,?,?,?,?,?,?)", (g, app_id, "official_communication", None, "open", audit.now(), None, None, None, db.jd({"notice_id": nid})))
    return {"id": nid, "version": ver, "status": "draft", **body}

@app.get("/api/v1/applications/{app_id}/notices")
def list_notices(app_id: str, a: Actor = Depends(actor)):
    rows = db.many("SELECT * FROM notices WHERE application_id=? ORDER BY version", (app_id,))
    for r in rows: r["body"] = db.jl(r["body"])
    if a.role == "applicant": rows = [r for r in rows if r["status"] == "issued"]
    return rows

class ApproveIn(BaseModel):
    due_date: str
    edited_note: str = ""

@app.post("/api/v1/notices/{nid}/approve")
def approve_notice(nid: str, body: ApproveIn, a: Actor = Depends(actor)):
    need(a, "scrutiny_officer")
    n = db.one("SELECT * FROM notices WHERE id=?", (nid,))
    if not n or n["status"] != "draft": raise HTTPException(409, "notice is not a draft")
    b = db.jl(n["body"]); b["edited_note"] = body.edited_note
    db.run("UPDATE notices SET status='issued', approved_by=?, approved_at=?, due_date=?, body=? WHERE id=?", (a.name, audit.now(), body.due_date, db.jd(b), nid))
    db.run("UPDATE applications SET status='deficiency_notice_issued' WHERE id=?", (n["application_id"],))
    for g in db.many("SELECT id FROM gates WHERE application_id=? AND gate_type='official_communication' AND status='open'", (n["application_id"],)):
        db.run("UPDATE gates SET status='resolved', resolved_at=?, resolved_by=?, outcome='notice_approved' WHERE id=?", (audit.now(), a.name, g["id"]))
    audit.append("deficiency_notice_approved", a.name, a.role, n["application_id"], refs={"notice_id": nid, "due_date": body.due_date})
    return {"ok": True, "status": "issued"}

@app.post("/api/v1/applications/{app_id}/decision")
def decision(app_id: str, body: DecisionIn, a: Actor = Depends(actor)):
    """Final regulatory decision: human-only (Tier C). The system never calls this itself."""
    if a.role not in ("competent_authority", "administrator"): raise HTTPException(403, "only a competent AICTE authority can record a final decision")
    app_or_404(app_id)
    if not body.rationale.strip(): raise HTTPException(422, "rationale is required")
    if db.one("SELECT 1 x FROM gates WHERE application_id=? AND status='open' AND gate_type!='final_decision'", (app_id,)):
        raise HTTPException(409, "open human gates must be resolved before a final decision is recorded")
    did = "DEC-" + uuid.uuid4().hex[:6].upper()
    db.run("INSERT INTO decisions VALUES(?,?,?,?,?,?)", (did, app_id, body.decision, body.rationale, a.name, audit.now()))
    db.run("UPDATE applications SET status='decided' WHERE id=?", (app_id,))
    audit.append("final_decision_recorded", a.name, a.role, app_id, refs={"decision_id": did, "decision": body.decision, "rationale": body.rationale})
    return {"id": did, "recorded": True}

# ------------------------------------------------------------------ audit, alerts, packs, dashboard
@app.get("/api/v1/applications/{app_id}/audit")
def app_audit(app_id: str, a: Actor = Depends(actor)):
    need(a, *OFFICER); return audit.list_events(app_id)

@app.get("/api/v1/audit")
def all_audit(limit: int = 300, a: Actor = Depends(actor)):
    need(a, *OFFICER); return audit.list_events(None, limit)

@app.get("/api/v1/audit/verify")
def verify_audit(a: Actor = Depends(actor)):
    return audit.verify_chain()

@app.get("/api/v1/alerts")
def get_alerts(application_id: Optional[str] = None, acked: Optional[bool] = None, a: Actor = Depends(actor)):
    rows = db.many("SELECT * FROM alerts ORDER BY event_at DESC LIMIT 300")
    out = []
    for r in rows:
        if application_id and r["application_id"] != application_id: continue
        if acked is not None and bool(r["acked_at"]) != acked: continue
        if a.role == "applicant" and "applicant" not in r["role_target"].split(","): continue
        r["channels"] = db.jl(r["channels"], []); out.append(r)
    return out

@app.post("/api/v1/alerts/{aid}/ack")
def ack_alert(aid: str, a: Actor = Depends(actor)):
    alerts.ack(aid, a.name, a.role); return {"ok": True}

@app.post("/api/v1/alerts/escalate")
def escalate(hours: float = 24, a: Actor = Depends(actor)):
    need(a, *OFFICER); return {"escalated": alerts.escalate_overdue(hours)}

@app.get("/api/v1/rulepacks")
def get_packs(a: Actor = Depends(actor)):
    return rulepacks.list_packs()

@app.get("/api/v1/rulepacks/{pid:path}")
def get_pack(pid: str, a: Actor = Depends(actor)):
    p = rulepacks.get_pack(pid)
    if not p: raise HTTPException(404, "pack not found")
    return p

@app.post("/api/v1/rulepacks")
def create_pack(body: PackIn, a: Actor = Depends(actor)):
    need(a, "rule_author", "regulatory_expert")
    try: pid, tr = rulepacks.create_draft(body.pack, a.name, body.changelog)
    except ValueError as e: raise HTTPException(422, str(e))
    return {"id": pid, "status": "draft", "tests": {k: tr[k] for k in ("total", "passed", "failed")}, "results": tr["results"]}

@app.post("/api/v1/rulepack-activate/{pid:path}")
def activate_pack(pid: str, a: Actor = Depends(actor)):
    need(a, "regulatory_expert")
    try: rulepacks.activate(pid, a.name)
    except LookupError: raise HTTPException(404, "pack not found")
    except PermissionError as e: raise HTTPException(403, str(e))
    except ValueError as e: raise HTTPException(409, str(e))
    return {"ok": True, "status": "active"}

@app.get("/api/v1/dashboard/summary")
def dashboard(a: Actor = Depends(actor)):
    need(a, *OFFICER)
    q = lambda s, *x: db.one(s, x)["n"] or 0
    by_cat = db.many("SELECT category, COUNT(*) n FROM applications GROUP BY category")
    by_status = db.many("SELECT status, COUNT(*) n FROM applications GROUP BY status")
    queues = db.many("SELECT queue, COUNT(*) n FROM findings WHERE active=1 AND status IN ('needs_review','deficiency','indicator') GROUP BY queue")
    pend = db.many("SELECT data FROM source_checks")
    pending = sum(1 for p in pend if db.jl(p["data"])["status"] in ("verification_pending", "source_unavailable", "manual_review_required"))
    totals = {k: 0 for k in proofcards.CARD_STATUSES}
    for ap in db.many("SELECT id FROM applications ORDER BY created_at DESC LIMIT 200"):
        rows = db.many("SELECT * FROM findings WHERE application_id=? AND active=1", (ap["id"],))
        fs = [x for x in (_finding_out(r, a) for r in rows) if x]
        for k, v in proofcards.build(ap["id"], supervisor.current_docs(ap["id"]), fs)["counts"].items(): totals[k] += v
    return {"label": "All figures computed from the live database (demo data is labelled per application).", "proof_totals": totals,
            "applications": q("SELECT COUNT(*) n FROM applications"), "by_category": by_cat, "by_status": by_status,
            "pending_officer_actions": q("SELECT COUNT(*) n FROM findings WHERE active=1 AND status IN ('needs_review','deficiency') AND review IS NULL"),
            "open_gates": q("SELECT COUNT(*) n FROM gates WHERE status='open'"), "unresolved_source_checks": pending,
            "deficiencies_awaiting_response": q("SELECT COUNT(*) n FROM applications WHERE status='deficiency_notice_issued'"),
            "unacknowledged_alerts": q("SELECT COUNT(*) n FROM alerts WHERE acked_at IS NULL"), "review_queues": queues,
            "alert_timeliness": alerts.timeliness(), "audit_chain": audit.verify_chain()}

SYSTEM_STATUS = [
    ("Document-wise Proof Cards and case roll-up (verified only when the source confirmed)", "implemented"),
    ("Upload, SHA-256, immutable originals, versioning", "implemented"), ("PDF text-layer extraction with page coordinates", "implemented"),
    ("OCR for scanned pages", "implemented (requires Tesseract installed; otherwise reported as a processing status)"),
    ("Document classification (keyword, 'unknown' allowed)", "implemented"), ("Executable Handbook: versioned rule packs, tests, maker-checker", "implemented"),
    ("Irregular-date rules incl. day/month ambiguity", "implemented"), ("Cross-document and record reconciliation", "implemented"),
    ("No-evidence-no-flag finding validator", "implemented"), ("Verification Passport", "implemented"),
    ("Hash-chained audit ledger", "implemented"), ("Pre-submission check, targeted re-check, pre/final diff", "implemented"),
    ("PDF signature validation", "implemented (pyHanko; no trust roots configured, so 'untrusted' is the best result)"),
    ("PDF metadata / xref analysis, exact + near duplicate", "implemented"), ("ELA image-region indicator", "implemented (optional, heuristic)"),
    ("Floor-plan geometry with calibration", "implemented (vector PDFs; raster plans need manual marking)"),
    ("GPS/EXIF, capture date, evidence quality, reused-image checks", "implemented"),
    ("AICTE record adapter", "mocked (synthetic fixture, labelled)"), ("Issuer / QR / bank / professional-registry verification", "designed (manual-confirmation tasks created)"),
    ("Vision-model facility recognition in photos", "designed (not implemented)"), ("Video key-frame / GPS-track continuity", "designed (not implemented)"),
    ("Rule Compiler (handbook -> candidate rules)", "designed (not implemented; drafts are authored manually via API)"),
    ("Email / SMS delivery", "mocked (gateway simulated)"), ("LLM plain-language explanations", "implemented (optional, off by default; deterministic template otherwise; verdicts never come from the model)"),
    ("SSO / token authentication", "mocked (header-mapped roles in prototype)"),
]

@app.post("/api/v1/demo/seed")
def demo_seed(a: Actor = Depends(actor)):
    from . import demo
    need(a, "scrutiny_officer", "administrator", "applicant")
    out = demo.seed_demo(a.name if a.role == "applicant" else "applicant.demo")
    audit.append("demo_dataset_seeded", a.name, a.role, refs={"applications": out["application_ids"], "label": "synthetic"})
    return out

@app.get("/api/v1/system/status")
def system_status():
    return {"tool_version": TOOL_VERSION, "policy": "Planned features are never presented as implemented.",
            "capabilities": [{"capability": c, "status": s} for c, s in SYSTEM_STATUS]}

@app.get("/api/v1/applications/{app_id}/report")
def report(app_id: str, a: Actor = Depends(actor)):
    """Exported report separating rule results, unresolved items and advisory indicators."""
    need(a, *OFFICER)
    ap = app_or_404(app_id)
    fs = [x for x in (_finding_out(r, a) for r in db.many("SELECT * FROM findings WHERE application_id=? AND active=1", (app_id,))) if x]
    rule_results = [f for f in fs if f["family"] in ("completeness", "validity", "consistency", "record", "quantitative") and f["status"] in ("pass", "deficiency")]
    unresolved = [f for f in fs if f["status"] in ("needs_review", "not_checked", "processing") and f["family"] not in ("integrity", "infrastructure")]
    advisory = [f for f in fs if f["family"] in ("integrity", "infrastructure") and f["status"] != "pass"]
    audit.append("report_exported", a.name, a.role, app_id)
    return {"application": {k: ap[k] for k in ("id", "institution_name", "category", "status", "is_demo")}, "generated_at": audit.now(),
            "demo_data_label": "DEMO DATA - synthetic dossier" if ap["is_demo"] else None,
            "rule_results": rule_results, "unresolved_items": unresolved, "advisory_indicators": advisory,
            "notice": "Decision support only. Indicators are not proof. Final decisions rest with the competent authority.",
            "audit_chain": audit.verify_chain()}
