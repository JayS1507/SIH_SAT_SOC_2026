# SIH Slide: Feasibility, Risks & Mitigation

## Why SOC-Inspect is Feasible

- **Offline-first:** Operates in air-gapped environments without live telemetry or external cloud APIs.
- **Evidence-compatible:** Accepts periodic JSON, CSV, XLSX, and restricted plain-text PostgreSQL exports.
- **Explainable by design:** Every finding includes source evidence, calculation, rule version, confidence, and limitations.
- **Human-supervised:** Prioritizes entities and cases for review; it never replaces supervisory judgement.
- **Scalable architecture:** Starts with a single-machine prototype and scales to PostgreSQL, MinIO, Redis/Celery, and a configured Keycloak deployment.
- **Validated prototype:** 15 backend tests passed; frontend build, migrations, authentication, reports, metrics, and Docker deployment verified.

## Potential Challenges & Risks

- Heterogeneous schemas and inconsistent SOC submissions.
- Missing or inaccurate evidence may create misleading findings.
- False positives and false negatives in supervisory analysis.
- Sensitive alert, case, asset, and investigation data.
- Limited labelled real-world SOC datasets.
- Bias when comparing entities with different sectors, sizes, and SOC models.
- Resistance if the platform is perceived as an automated compliance judge.

## Mitigation Strategies

- **Versioned adapters + canonical evidence model** for consistent normalization.
- **Evidence-sufficiency classification** separating poor performance, missing evidence, and insufficient data.
- **Human-in-the-loop review** with supervisor acceptance, rejection, and annotation.
- **Evidence-linked explainability** with source rows, calculations, confidence, and limitations.
- **Air-gapped deployment, RBAC, encryption, audit logs, and integrity-evident artifacts** for privacy.
- **Synthetic labelled datasets + domain-expert validation** before real deployment.
- **Context-aware peer groups** using sector, entity size, asset count, and alert volume.
- **Pilot-first rollout** with one or two critical-sector entities before scaling.

## Pilot Value

> **Faster identification of high-risk entities and cases • Consistent supervisory review • Reduced manual sampling effort • Reproducible audit-ready reports • No access to live SOC telemetry required**

## Strong Closing Statement

> **SOC-Inspect is feasible to pilot because it uses periodic evidence, proven open technologies, explainable analytics, and offline deployment. Its risks are measurable and controlled through validation, privacy safeguards, contextual benchmarking, and human supervisory review.**

## Recommended Visual Layout

```text
┌────────────────────────────────────────────────────────────┐
│          FEASIBILITY, RISKS & MITIGATION                   │
│  Evidence-based | Offline-first | Human-supervised         │
├───────────────┬──────────────────┬─────────────────────────┤
│ WHY FEASIBLE  │ CHALLENGES/RISKS │ MITIGATION STRATEGIES    │
│ ✓ Offline     │ ! Data variation │ → Adapters + model      │
│ ✓ Explainable │ ! Missing data   │ → Sufficiency scoring   │
│ ✓ Scalable    │ ! False alerts   │ → Human review          │
│ ✓ Validated   │ ! Privacy        │ → RBAC + encryption     │
│               │ ! Adoption       │ → Pilot-first rollout   │
├────────────────────────────────────────────────────────────┤
│ PILOT VALUE: Faster review • Audit-ready • Privacy-safe     │
└────────────────────────────────────────────────────────────┘
```

## Design Recommendations

- Use three colors only:
  - Blue for feasibility.
  - Orange for risks.
  - Green for mitigation.
- Use icons instead of long paragraphs.
- Keep each column to 5–7 short bullets.
- Highlight **Offline-first**, **Explainable**, **Human-in-the-loop**, and **Pilot-ready**.
- Put “15 backend tests passed” in a small proof badge.
- Do not list every technology on this slide; keep detailed technologies on the architecture slide.

## 30-Second Judge Explanation

> “Our solution is feasible because it does not require live SOC telemetry or cloud access. It analyses periodic evidence using a canonical model and deterministic, explainable rules. The major risks are inconsistent data, missing evidence, false findings, privacy, and adoption. We address these through versioned adapters, evidence-sufficiency scoring, human review, RBAC, immutable audit trails, synthetic validation data, and context-aware peer groups. We can pilot it with one critical-sector entity today and scale later to PostgreSQL, MinIO, Redis, and Keycloak.”
