# SIH Slide: Research & References

## Research Basis

SOC-Inspect is grounded in established cybersecurity, incident-response, log-management, security-control, privacy, and human-supervision practices. The project combines these references into a focused supervisory evidence-analysis layer rather than presenting itself as a replacement for a SIEM, SOAR, SOC, or regulatory framework.

### Research questions

1. How can a supervisor compare declared SOC capability with operational evidence?
2. How can alerts, cases, investigations, escalations, responses, and closures be assessed as one lifecycle?
3. How can missing evidence be distinguished from poor performance?
4. How can review be prioritized across entities without exposing unnecessary sensitive information?
5. How can every automated finding remain explainable, reproducible, and human-verifiable?
6. How can sensitive evidence be processed in an offline or air-gapped environment?

### Research-to-design conclusions

| Research observation | SOC-Inspect design response |
|---|---|
| Cybersecurity assessment needs governance and risk context | Entity, capability, peer, and supervisory risk indicators |
| Incident records have a lifecycle, not just an alert count | Alert → triage → investigation → escalation → response → closure model |
| Logs and evidence need consistent management | Canonical mapping, source-row lineage, validation, and integrity-evident artifacts |
| Missing data can be misinterpreted | Separate data-quality failure, insufficient evidence, and performance weakness |
| Controls and findings must be auditable | Versioned rules, calculations, confidence, limitations, audit events, and hashes |
| Operational analytics should support—not replace—people | Human-in-the-loop decisions, annotations, and review queue |
| Sensitive cyber data should remain protected | Offline-first processing, RBAC, local storage, and optional private MinIO |

---

## Primary Problem-Statement Reference

### 1. Smart India Hackathon 2026 — SIH26157

**Problem statement:** Supervisory Analytics Tool for SOC Assessment (SAT-SA)  
**Working solution:** SOC-Inspect

The official problem statement establishes the need to:

- Ingest periodic alert, case, investigation, escalation, closure, and asset records.
- Detect execution gaps, negative space, anomalies, and suspicious operational patterns.
- Compare entities using privacy-preserving peer benchmarks.
- Produce explainable findings and review priorities.
- Support human supervisory judgement rather than autonomous decisions.
- Exclude real-time monitoring, SIEM replacement, SOAR replacement, continuous telemetry, and a national centralized SOC.

**Source used for implementation:**  
Official SIH 2026 Problem Statement — **SIH26157**

**How it informed the project:**

- Defined the canonical alert-to-case evidence model.
- Defined the eight capability domains.
- Defined the ingestion, assessment, review, reporting, and audit API surfaces.
- Defined the offline/air-gapped deployment boundary.
- Defined the synthetic-data and validation strategy.

---

## Standards and Technical References

### 2. NIST Cybersecurity Framework 2.0

**Organization:** National Institute of Standards and Technology  
**Publication:** NIST CSWP 29, 2024  
**Official link:**  
https://www.nist.gov/publications/nist-cybersecurity-framework-csf-20

**Relevant concepts:**

- Govern.
- Identify.
- Protect.
- Detect.
- Respond.
- Recover.

**Use in SOC-Inspect:**

- Supports governance and oversight as a capability domain.
- Provides a risk-management vocabulary for supervisory indicators.
- Reinforces the distinction between evidence, risk, and final organizational judgement.

### 3. NIST SP 800-61 Revision 3 — Incident Response Recommendations and Considerations

**Organization:** NIST Computer Security Resource Center  
**Official publication page:**  
https://csrc.nist.gov/publications/detail/sp/800-61/rev-3/final

**Relevant concepts:**

- Incident-response preparation.
- Detection and analysis.
- Response activities.
- Recovery and improvement.

**Use in SOC-Inspect:**

- Supports lifecycle analysis from detection through response and closure.
- Informs workflow-order and missing-response checks.
- Supports the use of post-assessment improvement actions.

**Historical reference:** NIST SP 800-61 Rev. 2 remains useful for legacy research but was superseded by Rev. 3.

### 4. NIST SP 800-92 — Guide to Computer Security Log Management

**Organization:** National Institute of Standards and Technology  
**Official publication page:**  
https://csrc.nist.gov/pubs/sp/800/92/final

**Relevant concepts:**

- Log-management infrastructure.
- Log collection and retention.
- Consistency and usefulness of security records.
- Operational log review.

**Use in SOC-Inspect:**

- Supports periodic evidence ingestion and normalization.
- Supports source-row lineage and data-quality validation.
- Supports the principle that evidence must be reliable before conclusions are drawn.

### 5. NIST SP 800-53 Revision 5 — Security and Privacy Controls

**Organization:** National Institute of Standards and Technology  
**Official publication page:**  
https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final

**Relevant concepts:**

- Security controls.
- Privacy controls.
- Accountability.
- Assessment evidence.
- Risk and control monitoring.

**Use in SOC-Inspect:**

- Supports capability and control-oriented findings.
- Informs auditability, access control, evidence handling, and privacy safeguards.
- Supports configurable control expectations rather than hard-coded organizational judgement.

### 6. MITRE ATT&CK

**Organization:** MITRE  
**Official knowledge base:**  
https://attack.mitre.org/

**Relevant concepts:**

- Adversary tactics.
- Techniques and sub-techniques.
- Detection and coverage language.
- Common cybersecurity vocabulary.

**Use in SOC-Inspect:**

- Provides an optional vocabulary for future alert and capability enrichment.
- Supports future coverage indicators without making ATT&CK mapping the only measure of SOC effectiveness.
- Reinforces that detection coverage alone does not prove investigation or escalation quality.

---

## Indian Regulatory and Governance References

### 7. CERT-In

**Organization:** Indian Computer Emergency Response Team  
**Official portal:**  
https://www.cert-in.org.in/

**Relevance:**

- Indian cybersecurity incident reporting and response context.
- National cyber incident coordination.
- Security guidance and advisories.

**Use in SOC-Inspect:**

- Supports the India-specific operational and regulatory context.
- Provides a reference point for future reporting and sector-specific control mappings.

### 8. Digital Personal Data Protection Act, 2023

**Official India Code portal:**  
https://www.indiacode.nic.in/

**Relevance:**

- Data protection and responsible processing context.
- Governance expectations for sensitive information.

**Use in SOC-Inspect:**

- Supports privacy-preserving, purpose-limited, access-controlled evidence processing.
- Reinforces the need to avoid unnecessary raw sensitive information in logs and reports.

---

## Architecture and Engineering References

### 9. FastAPI

**Official documentation:**  
https://fastapi.tiangolo.com/

**Use:**

- Typed REST APIs.
- OpenAPI documentation.
- Request validation.
- Role-protected service endpoints.

### 10. SQLAlchemy

**Official documentation:**  
https://docs.sqlalchemy.org/

**Use:**

- SQLite offline persistence.
- PostgreSQL-compatible database layer.
- Typed ORM models and migration-ready schema.

### 11. Alembic

**Official documentation:**  
https://alembic.sqlalchemy.org/

**Use:**

- Versioned schema migrations.
- Repeatable upgrade and downgrade process.
- PostgreSQL and SQLite deployment support.

### 12. OpenID Connect / OAuth 2.0

**OpenID Connect specification:**  
https://openid.net/specs/openid-connect-core-1_0.html

**OAuth 2.0 RFC 6749:**  
https://www.rfc-editor.org/rfc/rfc6749

**Use:**

- Standards-based identity and access.
- Keycloak-compatible issuer, audience, and JWKS validation.
- Role-bearing identity claims for supervisory access control.

### 13. Prometheus exposition format

**Official documentation:**  
https://prometheus.io/docs/instrumenting/exposition_formats/

**Use:**

- Request, error, latency, and assessment-stage metrics.
- Monitoring integration without coupling the application to a particular dashboard product.

### 14. Docker Compose

**Official documentation:**  
https://docs.docker.com/compose/

**Use:**

- Reproducible offline demo deployment.
- Optional PostgreSQL, Redis, and MinIO services.
- Separation of frontend and backend containers.

---

## Research Methodology Used

### Phase 1 — Problem analysis

- Extracted mandatory capabilities and exclusions from SIH26157.
- Converted the statement into testable system requirements.

### Phase 2 — Architecture mapping

- Mapped requirements to presentation, API, ingestion, canonical model, analytics, review, reporting, storage, identity, and observability layers.

### Phase 3 — Evidence-first design

- Made source lineage, rule versions, calculations, limitations, and hashes part of the finding model.

### Phase 4 — Prototype implementation

- Built a working offline FastAPI and React/TypeScript prototype.
- Added SQLAlchemy, Alembic, JWT/OIDC, artifacts, task boundaries, metrics, and Docker deployment.

### Phase 5 — Synthetic validation

- Used controlled scenarios such as missing escalation, incomplete evidence, duplicate records, response anomalies, reporting gaps, and coverage gaps.

### Phase 6 — Conformance testing

- Validated ingestion, analytics, reports, authentication, artifacts, SQL safety, migrations, readiness, metrics, frontend build, and Docker configuration.

---

## Validation Evidence

```text
Backend tests:              15 passed
Frontend production build:  passed
Alembic upgrade/downgrade:  passed
Docker Compose profiles:    validated
SQL safety parser:          passed
JWT/RBAC tests:             passed
OIDC claim-role test:       passed
Artifact hash test:         passed
Metrics endpoint:           passed
Readiness endpoint:         passed
```

---

## Reference Slide Version

### Research and References

- **SIH26157 SAT-SA problem statement:** Defines periodic SOC evidence, execution gaps, negative space, peer benchmarking, explainability, and human supervision.
- **NIST CSF 2.0:** Governance and cybersecurity risk-management functions.
- **NIST SP 800-61 Rev. 3:** Incident-response lifecycle and improvement.
- **NIST SP 800-92:** Security log-management and evidence practices.
- **NIST SP 800-53 Rev. 5:** Security, privacy, accountability, and assessment controls.
- **MITRE ATT&CK:** Common language for detection and adversary-behaviour coverage.
- **CERT-In:** Indian incident-response and national cybersecurity context.
- **DPDP Act, 2023:** Privacy and responsible data-processing context.
- **FastAPI, SQLAlchemy, Alembic, OIDC, Prometheus, Docker:** Implementation standards and engineering foundations.

### Research conclusion

> **The research supports an evidence-first, explainable, privacy-preserving supervisory layer that complements SOC operations instead of replacing them.**

## Citation Guidance

- Use the official links above in the PPT reference slide or speaker notes.
- Keep the visible slide to 6–9 references.
- Put the complete bibliography in the project report.
- Cite SIH26157 first because it is the primary problem-statement source.
- Do not claim that any framework directly proves SOC effectiveness; explain that the frameworks inform the evidence model, controls, lifecycle, and governance design.
