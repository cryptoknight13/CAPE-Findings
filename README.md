# CAPE-Findings

Findings and evaluation data for **CAPE** (Context-Aware Prioritization Engine), a framework
that ranks scanner-reported dependency vulnerabilities by how exploitable they are in the
deployed application, not by generic severity alone. This repository holds the frozen study
corpus and results only; it does not contain the CAPE tool source code.

## The problem

Software composition analysis scanners (Grype, Trivy, …) match `(component, version)` pairs
against vulnerability databases. A non-trivial application routinely gets hundreds of CVEs back,
and teams usually work through them top-down by CVSS score, or filter by EPSS or CISA KEV.
That practice is context-blind:

- A build-time bundle never shipped to production, a library with a backported fix and no
  version bump, and a library imported on every request all produce the same scanner row.
- CVSS says nothing about whether the vulnerable code is reachable from the application's
  entry points, whether the buggy lines are physically present in the installed artifact, or
  how central the component is to the application.

We call CVEs that no execution of the deployed application can trigger **context-aware false
positives**.

## How CAPE works

CAPE builds the target project locally at a pinned commit, generates an SPDX SBOM with Syft
from the installed dependency tree (`.venv/` or `node_modules/`), scans it with Grype, and then
enriches every finding through seven stages:

| Stage | What it does |
|---|---|
| S1 Normalization | Collapses advisory aliases (NVD, GHSA, OSV) into one finding per `(component, version, CVE)` |
| S2 Enrichment | Adds OSV metadata, EPSS probability and KEV membership (EPSS/KEV used only as baselines) |
| S3 Code evidence | Fetches the CVE's fix commit (NVD, OSV) and searches the installed artifact for pre-fix (buggy) and post-fix (patched) line signatures |
| S4 Call graph | Builds a typed multi-level call graph of the application **and** its installed dependencies with Tree-sitter (CALLS, IMPORTS, DEPENDS_ON, CONTAINS, …) |
| S5 Reachability | Multi-source BFS from application entry points over the call graph (test files and CONTAINS edges excluded) |
| S6 Centrality | Impact radius, hub score and eigenvector centrality of the affected component, or of the affected files when S3 found them |
| S7 Exploitability | Combines the evidence into a VEX-style regime per finding |

**Regimes.** R1 = component not in the artifact (not affected); R2 = no fix commit found
(needs manual investigation); R3 = fix commit found but affected files absent from the
installed package; R4 = affected files present and already patched; R5 = affected files
present and buggy code confirmed.

**Scoring.** Each finding gets a priority score P(f) ∈ [0, 1] from four evidence dimensions:

| Dimension | Signal |
|---|---|
| φ1 Exploitability | CVSS base score / 10 |
| φ2 Reachability | 1.0 reachable, 0.0 not reachable, 0.5 no call graph |
| φ3 Code evidence | R5 = 1.0, R4 = 0.8, R3 = 0.5, R1/R2 = absent |
| φ4 Centrality | 0.5 · impact radius + 0.3 · hub score + 0.2 · eigenvector centrality |

Weights come from an Analytic Hierarchy Process prior, w̄ = (0.318, 0.261, 0.227, 0.193),
consistency ratio 0.06. When a dimension is structurally absent (φ3 in R2), its weight is
redistributed proportionally over the rest, giving (0.412, 0.338, –, 0.250). Three gates then
apply in order:

- **G1:** R1 → P = 0 (component absent).
- **G2:** R3–R5 and not reachable → P × 0.40 (soft penalty that keeps the signal in case of
  dynamic dispatch static analysis missed).
- **G3:** R5 → P floored at 0.80 (confirmed-buggy code cannot be outranked on CVSS alone).

Nothing is discarded: unreachable and no-evidence findings are still scored and ranked.

## Key findings

Evaluated on **30 open-source agentic / AI applications** (18 Python, 11 TypeScript,
1 JavaScript) with **6,138 scanner-reported CVEs** (8–719 per project). Baselines: CVSS, EPSS,
EPSS percentile and KEV (KEV-listed first, then CVSS).

**RQ1: How many scanner CVEs are statically unreachable?**
2,656 of 6,138 CVEs (**43.3%**) are unreachable from any application entry point:
**53.1%** for TypeScript/JavaScript projects vs. **27.4%** for Python, up to **76.1%** in the
worst case (cve-lite-cli, 530 of 696). npm projects install large `node_modules/` trees full of
bundlers, transpilers and linters that are never called at runtime. Without reachability
analysis, 43.3% of remediation effort goes to CVEs that cannot be triggered.

**RQ2: How early does a confirmed-exploitable CVE (reachable + buggy code present) appear?**
Over the 29 projects with at least one R5 CVE, CAPE has a strictly lower rank-of-first-true-
positive (MRFTP) than every baseline in 19, ties in 7 and loses in 3; against CVSS alone it wins
24, ties 3, loses 2. Across the 19 wins mean MRFTP drops from **23.4 (CVSS) to 3.3 (CAPE)**,
an **86.0% reduction**, with 11 of the 19 at rank 1. Examples: CVE-2026-24486
(python-multipart, mindsdb) moves from CVSS rank 25 to 1; CVE-2026-8723 (qs, kimi-code) from
CVSS rank 133 to 6. The losses are deliberate: a confirmed-buggy but unreachable CVE is ranked
below reachable findings.

**RQ3: Ranking quality.**

| Metric (mean over 30 cases) | CAPE | CVSS | EPSS | KEV |
|---|---|---|---|---|
| NDCG@5 | **0.651** | 0.171 | 0.271 | 0.171 |
| NDCG@10 | **0.657** | 0.224 | 0.288 | 0.224 |
| NDCG@all | **0.821** | 0.577 | 0.644 | 0.577 |
| AUROC | **0.911** | 0.463 | 0.579 | 0.463 |
| CAPE wins (NDCG@10) | – | 28/30 | 25/30 | 28/30 |
| CAPE wins (AUROC) | – | 30/30 | 29/30 | 30/30 |

EPSS percentile gives near-identical results to EPSS. Relevance grades come from regime and
reachability only, independent of the CVSS and centrality dimensions, so the evaluation does
not reward CAPE for its own inputs.

**RQ4: Sensitivity and centrality choice.**
One-at-a-time perturbation of the AHP weights leaves the median ranking stable
(Kendall τb ≥ 0.93 for every dimension). For centrality, hub score is the strongest single
metric on NDCG@10 (0.774) and authority on AUROC (0.947); the adopted blend
0.5 · ir + 0.3 · hub + 0.2 · ev reaches NDCG@10 0.653 and AUROC 0.911, beating the earlier
0.6 · ir + 0.4 · ev blend in 21/30 (NDCG@10) and 26/30 (AUROC) cases. Hub score is the most
distinct metric (τb ≤ 0.866 with eigenvector/authority/fan-in, which cluster at τb ≥ 0.949).

### Exploit-label cross-check (`exploit-validation/`)

Ranks of CVEs that appear in CISA KEV (4 unique CVEs, 14 findings, 6 cases) and ExploitDB
(10 unique CVEs, 34 findings, 15 cases) under CAPE, CVSS and EPSS. EPSS ranks these highest,
as expected, since it uses exploitation activity and public exploit code as inputs. CAPE ranks
6 of 14 KEV findings and 14 of 34 ExploitDB findings above CVSS, mostly where the component is
reachable; it ranks them lower where the component is unreachable or the fixed files are absent
from the installed package.

## Contents

| Path | What it is |
|---|---|
| `Evaluation-cases/` | Frozen corpus: 30 open-source projects, 6,138 scanner findings |
| `Evaluation-cases/project_registry.json` | Project name, GitHub URL, pinned commit, language, finding count per case |
| `aggregate-results/` | Cross-case metrics (MRFTP, NDCG@k, AUROC, Kendall's tau) and centrality-variant study |
| `supplementary-figures/` | Sensitivity, ablation, grid, curve and heatmap figures (PDF) with summary CSVs |
| `exploit-validation/` | CAPE vs. CVSS vs. EPSS ranks for CISA KEV and ExploitDB CVEs |
| `KEV/` | CISA Known Exploited Vulnerabilities catalog snapshot used in the study |

### Per-case files (`Evaluation-cases/case_NNN/`)

| File | Contents |
|---|---|
| `sbom.spdx.json` | SPDX SBOM of the project at the pinned commit |
| `grype_report.json`, `raw_scanner.csv` | Raw Grype scanner output |
| `findings.json` | Enriched findings (CVSS, EPSS, KEV, fix commits) |
| `*_report_callgraph.json` | Multi-level call graph (application + dependencies) |
| `*_report_centrality.json` | Component centrality scores |
| `*_report_code_evidence.json` | Code-evidence regime (R1–R5) per finding |
| `*_report_exploitability_results.json` | Reachability / exploitability results |
| `*_report_priority_ranking.{csv,json}` | Final CAPE ranking with CVSS-only and EPSS-only baseline ranks |
| `evaluation_metrics.json` | Per-case evaluation metrics |

Code-evidence regimes: R2 = no fix commit; R3 = fix commit found but fixed files absent from the
installed package; R4 = patched code present; R5 = vulnerable code present.

## Large files

Several call-graph files are stored with Git LFS. Clone with `git lfs install` first, or run
`git lfs pull` after cloning.

## Third-party data

The KEV catalog and ExploitDB index snapshots belong to CISA and OffSec respectively and
remain under their own terms.
