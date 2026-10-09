# CAPE-Findings

Findings and evaluation data for **CAPE**, a context-aware prioritization approach for
dependency vulnerabilities. This repository holds the frozen study corpus and results only;
it does not contain the CAPE tool source code.

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
