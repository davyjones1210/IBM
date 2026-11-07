# Before the Breach — vulnerability prioritization report

## Executive summary

The model ranked 72,670 benchmark CVEs using historical monthly EPSS and public-exploit signals. Engineers should start with the first-ranked items, confirm that affected products and versions are actually present in their environment, then prioritize exposed, business-critical assets and apply vendor fixes or mitigations. A high score indicates a stronger learned association with near-term KEV additions; it is not proof of exploitation or a calibrated probability. The historical cohort has only 73 positive outcomes, so treat the ranking as an experimental triage signal.

**Summary backend:** deterministic local summary (watsonx credentials not configured).

## What this run predicts

The model estimates a relative **90-day KEV-addition risk ranking** from information in each CVE's snapshot month. Historical labels are CISA KEV additions in the 90 days after snapshot month-end. The benchmark ranking is predictive, not a claim that an item is already being exploited.

- Benchmark rows scored: **72,670**
- Candidates in `top500.csv`: **500**
- Historical eligible examples: **75,149**
- Historical positive labels: **73**
- KEV outcome data available through: **2025-12-31**
- Candidate ranking order: descending model score; ties preserve input order.

## What engineers should fix first, and why

Use the ranking as a triage queue, not a patch command. Begin with the first rows below, then check whether the vulnerable product/version is deployed, externally reachable, and business-critical. Expedite fixes or mitigations when a high-ranked CVE affects an internet-facing or critical asset. If immediate patching is not possible, apply the vendor's mitigation, add monitoring, and track an owner and due date. A CVE not present in your asset inventory may be deprioritized for your environment even if its general exploitation risk is high.

The `why_ranked` field reports positive feature contributions from snapshot-time EPSS/public-code signals; it does not establish causation. Public signals shown in their own columns may not have raised an individual score. The score is a logistic model output used for ordering. **It is not calibrated as a real-world probability.**

### Highest-ranked benchmark candidates

| Rank | CVE | Snapshot | Model score* | EPSS | Public signals | Why it ranked |
|---:|---|---|---:|---:|---|---|
| 1 | CVE-2025-14558 | 2026-03 | 0.075383 | 0.53599 | exploitdb, metasploit, poc_github | EPSS 0.536 raised the model score; positive model contribution from: exploitdb, metasploit, poc_github |
| 2 | CVE-2026-43500 | 2026-05 | 0.075267 | 0.40266 | exploitdb, metasploit, poc_github | EPSS 0.4027 raised the model score; positive model contribution from: exploitdb, metasploit, poc_github |
| 3 | CVE-2026-48909 | 2026-07 | 0.068005 | 0.07638 | exploitdb, nuclei, poc_github | EPSS 0.07638 raised the model score; positive model contribution from: exploitdb, nuclei, poc_github |
| 4 | CVE-2026-49952 | 2026-07 | 0.067785 | 0.04194 | exploitdb, nuclei, poc_github | EPSS 0.04194 raised the model score; positive model contribution from: exploitdb, nuclei, poc_github |
| 5 | CVE-2026-43284 | 2026-05 | 0.062727 | 0.38453 | metasploit, poc_github | EPSS 0.3845 raised the model score; positive model contribution from: metasploit, poc_github |
| 6 | CVE-2025-67888 | 2026-05 | 0.062668 | 0.32388 | metasploit, poc_github | EPSS 0.3239 raised the model score; positive model contribution from: metasploit, poc_github |
| 7 | CVE-2026-19681 | 2026-08 | 0.062185 | 0.07801 | metasploit, poc_github | EPSS 0.07801 raised the model score; positive model contribution from: metasploit, poc_github |
| 8 | CVE-2026-75604 | 2026-09 | 0.061773 | 0.02296 | metasploit, poc_github | EPSS 0.02296 raised the model score; positive model contribution from: metasploit, poc_github |
| 9 | CVE-2026-52806 | 2026-07 | 0.061651 | 0.01598 | metasploit, poc_github | EPSS 0.01598 raised the model score; positive model contribution from: metasploit, poc_github |
| 10 | CVE-2026-19626 | 2026-08 | 0.061617 | 0.01444 | metasploit, poc_github | EPSS 0.01444 raised the model score; positive model contribution from: metasploit, poc_github |
| 11 | CVE-2026-8037 | 2026-07 | 0.057364 | 0.84793 | nuclei, poc_github | EPSS 0.8479 raised the model score; positive model contribution from: nuclei, poc_github |
| 12 | CVE-2026-27771 | 2026-07 | 0.057152 | 0.43068 | nuclei, poc_github | EPSS 0.4307 raised the model score; positive model contribution from: nuclei, poc_github |
| 13 | CVE-2026-64638 | 2026-08 | 0.057052 | 0.31204 | nuclei, poc_github | EPSS 0.312 raised the model score; positive model contribution from: nuclei, poc_github |
| 14 | CVE-2026-1492 | 2026-03 | 0.057050 | 0.30987 | nuclei, poc_github | EPSS 0.3099 raised the model score; positive model contribution from: nuclei, poc_github |
| 15 | CVE-2026-2413 | 2026-03 | 0.056998 | 0.26217 | nuclei, poc_github | EPSS 0.2622 raised the model score; positive model contribution from: nuclei, poc_github |
| 16 | CVE-2026-71362 | 2026-08 | 0.056984 | 0.25136 | nuclei, poc_github | EPSS 0.2514 raised the model score; positive model contribution from: nuclei, poc_github |
| 17 | CVE-2026-6875 | 2026-07 | 0.056976 | 0.24489 | nuclei, poc_github | EPSS 0.2449 raised the model score; positive model contribution from: nuclei, poc_github |
| 18 | CVE-2026-2699 | 2026-04 | 0.056967 | 0.23777 | nuclei, poc_github | EPSS 0.2378 raised the model score; positive model contribution from: nuclei, poc_github |
| 19 | CVE-2026-28496 | 2026-07 | 0.056874 | 0.17612 | nuclei, poc_github | EPSS 0.1761 raised the model score; positive model contribution from: nuclei, poc_github |
| 20 | CVE-2026-22200 | 2026-01 | 0.056868 | 0.17276 | nuclei, poc_github | EPSS 0.1728 raised the model score; positive model contribution from: nuclei, poc_github |

`ranked_vulnerabilities.csv` includes the full benchmark ranking and feature snapshot. `top500.csv` has exactly one column (`cve_id`) and is the submission list.

## Model, data, and validation

The pipeline uses:

1. `vulnerabilities.csv` publication date to select one historical row per CVE, using its publication month as the snapshot month.
2. The matching month's `exploit_signals_2024.csv` / `exploit_signals_2025.csv` row for EPSS and the four public-code flags (`exploitdb`, `metasploit`, `nuclei`, `poc_github`). Missing signal rows become zero-valued signals.
3. `known_exploited.csv` `date_added` as the outcome label: addition after the snapshot and within 90 days. Already-known KEVs are excluded. Rows are eligible only when their full 90-day window ends by 2025-12-31.
4. A regularized logistic regression using log-scaled EPSS and the four binary exploit flags. No current NVD scores, references, review status, product counts, or post-snapshot content is used by the model.

The temporal holdout compares 2025-07 through 2025-09 against models trained on earlier publication months:

Hold out **2025-07 through 2025-09** (11,702 CVEs, 13 KEV additions within 90 days). Train on earlier publication months only, then compare precision@500 and recall@500:

| Ranking | Precision@K | Recall@K | Lift over holdout prevalence |
|---|---:|---:|---:|
| Logistic model | 1.000% | 38.462% | 9.00x |
| EPSS only | 0.400% | 15.385% | 3.60x |
| Public exploit flags, then EPSS | 1.000% | 38.462% | 9.00x |


There are only **73 positive labels** in the full training cohort and **13** in the holdout. The precision/recall figures can therefore change substantially with a few CVEs and should be treated as preliminary, not as stable performance estimates.

The historical cohort uses CVEs published January 2024–September 2025. Snapshot-month signals are selected, not later signals. This design limits feature leakage, but it is still a small and time-specific historical sample. Later KEV additions can be undercounted when their addition date is absent from the provided catalog.

### Historical outcome counts

| Publication month | Eligible examples | KEV additions within 90 days |
|---|---:|---:|
| 2024-01 | 2,585 | 0 |
| 2024-02 | 2,773 | 1 |
| 2024-03 | 3,305 | 1 |
| 2024-04 | 3,612 | 0 |
| 2024-05 | 4,991 | 3 |
| 2024-06 | 3,075 | 4 |
| 2024-07 | 3,105 | 1 |
| 2024-08 | 2,885 | 5 |
| 2024-09 | 2,508 | 5 |
| 2024-10 | 3,554 | 6 |
| 2024-11 | 4,048 | 3 |
| 2024-12 | 3,427 | 3 |
| 2025-01 | 4,267 | 7 |
| 2025-02 | 3,664 | 3 |
| 2025-03 | 3,982 | 4 |
| 2025-04 | 4,024 | 5 |
| 2025-05 | 3,968 | 5 |
| 2025-06 | 3,674 | 4 |
| 2025-07 | 3,768 | 2 |
| 2025-08 | 3,621 | 5 |
| 2025-09 | 4,313 | 6 |

## IBM technology

The project can draft its executive summary with IBM Granite either through watsonx.ai or a local vLLM-compatible server. For watsonx.ai, configure `WATSONX_APIKEY` and `WATSONX_PROJECT_ID` (and optionally `WATSONX_URL`, `WATSONX_GRANITE_MODEL`). For local inference, set `WATSONX_BACKEND=local`, run a vLLM server exposing an OpenAI-compatible API, and configure `GRANITE_BASE_URL` and `GRANITE_MODEL`. The backend used for this run is reported above. Granite drafts report prose only; benchmark scores and rankings are produced by the transparent local logistic regression and do not depend on Granite.

## Important limitations and fairness

- The supplied `known_exploited.csv` ends **December 31, 2025**. The README describes judging 2026 CVEs against KEV additions through November 4, 2026, but those future outcome labels are **not present** in these files. Therefore this run cannot verify which 2026 predictions actually became KEV.
- Benchmark rows are ranked from their provided `snapshot_month` signals. June 2026 uses the supplied July snapshot as documented in the data dictionary.
- Current NVD descriptions/details may have been revised after publication. They are intentionally not used as model features.
- KEV membership is a useful confirmed-exploitation label, not a complete record of all attacks. A negative means “not added to this KEV file in the horizon,” not “never exploited.”
- EPSS changed in March 2025. The temporal evaluation spans this change; performance can shift across periods.
- There is no organization-specific asset inventory, product deployment, internet exposure, patch availability, or business impact in this dataset. Those must be joined internally before assigning operational remediation priority.

## Reproduce

From the project directory:

```powershell
python -m pip install -r requirements.txt
python -m unittest discover -s tests -v
python vulnrank.py --data-dir data\data --output-dir output
```

For local IBM Granite 4.2 with vLLM, start the server in a supported Linux/GPU environment (for example WSL2):

```bash
pip install "vllm>=0.20"
vllm serve ibm-granite/granite-4.2-3b --served-model-name granite-4.2-3b
```

In PowerShell, select the local API and rerun the pipeline:

```powershell
$env:WATSONX_BACKEND = "local"
$env:GRANITE_BASE_URL = "http://127.0.0.1:8000/v1"
$env:GRANITE_MODEL = "granite-4.2-3b"
python vulnrank.py --data-dir data\data --output-dir output
```

The local backend sends a chat-completions request to vLLM. If the server is unavailable or the model name is wrong, the run fails explicitly rather than silently claiming Granite was used.

Outputs: `REPORT.md`, `top500.csv`, `ranked_vulnerabilities.csv`, and `run_summary.json` in the output directory.
