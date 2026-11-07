# Before the Breach — vulnerability ranking project

This project trains a time-aware model on the supplied vulnerability and exploit-signal data, ranks the 2026 benchmark CVEs, and creates a report that helps security engineers decide where to investigate and remediate first.

## What the code does

- Uses the vulnerability publication month as the historical snapshot.
- Trains a regularized logistic regression from historical EPSS and public exploit-code signals.
- Labels historical examples when they were added to CISA KEV within 90 days after that snapshot; already-known KEVs and incomplete outcome windows are excluded.
- Evaluates on a later temporal holdout and compares against EPSS-only and public-exploit-first rankings.
- Scores all CVEs in `scoreboard_2026.csv` from the supplied snapshot features.
- Writes `output/REPORT.md`, `output/top500.csv` (one `cve_id` column), `output/ranked_vulnerabilities.csv`, and `output/run_summary.json`.
- Explains each rank using the available snapshot EPSS/public-code signals. The score is a ranking score, not a calibrated probability.

The supplied KEV file ends December 31, 2025, so the run cannot independently confirm 2026 outcomes through November 4, 2026.

## Report summary

The generated report ranks 72,670 benchmark CVEs by a model score intended to prioritize likely additions to CISA KEV within a 90-day horizon. In the temporal holdout, the model found 5 of 13 positive cases in its top 500, compared with 2 for EPSS-only. This is preliminary evidence, not a reliable performance guarantee: the full historical training cohort has only 73 positive labels, and the supplied KEV data does not include 2026 outcomes. Treat the ranking as a triage aid, then verify affected products and versions, asset exposure, and business criticality before deciding what to patch first.

## What `output/REPORT.md` contains

- Executive summary and explanation of the prediction target.
- The highest-ranked benchmark CVEs, their scores, snapshot signals, and ranking rationale.
- Temporal holdout metrics against EPSS-only and public-exploit baselines, plus historical outcome counts.
- Model/data methodology, supported IBM Granite via watsonx.ai integration, and whether Granite was actually used for that run.
- Remediation guidance, leakage/fairness notes, and limitations, including missing 2026 KEV outcomes.
- Reproduction instructions and descriptions of the generated output files.

## What engineers should fix first, and why

Use the ranking as a triage queue, not an automatic patch order. Start with the highest-ranked CVEs below, then confirm that the affected product and version are deployed in your environment. Prioritize items that are present on internet-facing or business-critical assets; apply the vendor patch or mitigation, and track an owner and due date. If an item is not present in your asset inventory, it may not be a priority for your environment.

The model score is a relative ranking signal, **not a calibrated probability or proof of active exploitation**. EPSS and public exploit-code signals explain why items ranked highly, but do not establish causation. Validate exposure and business impact before scheduling remediation.

## 20 highest-ranked benchmark candidates

| Rank | CVE | Snapshot | Model score | EPSS | Public exploit signals |
|---:|---|---|---:|---:|---|
| 1 | CVE-2025-14558 | 2026-03 | 0.075383 | 0.53599 | exploitdb, metasploit, poc_github |
| 2 | CVE-2026-43500 | 2026-05 | 0.075267 | 0.40266 | exploitdb, metasploit, poc_github |
| 3 | CVE-2026-48909 | 2026-07 | 0.068005 | 0.07638 | exploitdb, nuclei, poc_github |
| 4 | CVE-2026-49952 | 2026-07 | 0.067785 | 0.04194 | exploitdb, nuclei, poc_github |
| 5 | CVE-2026-43284 | 2026-05 | 0.062727 | 0.38453 | metasploit, poc_github |
| 6 | CVE-2025-67888 | 2026-05 | 0.062668 | 0.32388 | metasploit, poc_github |
| 7 | CVE-2026-19681 | 2026-08 | 0.062185 | 0.07801 | metasploit, poc_github |
| 8 | CVE-2026-75604 | 2026-09 | 0.061773 | 0.02296 | metasploit, poc_github |
| 9 | CVE-2026-52806 | 2026-07 | 0.061651 | 0.01598 | metasploit, poc_github |
| 10 | CVE-2026-19626 | 2026-08 | 0.061617 | 0.01444 | metasploit, poc_github |
| 11 | CVE-2026-8037 | 2026-07 | 0.057364 | 0.84793 | nuclei, poc_github |
| 12 | CVE-2026-27771 | 2026-07 | 0.057152 | 0.43068 | nuclei, poc_github |
| 13 | CVE-2026-64638 | 2026-08 | 0.057052 | 0.31204 | nuclei, poc_github |
| 14 | CVE-2026-1492 | 2026-03 | 0.057050 | 0.30987 | nuclei, poc_github |
| 15 | CVE-2026-2413 | 2026-03 | 0.056998 | 0.26217 | nuclei, poc_github |
| 16 | CVE-2026-71362 | 2026-08 | 0.056984 | 0.25136 | nuclei, poc_github |
| 17 | CVE-2026-6875 | 2026-07 | 0.056976 | 0.24489 | nuclei, poc_github |
| 18 | CVE-2026-2699 | 2026-04 | 0.056967 | 0.23777 | nuclei, poc_github |
| 19 | CVE-2026-28496 | 2026-07 | 0.056874 | 0.17612 | nuclei, poc_github |
| 20 | CVE-2026-22200 | 2026-01 | 0.056868 | 0.17276 | nuclei, poc_github |

## IBM technology

The project supports **IBM Granite through watsonx.ai** for generating a short, evidence-grounded report summary. The model is configurable with environment variables:

- `WATSONX_APIKEY`
- `WATSONX_PROJECT_ID`
- Optional: `WATSONX_URL` and `WATSONX_GRANITE_MODEL`

By default the model ID is `ibm/granite-3-3-8b-instruct`. If watsonx credentials are absent, the report uses a deterministic local summary and says so; the risk-ranking model remains local and reproducible. The code does not claim that Granite ran unless the configured watsonx call succeeds.

## Run

Requires Python 3.10+ and the listed NumPy dependency. From the project root in PowerShell:

```powershell
python -m pip install -r requirements.txt
python -m unittest discover -s tests -v
python vulnrank.py --data-dir data\data --output-dir output
```

See `output/REPORT.md` after running for the ranked candidates, temporal evaluation, limitations, and remediation guidance.
