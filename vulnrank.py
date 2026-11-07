#!/usr/bin/env python3
"""Train a time-aware KEV ranking model and write benchmark outputs."""

from __future__ import annotations

import argparse
import csv
import json
import math
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter
from dataclasses import dataclass
from datetime import date, datetime, timedelta
from pathlib import Path
from typing import Iterable, Mapping, Sequence

import numpy as np


SIGNAL_NAMES = ("exploitdb", "metasploit", "nuclei", "poc_github")
FEATURE_NAMES = ("epss_log10",) + SIGNAL_NAMES
HORIZON_DAYS = 90
KEV_CUTOFF = date(2025, 12, 31)
HOLDOUT_START = "2025-07"
HOLDOUT_END = "2025-09"
WATSONX_GRANITE_MODEL = "ibm/granite-3-3-8b-instruct"
LOCAL_GRANITE_MODEL = "granite-4.2-3b"


@dataclass
class Dataset:
    cve_ids: list[str]
    months: list[str]
    features: np.ndarray
    labels: np.ndarray


@dataclass
class LogisticModel:
    mean: np.ndarray
    scale: np.ndarray
    coefficients: np.ndarray

    @classmethod
    def fit(
        cls, features: np.ndarray, labels: np.ndarray, iterations: int = 400
    ) -> "LogisticModel":
        if len(features) == 0 or len(np.unique(labels)) < 2:
            raise ValueError("Training requires at least one positive and one negative.")
        mean = features.mean(axis=0)
        scale = features.std(axis=0)
        scale[scale == 0] = 1.0
        standardized = (features - mean) / scale
        design = np.column_stack((np.ones(len(features)), standardized))
        coefficients = np.zeros(design.shape[1], dtype=float)
        penalty = np.ones_like(coefficients)
        penalty[0] = 0.0
        learning_rate = 0.12
        regularization = 0.01
        for _ in range(iterations):
            logits = np.clip(design @ coefficients, -35.0, 35.0)
            probabilities = 1.0 / (1.0 + np.exp(-logits))
            gradient = design.T @ (probabilities - labels) / len(labels)
            gradient += regularization * penalty * coefficients
            coefficients -= learning_rate * gradient
        return cls(mean=mean, scale=scale, coefficients=coefficients)

    def scores(self, features: np.ndarray) -> np.ndarray:
        standardized = (features - self.mean) / self.scale
        design = np.column_stack((np.ones(len(features)), standardized))
        logits = np.clip(design @ self.coefficients, -35.0, 35.0)
        return 1.0 / (1.0 + np.exp(-logits))

    def contributions(self, features: np.ndarray) -> np.ndarray:
        standardized = (features - self.mean) / self.scale
        return standardized * self.coefficients[1:]


def _parse_date(value: str, column: str) -> date:
    try:
        return date.fromisoformat(value[:10])
    except (TypeError, ValueError) as exc:
        raise ValueError(f"Invalid {column} date: {value!r}") from exc


def _month_end(month: str) -> date:
    parsed = datetime.strptime(month, "%Y-%m").date()
    if parsed.month == 12:
        return date(parsed.year, 12, 31)
    return date(parsed.year, parsed.month + 1, 1) - timedelta(days=1)


def feature_vector(epss: str | float | None, signals: Mapping[str, str | int]) -> list[float]:
    try:
        value = float(epss or 0.0)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"Invalid EPSS value: {epss!r}") from exc
    if not math.isfinite(value) or not 0.0 <= value <= 1.0:
        raise ValueError(f"EPSS must be between 0 and 1, got {value!r}")
    result = [math.log10(max(value, 1e-6))]
    for name in SIGNAL_NAMES:
        raw = signals.get(name, 0)
        try:
            flag = int(raw or 0)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"Invalid {name} flag: {raw!r}") from exc
        if flag not in (0, 1):
            raise ValueError(f"{name} must be 0 or 1, got {flag!r}")
        result.append(float(flag))
    return result


def load_kev(path: Path) -> dict[str, date]:
    result: dict[str, date] = {}
    with path.open(encoding="utf-8-sig", newline="") as stream:
        for row in csv.DictReader(stream):
            cve_id = row["cve_id"]
            if cve_id in result:
                raise ValueError(f"Duplicate KEV entry: {cve_id}")
            result[cve_id] = _parse_date(row["date_added"], "date_added")
    return result


def load_historical_dataset(data_dir: Path, kev_dates: Mapping[str, date]) -> Dataset:
    metadata: dict[str, tuple[str, str]] = {}
    with (data_dir / "vulnerabilities.csv").open(
        encoding="utf-8-sig", newline=""
    ) as stream:
        for row in csv.DictReader(stream):
            published = _parse_date(row["published"], "published")
            month = published.strftime("%Y-%m")
            if "2024-01" <= month <= "2025-09":
                metadata[row["cve_id"]] = (month, row["published"])

    features_by_cve: dict[str, list[float]] = {}
    for filename in ("exploit_signals_2024.csv", "exploit_signals_2025.csv"):
        with (data_dir / filename).open(encoding="utf-8-sig", newline="") as stream:
            for row in csv.DictReader(stream):
                cve_id = row["cve_id"]
                entry = metadata.get(cve_id)
                if entry is None or row["month"] != entry[0]:
                    continue
                features_by_cve[cve_id] = feature_vector(row["epss"], row)

    cve_ids: list[str] = []
    months: list[str] = []
    x_rows: list[list[float]] = []
    y_rows: list[int] = []
    for cve_id, (month, _published) in metadata.items():
        snapshot_end = _month_end(month)
        added = kev_dates.get(cve_id)
        if added is not None and added <= snapshot_end:
            continue
        if snapshot_end + timedelta(days=HORIZON_DAYS) > KEV_CUTOFF:
            continue
        cve_ids.append(cve_id)
        months.append(month)
        x_rows.append(features_by_cve.get(cve_id, feature_vector(0.0, {})))
        y_rows.append(
            int(
                added is not None
                and snapshot_end < added <= snapshot_end + timedelta(days=HORIZON_DAYS)
            )
        )
    if not x_rows:
        raise ValueError("No complete historical training examples were found.")
    return Dataset(
        cve_ids=cve_ids,
        months=months,
        features=np.asarray(x_rows, dtype=float),
        labels=np.asarray(y_rows, dtype=int),
    )


def read_benchmark(path: Path) -> tuple[list[dict[str, str]], np.ndarray]:
    rows: list[dict[str, str]] = []
    features: list[list[float]] = []
    with path.open(encoding="utf-8-sig", newline="") as stream:
        for row in csv.DictReader(stream):
            rows.append(row)
            features.append(feature_vector(row["epss"], row))
    if not rows:
        raise ValueError(f"Benchmark is empty: {path}")
    return rows, np.asarray(features, dtype=float)


def precision_recall_at_k(labels: np.ndarray, scores: np.ndarray, k: int) -> dict[str, float]:
    count = min(k, len(labels))
    if count == 0:
        return {"k": 0.0, "precision": 0.0, "recall": 0.0, "lift": 0.0}
    top = np.argsort(-scores, kind="stable")[:count]
    found = int(labels[top].sum())
    positives = int(labels.sum())
    prevalence = positives / len(labels) if len(labels) else 0.0
    return {
        "k": float(count),
        "precision": found / count,
        "recall": found / positives if positives else 0.0,
        "lift": (found / count) / prevalence if prevalence else 0.0,
    }


def _public_exploit_rank(features: np.ndarray) -> np.ndarray:
    flags = features[:, 1:].sum(axis=1)
    return flags * (features[:, 0] + 8.0) + features[:, 0]


def _top_reason(row: Mapping[str, str], contributions: np.ndarray) -> str:
    details: list[str] = []
    if float(contributions[0]) > 0:
        details.append(f"EPSS {float(row['epss'] or 0):.4g} raised the model score")
    positive_signal_contributions = [
        name
        for name, contribution in zip(SIGNAL_NAMES, contributions[1:])
        if str(row.get(name, "0") or "0") == "1" and float(contribution) > 0
    ]
    if positive_signal_contributions:
        details.append("positive model contribution from: " + ", ".join(positive_signal_contributions))
    if details:
        return "; ".join(details)
    return "No input feature has a positive contribution; rank reflects the combined learned feature pattern."


def _watsonx_granite_summary(top_rows: Sequence[Mapping[str, str]]) -> str | None:
    api_key = os.getenv("WATSONX_APIKEY")
    project_id = os.getenv("WATSONX_PROJECT_ID")
    if not api_key or not project_id:
        return None

    base_url = os.getenv("WATSONX_URL", "https://us-south.ml.cloud.ibm.com").rstrip("/")
    model_id = os.getenv("WATSONX_GRANITE_MODEL", WATSONX_GRANITE_MODEL)
    token_request = urllib.request.Request(
        "https://iam.cloud.ibm.com/identity/token",
        data=urllib.parse.urlencode(
            {
                "grant_type": "urn:ibm:params:oauth:grant-type:apikey",
                "apikey": api_key,
            }
        ).encode(),
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    with urllib.request.urlopen(token_request, timeout=30) as response:
        token = json.load(response)["access_token"]

    prompt = (
        "Write a concise, evidence-grounded executive summary of this vulnerability "
        "ranking. Do not claim exploitation is confirmed; scores are model rankings. "
        "Recommend engineers validate asset exposure and patch feasibility. "
        "Top-ranked rows (rank, CVE, score, EPSS, public-signal explanation):\n"
        + json.dumps(list(top_rows), ensure_ascii=True)
    )
    payload = {
        "model_id": model_id,
        "project_id": project_id,
        "input": prompt,
        "parameters": {"max_new_tokens": 350, "temperature": 0.2},
    }
    request = urllib.request.Request(
        f"{base_url}/ml/v1/text/generation?version=2024-05-31",
        data=json.dumps(payload).encode(),
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=90) as response:
        result = json.load(response)
    generated = result["results"][0]["generated_text"].strip()
    if not generated:
        raise ValueError("watsonx Granite returned an empty summary.")
    return generated


def _local_granite_summary(top_rows: Sequence[Mapping[str, str]]) -> str:
    base_url = os.getenv("GRANITE_BASE_URL", "http://127.0.0.1:8000/v1").rstrip("/")
    model_id = os.getenv("GRANITE_MODEL", LOCAL_GRANITE_MODEL)
    prompt = (
        "Write a concise, evidence-grounded executive summary of this vulnerability "
        "ranking. Do not claim exploitation is confirmed; scores are model rankings. "
        "Recommend engineers validate asset exposure and patch feasibility. "
        "Top-ranked rows (rank, CVE, score, EPSS, public-signal explanation):\n"
        + json.dumps(list(top_rows), ensure_ascii=True)
    )
    payload = {
        "model": model_id,
        "messages": [{"role": "user", "content": prompt}],
        "max_tokens": 350,
        "temperature": 0.2,
    }
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    api_key = os.getenv("GRANITE_API_KEY")
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    request = urllib.request.Request(
        f"{base_url}/chat/completions",
        data=json.dumps(payload).encode(),
        headers=headers,
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=180) as response:
        result = json.load(response)
    try:
        generated = result["choices"][0]["message"]["content"].strip()
    except (KeyError, IndexError, TypeError, AttributeError) as exc:
        raise ValueError("Local Granite API returned an invalid chat completion.") from exc
    if not generated:
        raise ValueError("Local Granite API returned an empty summary.")
    return generated


def _generate_granite_summary(
    top_rows: Sequence[Mapping[str, str]],
) -> tuple[str | None, str]:
    backend = os.getenv("WATSONX_BACKEND", "watsonx").strip().lower()
    if backend == "local":
        model_id = os.getenv("GRANITE_MODEL", LOCAL_GRANITE_MODEL)
        return (
            _local_granite_summary(top_rows),
            f"local IBM Granite via vLLM ({model_id})",
        )
    if backend != "watsonx":
        raise ValueError("WATSONX_BACKEND must be either 'watsonx' or 'local'.")

    model_id = os.getenv("WATSONX_GRANITE_MODEL", WATSONX_GRANITE_MODEL)
    summary = _watsonx_granite_summary(top_rows)
    if summary:
        return summary, f"IBM watsonx.ai Granite ({model_id})"
    return None, "deterministic local summary (watsonx credentials not configured)"


def _write_csv(path: Path, rows: Iterable[Mapping[str, object]], fields: Sequence[str]) -> None:
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def generate(data_dir: Path, output_dir: Path) -> dict[str, object]:
    required = (
        "vulnerabilities.csv",
        "known_exploited.csv",
        "exploit_signals_2024.csv",
        "exploit_signals_2025.csv",
        "scoreboard_2026.csv",
    )
    missing = [filename for filename in required if not (data_dir / filename).is_file()]
    if missing:
        raise FileNotFoundError(f"Required data files missing from {data_dir}: {', '.join(missing)}")
    output_dir.mkdir(parents=True, exist_ok=True)

    kev_dates = load_kev(data_dir / "known_exploited.csv")
    historical = load_historical_dataset(data_dir, kev_dates)
    month_array = np.asarray(historical.months)
    holdout_mask = (month_array >= HOLDOUT_START) & (month_array <= HOLDOUT_END)
    train_mask = month_array < HOLDOUT_START
    holdout_metrics: dict[str, object] = {}
    if holdout_mask.any() and train_mask.any() and len(np.unique(historical.labels[train_mask])) > 1:
        validation_model = LogisticModel.fit(
            historical.features[train_mask], historical.labels[train_mask]
        )
        validation_scores = validation_model.scores(historical.features[holdout_mask])
        validation_labels = historical.labels[holdout_mask]
        k = min(500, len(validation_labels))
        model_metrics = precision_recall_at_k(validation_labels, validation_scores, k)
        epss_metrics = precision_recall_at_k(
            validation_labels, historical.features[holdout_mask, 0], k
        )
        public_metrics = precision_recall_at_k(
            validation_labels, _public_exploit_rank(historical.features[holdout_mask]), k
        )
        holdout_metrics = {
            "months": f"{HOLDOUT_START} through {HOLDOUT_END}",
            "examples": int(holdout_mask.sum()),
            "positive_examples": int(validation_labels.sum()),
            "top_k": k,
            "model": model_metrics,
            "epss_only": epss_metrics,
            "public_exploit_then_epss": public_metrics,
        }

    model = LogisticModel.fit(historical.features, historical.labels)
    benchmark_rows, benchmark_features = read_benchmark(data_dir / "scoreboard_2026.csv")
    scores = model.scores(benchmark_features)
    contributions = model.contributions(benchmark_features)
    ordered_indices = np.argsort(-scores, kind="stable")
    ranked: list[dict[str, object]] = []
    for rank, index in enumerate(ordered_indices, start=1):
        source = benchmark_rows[int(index)]
        ranked.append(
            {
                "rank": rank,
                "cve_id": source["cve_id"],
                "snapshot_month": source["snapshot_month"],
                "model_score": f"{scores[index]:.8f}",
                "epss": source["epss"],
                **{name: source[name] for name in SIGNAL_NAMES},
                "why_ranked": _top_reason(source, contributions[index]),
            }
        )
    _write_csv(
        output_dir / "ranked_vulnerabilities.csv",
        ranked,
        (
            "rank",
            "cve_id",
            "snapshot_month",
            "model_score",
            "epss",
            *SIGNAL_NAMES,
            "why_ranked",
        ),
    )
    _write_csv(output_dir / "top500.csv", ranked[:500], ("cve_id",))

    granite_summary, backend = _generate_granite_summary(ranked[:10])
    positive_rates = {
        month: {
            "examples": int(np.sum(month_array == month)),
            "positive_examples": int(historical.labels[month_array == month].sum()),
        }
        for month in sorted(set(historical.months))
    }
    report = _make_report(
        historical,
        ranked,
        holdout_metrics,
        positive_rates,
        kev_dates,
        backend,
        granite_summary,
    )
    (output_dir / "REPORT.md").write_text(report, encoding="utf-8")
    summary = {
        "training_examples": len(historical.labels),
        "training_positives": int(historical.labels.sum()),
        "benchmark_rows": len(benchmark_rows),
        "top500_rows": min(500, len(ranked)),
        "holdout": holdout_metrics,
        "summary_backend": backend,
        "output_dir": str(output_dir.resolve()),
    }
    (output_dir / "run_summary.json").write_text(
        json.dumps(summary, indent=2), encoding="utf-8"
    )
    return summary


def _make_report(
    historical: Dataset,
    ranked: Sequence[Mapping[str, object]],
    holdout: Mapping[str, object],
    month_counts: Mapping[str, Mapping[str, int]],
    kev_dates: Mapping[str, date],
    backend: str,
    granite_summary: str | None,
) -> str:
    top_lines = [
        "| Rank | CVE | Snapshot | Model score* | EPSS | Public signals | Why it ranked |",
        "|---:|---|---|---:|---:|---|---|",
    ]
    for row in ranked[:20]:
        signals = ", ".join(name for name in SIGNAL_NAMES if str(row[name]) == "1") or "None"
        explanation = str(row["why_ranked"]).replace("|", "\\|")
        top_lines.append(
            f"| {row['rank']} | {row['cve_id']} | {row['snapshot_month']} | "
            f"{float(row['model_score']):.6f} | {row['epss'] or '0'} | "
            f"{signals} | {explanation} |"
        )

    holdout_section = "Temporal holdout could not be computed with the available labeled examples."
    if holdout:
        model_result = holdout["model"]
        epss_result = holdout["epss_only"]
        public_result = holdout["public_exploit_then_epss"]
        holdout_section = (
            f"Hold out **{holdout['months']}** ({holdout['examples']:,} CVEs, "
            f"{holdout['positive_examples']:,} KEV additions within 90 days). "
            f"Train on earlier publication months only, then compare precision@{holdout['top_k']} "
            f"and recall@{holdout['top_k']}:\n\n"
            "| Ranking | Precision@K | Recall@K | Lift over holdout prevalence |\n"
            "|---|---:|---:|---:|\n"
            f"| Logistic model | {model_result['precision']:.3%} | {model_result['recall']:.3%} | {model_result['lift']:.2f}x |\n"
            f"| EPSS only | {epss_result['precision']:.3%} | {epss_result['recall']:.3%} | {epss_result['lift']:.2f}x |\n"
            f"| Public exploit flags, then EPSS | {public_result['precision']:.3%} | {public_result['recall']:.3%} | {public_result['lift']:.2f}x |\n"
        )

    monthly_lines = [
        "| Publication month | Eligible examples | KEV additions within 90 days |",
        "|---|---:|---:|",
    ]
    for month, counts in sorted(month_counts.items()):
        monthly_lines.append(
            f"| {month} | {counts['examples']:,} | {counts['positive_examples']:,} |"
        )
    executive_summary = granite_summary or (
        f"The model ranked {len(ranked):,} benchmark CVEs using historical monthly EPSS and "
        "public-exploit signals. Engineers should start with the first-ranked items, confirm "
        "that affected products and versions are actually present in their environment, then "
        "prioritize exposed, business-critical assets and apply vendor fixes or mitigations. "
        "A high score indicates a stronger learned association with near-term KEV additions; "
        f"it is not proof of exploitation or a calibrated probability. The historical cohort "
        f"has only {int(historical.labels.sum())} positive outcomes, so treat the ranking as "
        "an experimental triage signal."
    )
    return f"""# Before the Breach — vulnerability prioritization report

## Executive summary

{executive_summary}

**Summary backend:** {backend}.

## What this run predicts

The model estimates a relative **90-day KEV-addition risk ranking** from information in each CVE's snapshot month. Historical labels are CISA KEV additions in the 90 days after snapshot month-end. The benchmark ranking is predictive, not a claim that an item is already being exploited.

- Benchmark rows scored: **{len(ranked):,}**
- Candidates in `top500.csv`: **{min(500, len(ranked)):,}**
- Historical eligible examples: **{len(historical.labels):,}**
- Historical positive labels: **{int(historical.labels.sum()):,}**
- KEV outcome data available through: **{KEV_CUTOFF.isoformat()}**
- Candidate ranking order: descending model score; ties preserve input order.

## What engineers should fix first, and why

Use the ranking as a triage queue, not a patch command. Begin with the first rows below, then check whether the vulnerable product/version is deployed, externally reachable, and business-critical. Expedite fixes or mitigations when a high-ranked CVE affects an internet-facing or critical asset. If immediate patching is not possible, apply the vendor's mitigation, add monitoring, and track an owner and due date. A CVE not present in your asset inventory may be deprioritized for your environment even if its general exploitation risk is high.

The `why_ranked` field reports positive feature contributions from snapshot-time EPSS/public-code signals; it does not establish causation. Public signals shown in their own columns may not have raised an individual score. The score is a logistic model output used for ordering. **It is not calibrated as a real-world probability.**

### Highest-ranked benchmark candidates

{chr(10).join(top_lines)}

`ranked_vulnerabilities.csv` includes the full benchmark ranking and feature snapshot. `top500.csv` has exactly one column (`cve_id`) and is the submission list.

## Model, data, and validation

The pipeline uses:

1. `vulnerabilities.csv` publication date to select one historical row per CVE, using its publication month as the snapshot month.
2. The matching month's `exploit_signals_2024.csv` / `exploit_signals_2025.csv` row for EPSS and the four public-code flags (`exploitdb`, `metasploit`, `nuclei`, `poc_github`). Missing signal rows become zero-valued signals.
3. `known_exploited.csv` `date_added` as the outcome label: addition after the snapshot and within 90 days. Already-known KEVs are excluded. Rows are eligible only when their full 90-day window ends by {KEV_CUTOFF.isoformat()}.
4. A regularized logistic regression using log-scaled EPSS and the four binary exploit flags. No current NVD scores, references, review status, product counts, or post-snapshot content is used by the model.

The temporal holdout compares {HOLDOUT_START} through {HOLDOUT_END} against models trained on earlier publication months:

{holdout_section}

There are only **{int(historical.labels.sum())} positive labels** in the full training cohort and **{int(holdout.get("positive_examples", 0))}** in the holdout. The precision/recall figures can therefore change substantially with a few CVEs and should be treated as preliminary, not as stable performance estimates.

The historical cohort uses CVEs published January 2024–September 2025. Snapshot-month signals are selected, not later signals. This design limits feature leakage, but it is still a small and time-specific historical sample. Later KEV additions can be undercounted when their addition date is absent from the provided catalog.

### Historical outcome counts

{chr(10).join(monthly_lines)}

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
python vulnrank.py --data-dir data\\data --output-dir output
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
python vulnrank.py --data-dir data\\data --output-dir output
```

The local backend sends a chat-completions request to vLLM. If the server is unavailable or the model name is wrong, the run fails explicitly rather than silently claiming Granite was used.

Outputs: `REPORT.md`, `top500.csv`, `ranked_vulnerabilities.csv`, and `run_summary.json` in the output directory.
"""


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-dir", type=Path, default=Path("data") / "data")
    parser.add_argument("--output-dir", type=Path, default=Path("output"))
    args = parser.parse_args(argv)
    summary = generate(args.data_dir, args.output_dir)
    print(json.dumps(summary, indent=2))
    backend = os.getenv("WATSONX_BACKEND", "watsonx").strip().lower()
    if backend == "local":
        print(
            "Using local IBM Granite via the configured vLLM-compatible API.",
            file=sys.stderr,
        )
    elif "WATSONX_APIKEY" not in os.environ or "WATSONX_PROJECT_ID" not in os.environ:
        print(
            "Notice: IBM watsonx.ai Granite was not invoked because its credentials are not configured.",
            file=sys.stderr,
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
