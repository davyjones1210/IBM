import tempfile
import unittest
from datetime import date
from pathlib import Path
from unittest.mock import patch
import json

import numpy as np

from vulnrank import (
    Dataset,
    LogisticModel,
    _generate_granite_summary,
    _local_granite_summary,
    _month_end,
    feature_vector,
    load_historical_dataset,
    precision_recall_at_k,
)


class FeatureTests(unittest.TestCase):
    def test_feature_vector_encodes_epss_and_public_signals(self):
        actual = feature_vector(
            "0.01",
            {"exploitdb": "1", "metasploit": "0", "nuclei": "1", "poc_github": "0"},
        )
        self.assertAlmostEqual(actual[0], -2.0)
        self.assertEqual(actual[1:], [1.0, 0.0, 1.0, 0.0])

    def test_invalid_epss_is_rejected(self):
        with self.assertRaises(ValueError):
            feature_vector("1.2", {})

    def test_month_end_handles_leap_year_and_december(self):
        self.assertEqual(_month_end("2024-02"), date(2024, 2, 29))
        self.assertEqual(_month_end("2025-12"), date(2025, 12, 31))


class ModelTests(unittest.TestCase):
    def test_logistic_model_ranks_positive_signal_higher(self):
        features = np.asarray(
            [[-5.0, 0, 0, 0, 0], [-4.0, 0, 0, 0, 0], [-1.0, 1, 0, 0, 0], [-2.0, 1, 1, 0, 0]],
            dtype=float,
        )
        labels = np.asarray([0, 0, 1, 1])
        model = LogisticModel.fit(features, labels, iterations=300)
        scores = model.scores(features)
        self.assertGreater(scores[2], scores[0])

    def test_precision_recall_at_k(self):
        result = precision_recall_at_k(np.asarray([0, 1, 0, 1]), np.asarray([0.1, 0.9, 0.2, 0.8]), 2)
        self.assertEqual(result["precision"], 1.0)
        self.assertEqual(result["recall"], 1.0)

    def test_training_rejects_single_class(self):
        with self.assertRaises(ValueError):
            LogisticModel.fit(np.asarray([[0.0] * 5]), np.asarray([0]))

    @patch.dict("os.environ", {"WATSONX_BACKEND": "local", "GRANITE_MODEL": "granite-test"})
    @patch("vulnrank.urllib.request.urlopen")
    def test_local_granite_uses_chat_api_and_configured_model(self, urlopen):
        response = urlopen.return_value.__enter__.return_value
        response.read.return_value = json.dumps(
            {"choices": [{"message": {"content": "Summary from Granite."}}]}
        ).encode()

        text, backend = _generate_granite_summary(
            [{"cve_id": "CVE-2026-1234", "model_score": "0.5"}]
        )

        self.assertEqual(text, "Summary from Granite.")
        self.assertEqual(backend, "local IBM Granite via vLLM (granite-test)")
        request = urlopen.call_args.args[0]
        self.assertEqual(request.full_url, "http://127.0.0.1:8000/v1/chat/completions")
        payload = json.loads(request.data)
        self.assertEqual(payload["model"], "granite-test")
        self.assertEqual(payload["messages"][0]["role"], "user")

    @patch.dict("os.environ", {"WATSONX_BACKEND": "unknown"})
    def test_unknown_granite_backend_is_rejected(self):
        with self.assertRaises(ValueError):
            _generate_granite_summary([])

    @patch("vulnrank.urllib.request.urlopen")
    def test_local_granite_rejects_invalid_api_response(self, urlopen):
        response = urlopen.return_value.__enter__.return_value
        response.read.return_value = b'{"choices":[]}'
        with self.assertRaisesRegex(ValueError, "invalid chat completion"):
            _local_granite_summary([])


class HistoricalDatasetTests(unittest.TestCase):
    def test_uses_snapshot_signals_and_future_90_day_kev_label(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "vulnerabilities.csv").write_text(
                "cve_id,published\n"
                "CVE-2024-0001,2024-01-15\n"
                "CVE-2024-0002,2024-01-15\n",
                encoding="utf-8",
            )
            signal_columns = (
                "month,cve_id,epss,in_kev,exploitdb,metasploit,nuclei,poc_github\n"
                "2024-01,CVE-2024-0001,0.2,0,1,0,0,0\n"
            )
            for filename in ("exploit_signals_2024.csv", "exploit_signals_2025.csv"):
                (root / filename).write_text(signal_columns, encoding="utf-8")
            dataset = load_historical_dataset(
                root, {"CVE-2024-0001": date(2024, 2, 1)}
            )
            self.assertEqual(dataset.cve_ids, ["CVE-2024-0001", "CVE-2024-0002"])
            self.assertEqual(dataset.labels.tolist(), [1, 0])
            self.assertEqual(dataset.features[0, 1], 1.0)
            self.assertEqual(dataset.features[1].tolist(), [-6.0, 0, 0, 0, 0])


if __name__ == "__main__":
    unittest.main()
