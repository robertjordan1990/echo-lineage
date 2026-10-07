from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from tools.tools.echo_msg_hash import chain_cmd, read_jsonl, verify_cmd


class EchoHashRecomputeTests(unittest.TestCase):
    def run_quietly(self, func, *args, **kwargs) -> int:
        with contextlib.redirect_stdout(io.StringIO()):
            return func(*args, **kwargs)

    def assert_jsonl_error(self, text: str, pattern: str) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "invalid.jsonl"
            source.write_text(text, encoding="utf-8")
            with self.assertRaisesRegex(SystemExit, pattern):
                list(read_jsonl(source))

    def test_frozen_two_record_echohash_chain(self) -> None:
        records = [
            {
                "t": 12,
                "timestamp": "2026-02-01T18:47:12Z",
                "w_t": "Zażółć e\u0301",
                "y_t": "🙂/雪",
                "mode": "TECH",
                "L_t": 3,
                "model_id": "",
                "params": {
                    "temperature": 0.7,
                    "top_p": 1.0,
                    "stop": ["\n", "e\u0301"],
                },
            },
            {
                "t": 13,
                "timestamp": "2026-02-01T18:47:20Z",
                "w_t": "",
                "y_t": "done",
                "mode": "TECH",
                "L_t": 3,
                "model_id": "",
            },
        ]
        expected = [
            {
                "payload_sha256": (
                    "2a418e3327f24639ac9b28b1a6884aca"
                    "0f9096637211915a54732c350aabe4e0"
                ),
                "context_sha256": (
                    "cdab4a075864d03c48670fe09bab0681b"
                    "df87e384e3bbe26cc8c66d8624a22c3"
                ),
                "prev_msg_sha256": "0" * 64,
                "msg_sha256": (
                    "7b5bc2bc1602332dbd45ae42f8e91edd"
                    "706c1be62c256da09b45d124f9528b3b"
                ),
            },
            {
                "payload_sha256": (
                    "6d4785c15cbdf939c1cf9f0b892f1d05"
                    "6d970ad0e392e71e2cdc2e1e6f91adec"
                ),
                "context_sha256": (
                    "860dcc7533eab69aa45e2c2807cd2f435"
                    "a4ad4d6a211a566d5192cdaf96276da"
                ),
                "prev_msg_sha256": (
                    "7b5bc2bc1602332dbd45ae42f8e91edd"
                    "706c1be62c256da09b45d124f9528b3b"
                ),
                "msg_sha256": (
                    "ebdfa54204679bfb26c510a0775fe5ecc"
                    "86c8a091fedc888ddc0b38917394772"
                ),
            },
        ]

        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            source = base / "source.jsonl"
            chained = base / "chained.jsonl"
            source.write_text(
                "".join(
                    json.dumps(record, ensure_ascii=False, separators=(",", ":"))
                    + "\n"
                    for record in records
                ),
                encoding="utf-8",
            )

            self.assertEqual(
                self.run_quietly(
                    chain_cmd,
                    source,
                    chained,
                    strip_content=False,
                    include_params=True,
                ),
                0,
            )
            actual = [
                json.loads(line)
                for line in chained.read_text(encoding="utf-8").splitlines()
            ]
            for row, frozen in zip(actual, expected, strict=True):
                with self.subTest(t=row["t"]):
                    for field, value in frozen.items():
                        self.assertEqual(row[field], value)

    def test_read_jsonl_rejects_duplicate_keys(self) -> None:
        self.assert_jsonl_error(
            '{"t":1,"t":2}\n',
            r"line 1: duplicate JSON key",
        )

    def test_read_jsonl_rejects_non_finite_numbers(self) -> None:
        for token in ("NaN", "Infinity", "-Infinity", "1e400", "-1e400"):
            with self.subTest(token=token):
                self.assert_jsonl_error(
                    f'{{"t":1,"value":{token}}}\n',
                    r"line 1: non-finite JSON number",
                )

    def test_read_jsonl_requires_object_records(self) -> None:
        for value in ("[]", "null", '"text"', "42"):
            with self.subTest(value=value):
                self.assert_jsonl_error(
                    value + "\n",
                    r"line 1 must be an object",
                )

    def test_recompute_detects_content_tampering(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            source = base / "source.jsonl"
            chained = base / "chained.jsonl"
            source.write_text(
                json.dumps(
                    {
                        "t": 0,
                        "timestamp": "2026-07-24T00:00:00Z",
                        "w_t": "request",
                        "y_t": "original response",
                        "mode": "TECH",
                        "L_t": 1,
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            self.assertEqual(
                self.run_quietly(
                    chain_cmd,
                    source,
                    chained,
                    strip_content=False,
                    include_params=False,
                ),
                0,
            )

            row = json.loads(chained.read_text(encoding="utf-8"))
            row["y_t"] = "tampered response"
            chained.write_text(json.dumps(row) + "\n", encoding="utf-8")

            # Stored chain values remain internally consistent.
            self.assertEqual(
                self.run_quietly(
                    verify_cmd,
                    chained,
                    recompute=False,
                    include_params=False,
                ),
                0,
            )
            # Recomputing from content must detect the change.
            self.assertEqual(
                self.run_quietly(
                    verify_cmd,
                    chained,
                    recompute=True,
                    include_params=False,
                ),
                2,
            )

    def test_ci_requires_recompute(self) -> None:
        ci = (Path(__file__).resolve().parents[1] / ".github" / "workflows" / "ci.yml")
        text = ci.read_text(encoding="utf-8")
        self.assertIn(
            "echo_msg_hash.py verify --in Ht_pair.jsonl --recompute",
            text,
        )


if __name__ == "__main__":
    unittest.main()
