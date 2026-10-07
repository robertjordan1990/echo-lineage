from __future__ import annotations

import math
import unittest

from tools.tools.echo_canonical import (
    CanonicalJSONError,
    canon_json_bytes,
    loads_json_strict,
    sha256_hex,
)
from tools.tools.echo_msg_hash import canon_json_bytes as echohash_canon


class CanonicalJSONTests(unittest.TestCase):
    def test_frozen_echohash_vector(self) -> None:
        value = {"z": [1, True, None], "a": "e\u0301"}
        expected = '{"a":"é","z":[1,true,null]}'.encode("utf-8")
        self.assertEqual(canon_json_bytes(value), expected)
        self.assertEqual(echohash_canon(value), expected)
        self.assertEqual(
            sha256_hex(expected),
            "4ab501d6475772598121dfb387250b231"
            "f7173c861662d3e1350f4d3d814ccc9",
        )

    def test_frozen_echohash_payload_and_context_vectors(self) -> None:
        # These bytes and digests are frozen outputs from the pre-refactor
        # ECHOHASH/v1 implementation, not values derived by this test.
        vectors = (
            (
                {
                    "t": 12,
                    "w_t": "Zażółć e\u0301",
                    "y_t": "🙂/雪",
                },
                '{"t":12,"w_t":"Zażółć é","y_t":"🙂/雪"}'.encode("utf-8"),
                "2a418e3327f24639ac9b28b1a6884aca"
                "0f9096637211915a54732c350aabe4e0",
            ),
            (
                {
                    "algo": "ECHOHASH/v1",
                    "timestamp": "2026-02-01T18:47:12Z",
                    "mode": "TECH",
                    "L_t": 3,
                    "model_id": "",
                    "params": {
                        "temperature": 0.7,
                        "top_p": 1.0,
                        "stop": ["\n", "e\u0301"],
                    },
                },
                (
                    '{"L_t":3,"algo":"ECHOHASH/v1","mode":"TECH",'
                    '"model_id":"","params":{"stop":["\\n","é"],'
                    '"temperature":0.7,"top_p":1.0},'
                    '"timestamp":"2026-02-01T18:47:12Z"}'
                ).encode("utf-8"),
                "cdab4a075864d03c48670fe09bab0681b"
                "df87e384e3bbe26cc8c66d8624a22c3",
            ),
        )

        for value, expected_bytes, expected_sha256 in vectors:
            with self.subTest(expected_sha256=expected_sha256):
                self.assertEqual(canon_json_bytes(value), expected_bytes)
                self.assertEqual(echohash_canon(value), expected_bytes)
                self.assertEqual(sha256_hex(expected_bytes), expected_sha256)

    def test_duplicate_json_keys_rejected(self) -> None:
        with self.assertRaisesRegex(CanonicalJSONError, "duplicate JSON key"):
            loads_json_strict('{"item":1,"item":2}')

    def test_normalized_duplicate_keys_rejected(self) -> None:
        with self.assertRaisesRegex(
            CanonicalJSONError, "duplicate key after NFC normalization"
        ):
            loads_json_strict('{"é":1,"e\\u0301":2}')

    def test_non_finite_numbers_rejected(self) -> None:
        for text in (
            '{"n":NaN}',
            '{"n":Infinity}',
            '{"n":-Infinity}',
            '{"n":1e400}',
            '{"n":-1e400}',
        ):
            with self.subTest(text=text):
                with self.assertRaisesRegex(
                    CanonicalJSONError, "non-finite JSON number"
                ):
                    loads_json_strict(text)
        for value in (math.nan, math.inf, -math.inf):
            with self.subTest(value=value):
                with self.assertRaises(CanonicalJSONError):
                    canon_json_bytes({"n": value})

    def test_lone_surrogates_raise_controlled_error(self) -> None:
        for text in (r'"\ud800"', r'"\udfff"', r'{"\ud800":1}'):
            with self.subTest(text=text):
                with self.assertRaisesRegex(CanonicalJSONError, "surrogate"):
                    loads_json_strict(text)

        with self.assertRaisesRegex(CanonicalJSONError, "surrogate"):
            canon_json_bytes({"value": "\ud800"})

    def test_valid_surrogate_pair_is_accepted(self) -> None:
        value = loads_json_strict(r'{"emoji":"\ud83d\ude00"}')
        self.assertEqual(value, {"emoji": "😀"})
        self.assertEqual(canon_json_bytes(value), '{"emoji":"😀"}'.encode("utf-8"))


if __name__ == "__main__":
    unittest.main()
