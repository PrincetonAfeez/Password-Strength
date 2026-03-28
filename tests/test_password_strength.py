"""Offline tests for password_strength (no network)."""
import hashlib
import json
import os
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from password_strength import (
    DataArchitect,
    SecurityValidator,
    _levenshtein,
    _similar_to_blacklist,
    mask_password,
)


class TestMaskPassword(unittest.TestCase):
    def test_empty(self):
        self.assertEqual(mask_password(""), "")

    def test_short(self):
        self.assertEqual(mask_password("a"), "*")
        self.assertEqual(mask_password("ab"), "**")

    def test_normal(self):
        self.assertEqual(mask_password("abc"), "a*c")
        self.assertEqual(mask_password("secret"), "s****t")


class TestLevenshtein(unittest.TestCase):
    def test_distance(self):
        self.assertEqual(_levenshtein("", ""), 0)
        self.assertEqual(_levenshtein("a", "b"), 1)
        self.assertEqual(_levenshtein("passwrd", "password"), 1)


class TestSimilarToBlacklist(unittest.TestCase):
    def test_short_word_skipped(self):
        self.assertFalse(_similar_to_blacklist("administrator", "adm"))

    def test_ratio_requires_length(self):
        self.assertFalse(_similar_to_blacklist("abcde", "abcdf"))

    def test_ratio_when_long_enough(self):
        self.assertTrue(_similar_to_blacklist("password", "password"))

    def test_levenshtein_when_long_enough(self):
        self.assertTrue(_similar_to_blacklist("passwore", "password"))


class TestValidateRules(unittest.TestCase):
    def test_unicode_letters_and_symbol(self):
        v = SecurityValidator(blacklist_path="/__unused__")
        pw = "abcdefghijklÉñ§"  # 12+ chars, upper É, lower ñ, symbol §, no digit
        v.validate_rules(pw, add_feedback=True)
        self.assertLess(v.score, 5)

        v2 = SecurityValidator(blacklist_path="/__unused__")
        pw2 = "abcdefghijklÉñ9§"
        v2.validate_rules(pw2, add_feedback=True)
        self.assertEqual(v2.score, 5)


class TestHibpParsing(unittest.TestCase):
    @patch("password_strength.requests.get")
    def test_suffix_match(self, mock_get):
        pw = "hibptestvalue123"
        digest = hashlib.sha1(pw.encode("utf-8")).hexdigest().upper()
        suffix = digest[5:]
        mock_get.return_value = MagicMock(status_code=200, text=f"{suffix}:999\n")

        v = SecurityValidator(blacklist_path="/nonexistent")
        self.assertTrue(v.check_pwned_api(pw))
        mock_get.assert_called_once()

    @patch("password_strength.requests.get")
    def test_not_listed(self, mock_get):
        mock_get.return_value = MagicMock(
            status_code=200, text="00000000000000000000000000000000000:1\n"
        )
        v = SecurityValidator(blacklist_path="/nonexistent")
        self.assertFalse(v.check_pwned_api("unique-not-in-mock"))

    @patch("password_strength.console.print")
    @patch("password_strength.requests.get")
    def test_non_200_returns_false(self, mock_get, _print):
        mock_get.return_value = MagicMock(status_code=503, text="")
        v = SecurityValidator(blacklist_path="/nonexistent")
        self.assertFalse(v.check_pwned_api("anything"))


class TestBlacklistFile(unittest.TestCase):
    def test_exact_and_leet(self):
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".txt", delete=False, encoding="utf-8"
        ) as f:
            f.write("dragon\n")
            path = f.name
        try:
            v = SecurityValidator(blacklist_path=path)
            self.assertTrue(v.check_blacklist_and_fuzzy("Dragon"))
            v2 = SecurityValidator(blacklist_path=path)
            self.assertTrue(v2.check_blacklist_and_fuzzy("dr@g0n"))
        finally:
            os.unlink(path)


class TestDataArchitect(unittest.TestCase):
    def test_suggestion_shape(self):
        d = DataArchitect(
            history_file=os.path.join(tempfile.gettempdir(), "_pw_hist_unused.json"),
            report_file=os.path.join(tempfile.gettempdir(), "_pw_rep_unused.json"),
        )
        pw = d.generate_suggestion()
        self.assertEqual(len(pw), 16)
        self.assertTrue(any(c.islower() for c in pw))
        self.assertTrue(any(c.isupper() for c in pw))
        self.assertTrue(any(c.isdigit() for c in pw))
        self.assertTrue(any(not c.isalnum() for c in pw))


class TestHistoryRoundTrip(unittest.TestCase):
    def test_masked_only(self):
        fd, path = tempfile.mkstemp(suffix=".json")
        os.close(fd)
        try:
            arch = DataArchitect(history_file=path, report_file=path + ".rpt")
            arch.save_to_history(
                {"password_masked": "a*b", "score": 3, "entropy": 2.5, "audited_at": "t"}
            )
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
            self.assertEqual(data[0]["password_masked"], "a*b")
            self.assertNotIn("password", data[0])
        finally:
            os.unlink(path)


if __name__ == "__main__":
    unittest.main()
