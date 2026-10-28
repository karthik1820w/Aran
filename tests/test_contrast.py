import unittest

from helpers import ROOT  # noqa: F401  (puts the project on sys.path)
from brandguardian.contrast import ColourError, contrast_ratio, evaluate, parse_hex


class ContrastTests(unittest.TestCase):
    def test_known_ratios(self):
        self.assertAlmostEqual(contrast_ratio("#000000", "#ffffff"), 21.0, places=2)
        self.assertAlmostEqual(contrast_ratio("#fff", "#fff"), 1.0, places=2)
        self.assertAlmostEqual(contrast_ratio("#777777", "#ffffff"), 4.48, places=2)  # the classic just-fails-AA grey

    def test_symmetry(self):
        self.assertAlmostEqual(contrast_ratio("#123456", "#fedcba"), contrast_ratio("#fedcba", "#123456"))

    def test_parse_variants(self):
        self.assertEqual(parse_hex("#abc"), (170, 187, 204))
        self.assertEqual(parse_hex("FFFFFF"), (255, 255, 255))
        for bad in ("#12", "#gggggg", "", "red", None, 5, "#1234567"):
            with self.assertRaises(ColourError):
                parse_hex(bad)

    def test_thresholds_normal_and_large(self):
        r = evaluate("#777777", "#ffffff")
        self.assertEqual((r["aa"], r["aaa"], r["ratio"]), (False, False, 4.48))
        self.assertTrue(evaluate("#777777", "#ffffff", large=True)["aa"])
        r = evaluate("#666666", "#ffffff")
        self.assertEqual((r["aa"], r["aaa"]), (True, False))
        self.assertTrue(evaluate("#000", "#fff")["aaa"])

    def test_suggestion_passes_aa_on_light_and_dark_backgrounds(self):
        for fg, bg in (("#999999", "#ffffff"), ("#555566", "#222233"), ("#ffcc00", "#ffffff")):
            r = evaluate(fg, bg)
            self.assertFalse(r["aa"])
            self.assertIsNotNone(r["suggested_foreground"], (fg, bg))
            self.assertGreaterEqual(contrast_ratio(r["suggested_foreground"], bg), 4.5)

    def test_passing_pair_has_no_suggestion(self):
        self.assertIsNone(evaluate("#000", "#fff")["suggested_foreground"])


if __name__ == "__main__":
    unittest.main()
