"""Offline tests for the ablation benchmark's Rust editing (no builds)."""
from pathlib import Path
import sys
import unittest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "bench"))
sys.path.insert(0, str(HERE.parent / "tools"))
import bench

TRICKY = r'''
// see fn f below
trait T { fn f(&self); }
const S: &str = r#"fn f() { } }"#;
/* outer /* nested fn f() { */ still comment } */
fn f(seed: [u8; 32], c: char) -> [u8; 8] where 'a: 'b {
    let s = "}"; let ch = '}'; let lt: &'static str = "x"; let b = b'{';
    if true { [0; 8] } else { [1; 8] }
}
fn g() {}
'''


class BenchTests(unittest.TestCase):
    def test_find_fn_skips_comments_strings_and_declarations(self):
        a, b = bench.find_fn(TRICKY, "f")
        body = TRICKY[a:b]
        self.assertTrue(body.startswith("{\n    let s"))
        self.assertTrue(body.endswith("}"))
        self.assertNotIn("fn g", body)

    def test_blank_keeps_every_line_number(self):
        out, removed = bench.blank_body(TRICKY, "f")
        self.assertEqual(out.count("\n"), TRICKY.count("\n"))
        self.assertIn("todo!()", out)
        self.assertIn("fn g() {}", out)
        self.assertIn("let s", removed)

    def test_unterminated_input_errors_instead_of_hanging(self):
        for text in ("fn f() { /* never closed", 'fn f() { let s = "never closed; }'):
            with self.assertRaises(SystemExit):
                bench.find_fn(text, "f")


if __name__ == "__main__":
    unittest.main()
