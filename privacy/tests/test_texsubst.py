import unittest

from privacy import identity as ident
from privacy import texsubst as ts
from privacy.tests.fixtures import CANARY, TRICKY

TRICKY_N = ident.normalise(TRICKY)
CANARY_N = ident.normalise(CANARY)


class Escape(unittest.TestCase):
    def test_text_specials(self):
        self.assertEqual(ts.escape("a&b%c$d#e_f{g}h"), r"a\&b\%c\$d\#e\_f\{g\}h")
        self.assertEqual(ts.escape("~^\\"),
                         r"\textasciitilde{}\textasciicircum{}\textbackslash{}")

    def test_url_tilde(self):
        self.assertEqual(ts.escape("https://x/~a%C3", url=True), r"https://x/\~a\%C3")

    def test_unicode_passes_through(self):
        self.assertEqual(ts.escape("Ørnbjerg-Ældremøller"), "Ørnbjerg-Ældremøller")


class UrlSpans(unittest.TestCase):
    def test_nested_braces(self):
        src = r"\extrainfo{\href{a{b}c}{L}}"
        (a, b), = ts.url_spans(src)
        self.assertEqual(src[a:b], "a{b}c")

    def test_escaped_brace_ignored(self):
        src = r"\href{a\}b}{x}"
        (a, b), = ts.url_spans(src)
        self.assertEqual(src[a:b], r"a\}b")

    def test_unbalanced(self):
        with self.assertRaises(ts.SubstitutionError):
            ts.url_spans(r"\href{abc")


class Substitute(unittest.TestCase):
    def test_contexts(self):
        src = (r"\name{ZZFIRSTNAMEZZ}{ZZLASTNAMEZZ} "
               r"\href{ZZWEBSITEZZ}{ZZWEBSITEZZ} \email{ZZEMAILZZ}")
        out, used = ts.substitute(src, TRICKY_N)
        self.assertIn(r"\name{Åse-Marie}{O'Brien \& Søn}", out)
        self.assertIn(r"\href{https://example.invalid/\~aase/cv}"
                      r"{https://example.invalid/\textasciitilde{}aase/cv}", out)
        self.assertIn(r"\email{aase\_marie+jobs@example.invalid}", out)
        self.assertEqual(used, {"ZZFIRSTNAMEZZ", "ZZLASTNAMEZZ",
                                "ZZWEBSITEZZ", "ZZEMAILZZ"})

    def test_no_token_left(self):
        src = " ".join(ident.TOKENS[f] for f in CANARY_N)
        out, _ = ts.substitute(src, CANARY_N)
        self.assertEqual(ts.tokens_in(out), set())

    def test_unknown_token(self):
        with self.assertRaises(ts.SubstitutionError) as cm:
            ts.substitute("ZZPASSWORDZZ", CANARY_N)
        self.assertIn("ZZPASSWORDZZ", str(cm.exception))

    def test_empty_field_names_token_not_value(self):
        with self.assertRaises(ts.SubstitutionError) as cm:
            ts.substitute("ZZWEBSITEZZ ZZNAMEZZ", CANARY_N)
        msg = str(cm.exception)
        self.assertIn("ZZWEBSITEZZ (website)", msg)
        for v in CANARY_N.values():
            self.assertNotIn(v, msg)

    def test_value_cannot_inject_tex(self):
        evil = dict(CANARY_N, address=r"x}\input{/etc/passwd}{")
        out, _ = ts.substitute(r"\address{ZZADDRESSZZ}{}{}", evil)
        self.assertNotIn(r"\input{", out)


if __name__ == "__main__":
    unittest.main()
