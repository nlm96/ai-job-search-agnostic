"""Synthetic test identities. None of these is a real person.

``CANARY`` uses unique strings so a leak is unambiguous in any grep.
``TRICKY`` exercises the characters that break naive TeX substitution:
non-ASCII letters, an ampersand and apostrophe in the name, an underscore
and plus in the email, and a percent-encoded URL.
"""

CANARY = {
    "first_name": "Qvistrup",
    "last_name": "Ørnbjerg-Ældremøller",
    "email": "qx7canary@example.invalid",
    "phone": "+45 99 88 77 66",
    "address": "Canaryvej 7, 9999 Testby, Denmark",
    "linkedin": "https://www.linkedin.com/in/qx7canary",
    "github": "https://github.com/qx7canary",
}

TRICKY = {
    "first_name": "Åse-Marie",
    "last_name": "O'Brien & Søn",
    "email": "aase_marie+jobs@example.invalid",
    "phone": "+45 (12) 34-56.78",
    "address": "Æblevej 1, 2. tv, 1234 Østby",
    "linkedin": "https://www.linkedin.com/in/%C3%A5se-marie",
    "website": "https://example.invalid/~aase/cv",
}

TEST_PASSPHRASE = "correct horse battery staple (test only)"
