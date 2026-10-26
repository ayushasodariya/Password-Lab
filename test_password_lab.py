import unittest

from analyzer import analyze_password
from generator import generate_password, generate_passphrase


class PasswordAnalyzerTests(unittest.TestCase):
    def test_empty_password(self):
        result = analyze_password("")
        self.assertEqual(result.score, 0)
        self.assertEqual(result.label, "Very Weak")

    def test_short_password(self):
        result = analyze_password("abc")
        self.assertTrue(any(f.category == "length" for f in result.findings))

    def test_long_password_is_not_truncated(self):
        password = "Ab3!" * 30
        result = analyze_password(password)
        self.assertEqual(result.length, len(password))

    def test_common_password(self):
        result = analyze_password("password")
        self.assertTrue(any(f.category == "blocklist" for f in result.findings))
        self.assertLessEqual(result.score, 15)

    def test_repeated_characters(self):
        result = analyze_password("aaaaaaaA1!")
        self.assertTrue(any(f.category == "repetition" for f in result.findings))

    def test_sequence(self):
        result = analyze_password("abcd1234!Q")
        self.assertTrue(any(f.category == "sequence" for f in result.findings))

    def test_keyboard_pattern(self):
        result = analyze_password("1qaz2wsx!")
        self.assertTrue(any(f.category == "keyboard" for f in result.findings))

    def test_dictionary_word(self):
        result = analyze_password("WelcomeSunshine123!")
        self.assertTrue(any(f.category in {"dictionary", "predictable"} for f in result.findings))

    def test_leetspeak(self):
        result = analyze_password("P@ssw0rd123!")
        self.assertTrue(any(f.category in {"blocklist", "dictionary", "predictable"} for f in result.findings))

    def test_unicode(self):
        result = analyze_password("correct-horse-🐎-battery")
        self.assertTrue(result.character_groups["unicode"])

    def test_whitespace(self):
        result = analyze_password("  abc123!  ")
        self.assertTrue(result.character_groups["whitespace"])
        self.assertTrue(any(f.category == "whitespace" for f in result.findings))

    def test_personal_information(self):
        result = analyze_password("MyFluffyDog2024!", personal_info=["Fluffy"])
        self.assertTrue(any(f.category == "personal" for f in result.findings))

    def test_generated_password_length_and_groups(self):
        password = generate_password(24)
        self.assertEqual(len(password), 24)
        self.assertTrue(any(c.islower() for c in password))
        self.assertTrue(any(c.isupper() for c in password))
        self.assertTrue(any(c.isdigit() for c in password))
        self.assertTrue(any(not c.isalnum() for c in password))

    def test_generated_passphrase(self):
        phrase = generate_passphrase(5, add_number=True)
        self.assertGreaterEqual(len(phrase.split("-")), 6)

    def test_invalid_generator_settings(self):
        with self.assertRaises(ValueError):
            generate_password(7)
        with self.assertRaises(ValueError):
            generate_password(12, False, False, False, False)


if __name__ == "__main__":
    unittest.main()
