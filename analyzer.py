from __future__ import annotations

import math
import re
import string
import unicodedata
from dataclasses import dataclass, field
from typing import Iterable


MIN_LENGTH = 12
MAX_LENGTH = 256

COMMON_PASSWORDS = {
    "password", "password1", "password123", "password123!", "123456",
    "1234567", "12345678", "123456789", "1234567890", "qwerty",
    "qwerty123", "qwertyuiop", "admin", "admin123", "letmein",
    "welcome", "welcome1", "welcome123", "iloveyou", "monkey",
    "dragon", "abc123", "111111", "000000", "123123", "passw0rd",
    "p@ssw0rd", "changeme", "secret", "football", "baseball",
}
COMMON_WORDS = {
    "password", "welcome", "admin", "letmein", "love", "iloveyou",
    "hello", "secret", "qwerty", "monkey", "dragon", "football",
    "baseball", "sunshine", "princess", "master", "login", "user",
    "summer", "winter", "spring", "autumn", "happy", "family",
    "friend", "computer", "freedom", "whatever", "star", "flower",
    "angel", "shadow", "killer", "trustno", "coffee", "cookie",
    "apple", "orange", "purple", "blue", "green", "black", "white",
}
COMMON_NAMES = {"john", "michael", "jessica", "daniel", "ashley", "robert", "ayush"}
KEYBOARD_ROWS = ("qwertyuiop", "asdfghjkl", "zxcvbnm")
KEYBOARD_REVERSED = tuple(row[::-1] for row in KEYBOARD_ROWS)
LEET_TRANSLATION = str.maketrans({
    "@": "a", "4": "a", "8": "b", "(": "c", "3": "e", "6": "g",
    "1": "i", "!": "i", "0": "o", "$": "s", "5": "s", "7": "t",
    "+": "t", "2": "z",
})


@dataclass
class Finding:
    category: str
    message: str
    severity: str = "warning"  # info, warning, critical
    suggestion: str = ""


@dataclass
class Analysis:
    score: int
    label: str
    length: int
    entropy_bits_estimate: float
    character_groups: dict[str, bool]
    findings: list[Finding] = field(default_factory=list)
    passed_checks: list[str] = field(default_factory=list)
    failed_checks: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


def _has_keyboard_pattern(text: str, min_run: int = 4) -> bool:
    normalized = text.lower()
    for row in KEYBOARD_ROWS + KEYBOARD_REVERSED:
        doubled = row + row
        for n in range(min_run, len(row) + 1):
            for i in range(len(doubled) - n + 1):
                fragment = doubled[i:i+n]
                if fragment in normalized:
                    return True
    # Common keyboard walks and vertical/diagonal paths.
    patterns = ("1qaz", "2wsx", "3edc", "4rfv", "5tgb", "6yhn",
                "7ujm", "8ik,", "9ol.", "qazx", "wsxc", "edcv",
                "zaq1", "xsw2", "cde3", "qweasdzxc", "1qaz2wsx")
    return any(p in normalized for p in patterns)


def _has_sequence(text: str, run: int = 4) -> bool:
    """Detect ascending/descending ASCII alphanumeric runs and alternating patterns."""
    s = text.lower()
    for i in range(len(s) - run + 1):
        chunk = s[i:i+run]
        if all(ord(chunk[j+1]) - ord(chunk[j]) == 1 for j in range(len(chunk)-1)):
            if chunk.isalnum():
                return True
        if all(ord(chunk[j+1]) - ord(chunk[j]) == -1 for j in range(len(chunk)-1)):
            if chunk.isalnum():
                return True
    # Alternating ABAB or 1212-style patterns.
    for period in (1, 2):
        for i in range(max(0, len(s) - 7)):
            part = s[i:i+8]
            if len(part) == 8 and part == (part[:period] * (8 // period)):
                return True
    return False


def _repeated_substring(text: str) -> bool:
    if len(text) < 6:
        return False
    for width in range(1, len(text) // 2 + 1):
        if len(text) % width == 0:
            unit = text[:width]
            if unit * (len(text) // width) == text:
                return True
        # Also catch abcabcabc when not the entire password.
        if width >= 2:
            for start in range(0, len(text) - width * 3 + 1):
                unit = text[start:start+width]
                if text.startswith(unit * 3, start):
                    return True
    return False


def _dictionary_matches(password: str) -> list[str]:
    lowered = password.casefold()
    normalized = lowered.translate(LEET_TRANSLATION)
    # Keep alpha runs so punctuation does not hide common words.
    runs = re.findall(r"[^\W\d_]+", normalized, flags=re.UNICODE)
    matches = []
    for word in COMMON_WORDS | COMMON_NAMES:
        if word in normalized or word in runs:
            matches.append(word)
    # Detect common word + optional digits/year/symbol patterns.
    if re.fullmatch(r"(?i)(password|welcome|admin|letmein|qwerty|iloveyou|monkey|dragon)[^a-z]*\d{0,4}[^a-z]*", password):
        matches.append("common-word-plus-suffix")
    return sorted(set(matches))


def _estimate_entropy(password: str, groups: dict[str, bool], findings: list[Finding]) -> float:
    """Naive character-pool estimate adjusted downward for obvious patterns."""
    if not password:
        return 0.0
    pool = 0
    if groups["lowercase"]:
        pool += 26
    if groups["uppercase"]:
        pool += 26
    if groups["digits"]:
        pool += 10
    if groups["special"]:
        pool += 33
    if groups["unicode"]:
        # Don't pretend all Unicode code points are equally likely; modest allowance only.
        pool += 40
    if pool == 0:
        pool = 1
    estimate = len(password) * math.log2(pool)
    reduction = 0.0
    for finding in findings:
        if finding.category in {"blocklist", "dictionary"}:
            reduction += min(35, estimate * 0.35)
        elif finding.category in {"repetition", "sequence", "keyboard", "predictable"}:
            reduction += min(20, estimate * 0.20)
    return max(0.0, round(estimate - min(estimate * 0.8, reduction), 1))


def analyze_password(password: str, personal_info: Iterable[str] | None = None,
                     blocklist: set[str] | None = None) -> Analysis:
    """Analyze password as typed; never normalize or modify the original password."""
    findings: list[Finding] = []
    passed: list[str] = []
    failed: list[str] = []
    warnings: list[str] = []
    length = len(password)  # Python Unicode code points; grapheme clusters may differ.

    def add(category: str, message: str, severity: str = "warning", suggestion: str = ""):
        findings.append(Finding(category, message, severity, suggestion))

    if not password:
        add("length", "Password is empty.", "critical", "Enter a password or generate one.")
    elif length < 8:
        add("length", f"Very short password ({length} characters).", "critical",
            "Use at least 12 characters; longer is generally better.")
    elif length < MIN_LENGTH:
        add("length", f"Shorter than the recommended {MIN_LENGTH} characters.", "warning",
            f"Prefer {MIN_LENGTH}–16+ characters.")
    elif length >= 16:
        passed.append("Length is 16 or more characters")
    else:
        passed.append(f"Length is at least {MIN_LENGTH} characters")
    if length > 64:
        add("length", "Long password/passphrase; check the target site's maximum.", "info",
            "Long passphrases can be excellent if the website supports them.")
    if length > MAX_LENGTH:
        add("length", f"Exceeds this tool's analysis limit of {MAX_LENGTH} characters.", "critical",
            "Use a shorter password within the tool limit; it has not been truncated.")

    groups = {
        "uppercase": bool(re.search(r"[A-Z]", password)),
        "lowercase": bool(re.search(r"[a-z]", password)),
        "digits": bool(re.search(r"\d", password)),
        "special": bool(re.search(r"[^A-Za-z0-9\s]", password)),
        "whitespace": bool(re.search(r"\s", password)),
        "unicode": any(ord(ch) > 127 for ch in password),
        "letters_only": bool(password) and bool(re.fullmatch(r"[^\W\d_]+", password, re.UNICODE)),
        "numbers_only": bool(password) and bool(re.fullmatch(r"\d+", password)),
        "alphanumeric_only": bool(password) and bool(re.fullmatch(r"[A-Za-z0-9]+", password)),
    }
    present_groups = sum(groups[k] for k in ("uppercase", "lowercase", "digits", "special"))
    if groups["uppercase"]: passed.append("Contains uppercase letters")
    if groups["lowercase"]: passed.append("Contains lowercase letters")
    if groups["digits"]: passed.append("Contains digits")
    if groups["special"]: passed.append("Contains special characters")
    if present_groups <= 1 and password:
        add("composition", "Very limited character variety.", "warning",
            "Prefer a longer password or passphrase; character variety alone does not guarantee strength.")
    if groups["letters_only"]:
        add("composition", "Letters-only password.", "warning",
            "Increase length substantially or use a randomly generated passphrase.")
    if groups["numbers_only"]:
        add("composition", "Numbers-only password.", "critical",
            "Avoid numeric-only passwords; they are easy to guess.")
    if groups["alphanumeric_only"] and not groups["special"]:
        add("composition", "Contains only ASCII letters and digits.", "info",
            "A longer random password can still be strong; symbols are optional, not mandatory.")
    if groups["whitespace"]:
        if password != password.strip():
            add("whitespace", "Leading or trailing whitespace detected.", "warning",
                "Remove unintended spaces manually; the checker never changes your input.")
        if re.search(r"\s", password.strip()):
            add("whitespace", "Internal whitespace detected (may be intentional in a passphrase).",
                "info", "Confirm the website accepts spaces and preserve them exactly.")
    if groups["unicode"]:
        add("unicode", "Unicode characters detected.", "info",
            "Unicode may be valid, but verify the target service handles it consistently.")
        warnings.append("Length counts Python Unicode code points, not user-perceived grapheme clusters.")

    if length >= 12 and present_groups >= 2:
        passed.append("Reasonable length and character variety")

    lowered = password.casefold()
    normalized_leet = lowered.translate(LEET_TRANSLATION)
    active_blocklist = COMMON_PASSWORDS if blocklist is None else {p.casefold() for p in blocklist}
    if lowered in active_blocklist or normalized_leet in {p.translate(LEET_TRANSLATION) for p in active_blocklist}:
        add("blocklist", "Matches a known common/weak password or a simple leetspeak variant.",
            "critical", "Use a unique randomly generated password or a long random passphrase.")
    else:
        passed.append("Not an exact match for the local common-password blocklist")

    repeated = bool(re.search(r"(.)\1{2,}", password, re.DOTALL))
    if repeated:
        add("repetition", "Three or more identical consecutive characters.", "warning",
            "Avoid runs such as 'aaaa' or '1111'.")
    if password and len(set(password)) == 1:
        add("repetition", "Every character is identical.", "critical",
            "Generate a new password with varied characters.")
    if re.search(r"(..)\1{1,}", password):
        add("repetition", "Repeated adjacent pair detected.", "warning",
            "Avoid repeating pairs such as 'abab' or '1212'.")
    if _repeated_substring(password):
        add("repetition", "Repeated substring detected (for example, 'abcabcabc').",
            "warning", "Use a non-repeating random string or passphrase.")
    if re.search(r"(\d)\1{2,}", password):
        add("repetition", "Repeated digit run detected.", "warning", "Avoid repeated digit runs.")
    if re.search(r"([^\w\s])\1{2,}", password):
        add("repetition", "Repeated symbol run detected.", "info", "Repeated symbols add little unpredictability.")
    if _has_sequence(password):
        add("sequence", "Ascending, descending, or alternating sequence detected.",
            "warning", "Avoid sequences such as 'abcd', '4321', or 'abababab'.")
    if _has_keyboard_pattern(password):
        add("keyboard", "Keyboard-row, reversed-row, or keyboard-walk pattern detected.",
            "warning", "Avoid keyboard walks such as 'qwerty', 'asdf', or '1qaz2wsx'.")

    dictionary_matches = _dictionary_matches(password)
    if dictionary_matches:
        visible = ", ".join(dictionary_matches[:4])
        add("dictionary", f"Common word/name or predictable phrase detected ({visible}).",
            "warning", "Avoid common words, names, and familiar phrases unless used in a long random word sequence.")
    elif length:
        passed.append("No obvious match to the built-in common-word list")

    # Predictable suffixes, years, simple capitalization, and common transformed words.
    if re.search(r"(19\d{2}|20\d{2})", password):
        add("predictable", "A year-like number was detected.", "info",
            "Years and dates are often guessed; avoid personal or predictable dates.")
    if re.search(r"(?i)(password|welcome|admin|qwerty|letmein|iloveyou|passw0rd|p@ssw0rd)", password):
        add("predictable", "Contains a highly predictable password word or variation.",
            "critical", "Do not rely on capitalization, a trailing number, or symbol substitutions.")
    if re.fullmatch(r"(?i)[a-z]+[!@#$%^&*]*\d{1,4}[!@#$%^&*]*", password) and dictionary_matches:
        add("predictable", "Common word followed by digits/symbols pattern detected.",
            "warning", "Use a unique generated password instead of a word plus suffix.")
    if re.search(r"(?i)(.)\1{1,}", password):
        # Captures repeated characters independent of case; detailed repetition finding above.
        pass

    info_values = [str(v).strip().casefold() for v in (personal_info or []) if str(v).strip()]
    for value in info_values:
        if len(value) >= 3 and value in lowered:
            add("personal", "A user-provided personal-information value appears in the password.",
                "critical", "Avoid names, usernames, pet names, dates, phone numbers, and other personal details.")
            break
        value_leet = value.translate(LEET_TRANSLATION)
        if len(value_leet) >= 3 and value_leet in normalized_leet:
            add("personal", "A leetspeak variation of personal information appears in the password.",
                "critical", "Avoid personal details even when letters are replaced with symbols or digits.")
            break

    # Score is transparent and heuristic: positive fundamentals minus detected risks.
    if not password:
        score = 0
    else:
        score = 0
        score += min(35, length * 2)  # length matters most, capped
        score += min(20, max(0, present_groups - 1) * 7)
        # Mild bonus for long passphrases; words alone do not imply randomness.
        if length >= 20:
            score += 8
        if length >= 28:
            score += 5
        penalties = {
            "blocklist": 55, "dictionary": 18, "predictable": 20, "keyboard": 18,
            "sequence": 12, "repetition": 15, "personal": 35, "whitespace": 0,
            "composition": 8, "length": 15, "unicode": 0,
        }
        for finding in findings:
            if finding.severity == "critical":
                score -= penalties.get(finding.category, 10)
            elif finding.severity == "warning":
                score -= max(3, penalties.get(finding.category, 5) // 2)
        # Do not reward diversity enough to rescue a blocklisted password.
        if any(f.category == "blocklist" for f in findings):
            score = min(score, 15)
        if length < 8:
            score = min(score, 20)
        score = max(0, min(100, score))

    if score < 20:
        label = "Very Weak"
    elif score < 40:
        label = "Weak"
    elif score < 60:
        label = "Fair"
    elif score < 80:
        label = "Strong"
    else:
        label = "Very Strong"

    entropy = _estimate_entropy(password, groups, findings)
    if findings:
        for finding in findings:
            if finding.suggestion:
                warnings.append(finding.suggestion)
    else:
        passed.append("No obvious weaknesses detected by this heuristic checker")

    # De-duplicate while preserving order.
    warnings = list(dict.fromkeys(warnings))
    return Analysis(score, label, length, entropy, groups, findings, passed, failed, warnings)
