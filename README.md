# Password Lab Pro

A modular desktop password strength checker and secure password/passphrase generator built with **Python 3.10+, Tkinter, regular expressions, strings, and `secrets`**.

## Features

- Live strength score from 0–100 with five labels: Very Weak, Weak, Fair, Strong, Very Strong.
- Character composition checks, whitespace and Unicode notes, exact length reporting, and a local common-password blocklist.
- Heuristic detection of repeated characters/pairs/substrings, sequences, keyboard walks, common words, leetspeak, predictable suffixes, years, and optional personal information.
- Estimated entropy display, explicitly labelled as an estimate.
- Cryptographically secure password generator with adjustable length, character groups, ambiguous-character exclusion, and multiple suggestions.
- Memorable passphrase generation.
- Copy-to-clipboard and clear controls.
- Password analysis runs locally; there are no network requests, logs, or password files.
- Unit tests for major weakness categories and generator behavior.

## Run

Python 3.10+ is recommended. Tkinter is included with most Windows/macOS Python installers.

```bash
python main.py
```

Run tests:

```bash
python -m unittest -v
```

On some Linux distributions, Tkinter may need a system package such as `python3-tk`.

## Files

```text
Password_Strength_Checker_Pro/
├── main.py
├── analyzer.py
├── generator.py
├── test_password_lab.py
└── README.md
```

## Design notes and limitations

- **The score is a transparent heuristic, not a formal measurement of real-world guess resistance.** Its entropy figure is a rough character-pool estimate adjusted for detected patterns, not a calibrated attacker model.
- The built-in blocklist and word list are intentionally small offline examples. They are not a comprehensive dictionary or breach corpus. You can extend them with a locally stored blocklist, but avoid shipping huge lists without understanding licensing and memory costs.
- No external compromised-password service is called. For optional future integration, use a k-anonymity range-query design (send only a short hash prefix, never the raw password) and explain the privacy trade-off to users.
- Personal information is optional and only used in memory during analysis. Avoid typing sensitive data into a shared computer.
- The app does not silently trim, normalize, or truncate passwords. Python's `len()` counts Unicode code points, which may differ from visible grapheme clusters.
- The clipboard is controlled by the operating system and may be readable by other applications. Clear it after use on shared devices.
- A long, unique random password or a long random passphrase is usually preferable to a short password that merely satisfies character-class rules.

## Academic concepts demonstrated

| Concept | Use |
|---|---|
| Regex (`re`) | Character groups, whitespace, repeated runs, suffixes and common patterns |
| Strings and sequence analysis | Keyboard walks, substrings, transformations and passphrases |
| Tkinter / ttk | GUI, notebook tabs, controls, progress bar, checklist and feedback |
| `secrets` | Secure random selection and shuffling |
| `threading` + `queue` | Keep analysis work off the GUI event loop |
| `unittest` | Automated functional tests |
| Dataclasses | Structured analysis findings and results |
