# 🔐 Password Lab

**A local-first desktop app that checks how strong a password is and generates secure passwords and passphrases.**

Built with **Python 3.10+**, **Tkinter**, **regular expressions** and the **`secrets`** module. No internet, no accounts, no logs: everything runs on your own machine.

> Academic project · A.D. Patel Institute of Technology (ADIT), CVM University · Enrollment No. 12502080603002

---

## Table of Contents

1. [Features](#features)
2. [Quick Start](#quick-start)
3. [How to Use](#how-to-use)
4. [Project Structure](#project-structure)
   - [Documentation](#documentation)
5. [How the Strength Score Works](#how-the-strength-score-works)
6. [How Generation Works](#how-generation-works)
7. [Example Results](#example-results)
8. [Testing](#testing)
9. [Privacy and Security Notes](#privacy-and-security-notes)
10. [Known Limitations](#known-limitations)
11. [Future Improvements](#future-improvements)
12. [Concepts Demonstrated](#concepts-demonstrated)

---

## Features

### Strength Checker
- **Live score from 0 to 100** with five labels: *Very Weak, Weak, Fair, Strong, Very Strong*.
- **Character-group detection:** uppercase, lowercase, digits, special characters, whitespace and Unicode.
- **Weakness detection:**
  - common-password blocklist (including simple leetspeak such as `p@ssw0rd`)
  - repeated characters, repeated pairs and repeated substrings (`abcabcabc`)
  - sequences (`abcd`, `4321`) and keyboard walks (`qwerty`, `1qaz2wsx`)
  - common words and names, years, and "word + digits" patterns
  - optional **personal information** (name, pet, username) that must not appear in the password
- **Entropy estimate** (clearly labelled as an estimate).
- **Checklist and suggestions:** each issue comes with advice on how to fix it.
- **Show/hide** toggle and a **Clear** button.

### Generator
- **Random passwords:** length 8–128, choose uppercase / lowercase / digits / symbols, exclude look-alike characters, and get 1–8 suggestions at once. Every suggestion is scored automatically.
- **Memorable passphrases:** 3–10 random words, optional number, optional capitalization.
- **One-click copy** to the clipboard.

### Engineering
- Analysis runs on a **background thread** (with a 180 ms debounce) so typing never lags.
- **15 automated unit tests.**

---

## Quick Start

**Requirements:** Python 3.10 or newer. Tkinter ships with the standard Windows and macOS installers. No third-party packages are needed.

```bash
# 1. Clone the repository
git clone https://github.com/ayushasodariya/Password-Lab.git
cd Password-Lab

# 2. Run the app
python main.py
```

On some Linux distributions, install Tkinter first:

```bash
sudo apt install python3-tk      # Debian / Ubuntu
```

---

## How to Use

**Checking a password**
1. Open the **Strength checker** tab.
2. Type a password. The score, label, entropy, checklist and suggestions update as you type.
3. *(Optional)* Enter personal details (comma-separated) to be warned if they appear in your password.
4. Use **Show / hide** to see what you typed and **Clear** to wipe both fields.

**Generating a password**
1. Open the **Password generator** tab.
2. Choose the length, character groups and number of suggestions.
3. Click **Generate suggestions**, then **Copy** next to the one you like.

**Generating a passphrase**
1. In the same tab, choose the number of words and options.
2. Click **Generate passphrase**, then **Copy passphrase**.

---

## Project Structure

```text
Password-Lab/
├── main.py                # Tkinter GUI (PasswordLabApp), threading + queue
├── analyzer.py            # analyze_password(): rules, score, entropy
├── generator.py           # generate_password(), generate_passphrase()
├── test_password_lab.py   # 15 unit tests (unittest)
├── Report.pdf             # Project report (6 pages)
├── Presentation.pptx      # Project presentation (5 slides)
├── README.md
└── .gitignore
```

| Module | Responsibility |
|---|---|
| `analyzer.py` | Pure logic with no GUI code. Returns an `Analysis` dataclass holding the score, label, entropy, findings and checklist items. |
| `generator.py` | Pure logic with no GUI code. Uses `secrets` for all randomness. |
| `main.py` | Builds the interface, calls the two modules above and displays the results. |

### Documentation

| File | Contents |
|---|---|
| [`Report.pdf`](Report.pdf) | Full project report: abstract, design, implementation, testing, limitations, references |
| [`Presentation.pptx`](Presentation.pptx) | 5-slide presentation: problem, design, results, conclusion |

---

## How the Strength Score Works

The score is **transparent**: it is built from simple, explainable parts.

**Step 1: add points for good fundamentals**

| Component | Points |
|---|---|
| Length | `min(35, 2 × length)` |
| Character variety (upper / lower / digit / special) | `min(20, 7 × (groups − 1))` |
| Length ≥ 20 | +8 |
| Length ≥ 28 | +5 more |

**Step 2: subtract points for each problem found**

| Problem category | Penalty if *critical* | Penalty if *warning* |
|---|---|---|
| Common-password blocklist | 55 | – |
| Personal information | 35 | – |
| Predictable pattern / year / common word | 20 | 10 |
| Dictionary word or name | 18 | 9 |
| Keyboard walk | 18 | 9 |
| Repetition | 15 | 7 |
| Sequence | 12 | 6 |
| Short length | 15 | 7 |
| Weak composition | 8 | 4 |

A *warning* costs half the category penalty (never less than 3); *info* findings cost nothing.

**Step 3: apply hard caps**
- A blocklisted password can never score above **15**.
- A password shorter than 8 characters can never score above **20**.
- The final score is clamped to 0–100.

**Step 4: pick the label**

| Score | Label |
|---|---|
| 0–19 | Very Weak |
| 20–39 | Weak |
| 40–59 | Fair |
| 60–79 | Strong |
| 80–100 | Very Strong |

**Entropy estimate:** `length × log₂(pool size)`, where the pool is the sum of the groups present (26 + 26 + 10 + 33, plus 40 for Unicode), then reduced when blocklist, dictionary, repetition, sequence, keyboard or predictable findings exist.

---

## How Generation Works

**Random passwords** (`generate_password`)
1. Build one pool per enabled group (lowercase, uppercase, digits, 24 symbols).
2. Optionally remove ambiguous characters such as `O 0 o I l 1 |`.
3. Pick **one character from every enabled group**, so each chosen group is always present.
4. Fill the remaining length from the combined pool with `secrets.choice`.
5. Shuffle with `secrets.SystemRandom().shuffle`.

**Passphrases** (`generate_passphrase`)
- Pick 3–10 words with `secrets.choice` from a built-in list of 168 words, join them with `-`, and optionally add a two-digit number.

---

## Example Results

Real output from the analyzer:

| Input | Score | Label | Main findings |
|---|---|---|---|
| `password` | 0 | Very Weak | blocklist, dictionary, predictable |
| `abc` | 0 | Very Weak | too short, weak composition |
| `1qaz2wsx!` | 16 | Very Weak | keyboard walk |
| `P@ssw0rd123!` | 0 | Very Weak | leetspeak variant of a blocklisted password |
| `WelcomeSunshine123!` | 16 | Very Weak | common words, predictable |
| `Tr9#kLm2$vQx8!pZ` | 52 | Fair | none |
| `correct-horse-battery-staple-92` | 62 | Strong | none |

Sample generator output: `Ie+e#2:F5@H+VL30` and `emerald-candle-canyon-pumpkin-spirit-10`.

---

## Testing

```bash
python -m unittest -v
```

All **15 tests pass**. They cover:

| Area | Tests |
|---|---|
| Edge cases | empty password, very short password, 120-character password is not truncated |
| Weakness detection | blocklist, repetition, sequence, keyboard walk, dictionary word, leetspeak, personal information |
| Character handling | Unicode, whitespace |
| Generator | correct length and character groups, passphrase word count, invalid settings raise `ValueError` |

---

## Privacy and Security Notes

- **Everything is local.** There are no network requests, no log files and no saved passwords.
- The checker **never trims, normalizes or truncates** what you type.
- Personal details are used **in memory only** during analysis.
- All random choices use Python's **`secrets`** module, not `random`.
- The clipboard is shared with other programs. Clear it after use on shared computers.

---

## Known Limitations

- **The score is a heuristic**, not a measurement of real-world guess resistance.
- The built-in blocklist (31 entries) and word lists are **small offline samples**, not a breach database.
- The entropy figure is a character-pool estimate. It **overestimates word-based passphrases**, because it treats them like random characters. For example, a 5-word passphrase from the 168-word list has only about 43 bits of real randomness.
- Because length points are capped at 35 and variety at 20, a random password under 20 characters can score at most 55 ("Fair"). Reaching "Strong" needs the length bonus.
- Length counts Python Unicode code points, not visible characters (grapheme clusters).

---

## Future Improvements

- Use a larger audited word list (for example, 7,776 words, about 12.9 bits per word) for passphrases.
- Load a larger local blocklist from a file.
- Optional breached-password check using a **k-anonymity** range query (send only a short hash prefix, never the password).
- A more realistic entropy model that accounts for word-based passwords.
- Light/dark theme switch and automatic clipboard clearing.
- A packaged `.exe` for Windows.

---

## Concepts Demonstrated

| Concept | Where it is used |
|---|---|
| Regular expressions (`re`) | Character groups, repeated runs, suffix and year patterns |
| String processing | Keyboard walks, leetspeak translation, substring detection |
| Cryptographically secure randomness (`secrets`) | Password and passphrase generation |
| GUI programming (Tkinter / ttk) | Tabs, progress bar, checklist, dialogs |
| Concurrency (`threading` + `queue`) | Keeps the interface responsive |
| Dataclasses | `Finding` and `Analysis` result objects |
| Unit testing (`unittest`) | Automated checks of the logic |

---

## Author

**Ayush Asodariya**: B.Tech Information Technology, A.D. Patel Institute of Technology (ADIT), CVM University
GitHub: [@ayushasodariya](https://github.com/ayushasodariya)
