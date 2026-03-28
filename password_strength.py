import sys
import math
import hashlib
import requests
from difflib import SequenceMatcher
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
import secrets
import string
import json
import os
from datetime import datetime, timezone

console = Console()

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))


def mask_password(pw):
    """Mask for display and storage; never leaks full password for len <= 2."""
    n = len(pw)
    if n == 0:
        return ""
    if n <= 2:
        return "*" * n
    return pw[0] + "*" * (n - 2) + pw[-1]


def _levenshtein(a, b):
    """Classic edit distance for short blacklist strings."""
    m, n = len(a), len(b)
    if m < n:
        a, b = b, a
        m, n = n, m
    prev = list(range(n + 1))
    for i in range(1, m + 1):
        cur = [i] + [0] * n
        ai = a[i - 1]
        for j in range(1, n + 1):
            cost = 0 if ai == b[j - 1] else 1
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
        prev = cur
    return prev[n]


def _similar_to_blacklist(normalized_pw, word, ratio_threshold=0.88):
    """Leet-normalized equality already handled; ratio only for longer strings to limit false positives."""
    if len(word) < 4:
        return False
    lo, hi = len(normalized_pw), len(word)
    shortest = min(lo, hi)
    longest = max(lo, hi)
    if shortest >= 6 and longest >= 6:
        if SequenceMatcher(None, normalized_pw, word).ratio() >= ratio_threshold:
            return True
    if shortest >= 6 and abs(lo - hi) <= 3 and _levenshtein(normalized_pw, word) <= 2:
        return True
    return False


class SecurityValidator:
    """Handles all logic related to checking if a password is safe or breached."""

    def __init__(self, blacklist_path=None):
        self.improvements = []
        self.score = 0
        self.blacklist_path = blacklist_path or os.path.join(SCRIPT_DIR, "common_passwords.txt")

    def check_pwned_api(self, password):
        """Checks HaveIBeenPwned API using k-Anonymity; parses range lines correctly."""
        sha1_password = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
        prefix, suffix = sha1_password[:5], sha1_password[5:]
        try:
            response = requests.get(
                f"https://api.pwnedpasswords.com/range/{prefix}", timeout=5
            )
            if response.status_code == 200:
                for line in response.text.splitlines():
                    line = line.strip()
                    if not line or ":" not in line:
                        continue
                    hash_suffix = line.split(":", 1)[0].strip().upper()
                    if hash_suffix == suffix:
                        self.improvements.append(
                            "🚨 Found in data breaches! This password is compromised."
                        )
                        return True
            else:
                console.print(
                    f"[yellow]Pwned Passwords API returned HTTP {response.status_code}; "
                    "breach status unknown (treated as not listed).[/yellow]"
                )
        except Exception as e:
            console.print(f"[yellow]Skipping API check: {e}[/yellow]")
        return False

    def check_blacklist_and_fuzzy(self, password):
        """Common passwords, leet normalization, and similarity (ratio / edit distance)."""
        normalized_pw = (
            password.lower()
            .replace("0", "o")
            .replace("1", "i")
            .replace("3", "e")
            .replace("5", "s")
            .replace("7", "t")
            .replace("@", "a")
            .replace("$", "s")
        )
        try:
            with open(self.blacklist_path, "r", encoding="utf-8") as f:
                common_list = [line.strip().lower() for line in f if line.strip()]
            if password.lower() in common_list:
                self.improvements.append("Password is on a common blacklist.")
                return True
            for word in common_list:
                if normalized_pw == word:
                    self.improvements.append(
                        "Password is too similar to a blacklisted word (leet / fuzzy match)."
                    )
                    return True
                if _similar_to_blacklist(normalized_pw, word):
                    self.improvements.append(
                        "Password is too similar to a blacklisted word (similarity check)."
                    )
                    return True
        except FileNotFoundError:
            console.print(
                f"[yellow]Warning: blacklist not found at {self.blacklist_path}.[/yellow]"
            )
        return False

    def validate_rules(self, password, add_feedback=True):
        """Length and complexity; optional suppression when breach/blacklist already failed."""
        if len(password) < 12:
            if add_feedback:
                self.improvements.append("Increase length to at least 12 characters.")
        else:
            self.score += 1

        # Unicode-aware: letters/digits per str methods; symbols = not alphanumeric
        rules = (
            (
                "uppercase letter",
                lambda p: any(c.isupper() for c in p),
            ),
            (
                "lowercase letter",
                lambda p: any(c.islower() for c in p),
            ),
            (
                "digit",
                lambda p: any(c.isdigit() for c in p),
            ),
            (
                "symbol or punctuation",
                lambda p: any(not c.isalnum() for c in p),
            ),
        )
        for label, pred in rules:
            if pred(password):
                self.score += 1
            elif add_feedback:
                self.improvements.append(f"Add at least one {label}.")


class DataArchitect:
    """Mathematical scoring, suggestions, history, and JSON export."""

    def __init__(self, history_file=None, report_file=None):
        self.history_file = history_file or os.path.join(SCRIPT_DIR, "history.json")
        self.report_file = report_file or os.path.join(SCRIPT_DIR, "report.json")

    def calculate_entropy(self, password):
        """Shannon entropy H over character frequencies (bits per character)."""
        if not password:
            return 0
        probs = [
            float(password.count(c)) / len(password) for c in dict.fromkeys(list(password))
        ]
        return -sum(p * math.log2(p) for p in probs if p > 0)

    def generate_suggestion(self):
        """16 chars, cryptographically random, guaranteed upper/lower/digit/special."""
        spec_chars = string.punctuation
        pool = string.ascii_letters + string.digits + spec_chars
        required = [
            secrets.choice(string.ascii_lowercase),
            secrets.choice(string.ascii_uppercase),
            secrets.choice(string.digits),
            secrets.choice(spec_chars),
        ]
        rest = [secrets.choice(pool) for _ in range(12)]
        chars = required + rest
        secrets.SystemRandom().shuffle(chars)
        return "".join(chars)

    def save_to_history(self, entry):
        """Last 5 audits; entries must not contain plaintext passwords."""
        history = []
        if os.path.exists(self.history_file):
            with open(self.history_file, "r", encoding="utf-8") as f:
                try:
                    history = json.load(f)
                except json.JSONDecodeError:
                    history = []

        history.insert(0, entry)
        history = history[:5]

        with open(self.history_file, "w", encoding="utf-8") as f:
            json.dump(history, f, indent=4)

    def export_json(self, data):
        """Full audit payload for integrations."""
        with open(self.report_file, "w", encoding="utf-8") as jf:
            json.dump(data, jf, indent=4)
        console.print(f"[dim italic]Report exported to {self.report_file}[/dim italic]")


class PasswordUI:
    """Terminal I/O and Rich dashboard."""

    def get_user_password(self):
        pw = input("\n🛡️  Enter password to analyze (or 'h' for history, 'q' to quit): ")
        if pw.lower() == "q":
            sys.exit()
        return pw

    def show_history(self, history_file):
        if not os.path.exists(history_file):
            console.print("[yellow]No history found.[/yellow]")
            return

        with open(history_file, "r", encoding="utf-8") as f:
            history = json.load(f)

        table = Table(
            title="📜 Audit History (Last 5)",
            show_header=True,
            header_style="bold yellow",
        )
        table.add_column("Password (Masked)", style="dim")
        table.add_column("Score", justify="center")
        table.add_column("Entropy (H)", justify="right")

        for item in history:
            masked = item.get("password_masked")
            if masked is None and "password" in item:
                masked = mask_password(item["password"])
            elif masked is None:
                masked = "—"
            ent = item.get("entropy", 0)
            table.add_row(masked, str(item.get("score", "—")), f"{float(ent):.2f}")

        console.print(table)

    def render_report(self, pw, score, entropy, improvements):
        h_per_char = entropy
        total_est = h_per_char * len(pw) if pw else 0
        table = Table(
            title="🏗️  Architect's Report",
            show_header=True,
            header_style="bold cyan",
        )
        table.add_row("Length", str(len(pw)))
        table.add_row(
            "Entropy (Shannon H)",
            f"{h_per_char:.2f} bits/character",
        )
        table.add_row(
            "Entropy × length",
            f"{total_est:.2f} bits (rough upper bound on H×n; not guessing resistance)",
        )
        table.add_row(
            "Score",
            f"{score}/5",
            style="bold green" if score >= 4 else "bold red",
        )
        console.print(table)

        if improvements:
            text = "\n".join([f"• {i}" for i in improvements])
            console.print(
                Panel(text, title="[bold red]Improvements[/bold red]", border_style="red")
            )
        else:
            console.print(Panel("[bold green]✅ Meets Architect Standards![/bold green]"))


class PasswordArchitect:
    """Orchestrates validation, reporting, and persistence."""

    def __init__(self):
        self.ui = PasswordUI()
        self.data = DataArchitect()

    def run_analysis(self):
        user_input = self.ui.get_user_password()

        if user_input.lower() == "h":
            self.ui.show_history(self.data.history_file)
            return

        password = user_input
        validator = SecurityValidator()

        pwned = validator.check_pwned_api(password)
        blacklisted = validator.check_blacklist_and_fuzzy(password)
        blocked = pwned or blacklisted
        validator.validate_rules(password, add_feedback=not blocked)

        entropy = self.data.calculate_entropy(password)
        final_score = 0 if blocked else validator.score

        if final_score < 4:
            suggestion = self.data.generate_suggestion()
            console.print(
                Panel(
                    f"Try: [bold cyan]{suggestion}[/bold cyan]",
                    title="Architect Suggestion",
                )
            )

        self.ui.render_report(password, final_score, entropy, validator.improvements)

        entry = {
            "password_masked": mask_password(password),
            "score": final_score,
            "entropy": round(entropy, 4),
            "audited_at": datetime.now(timezone.utc).isoformat(),
        }
        self.data.save_to_history(entry)

        report = {
            "password_masked": entry["password_masked"],
            "length": len(password),
            "score": final_score,
            "entropy_bits_per_character": round(entropy, 4),
            "entropy_times_length_bits": round(entropy * len(password), 4) if password else 0,
            "pwned": pwned,
            "blacklisted": blacklisted,
            "improvements": validator.improvements,
            "audited_at": entry["audited_at"],
        }
        self.data.export_json(report)


if __name__ == "__main__":
    app = PasswordArchitect()
    while True:
        app.run_analysis()
