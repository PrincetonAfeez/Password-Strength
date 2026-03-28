import re  # Library for Regular Expression pattern matching
import sys  # Library for system-level operations like exiting the script
import math  # Library for mathematical functions (used for Shannon Entropy)
import hashlib  # Library for generating secure hashes (SHA-1 for API check)
import requests  # Library for making HTTP requests to the HIBP API
from rich.console import Console  # Rich tool for advanced terminal output
from rich.table import Table  # Rich tool for creating formatted data tables
from rich.panel import Panel  # Rich tool for displaying text in bordered boxes
import secrets  # Library for generating cryptographically secure random numbers
import string  # Library for string operations
import json  # Library for JSON operations
import os  # Library for operating system interactions (file checks)

# Initialize the Rich Console for professional CLI formatting
console = Console()

class SecurityValidator:
    """Handles all logic related to checking if a password is safe or breached."""
    
    def __init__(self):
        self.improvements = []  # List to store feedback strings for the current session
        self.score = 0  # Numerical strength rating (0-5)

    def check_pwned_api(self, password):
        """Advanced: Checks HaveIBeenPwned API using k-Anonymity (Privacy-First)."""
        sha1_password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()  # Secure SHA-1 hash
        prefix, suffix = sha1_password[:5], sha1_password[5:]  # Prefix-based anonymity
        try:
            response = requests.get(f"https://api.pwnedpasswords.com/range/{prefix}", timeout=5)  # API request
            if response.status_code == 200:  # Successful connection
                if suffix in response.text:  # Check if our suffix is in the leaked list
                    self.improvements.append("🚨 Found in data breaches! This password is compromised.")
                    return True  # Found in breach
        except Exception as e:  # Graceful error handling for network issues
            console.print(f"[yellow]Skipping API check: {e}[/yellow]")
        return False

    def check_blacklist_and_fuzzy(self, password):
        """AC 4 & Feature 6: Check against 'Common Passwords' and similar variations."""
        # Normalize password to catch 'leet-speak' variations (e.g., @ instead of a)
        normalized_pw = password.lower().replace("0", "o").replace("1", "i").replace("@", "a")
        try:
            with open("common_passwords.txt", "r") as f:  # Open local security file
                common_list = [line.strip().lower() for line in f.readlines()]  # Load list
                if password.lower() in common_list:  # Direct match
                    self.improvements.append("Password is on a common blacklist.")
                    return True
                for word in common_list:  # Fuzzy match check
                    if normalized_pw == word:
                        self.improvements.append("Password is too similar to a blacklisted word (Fuzzy Match).")
                        return True
        except FileNotFoundError:  # Error handling for missing local resources
            console.print("[yellow]Warning: common_passwords.txt not found.[/yellow]")
        return False

    def validate_rules(self, password):
        """AC 2 & AC 3: Checks length and complexity requirements."""
        if len(password) < 12:  # Architectural standard: minimum 12 chars
            self.improvements.append("Increase length to at least 12 characters.")
        else:
            self.score += 1  # Award point for length compliance

        # Defined complexity patterns for validation
        patterns = {"upper": r'[A-Z]', "lower": r'[a-z]', "num": r'[0-9]', "spec": r'[!@#$%^&]'}
        for name, pattern in patterns.items():  # Iterate through each rule
            if re.search(pattern, password):  # Pattern exists
                self.score += 1  # Award point for complexity
            else:
                self.improvements.append(f"Add at least one {name} character.")

class DataArchitect:
    """Handles mathematical scoring, suggestions, data persistence, and history."""
    
    def __init__(self, history_file="history.json"):
        self.history_file = history_file  # Storage location for session history

    def calculate_entropy(self, password):
        """Advanced: Calculates Shannon Entropy to measure mathematical randomness."""
        if not password: return 0  # Guard clause
        # Calculate frequency of each character
        probs = [float(password.count(c)) / len(password) for c in dict.fromkeys(list(password))]
        # Shannon Formula: H = -sum(p * log2(p))
        entropy = - sum(p * math.log2(p) for p in probs if p > 0)
        return entropy

    def generate_suggestion(self):
        """Feature 4: Generates a cryptographically secure 16-char password suggestion."""
        pool = string.ascii_letters + string.digits + "!@#$%^&"  # Secure pool
        return ''.join(secrets.choice(pool) for _ in range(16))  # Cryptographically random

    def save_to_history(self, entry):
        """New Feature: Maintains a history of the last 5 password audits."""
        history = []  # Initialize empty history
        if os.path.exists(self.history_file):  # Check if previous history exists
            with open(self.history_file, "r") as f:
                try:
                    history = json.load(f)  # Load existing data
                except json.JSONDecodeError:
                    history = []  # Handle corrupt file
        
        history.insert(0, entry)  # Add new entry to the front
        history = history[:5]  # Limit to 5 entries for storage efficiency
        
        with open(self.history_file, "w") as f:
            json.dump(history, f, indent=4)  # Write back to file

    def export_json(self, data):
        """Feature 5: Exports report data to JSON for system integration."""
        with open("report.json", "w") as jf:
            json.dump(data, jf, indent=4)
        console.print("[dim italic]Report exported to report.json[/dim italic]")

class PasswordUI:
    """Handles all terminal input and output (The Presentation Layer)."""
    
    def get_user_password(self):
        """Captures input and handles exit commands."""
        pw = input("\n🛡️  Enter password to analyze (or 'h' for history, 'q' to quit): ")
        if pw.lower() == 'q': sys.exit()  # Exit logic
        return pw

    def show_history(self, history_file="history.json"):
        """Displays the recent audit history in a table."""
        if not os.path.exists(history_file):
            console.print("[yellow]No history found.[/yellow]")
            return
            
        with open(history_file, "r") as f:
            history = json.load(f)
            
        table = Table(title="📜 Audit History (Last 5)", show_header=True, header_style="bold yellow")
        table.add_column("Password (Masked)", style="dim")
        table.add_column("Score", justify="center")
        table.add_column("Entropy", justify="right")
        
        for item in history:
            # Mask the password for security in history view
            masked = item['password'][0] + "*" * (len(item['password'])-2) + item['password'][-1]
            table.add_row(masked, str(item['score']), f"{item['entropy']:.2f}")
        
        console.print(table)

    def render_report(self, pw, score, entropy, improvements):
        """Renders the professional Rich Dashboard."""
        table = Table(title="🏗️  Architect's Report", show_header=True, header_style="bold cyan")
        table.add_row("Length", str(len(pw)))
        table.add_row("Entropy", f"{entropy:.2f} bits")
        table.add_row("Score", f"{score}/5", style="bold green" if score >= 4 else "bold red")
        console.print(table)
        
        if improvements:  # Provide constructive feedback
            text = "\n".join([f"• {i}" for i in improvements])
            console.print(Panel(text, title="[bold red]Improvements[/bold red]", border_style="red"))
        else:  # Reward high-standard security
            console.print(Panel("[bold green]✅ Meets Architect Standards![/bold green]"))

class PasswordArchitect:
    """The Main Orchestrator that connects all components (System Hub)."""
    
    def __init__(self):
        self.ui = PasswordUI()  # Presentation layer
        self.data = DataArchitect()  # Logic/Data layer
        
    def run_analysis(self):
        """Main operational flow of the system."""
        user_input = self.ui.get_user_password()
        
        if user_input.lower() == 'h':  # History trigger
            self.ui.show_history()
            return

        password = user_input
        validator = SecurityValidator()  # Transient validator for this session
        
        # Security Auditing
        pwned = validator.check_pwned_api(password)
        blacklisted = validator.check_blacklist_and_fuzzy(password)
        validator.validate_rules(password)
        
        # Data Processing
        entropy = self.data.calculate_entropy(password)
        final_score = 0 if (pwned or blacklisted) else validator.score
        
        # UX Enhancement: Suggestion logic
        if final_score < 4:
            suggestion = self.data.generate_suggestion()
            console.print(Panel(f"Try: [bold cyan]{suggestion}[/bold cyan]", title="Architect Suggestion"))
            
        # UI Rendering
        self.ui.render_report(password, final_score, entropy, validator.improvements)
        
        # State Persistence
        entry = {"password": password, "score": final_score, "entropy": entropy}
        self.data.save_to_history(entry)
        self.data.export_json(entry)

if __name__ == "__main__":
    app = PasswordArchitect()  # Instantiate system
    while True:
        app.run_analysis()  # Execute persistent loop