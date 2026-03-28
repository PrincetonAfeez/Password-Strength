import re # Regular Expressions
import sys # System Exit
import math # Shannon Entropy
from rich.console import Console # Rich CLI Library
from rich.table import Table # Rich Table Library
from rich.panel import Panel # Rich Panel Library
import hashlib # SHA-1 Hashing
import requests # HTTP Requests for API Integration


console = Console() # Initialize Console

class PasswordArchitect:
    def __init__(self):
        self.password = ""
        self.score = 0
        self.improvements = []

    def get_input(self):
        self.password = input("\n🛡️ Enter password to analyze (or 'q' to quit): ")
        if self.password.lower() == 'q':
            sys.exit()
        return self.password

    def check_length(self):
        if len(self.password) < 12:
            self.improvements.append("Increase length to at least 12 characters.")
            return False
        self.score += 1
        return True    

    def check_complexity(self):
        patterns = {
            "uppercase": r'[A-Z]',
            "lowercase": r'[a-z]',
            "number": r'[0-9]',
            "special": r'[!@#$%^&]'
        }
        
        for name, pattern in patterns.items():
            if not re.search(pattern, self.password):
                self.improvements.append(f"Add at least one {name} character.")
            else:
                self.score += 1

    def check_blacklist(self):
        try:
            with open("common_passwords.txt", "r") as f:
                common = [line.strip() for line in f.readlines()]
                if self.password in common:
                    self.improvements.append("Password is on a common blacklist. Change it entirely.")
                    self.score = 0 # Force fail
                    return False
        except FileNotFoundError:
            print("Warning: common_passwords.txt not found.")
        return True

    def calculate_entropy(self):
        """Calculates Shannon Entropy to measure randomness/unpredictability."""
        if not self.password:
            return 0
        
        # Calculate character frequencies
        probabilities = [float(self.password.count(c)) / len(self.password) for c in dict.fromkeys(list(self.password))]
        
        # Shannon Entropy Formula
        entropy = - sum(p * math.log2(p) for p in probabilities if p > 0)
        
        if entropy < 3.5:
            self.improvements.append(f"Low mathematical entropy ({entropy:.2f}). Use a more random variety of characters.")
        
        return entropy

    def check_pwned_api(self):
        """Checks if password has appeared in data breaches via HaveIBeenPwned API."""
        sha1_password = hashlib.sha1(self.password.encode('utf-8')).hexdigest().upper()
        prefix, suffix = sha1_password[:5], sha1_password[5:]
        
        try:
            response = requests.get(f"https://api.pwnedpasswords.com/range/{prefix}")
            if response.status_code == 200:
                hashes = (line.split(':') for line in response.text.splitlines())
                for h, count in hashes:
                    if h == suffix:
                        self.improvements.append(f"🚨 This password has appeared in {count} data breaches!")
                        self.score = 0
                        return True
        except Exception as e:
            print(f"Skipping API check: {e}")
        return False

    def analyze(self):
        self.score = 0
        self.improvements = []
        
        # Run all evaluators
        self.check_blacklist()
        self.check_pwned_api()
        self.check_length()
        self.check_complexity()
        entropy_val = self.calculate_entropy()

        # Guard Clauses: If these fail, we don't care about length/complexity
        is_blacklisted = not self.check_blacklist()
        is_pwned = self.check_pwned_api()

        if is_blacklisted or is_pwned:
            self.score = 0

        print(f"\n--- Analysis Result ---")
        print(f"Score: {self.score}/5")
        if self.improvements:
            print("Improvements Needed:")
            for item in self.improvements:
                print(f"  • {item}")
        else:
            print("✅ Strong Password!")


        # UI Rendering
        table = Table(title="Architect's Security Report")
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="magenta")
        
        table.add_row("Password Length", str(len(self.password)))
        table.add_row("Shannon Entropy", f"{entropy_val:.2f} bits")
        table.add_row("Final Score", f"{self.score}/5")

        console.print(table)
        
        if self.improvements:
            for imp in self.improvements:
                console.print(f"[bold red]•[/bold red] {imp}")
        else:
            console.print(Panel("[bold green]✅ This password meets Architect Standards![/bold green]"))






if __name__ == "__main__":
    architect = PasswordArchitect()
    while True:
        architect.get_input() # This sets self.password
        architect.analyze()   # This processes and prints the report