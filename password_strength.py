import re  # Library for Regular Expression pattern matching
import sys  # Library for system-level operations like exiting the script
import math  # Library for mathematical functions (used for Shannon Entropy)
import hashlib  # Library for generating secure hashes (SHA-1 for API check)
import requests  # Library for making HTTP requests to the HIBP API
from rich.console import Console  # Rich tool for advanced terminal output
from rich.table import Table  # Rich tool for creating formatted data tables
from rich.panel import Panel  # Rich tool for displaying text in bordered boxes

# Initialize the Rich Console for professional CLI formatting
console = Console()

class PasswordArchitect:
    def __init__(self):
        """Initializes the architect with an empty state for a new analysis."""
        self.password = ""  # Variable to hold the user's input string
        self.score = 0  # Counter for the 1-5 strength score
        self.improvements = []  # List to store feedback strings

    def get_input(self):
        """Captures user input and handles the exit command."""
        self.password = input("\n🛡️  Enter password to analyze (or 'q' to quit): ")
        if self.password.lower() == 'q':  # Check if user wants to exit
            sys.exit()  # Terminate the script
        return self.password

    def check_length(self):
        """AC 2: Check for a minimum of 12 characters."""
        if len(self.password) < 12:  # Compare length against requirement
            self.improvements.append("Increase length to at least 12 characters.")
            return False
        self.score += 1  # Increment score if requirement is met
        return True

    def check_complexity(self):
        """AC 3: Verify presence of Uppercase, Lowercase, Number, and Special Char."""
        patterns = {
            "uppercase": r'[A-Z]',  # Regex for any capital letter
            "lowercase": r'[a-z]',  # Regex for any lowercase letter
            "number": r'[0-9]',     # Regex for any digit
            "special": r'[!@#$%^&]' # Regex for specific allowed special symbols
        }
        
        for name, pattern in patterns.items():  # Iterate through the rules
            if not re.search(pattern, self.password):  # If pattern is missing
                self.improvements.append(f"Add at least one {name} character.")
            else:
                self.score += 1  # Add 1 point for every character type found

    def check_blacklist(self):
        """AC 4: Check against a 'Common Passwords' list."""
        try:
            with open("common_passwords.txt", "r") as f:  # Open the local file
                common = [line.strip() for line in f.readlines()]  # Read and clean lines
                if self.password in common:  # Check for exact match
                    self.improvements.append("Password is on a common blacklist. Change it entirely.")
                    return True  # Found in blacklist
        except FileNotFoundError:  # Handle case where file doesn't exist
            console.print("[yellow]Warning: common_passwords.txt not found. Skipping local check.[/yellow]")
        return False

    def calculate_entropy(self):
        """Advanced: Calculates Shannon Entropy to measure mathematical randomness."""
        if not self.password:
            return 0
        # Calculate the probability of each unique character occurring
        probabilities = [float(self.password.count(c)) / len(self.password) for c in dict.fromkeys(list(self.password))]
        # Formula: H = -sum(p * log2(p))
        entropy = - sum(p * math.log2(p) for p in probabilities if p > 0)
        
        if entropy < 3.5:  # Threshold for "random enough" for a short string
            self.improvements.append(f"Low mathematical entropy ({entropy:.2f}). Use more unique characters.")
        return entropy

    def check_pwned_api(self):
        """Advanced: Checks HaveIBeenPwned API using k-Anonymity (Privacy-First)."""
        sha1_password = hashlib.sha1(self.password.encode('utf-8')).hexdigest().upper()  # Hash the password
        prefix, suffix = sha1_password[:5], sha1_password[5:]  # Send only first 5 chars to API
        
        try:
            response = requests.get(f"https://api.pwnedpasswords.com/range/{prefix}", timeout=5)
            if response.status_code == 200:  # If API call is successful
                hashes = (line.split(':') for line in response.text.splitlines())  # Parse the response
                for h, count in hashes:  # Look for our hash suffix in the results
                    if h == suffix:
                        self.improvements.append(f"🚨 Found in {count} data breaches! This password is compromised.")
                        return True
        except Exception as e:  # Handle network timeouts or errors
            console.print(f"[yellow]Skipping API check: {e}[/yellow]")
        return False

    def analyze(self):
        """AC 5: Return a score (1-5) and a list of improvements."""
        self.score = 0  # Reset score for current run
        self.improvements = []  # Reset improvements for current run
        
        # Run critical security checks first
        is_blacklisted = self.check_blacklist()
        is_pwned = self.check_pwned_api()
        
        # Run standard policy checks
        self.check_length()
        self.check_complexity()
        entropy_val = self.calculate_entropy()
        
        # If the password is leaked or blacklisted, force the score to 0
        if is_blacklisted or is_pwned:
            self.score = 0

        # Build the Rich Report Table
        table = Table(title="🏗️  Architect's Security Report", show_header=True, header_style="bold cyan")
        table.add_column("Metric", style="dim")
        table.add_column("Value", justify="right")
        
        table.add_row("Password Length", str(len(self.password)))
        table.add_row("Shannon Entropy", f"{entropy_val:.2f} bits")
        table.add_row("Final Score", f"{self.score}/5", style="bold green" if self.score >= 4 else "bold red")
        
        console.print(table)  # Print the table to the console

        # Print improvements in a Red Panel if they exist
        if self.improvements:
            improvements_text = "\n".join([f"• {imp}" for imp in self.improvements])
            console.print(Panel(improvements_text, title="[bold red]Improvements Needed[/bold red]", border_style="red"))
        else:
            console.print(Panel("[bold green]✅ This password meets Architect Standards![/bold green]"))

# Main execution loop
if __name__ == "__main__":
    architect = PasswordArchitect()
    while True:
        architect.get_input()  # Get the password from the user
        architect.analyze()    # Run all checks and display results