import re  # Library for Regular Expression pattern matching
import sys  # Library for system-level operations like exiting the script
import math  # Library for mathematical functions (used for Shannon Entropy)
import hashlib  # Library for generating secure hashes (SHA-1 for API check)
import requests  # Library for making HTTP requests to the HIBP API
from rich.console import Console  # Rich tool for advanced terminal output
from rich.table import Table  # Rich tool for creating formatted data tables
from rich.panel import Panel  # Rich tool for displaying text in bordered boxes

console = Console()  # Creating a global console instance for consistent UI styling

class PasswordArchitect:
    def __init__(self):
        """Initializes the architect with empty state for each new scan."""
        self.password = ""  # Storage for the current user-input password
        self.score = 0  # Numerical strength rating (0-5)
        self.improvements = []  # List to collect specific feedback for the user

    def get_input(self):
        """Handles the CLI user interface for password ingestion."""
        self.password = input("\n🛡️ Enter password to analyze (or 'q' to quit): ")  # Prompting user
        if self.password.lower() == 'q':  # Checking for the quit command
            sys.exit()  # Terminating the script safely
        return self.password  # Returning the string for analysis

    def check_length(self):
        """Enforces the fundamental security policy of minimum length."""
        if len(self.password) < 12:  # Architectural standard: minimum 12 chars
            self.improvements.append("Increase length to at least 12 characters.")  # Logging the weakness
            return False  # Failing the length requirement
        self.score += 1  # Awarding 1 point for meeting length standards
        return True  # Passing the length requirement

    def check_complexity(self):
        """Uses RegEx to verify the presence of diverse character sets."""
        patterns = {  # Dictionary mapping character types to their RegEx patterns
            "uppercase": r'[A-Z]',  # Checks for at least one capital letter
            "lowercase": r'[a-z]',  # Checks for at least one small letter
            "number": r'[0-9]',  # Checks for at least one numerical digit
            "special": r'[!@#$%^&]'  # Checks for specific architectural symbols
        }
        
        for name, pattern in patterns.items():  # Iterating through each required pattern
            if not re.search(pattern, self.password):  # If pattern is NOT found in string
                self.improvements.append(f"Add at least one {name} character.")  # Suggesting the specific type
            else:
                self.score += 1  # Awarding 1 point for each character type found

    def check_blacklist(self):
        """Performs a local data integrity check against a known-bad list."""
        try:
            with open("common_passwords.txt", "r") as f:  # Opening the external data file
                common = [line.strip() for line in f.readlines()]  # Cleaning and loading list into memory
                if self.password in common:  # Checking if input exists in the blacklist
                    self.improvements.append("Password is on a common blacklist. Change it entirely.")  # Warning user
                    return True  # Returning True because it IS blacklisted (a failure state)
        except FileNotFoundError:  # Handling cases where the architect's data file is missing
            console.print("[yellow]Warning: common_passwords.txt not found. Skipping local check.[/yellow]")
        return False  # Password is not in the local blacklist

    def calculate_entropy(self):
        """Calculates Shannon Entropy (H) to measure mathematical randomness."""
        if not self.password:  # Guarding against empty strings
            return 0
        
        # Determining the probability of each unique character in the string
        probabilities = [float(self.password.count(c)) / len(self.password) for c in dict.fromkeys(list(self.password))]
        
        # Shannon Formula: H = -Sum(p * log2(p)) - measures bits of information per character
        entropy = - sum(p * math.log2(p) for p in probabilities if p > 0)
        
        if entropy < 3.5:  # Architects look for high unpredictability (> 3.5 bits)
            self.improvements.append(f"Low mathematical entropy ({entropy:.2f}). Use more unique characters.")
        
        return entropy  # Returning the raw entropy value for the UI report

    def check_pwned_api(self):
        """Securely checks global breach databases using k-Anonymity via SHA-1."""
        sha1_password = hashlib.sha1(self.password.encode('utf-8')).hexdigest().upper()  # Hashing input
        prefix, suffix = sha1_password[:5], sha1_password[5:]  # Splitting hash to maintain privacy
        
        try:
            response = requests.get(f"https://api.pwnedpasswords.com/range/{prefix}")  # Querying API with prefix
            if response.status_code == 200:  # If the external service responds successfully
                hashes = (line.split(':') for line in response.text.splitlines())  # Parsing the returned suffixes
                for h, count in hashes:  # Iterating through found hash suffixes
                    if h == suffix:  # If our suffix matches one in the breach list
                        self.improvements.append(f"🚨 Found in {count} data breaches! API recommends changing.")
                        return True  # Password is compromised
        except Exception as e:  # Catching network or timeout errors gracefully
            console.print(f"[yellow]Skipping API check due to connection: {e}[/yellow]")
        return False  # Password not found in the breach database

    def analyze(self):
        """Coordinates all evaluators and renders the final Architect's Report."""
        self.score = 0  # Resetting score for fresh analysis
        self.improvements = []  # Resetting feedback list
        
        # Running the 'Guard' evaluators (Breach check and Blacklist)
        is_blacklisted = self.check_blacklist()  # Check local file
        is_pwned = self.check_pwned_api()  # Check global API
        
        # Running the 'Policy' evaluators (Rules and Math)
        self.check_length()  # Evaluate length
        self.check_complexity()  # Evaluate character types
        entropy_val = self.calculate_entropy()  # Perform entropy math
        
        # Architectural Decision: If compromised globally/locally, the score is forced to 0
        if is_blacklisted or is_pwned:
            self.score = 0

        # UI Construction: Building the Rich Table
        table = Table(title="🏗️ Architect's Security Report", show_header=True, header_style="bold cyan")
        table.add_column("Metric", style="dim")  # Category column
        table.add_column("Value", justify="right")  # Data column
        
        table.add_row("Password Length", str(len(self.password)))  # Adding length data
        table.add_row("Shannon Entropy", f"{entropy_val:.2f} bits")  # Adding math data
        table.add_row("Security Score", f"{self.score}/5", style="bold green" if self.score > 3 else "bold red")
        
        console.print(table)  # Rendering the table to the CLI

        # Feedback Loop: Displaying improvements in a formatted Panel
        if self.improvements:
            improvements_text = "\n".join([f"• {imp}" for imp in self.improvements])  # Formatting list
            console.print(Panel(improvements_text, title="[bold red]Required Improvements[/bold red]", border_style="red"))
        else:
            console.print(Panel("[bold green]✅ This password meets System Architect standards![/bold green]"))

if __name__ == "__main__":
    architect = PasswordArchitect()  # Instantiating the class
    while True:  # Starting the persistent loop for the CLI session
        architect.get_input()  # Capturing user input
        architect.analyze()  # Running the full architectural suite