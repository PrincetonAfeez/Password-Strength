import re # Regular Expressions
import sys # System Exit
import math # Shannon Entropy

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

    def analyze(self):
        self.score = 0
        self.improvements = []
        
        self.check_blacklist()
        self.check_length()
        self.check_complexity()
        
        print(f"\n--- Analysis Result ---")
        print(f"Score: {self.score}/5")
        if self.improvements:
            print("Improvements Needed:")
            for item in self.improvements:
                print(f"  • {item}")
        else:
            print("✅ Strong Password!")

    def calculate_entropy(self):
        """Calculates Shannon Entropy to measure randomness/unpredictability."""
        if not self.password:
            return 0
        
        # Calculate character frequencies
        probabilities = [float(self.password.count(c)) / len(self.password) for c in dict.fromkeys(list(self.password))]
        
        # Shannon Entropy Formula
        entropy = - sum([p * math.log(p) / math.log(2.0) for p in prob] for p in probabilities if p > 0)
        
        if entropy < 3.5:
            self.improvements.append(f"Low mathematical entropy ({entropy:.2f}). Use a more random variety of characters.")
        
        return entropy

if __name__ == "__main__":
    architect = PasswordArchitect()
    while True:
        pw = architect.get_input()
        print(f"Analyzing: {pw}")