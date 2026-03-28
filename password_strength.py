import re # Regular Expressions
import sys # System Exit

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
            

if __name__ == "__main__":
    architect = PasswordArchitect()
    while True:
        pw = architect.get_input()
        print(f"Analyzing: {pw}")