import sys

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

if __name__ == "__main__":
    architect = PasswordArchitect()
    while True:
        pw = architect.get_input()
        print(f"Analyzing: {pw}")