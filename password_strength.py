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

if __name__ == "__main__":
    architect = PasswordArchitect()
    while True:
        pw = architect.get_input()
        print(f"Analyzing: {pw}")