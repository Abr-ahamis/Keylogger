
import re

def check_password_strength(password):
    strength_criteria = {
        "length": len(password) >= 8,
        "uppercase": bool(re.search(r'[A-Z]', password)),
        "lowercase": bool(re.search(r'[a-z]', password)),
        "digit": bool(re.search(r'\d', password)),
        "special_char": bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', password))
    }

    score = sum(strength_criteria.values())

    if score == 5:
        strength = "Strong"
    elif score >= 3:
        strength = "Moderate"
    else:
        strength = "Weak"

    print(f"Password Strength: {strength}")
    for criterion, met in strength_criteria.items():
        print(f"- {criterion.capitalize()}: {'✔' if met else '✘'}")

if __name__ == "__main__":
    password = input("Enter your password: ")
    check_password_strength(password)
