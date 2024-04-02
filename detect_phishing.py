import re

def detect_phishing_email(email_subject, email_body):
    # Перелік підозрілих слів, які часто використовуються у фішингових емейлах
    suspicious_keywords = ['urgent', 'account', 'verification', 'password', 'update']
    if any(keyword in email_subject.lower() for keyword in suspicious_keywords):
        return True
    # Перевірка на наявність підозрілих посилань
    if re.search(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', email_body):
        return True
    return False

# Приклад
email_subject = "Urgent account verification required!"
email_body = "Please click on this link to verify your account: http://suspicious-link.com"
is_phishing = detect_phishing_email(email_subject, email_body)
print(f"Is phishing: {is_phishing}")
