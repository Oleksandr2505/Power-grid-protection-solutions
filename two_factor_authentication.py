import pyotp
import hashlib

def two_factor_authentication(username, password, token):
    user_secret_key = 'BASE32SECRETKEYHERE' # Припустимо, це секретний ключ користувача
    hashed_password = hashlib.sha256(password.encode()).hexdigest()

    totp = pyotp.TOTP(user_secret_key)
    valid_token = totp.verify(token)

    if hashed_password == get_password_hash(username) and valid_token:
        return True
    return False

# Симуляція функції get_password_hash для прикладу
def get_password_hash(username):
    # Припустимо, що це функція повертає хеш пароля для заданого користувача
    # Тут ми повернемо хеш прикладу пароля 'password123' для демонстрації
    return hashlib.sha256('password123'.encode()).hexdigest()

# Генерація валідного OTP
def generate_valid_otp(secret_key):
    totp = pyotp.TOTP(secret_key)
    return totp.now()

# Секретний ключ, який використовується і в аутентифікації, і в генерації OTP
secret_key = 'BASE32SECRETKEYHERE'
valid_otp = generate_valid_otp(secret_key)

# Виклик функції аутентифікації зі згенерованим OTP
is_authenticated = two_factor_authentication('user1', 'password123', valid_otp)

print(f"Authenticated: {is_authenticated}")
