import secrets
import hashlib

password = "AdminTest123!"
salt = secrets.token_hex(16)
password_hash = hashlib.sha256((password + salt).encode()).hexdigest()

print("SALT =", salt)
print("HASH =", password_hash)