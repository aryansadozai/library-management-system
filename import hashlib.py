import hashlib
import secrets

password = "Admin123456"

salt = secrets.token_hex(16)

password_hash = hashlib.sha256(
    (password + salt).encode()
).hexdigest()

print("salt:", salt)
print("password_hash:", password_hash)