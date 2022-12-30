import base64
import datetime

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


def generate_key(password: str) -> bytes:
    """Generate a encryption key from a password using PBKDF2."""
    salt = b'specialcode'  # Salt can be added to improve the key generation process
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

# def decode_key(machineid: str) -> str:
#     salt = b'specialcode'  # Salt can be added to improve the key generation process
#     kdf = PBKDF2HMAC(
#         algorithm=hashes.SHA256(),
#         length=32,
#         salt=salt,
#         iterations=100000
#     )
#     machineid = kdf.derive(machineid)
#     print(f"machine id:{machineid}")
#     return


def encrypt(key: bytes, license_key: str, valid_until: datetime) -> str:
    """Encrypt the license key with a time limit using the given key."""
    # Add the time limit to the license key
    plaintext = f"{license_key}|{valid_until.strftime('%Y-%m-%d')}"
    print(plaintext)
    print(plaintext.encode())

    fernet = Fernet(key)
    print(fernet)
    print(fernet.encrypt(plaintext.encode()))
    return fernet.encrypt(plaintext.encode()).decode()


def decrypt(key: bytes, encrypted_license_key: str) -> tuple:
    """Decrypt the license key and check the time limit."""
    fernet = Fernet(key)
    plaintext = fernet.decrypt(encrypted_license_key.encode()).decode()
    print(f"decrypt():{plaintext}")
    license_key, valid_until_str = plaintext.split("|")
    valid_until = datetime.datetime.strptime(valid_until_str, '%Y-%m-%d')
    if valid_until < datetime.datetime.now():
        raise ValueError("License key has expired")
    return license_key, valid_until

# Generate a key from a password
key = generate_key("secretkey")
print(key)



# Encrypt a license key with a time limit of 30 days
encrypted_license_key = encrypt(key, "MachineID123", datetime.datetime.now() + datetime.timedelta(days=30))
print(encrypted_license_key)  # Outputs something like "gAAAAABcHU5..."

# Decrypt the license key and check the time limit
license_key, valid_until = decrypt(key, encrypted_license_key)
print(license_key)  # Outputs "LICENSE-KEY-123"
print(valid_until)  # Outputs the time the license key is valid until
