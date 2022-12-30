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



def encrypt(key: bytes, machine_id: str) -> str:
    """Encrypt the license key with a time limit using the given key."""
    # Add the time limit to the license key
    plaintext = f"{machine_id}"
    # print(plaintext)
    # print(plaintext.encode())

    fernet = Fernet(key)
    # print(fernet)
    # print(fernet.encrypt(plaintext.encode()))
    return fernet.encrypt(plaintext.encode()).decode()


def decrypt(key: bytes, encrypted_license_request: str) -> tuple:
    """Decrypt the license request"""
    fernet = Fernet(key)
    plaintext = fernet.decrypt(encrypted_license_request.encode()).decode()
    return plaintext

# Generate a key from a password
key = generate_key("secretkey")
print(key)

#if you dont want to keep the generat_key function, then can uncomment below line to use the fixed key
#key=b'5IGIaUE2rWwnFaRgcaSy7UCE6Iwoa5vsbzxsGvECsx0='

# Encrypt a license key with a time limit of 30 days
LicenseRequest = encrypt(key, "MachineID123")
# print(LicenseRequest.__class__)  # Outputs something like "gAAAAABcHU5..."
# LicenseRequest = LicenseRequest.encode()
# print(LicenseRequest.__class__)
with open("key.bin", "wb") as key_file:
    key_file.write(LicenseRequest.encode())

with open("key.bin", "rb") as machineidfile:
    machineIDencrypted = machineidfile.read().decode()


# Decrypt the license key and check the time limit
MachineID = decrypt(key, machineIDencrypted)
print(MachineID)  # Outputs "MachineID123"

