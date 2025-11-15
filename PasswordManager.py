import sqlite3
import base64
import os
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet

# Initialize or connect to the database
conn = sqlite3.connect('passwords.db')
cursor = conn.cursor()
cursor.execute('''
CREATE TABLE IF NOT EXISTS passwords (
    id INTEGER PRIMARY KEY,
    website TEXT NOT NULL,
    username TEXT NOT NULL,
    password TEXT NOT NULL
)
''')
conn.commit()

# Generate key from master password
def generate_key(master_password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(master_password.encode()))
    return key

def encrypt_password(key: bytes, password: str) -> str:
    f = Fernet(key)
    encrypted = f.encrypt(password.encode())
    return encrypted.decode()

def decrypt_password(key: bytes, encrypted_password: str) -> str:
    f = Fernet(key)
    decrypted = f.decrypt(encrypted_password.encode())
    return decrypted.decode()

def add_password(key: bytes):
    website = input("Website: ")
    username = input("Username: ")
    password = input("Password: ")
    encrypted_pass = encrypt_password(key, password)
    cursor.execute('INSERT INTO passwords (website, username, password) VALUES (?, ?, ?)',
                   (website, username, encrypted_pass))
    conn.commit()
    print("Password added successfully.")

def view_passwords(key: bytes):
    cursor.execute('SELECT website, username, password FROM passwords')
    rows = cursor.fetchall()
    for website, username, encrypted_pass in rows:
        decrypted_pass = decrypt_password(key, encrypted_pass)
        print(f"Website: {website}\nUsername: {username}\nPassword: {decrypted_pass}\n")

def main():
    master_password = input("Enter your master password: ")
    # Use a fixed salt here, in real applications this should be stored safely and uniquely per user
    salt = b'some_salt_12345'

    key = generate_key(master_password, salt)

    while True:
        print("\nPassword Manager")
        print("1. Add password")
        print("2. View passwords")
        print("3. Exit")
        choice = input("Select an option: ")

        if choice == "1":
            add_password(key)
        elif choice == "2":
            view_passwords(key)
        elif choice == "3":
            break
        else:
            print("Invalid option. Please select 1, 2, or 3.")

if __name__ == "__main__":
    main()
