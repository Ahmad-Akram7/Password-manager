import sqlite3
import os
import base64
import secrets
import string
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet, InvalidToken

# --- Database Setup ---
def init_db():
    """Initializes the database connection and creates the passwords table if it doesn't exist."""
    try:
        conn = sqlite3.connect('passwords.db')
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS passwords
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      username TEXT NOT NULL UNIQUE,
                      salt BLOB NOT NULL,
                      encrypted_password BLOB NOT NULL)''')
        conn.commit()
        return conn, c
    except sqlite3.Error as e:
        print(f"Database error: {e}")
        exit(1)

# --- Key Derivation ---
def derive_key(password: str, salt: bytes) -> bytes:
    """Derives a key from a password and salt using PBKDF2."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

# --- Encryption/Decryption ---
def encrypt_password(password: str, master_password: str) -> tuple[bytes, bytes]:
    """Encrypts a password using a key derived from the master password."""
    salt = os.urandom(16)
    key = derive_key(master_password, salt)
    f = Fernet(key)
    encrypted_password = f.encrypt(password.encode())
    return salt, encrypted_password

def decrypt_password(encrypted_password: bytes, salt: bytes, master_password: str) -> str:
    """Decrypts a password using a key derived from the master password."""
    key = derive_key(master_password, salt)
    f = Fernet(key)
    try:
        decrypted_password = f.decrypt(encrypted_password)
        return decrypted_password.decode()
    except InvalidToken:
        return ""

# --- Password Generation ---
def generate_password(length=16):
    """Generates a strong, random password."""
    alphabet = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(secrets.choice(alphabet) for i in range(length))
    return password

# --- Main Application Logic ---
def add_password(c, conn):
    """Adds a new password to the database."""
    try:
        username = input("Enter the username: ")
        choice = input("Generate a random password? (y/n): ").lower()
        if choice == 'y':
            password = generate_password()
            print(f"Generated password: {password}")
        else:
            password = input("Enter the password: ")
        master_password = input("Enter your master password: ")

        salt, encrypted_pass = encrypt_password(password, master_password)

        c.execute('''INSERT INTO passwords (username, salt, encrypted_password)
                     VALUES (?, ?, ?)''', (username, salt, encrypted_pass))
        conn.commit()
        print("Password added successfully!")
    except sqlite3.IntegrityError:
        print(f"Error: Username '{username}' already exists.")
    except Exception as e:
        print(f"An error occurred: {e}")

def retrieve_passwords(c):
    """Retrieves and decrypts passwords from the database."""
    try:
        master_password = input("Enter your master password to retrieve passwords: ")
        c.execute('''SELECT username, salt, encrypted_password FROM passwords''')
        results = c.fetchall()

        if results:
            print("\nDecrypted Passwords:")
            for result in results:
                username, salt, encrypted_password = result
                decrypted_password = decrypt_password(encrypted_password, salt, master_password)
                if decrypted_password:
                    print(f"Username: {username}, Password: {decrypted_password}")
                else:
                    print(f"Failed to decrypt password for username: {username} (check your master password)")
        else:
            print("No passwords found.")
    except Exception as e:
        print(f"An error occurred: {e}")

def delete_password(c, conn):
    """Deletes a password from the database."""
    try:
        username = input("Enter the username to delete: ")
        c.execute("SELECT id FROM passwords WHERE username=?", (username,))
        if c.fetchone():
            c.execute('''DELETE FROM passwords WHERE username=?''', (username,))
            conn.commit()
            print("Password deleted successfully!")
        else:
            print(f"Username '{username}' not found.")
    except Exception as e:
        print(f"An error occurred: {e}")

def update_password(c, conn):
    """Updates a password for a given username."""
    try:
        username = input("Enter the username to update: ")
        c.execute("SELECT id FROM passwords WHERE username=?", (username,))
        if c.fetchone():
            choice = input("Generate a random password? (y/n): ").lower()
            if choice == 'y':
                new_password = generate_password()
                print(f"Generated password: {new_password}")
            else:
                new_password = input("Enter the new password: ")
            master_password = input("Enter your master password: ")

            salt, encrypted_pass = encrypt_password(new_password, master_password)

            c.execute('''UPDATE passwords SET salt=?, encrypted_password=?
                         WHERE username=?''', (salt, encrypted_pass, username))
            conn.commit()
            print("Password updated successfully!")
        else:
            print(f"Username '{username}' not found.")
    except Exception as e:
        print(f"An error occurred: {e}")


def main():
    """Main function to run the password manager."""
    conn, c = init_db()

    while True:
        print("\nPassword Manager Menu:")
        print("1. Add a new password")
        print("2. Retrieve passwords")
        print("3. Update a password")
        print("4. Delete a password")
        print("5. Exit")

        choice = input("Enter your choice (1-5): ")

        if choice == '1':
            add_password(c, conn)
        elif choice == '2':
            retrieve_passwords(c)
        elif choice == '3':
            update_password(c, conn)
        elif choice == '4':
            delete_password(c, conn)
        elif choice == '5':
            print("Exiting Password Manager. STAY SAFE")
            break
        else:
            print("Invalid choice. Please enter a number from 1 to 5.")

    conn.close()

if __name__ == "__main__":
    main()
