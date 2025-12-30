# 🔑 PassSafe - A Secure Password Manager

## Introduction

This project is a secure password manager implemented in Python. It provides a modern and stylish Textual User Interface (TUI) to securely store, retrieve, update, and delete your passwords. The application uses strong AES encryption to protect your sensitive data.

## Features

- **Modern TUI:** A "cool and flashy" retro-futuristic TUI built with `textual`.
- **Strong Encryption:** Passwords are encrypted using AES with a key derived from your master password using PBKDF2.
- **Password Generation:** Generate strong, random passwords directly within the application.
- **CRUD Functionality:** Add, retrieve, update, and delete your passwords.

## Files

- **`tui_password_manager.py`:** The main application file that runs the `textual` TUI.
- **`password.py`:** The backend module that handles all the encryption and database logic.
- **`tui.css`:** The CSS file for styling the TUI.
- **`passwords.db`:** The SQLite database file where your encrypted passwords are stored.

## Usage

1. **Clone the repository:**
   ```bash
   git clone https://github.com/Ahmad-Akram7/Password-manager.git
   ```
2. **Navigate to the project directory:**
   ```bash
   cd Password-manager
   ```
3. **Install the dependencies:**
   ```bash
   pip install -r requirements.txt
   ```
4. **Run the application:**
   ```bash
   python tui_password_manager.py
   ```

## The TUI

The application will launch a TUI in your terminal. You can navigate the TUI using your keyboard.

- **`Add Password`:** Add a new username and password. You can also generate a random password.
- **`Retrieve Passwords`:** View all your stored passwords after entering your master password.
- **`Update Password`:** Update the password for an existing username.
- **`Delete Password`:** Delete a password for a given username.
- **`Quit`:** Press `q` to exit the application.

## Security

The application uses the `cryptography` library to implement strong encryption.

- **AES Encryption:** Passwords are encrypted using Fernet (AES128 in CBC mode with PKCS7 padding).
- **PBKDF2 Key Derivation:** The encryption key is derived from your master password using PBKDF2 with a random salt for each password. This makes it highly resistant to brute-force attacks.

## Conclusion

This password manager provides a secure and user-friendly way to manage your passwords directly from your terminal. The use of strong encryption and a modern TUI makes it a significant improvement over simple command-line password managers.