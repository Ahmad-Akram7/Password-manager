TITLE:Password Keeper with Caesar Cipher Encryption
Description:

 # Password Manager

## Introduction
This project is a simple password manager implemented in Python. It allows users to securely store and retrieve passwords using basic encryption techniques. The application utilizes SQLite for database management and implements a Caesar cipher for password encryption.

## Files and Functionality

### `password_manager.py`
This file contains the main logic of the password manager. It provides a menu-driven interface where users can add new passwords, retrieve stored passwords, delete passwords, and exit the application.

#### Functions:
- **Database Setup (`create_database()`)**:
  - Establishes a connection to an SQLite database (`passwords.db`) if it exists, or creates a new one.
  - Defines a table (`passwords`) with fields for `id` (primary key), `username`, and `encrypted_password`.

- **Encryption (`encrypt_password(password, key)`)**:
  - Encrypts a given password using a Caesar cipher with a specified key.
  - Utilizes modulus operation to handle overflow and maintain character integrity.

- **Decryption (`decrypt_password(encrypted_password, key)`)**:
  - Decrypts an encrypted password using the same Caesar cipher and key.
  - Returns the original password for display or further processing.

- **Main Loop (`while True`)**:
  - Displays a menu with options for adding, retrieving, and deleting passwords, as well as exiting the application.
  - Handles user input validation and executes corresponding database operations based on user choices.

### `passwords.db`
This SQLite database file stores all user credentials securely. It maintains a table (`passwords`) where each record consists of a username and an encrypted password.

## Design Choices

### Use of SQLite
SQLite was chosen for its lightweight nature and ease of integration with Python. It provides a robust solution for managing structured data without requiring a separate database server.

### Caesar Cipher Encryption
The Caesar cipher was selected for its simplicity and educational value. While not suitable for high-security applications due to its susceptibility to brute-force attacks, it serves as a practical demonstration of encryption principles for educational purposes.

### Menu-Driven Interface
A menu-driven interface was implemented to enhance user experience and interaction. It allows users to navigate through different functionalities intuitively, ensuring ease of use.

### Master Key Requirement
The application requires users to input a master key (integer) for encrypting and decrypting passwords. This enhances security by ensuring that only authorized users can access stored passwords.

## Usage
1. **Adding a New Password**:
   - Select option `1` from the menu.
   - Enter the username, password, and a master key.
   - The password will be encrypted and stored securely in the database.

2. **Retrieving Passwords**:
   - Select option `2` from the menu.
   - Enter the master key to decrypt and display stored passwords.

3. **Deleting a Password**:
   - Select option `3` from the menu.
   - Enter the username of the password to be deleted.
   - The corresponding record will be removed from the database.

4. **Exiting the Application**:
   - Select option `4` from the menu to exit the password manager.

## Conclusion
This password manager project demonstrates fundamental concepts of Python programming, database management with SQLite, and encryption techniques using the Caesar cipher. It serves as an educational tool for understanding basic security practices in handling sensitive information. Users are encouraged to explore and modify the code to further enhance functionality and security features.

