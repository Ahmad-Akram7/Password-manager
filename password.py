import sqlite3

# Create SQLite database table
conn = sqlite3.connect('passwords.db')
c = conn.cursor()
c.execute('''CREATE TABLE IF NOT EXISTS passwords
             (id INTEGER PRIMARY KEY AUTOINCREMENT,
              username TEXT NOT NULL,
              encrypted_password TEXT NOT NULL)''')
conn.commit()

# Function to encrypt a password using a Caesar cipher with a given key
def encrypt_password(password, key):
    encrypted_password = []
    for char in password:
        shifted_char = chr((ord(char) + key) % 256)  # Using modulus to handle overflow
        encrypted_password.append(shifted_char)
    return ''.join(encrypted_password)

# Function to decrypt an encrypted password using a Caesar cipher with a given key
def decrypt_password(encrypted_password, key):
    decrypted_password = []
    for char in encrypted_password:
        original_char = chr((ord(char) - key) % 256)  # Using modulus to handle overflow
        decrypted_password.append(original_char)
    return ''.join(decrypted_password)

# Main loop for password manager
while True:
    print("\nPassword Manager Menu:")
    print("1. Add a new password")
    print("2. Retrieve passwords")
    print("3. Delete a password")
    print("4. Exit")

    choice = input("Enter your choice (1-4): ")

    if choice == '1':
        # Add a new password
        username = input("Enter the username: ")
        password = input("Enter the password: ")
        master_key = int(input("Enter the master key (integer): "))

        # Encrypt the password using the master key
        encrypted_password = encrypt_password(password, master_key)

        # Store in database
        c.execute('''INSERT INTO passwords (username, encrypted_password)
                     VALUES (?, ?)''', (username, encrypted_password))
        conn.commit()

        print("Password added successfully!")

    elif choice == '2':
        # Retrieve passwords
        master_key = int(input("Enter your master key to retrieve passwords: "))

        # Retrieve all passwords and decrypt them using the master key
        c.execute('''SELECT username, encrypted_password FROM passwords''')
        results = c.fetchall()

        if results:
            print("\nDecrypted Passwords:")
            for result in results:
                username, encrypted_password = result

                # Decrypt the password using the master key
                decrypted_password = decrypt_password(encrypted_password, master_key)

                print(f"Username: {username}, Password: {decrypted_password}")
        else:
            print("No passwords found.")

    elif choice == '3':
        # Delete a password
        username = input("Enter the username: ")

        # Delete from database
        c.execute('''DELETE FROM passwords
                     WHERE username=?''', (username,))
        conn.commit()

        print("Password deleted successfully!")

    elif choice == '4':
        print("Exiting Password Manager. STAY SAFE")
        break

    else:
        print("Invalid choice. Please enter a number from 1 to 4.")

# Close the database connection
conn.close()
