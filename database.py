


##the one that encrypt the baalnce inside the database table
import sqlite3
import csv
from encryption import hash_password
from aesutils import encrypt_aes, decrypt_aes, generate_aes_key  , load_aes_key # Import AES methods


# 🔹 Database Workflow
# Stores users, balances, and transactions in atm.db.
# Passwords are hashed using SHA-256.
# Balances are AES-encrypted before storage.
# Transactions are logged for future reference.

#aes_key = generate_aes_key()
aes_key = load_aes_key()  # Load the persistent AES key


def setup_database():
    conn = sqlite3.connect('atm.db')
    cursor = conn.cursor()

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password TEXT NOT NULL,
            balance REAL NOT NULL
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            action TEXT NOT NULL,
            amount REAL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (username) REFERENCES users (username)
        )
    ''')

    conn.commit()
    conn.close()
#Hashes the input password and compares it with the stored hash.
def verify_login(username, password):
    conn = sqlite3.connect('atm.db')
    cursor = conn.cursor()

    cursor.execute("SELECT password FROM users WHERE username = ?", (username,))
    result = cursor.fetchone()

    conn.close()
    if result:
        stored_password_hash = result[0]
        return stored_password_hash == hash_password(password) 
    return False


def get_balance(username):
    conn = sqlite3.connect('atm.db')
    cursor = conn.cursor()

    cursor.execute("SELECT balance FROM users WHERE username = ?", (username,))
    result = cursor.fetchone()

    conn.close()
    if result and result[0]:  # Ensure result is not None
        encrypted_balance = result[0]
        try:
            decrypted_balance = decrypt_aes(encrypted_balance, aes_key)  # Decrypt balance
            return float(decrypted_balance)  # Ensure float format
        except Exception as e:
            print(f"Error decrypting balance for {username}: {e}")
            return 0.0  # Return default balance instead of None
    return 0.0  # Default balance for new accounts


def update_balance(username, new_balance):
    # Encrypt the balance using AES encryption before storing it
    encrypted_balance = encrypt_aes(str(new_balance), aes_key)
    
    conn = sqlite3.connect('atm.db')
    cursor = conn.cursor()

    cursor.execute("UPDATE users SET balance = ? WHERE username = ?", (encrypted_balance, username))
    conn.commit()
    conn.close()

def update_password(username, new_password):
    conn = sqlite3.connect('atm.db')
    cursor = conn.cursor()

    cursor.execute("UPDATE users SET password = ? WHERE username = ?", (hash_password(new_password), username))
    conn.commit()
    conn.close()

def log_transaction(username, action, amount):
    conn = sqlite3.connect('atm.db')
    cursor = conn.cursor()

    cursor.execute("INSERT INTO transactions (username, action, amount) VALUES (?, ?, ?)", (username, action, amount))
    conn.commit()
    conn.close()

def get_transactions(username):
    conn = sqlite3.connect('atm.db')
    cursor = conn.cursor()

    cursor.execute("SELECT action, amount, timestamp FROM transactions WHERE username = ? ORDER BY timestamp DESC", (username,))
    transactions = cursor.fetchall()

    conn.close()
    return transactions

def seed_data_from_csv(file_path):
    conn = sqlite3.connect('atm.db')
    cursor = conn.cursor()

    try:
        with open(file_path, mode='r', encoding='utf-8') as csv_file:
            reader = csv.DictReader(csv_file)
            for row in reader:
                username = row['username']
                password = hash_password(row['password'])
                balance = float(row['balance'])
                
                try:
                    cursor.execute("INSERT INTO users (username, password, balance) VALUES (?, ?, ?)", (username, password, balance))
                except sqlite3.IntegrityError:
                    pass 
    except FileNotFoundError:
        print(f"Error: The file {file_path} does not exist.")
    except KeyError as e:
        print(f"Error: Missing column in CSV file: {e}")

    conn.commit()
    conn.close()
