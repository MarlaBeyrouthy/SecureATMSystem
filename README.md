# Secure ATM System 💳🔐

This is a **secure ATM simulation system** built using **Python, RSA & AES encryption**. It provides users with a secure way to log in, check their balance, deposit/withdraw money, and transfer funds.

## Features 🚀
- **RSA Encryption** 🔑 for login credentials.
- **AES Encryption** 🔒 for storing and retrieving balances securely.
- **SQLite Database** 📂 to manage users and transactions.
- **Multi-threaded Server** 🖥️ handling multiple clients securely.

## How It Works ⚙️
1. **Users connect to the ATM server.**
2. **Secure Login**: Passwords are RSA-encrypted before transmission.
3. **Balance Retrieval**: Encrypted balance is sent and decrypted on the client-side.
4. **Transactions (Deposit, Withdraw, Transfer)**: Updated securely with encryption.

## Technologies Used 🛠️
- Python 🐍
- RSA & AES Encryption (cryptography library)
- SQLite Database
- Multi-threading (for handling multiple clients)
- Socket Programming (for communication)

## Setup Instructions 🏗️
1. Clone the repository:
   ```bash
   git clone https://github.com/MarlaBeyrouthy/SecureATMSystem.git
Install dependencies:
pip install cryptography
Run the server:
python server.py
Run the client:
python client.py
