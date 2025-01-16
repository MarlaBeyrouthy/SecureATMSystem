
import socket
import threading
from database import setup_database, seed_data_from_csv, verify_login, get_balance, update_balance, update_password, get_transactions, log_transaction
from encryption import load_rsa_keys, decrypt_rsa, encrypt_rsa
from cryptography.hazmat.primitives import serialization


# Use a thread-safe lock for shared resources

# 🔹 Server Workflow
# Starts and listens for connections on port 3000.
# When a client connects, it sends the public RSA key.
# The client sends encrypted login credentials.
# The server decrypts and verifies them.
# Users can then:
# Check balance (AES encrypted)
# Deposit/Withdraw money
# Transfer money
# Change password
# The server handles requests and updates the SQLite database securely.


logged_in_clients_lock = threading.Lock()
logged_in_clients = {}

def handle_client(client_socket, private_key, public_key):
    try:
        # Send public key to the client
        public_key_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        print("Sending public key to client:", public_key_pem.decode())
        client_socket.send(public_key_pem)

        while True:
            command = client_socket.recv(1024).decode()
            if not command:
                break

            # LOGIN Command
            if command == "LOGIN":
                username = client_socket.recv(1024).decode()
                encrypted_password = client_socket.recv(1024)
                print(f"Received encrypted password from client for {username}")

                try:
                    password = decrypt_rsa(private_key, encrypted_password)
                    print(f"Decrypted password for {username}: {password}")
                except Exception:
                    client_socket.send(b"FAIL")
                    continue

                if verify_login(username, password):
                    with logged_in_clients_lock:
                        logged_in_clients[client_socket] = username
                    client_socket.send(b"SUCCESS")
                else:
                    client_socket.send(b"FAIL")

            # Operations requiring login
            elif command in ["BALANCE", "DEPOSIT", "WITHDRAW", "CHANGE_PASSWORD", "TRANSFER", "TRANSACTIONS"]:
                with logged_in_clients_lock:
                    username = logged_in_clients.get(client_socket)
                if not username:
                    client_socket.send(b"LOGIN_REQUIRED")
                    continue

                """ if command == "BALANCE":
                    balance = get_balance(username)
                    encrypted_balance = encrypt_rsa(public_key, str(balance))
                    print(f"Encrypted balance for {username}: {encrypted_balance}")
                    client_socket.send(encrypted_balance) """
                
                if command == "BALANCE":
                    balance = get_balance(username)  # This should now be decrypted by get_balance()
    
                    if balance is not None:
                     encrypted_balance = encrypt_rsa(public_key, str(balance))  # Encrypting it properly for transmission
                     print(f"Encrypted balance for {username}: {encrypted_balance}")
                     client_socket.send(encrypted_balance)
                    else:
                     client_socket.send(b"ERROR")


                elif command == "DEPOSIT":
                    try:
                        encrypted_amount = client_socket.recv(1024)
                        amount = float(decrypt_rsa(private_key, encrypted_amount))
                        print(f"Decrypted deposit amount for {username}: {amount}")

                        balance = float(get_balance(username))
                        balance = 0.0 if balance is None else float(balance)  # Ensure it's a valid number

                        new_balance = balance + amount
                        update_balance(username, new_balance)
                        log_transaction(username, "DEPOSIT", amount)

                        client_socket.send(b"SUCCESS")
                    except Exception as e:
                        print(f"Error during deposit: {e}")
                        client_socket.send(b"FAIL")

                elif command == "WITHDRAW":
                    try:
                        encrypted_amount = client_socket.recv(1024)
                        amount = float(decrypt_rsa(private_key, encrypted_amount))
                        print(f"Decrypted withdrawal amount for {username}: {amount}")

                        balance = float(get_balance(username))
                        balance = 0.0 if balance is None else float(balance)  # Ensure it's a valid number

                        print(f"Current balance for {username}: {balance}")

                        if balance >= amount:
                            new_balance = balance - amount
                            update_balance(username, new_balance)
                            log_transaction(username, "WITHDRAW", amount)
                            client_socket.send(b"SUCCESS")
                        else:
                            client_socket.send(b"INSUFFICIENT_FUNDS")
                    except Exception as e:
                        print(f"Error during withdrawal: {e}")
                        client_socket.send(b"FAIL")

                elif command == "CHANGE_PASSWORD":
                    try:
                        old_password_encrypted = client_socket.recv(1024)
                        new_password_encrypted = client_socket.recv(1024)

                        old_password = decrypt_rsa(private_key, old_password_encrypted)
                        new_password = decrypt_rsa(private_key, new_password_encrypted)

                        print(f"Decrypted old password: {old_password}")
                        print(f"Decrypted new password: {new_password}")

                        if verify_login(username, old_password):
                            update_password(username, new_password)
                            client_socket.send(b"SUCCESS")
                        else:
                            client_socket.send(b"INVALID_OLD_PASSWORD")
                    except Exception as e:
                        print(f"Error during password change: {e}")
                        client_socket.send(b"FAIL")

                elif command == "TRANSFER":
                    try:
                        recipient = client_socket.recv(1024).decode()
                        encrypted_amount = client_socket.recv(1024)
                        amount = float(decrypt_rsa(private_key, encrypted_amount))

                        sender_balance = float(get_balance(username))
                        recipient_balance = float(get_balance(recipient))

                        if sender_balance >= amount:
                            update_balance(username, sender_balance - amount)
                            update_balance(recipient, recipient_balance + amount)
                            log_transaction(username, "TRANSFER", amount)
                            client_socket.send(b"SUCCESS")
                        else:
                            client_socket.send(b"INSUFFICIENT_FUNDS")
                    except Exception as e:
                        print(f"Error during transfer: {e}")
                        client_socket.send(b"FAIL")

                elif command == "TRANSACTIONS":
                    transactions = get_transactions(username)
                    client_socket.send(str(transactions).encode())

            elif command == "EXIT":
                with logged_in_clients_lock:
                    logged_in_clients.pop(client_socket, None)
                client_socket.send(b"GOODBYE")
                break

    finally:
        with logged_in_clients_lock:
            logged_in_clients.pop(client_socket, None)
        client_socket.close()

def start_server():
    private_key, public_key = load_rsa_keys()
    setup_database()
    seed_data_from_csv("users.csv")

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(("0.0.0.0", 3000))
    server_socket.listen(5)

    print("Server is running on port 3000...")

    while True:
        client_socket, _ = server_socket.accept()
        threading.Thread(target=handle_client, args=(client_socket, private_key, public_key)).start()

if __name__ == "__main__":
    start_server()








