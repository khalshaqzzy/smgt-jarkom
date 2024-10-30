# server.py

import socket
import threading
import sqlite3
import queue

def rc4(key, data):
    S = list(range(256))
    j = 0
    key_length = len(key)
    # Key Scheduling Algorithm (KSA)
    for i in range(256):
        j = (j + S[i] + key[i % key_length]) % 256
        S[i], S[j] = S[j], S[i]

    # Pseudo-Random Generation Algorithm (PRGA)
    i = 0
    j = 0
    result = bytearray()
    for byte in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        K = S[(S[i] + S[j]) % 256]
        result.append(byte ^ K)
    return bytes(result)

def handle_client_message(message_queue, server_socket, client_states, db_conn):
    while True:
        data, addr = message_queue.get()
        # Dekripsi data
        decrypted_data = rc4('mysecretkey'.encode(), data)
        message = decrypted_data.decode()
        # Parsing pesan
        parts = message.split('|')
        command = parts[0]
        cursor = db_conn.cursor()
        # Cetak verbose
        print(f"Diterima dari {addr}: {message}")

        if addr not in client_states:
            client_states[addr] = {'logged_in': False, 'username': None, 'current_chatroom': None}

        state = client_states[addr]

        if command == 'REGISTER':
            if len(parts) < 3:
                response = 'REGISTER_FAILURE|Missing username or password'
            else:
                username = parts[1]
                password = parts[2]
                cursor.execute("SELECT * FROM users WHERE username=?", (username,))
                if cursor.fetchone():
                    response = 'REGISTER_FAILURE|Username already exists'
                    print(f"Pendaftaran gagal untuk {username}: Username sudah ada")
                else:
                    cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, password))
                    db_conn.commit()
                    response = 'REGISTER_SUCCESS'
                    print(f"User terdaftar: {username}")
            # Kirim respons
            encrypted_response = rc4('mysecretkey'.encode(), response.encode())
            server_socket.sendto(encrypted_response, addr)

        elif command == 'LOGIN':
            if len(parts) < 3:
                response = 'LOGIN_FAILURE|Missing username or password'
            else:
                username = parts[1]
                password = parts[2]
                cursor.execute("SELECT * FROM users WHERE username=? AND password=?", (username, password))
                if cursor.fetchone():
                    state['logged_in'] = True
                    state['username'] = username
                    response = 'LOGIN_SUCCESS'
                    print(f"User login: {username}")
                else:
                    response = 'LOGIN_FAILURE|Invalid username or password'
                    print(f"Login gagal untuk {username}: Kredensial salah")
            # Kirim respons
            encrypted_response = rc4('mysecretkey'.encode(), response.encode())
            server_socket.sendto(encrypted_response, addr)

        elif not state['logged_in']:
            response = 'ERROR|You must log in first'
            encrypted_response = rc4('mysecretkey'.encode(), response.encode())
            server_socket.sendto(encrypted_response, addr)
        else:
            username = state['username']
            if command == 'CREATE_CHATROOM':
                if len(parts) < 3:
                    response = 'CREATE_CHATROOM_FAILURE|Missing chatroom name or password'
                else:
                    chatroom_name = parts[1]
                    chatroom_password = parts[2]
                    cursor.execute("SELECT * FROM chatrooms WHERE chatroom_name=?", (chatroom_name,))
                    if cursor.fetchone():
                        response = 'CREATE_CHATROOM_FAILURE|Chatroom already exists'
                        print(f"Pembuatan chatroom gagal: {chatroom_name} sudah ada")
                    else:
                        cursor.execute("INSERT INTO chatrooms (chatroom_name, chatroom_password) VALUES (?, ?)", (chatroom_name, chatroom_password))
                        db_conn.commit()
                        response = 'CREATE_CHATROOM_SUCCESS'
                        print(f"Chatroom dibuat: {chatroom_name} oleh {username}")
                encrypted_response = rc4('mysecretkey'.encode(), response.encode())
                server_socket.sendto(encrypted_response, addr)

            elif command == 'JOIN_CHATROOM':
                if len(parts) < 3:
                    response = 'JOIN_CHATROOM_FAILURE|Missing chatroom name or password'
                else:
                    chatroom_name = parts[1]
                    chatroom_password = parts[2]
                    cursor.execute("SELECT * FROM chatrooms WHERE chatroom_name=? AND chatroom_password=?", (chatroom_name, chatroom_password))
                    if cursor.fetchone():
                        state['current_chatroom'] = chatroom_name
                        response = 'JOIN_CHATROOM_SUCCESS'
                        print(f"{username} bergabung ke chatroom: {chatroom_name}")
                        # Kirim respons sukses
                        encrypted_response = rc4('mysecretkey'.encode(), response.encode())
                        server_socket.sendto(encrypted_response, addr)
                        # Kirim history chat
                        cursor.execute("SELECT username, message FROM chat_history WHERE chatroom_name=? ORDER BY timestamp", (chatroom_name,))
                        history_rows = cursor.fetchall()
                        if history_rows:
                            history_messages = [f"{row[0]}: {row[1]}" for row in history_rows]
                            history_response = 'CHAT_HISTORY|' + '|'.join(history_messages)
                            encrypted_history = rc4('mysecretkey'.encode(), history_response.encode())
                            server_socket.sendto(encrypted_history, addr)
                    else:
                        response = 'JOIN_CHATROOM_FAILURE|Invalid chatroom name or password'
                        print(f"Join chatroom gagal untuk {username}: Chatroom atau password salah")
                        encrypted_response = rc4('mysecretkey'.encode(), response.encode())
                        server_socket.sendto(encrypted_response, addr)

            elif command == 'LEAVE_CHATROOM':
                if state['current_chatroom']:
                    chatroom_name = state['current_chatroom']
                    print(f"{username} meninggalkan chatroom: {chatroom_name}")
                    state['current_chatroom'] = None
                    response = 'LEAVE_CHATROOM_SUCCESS'
                    encrypted_response = rc4('mysecretkey'.encode(), response.encode())
                    server_socket.sendto(encrypted_response, addr)
                else:
                    response = 'ERROR|You are not in a chatroom'
                    encrypted_response = rc4('mysecretkey'.encode(), response.encode())
                    server_socket.sendto(encrypted_response, addr)

            elif command == 'MESSAGE':
                if state['current_chatroom'] is None:
                    response = 'ERROR|You are not in a chatroom'
                    encrypted_response = rc4('mysecretkey'.encode(), response.encode())
                    server_socket.sendto(encrypted_response, addr)
                else:
                    message_text = parts[1]
                    chatroom_name = state['current_chatroom']
                    # Simpan pesan ke history
                    cursor.execute("INSERT INTO chat_history (chatroom_name, username, message) VALUES (?, ?, ?)",
                                   (chatroom_name, username, message_text))
                    db_conn.commit()
                    print(f"Pesan dari {username} di {chatroom_name}: {message_text}")
                    # Kirim pesan ke semua client di chatroom yang sama
                    for client_addr, client_state in client_states.items():
                        if client_state['current_chatroom'] == chatroom_name and client_state['logged_in']:
                            # Siapkan pesan
                            outgoing_message = f"MESSAGE|{username}|{message_text}"
                            encrypted_message = rc4('mysecretkey'.encode(), outgoing_message.encode())
                            server_socket.sendto(encrypted_message, client_addr)
            elif command == 'LOGOUT':
                print(f"User logout: {username}")
                state['logged_in'] = False
                state['username'] = None
                state['current_chatroom'] = None
                response = 'LOGOUT_SUCCESS'
                encrypted_response = rc4('mysecretkey'.encode(), response.encode())
                server_socket.sendto(encrypted_response, addr)
            else:
                response = 'ERROR|Unknown command'
                print(f"Perintah tidak dikenal dari {username}: {command}")
                encrypted_response = rc4('mysecretkey'.encode(), response.encode())
                server_socket.sendto(encrypted_response, addr)

def main():
    # Input IP dan Port
    server_ip = input("Masukkan IP server: ")
    server_port = int(input("Masukkan Port server: "))

    # Inisialisasi database SQLite
    db_conn = sqlite3.connect('chatserver.db', check_same_thread=False)
    cursor = db_conn.cursor()
    # Buat tabel jika belum ada
    cursor.execute('''CREATE TABLE IF NOT EXISTS users (
                      username TEXT PRIMARY KEY,
                      password TEXT
                      )''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS chatrooms (
                      chatroom_name TEXT PRIMARY KEY,
                      chatroom_password TEXT
                      )''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS chat_history (
                      chatroom_name TEXT,
                      username TEXT,
                      message TEXT,
                      timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
                      )''')
    db_conn.commit()

    # Buat socket UDP
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.bind((server_ip, server_port))
    print(f"Server dimulai di {server_ip}:{server_port}")

    client_states = {}  # Peta alamat client ke state (username, logged_in, chatroom saat ini)

    # Buat queue untuk pesan masuk
    message_queue = queue.Queue()

    # Mulai thread untuk menangani pesan dari queue
    handler_thread = threading.Thread(target=handle_client_message, args=(message_queue, server_socket, client_states, db_conn))
    handler_thread.daemon = True
    handler_thread.start()

    # Dengarkan pesan masuk dan masukkan ke queue
    while True:
        data, addr = server_socket.recvfrom(4096)
        message_queue.put((data, addr))

if __name__ == '__main__':
    main()
