# client.py

import socket
import threading
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

def receive_messages(client_socket, message_queue):
    while True:
        data, addr = client_socket.recvfrom(4096)
        message_queue.put(data)

def process_incoming_messages(message_queue):
    while True:
        data = message_queue.get()
        decrypted_data = rc4('mysecretkey'.encode(), data)
        message = decrypted_data.decode()
        parts = message.split('|')
        command = parts[0]
        if command == 'REGISTER_SUCCESS':
            print("Registrasi berhasil")
        elif command == 'REGISTER_FAILURE':
            print("Registrasi gagal:", parts[1])
        elif command == 'LOGIN_SUCCESS':
            print("Login berhasil")
        elif command == 'LOGIN_FAILURE':
            print("Login gagal:", parts[1])
        elif command == 'CREATE_CHATROOM_SUCCESS':
            print("Chatroom berhasil dibuat")
        elif command == 'CREATE_CHATROOM_FAILURE':
            print("Pembuatan chatroom gagal:", parts[1])
        elif command == 'JOIN_CHATROOM_SUCCESS':
            print("Berhasil bergabung ke chatroom")
        elif command == 'JOIN_CHATROOM_FAILURE':
            print("Gagal bergabung ke chatroom:", parts[1])
        elif command == 'CHAT_HISTORY':
            print("Riwayat chat:")
            for msg in parts[1:]:
                print(msg)
        elif command == 'LEAVE_CHATROOM_SUCCESS':
            print("Anda telah meninggalkan chatroom.")
            print("Perintah:")
            print("/register")
            print("/login")
            print("/create")
            print("/join")
            print("/logout")
            print("Ketik pesan Anda untuk mengirim ke chatroom")
        elif command == 'MESSAGE':
            sender = parts[1]
            message_text = parts[2]
            print(f"{sender}: {message_text}")
        elif command == 'ERROR':
            print("Error:", parts[1])
        elif command == 'LOGOUT_SUCCESS':
            print("Berhasil logout")
        else:
            print("Pesan tidak dikenal:", message)

def send_messages(client_socket, server_address, outgoing_queue):
    while True:
        message = outgoing_queue.get()
        encrypted_message = rc4('mysecretkey'.encode(), message.encode())
        client_socket.sendto(encrypted_message, server_address)

def user_input_thread(outgoing_queue):
    while True:
        user_input = input()
        if user_input.startswith('/register'):
            # Minta username dan password secara terpisah
            username = input("Masukkan username: ")
            password = input("Masukkan password: ")
            message = f'REGISTER|{username}|{password}'
        elif user_input.startswith('/login'):
            # Minta username dan password secara terpisah
            username = input("Masukkan username: ")
            password = input("Masukkan password: ")
            message = f'LOGIN|{username}|{password}'
        elif user_input.startswith('/create'):
            # Minta nama chatroom dan password
            chatroom_name = input("Masukkan nama chatroom: ")
            chatroom_password = input("Masukkan password chatroom: ")
            message = f'CREATE_CHATROOM|{chatroom_name}|{chatroom_password}'
        elif user_input.startswith('/join'):
            # Minta nama chatroom dan password
            chatroom_name = input("Masukkan nama chatroom: ")
            chatroom_password = input("Masukkan password chatroom: ")
            message = f'JOIN_CHATROOM|{chatroom_name}|{chatroom_password}'
        elif user_input.startswith('/back'):
            message = 'LEAVE_CHATROOM'
        elif user_input.startswith('/logout'):
            message = 'LOGOUT'
        else:
            # Anggap sebagai pesan chat
            message = f'MESSAGE|{user_input}'
        outgoing_queue.put(message)

def main():
    # Input IP dan Port server
    server_ip = input("Masukkan IP server: ")
    server_port = int(input("Masukkan Port server: "))

    server_address = (server_ip, server_port)
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # Bind ke alamat IP lokal dengan port 0 (otomatis pilih port tersedia)
    client_socket.bind(('', 0))
    client_ip, client_port = client_socket.getsockname()
    print(f"Client dimulai di {client_ip}:{client_port}")
    print("Perintah:")
    print("/register")
    print("/login")
    print("/create")
    print("/join")
    print("/logout")
    print("Ketik pesan Anda untuk mengirim ke chatroom")

    # Queue untuk pesan masuk dan keluar
    incoming_queue = queue.Queue()
    outgoing_queue = queue.Queue()

    # Mulai thread
    recv_thread = threading.Thread(target=receive_messages, args=(client_socket, incoming_queue))
    recv_thread.daemon = True
    recv_thread.start()

    process_thread = threading.Thread(target=process_incoming_messages, args=(incoming_queue,))
    process_thread.daemon = True
    process_thread.start()

    send_thread = threading.Thread(target=send_messages, args=(client_socket, server_address, outgoing_queue))
    send_thread.daemon = True
    send_thread.start()

    user_input_thread_instance = threading.Thread(target=user_input_thread, args=(outgoing_queue,))
    user_input_thread_instance.start()

if __name__ == '__main__':
    main()
