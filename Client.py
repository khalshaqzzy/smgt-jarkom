import socket
import threading
import queue
import tkinter as tk
from tkinter import scrolledtext, messagebox

def rc4(key, data):
    """Fungsi untuk mengenkripsi dan mendekripsi data menggunakan RC4."""
    S = list(range(256))
    j = 0
    key_length = len(key)
    key = [ord(c) for c in key]
    # Key Scheduling Algorithm (KSA)
    for i in range(256):
        j = (j + S[i] + key[i % key_length]) % 256
        S[i], S[j] = S[j], S[i]
    # Pseudo-Random Generation Algorithm (PRGA)
    i = j = 0
    result = bytearray()
    for byte in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        K = S[(S[i] + S[j]) % 256]
        result.append(byte ^ K)
    return bytes(result)

def simple_hash(message):
    """Fungsi hash sederhana untuk membuat checksum pesan."""
    hash_value = 0
    for c in message:
        hash_value = (hash_value * 31 + ord(c)) % (2**32)
    return hash_value

def sign_message(secret_key, message):
    """Membuat tanda tangan digital menggunakan kunci rahasia dan pesan."""
    combined = secret_key + message
    signature = simple_hash(combined)
    return signature

def verify_signature(secret_key, message, signature):
    """Memverifikasi tanda tangan digital."""
    expected_signature = sign_message(secret_key, message)
    return expected_signature == signature

class ChatClient:
    def __init__(self, master):
        self.master = master
        self.master.title("Chat Client")

        self.server_ip = ''
        self.server_port = 0

        self.client_socket = None
        self.server_address = None
        self.incoming_queue = queue.Queue()
        self.outgoing_queue = queue.Queue()

        self.current_chatroom = None
        self.username = None  # Menyimpan username setelah login

        # Kunci untuk enkripsi signature
        self.secret_key = 'cintajarkom'

  
        self.bg_color = '#FDFD96'  
        self.fg_color = '#355C7D'  
        self.btn_color = '#A8E6CF'

        self.master.configure(bg=self.bg_color)

        self.create_connection_window()

    def create_connection_window(self):
        """Membuat jendela untuk memasukkan IP dan Port server."""
        self.clear_window()
        self.master.configure(bg=self.bg_color)

        frame = tk.Frame(self.master, bg=self.bg_color)
        frame.pack(expand=True)

        tk.Label(frame, text="Masukkan IP server:", bg=self.bg_color, fg=self.fg_color).grid(row=0, column=0, padx=5, pady=5)
        self.server_ip_entry = tk.Entry(frame)
        self.server_ip_entry.grid(row=0, column=1, padx=5, pady=5)
        tk.Label(frame, text="Masukkan Port server:", bg=self.bg_color, fg=self.fg_color).grid(row=1, column=0, padx=5, pady=5)
        self.server_port_entry = tk.Entry(frame)
        self.server_port_entry.grid(row=1, column=1, padx=5, pady=5)
        tk.Button(frame, text="Connect", command=self.connect_to_server, bg=self.btn_color).grid(row=2, column=0, columnspan=2, pady=10)

        frame.grid_rowconfigure(0, weight=1)
        frame.grid_columnconfigure(0, weight=1)
        frame.grid_columnconfigure(1, weight=1)

    def connect_to_server(self):
        """Menghubungkan client ke server."""
        self.server_ip = self.server_ip_entry.get()
        self.server_port = int(self.server_port_entry.get())
        self.server_address = (self.server_ip, self.server_port)
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.client_socket.bind(('', 0))
        client_ip, client_port = self.client_socket.getsockname()
        print(f"Client dimulai di {client_ip}:{client_port}")

        # Memulai thread
        threading.Thread(target=self.receive_messages, daemon=True).start()
        threading.Thread(target=self.process_incoming_messages, daemon=True).start()
        threading.Thread(target=self.send_messages, daemon=True).start()

        self.create_main_menu()

    def create_main_menu(self):
        """Membuat menu utama."""
        self.clear_window()
        self.master.configure(bg=self.bg_color)

        frame = tk.Frame(self.master, bg=self.bg_color)
        frame.pack(expand=True)

        if self.username:
            tk.Label(frame, text=f"User: {self.username}", bg=self.bg_color, fg=self.fg_color, anchor='w').grid(row=0, column=0, padx=10, pady=5, sticky='w')

        tk.Label(frame, text="Main Menu", font=('Helvetica', 16), bg=self.bg_color, fg=self.fg_color).grid(row=1, column=0, columnspan=2, pady=10)

        tk.Button(frame, text="Register", command=self.register_window, bg=self.btn_color, width=20).grid(row=2, column=0, columnspan=2, pady=5)
        tk.Button(frame, text="Login", command=self.login_window, bg=self.btn_color, width=20).grid(row=3, column=0, columnspan=2, pady=5)
        tk.Button(frame, text="Create Chatroom", command=self.create_chatroom_window, bg=self.btn_color, width=20).grid(row=4, column=0, columnspan=2, pady=5)
        tk.Button(frame, text="Join Chatroom", command=self.join_chatroom_window, bg=self.btn_color, width=20).grid(row=5, column=0, columnspan=2, pady=5)
        tk.Button(frame, text="Logout", command=self.logout, bg=self.btn_color, width=20).grid(row=6, column=0, columnspan=2, pady=5)

        frame.grid_rowconfigure(0, weight=1)
        frame.grid_columnconfigure(0, weight=1)

    def register_window(self):
        """Membuat jendela registrasi."""
        self.clear_window()
        self.master.configure(bg=self.bg_color)

        frame = tk.Frame(self.master, bg=self.bg_color)
        frame.pack(expand=True)

        tk.Label(frame, text="Register", font=('Helvetica', 16), bg=self.bg_color, fg=self.fg_color).grid(row=0, column=0, columnspan=2, pady=10)

        tk.Label(frame, text="Username:", bg=self.bg_color, fg=self.fg_color).grid(row=1, column=0, padx=5, pady=5)
        self.register_username = tk.Entry(frame)
        self.register_username.grid(row=1, column=1, padx=5, pady=5)
        tk.Label(frame, text="Password:", bg=self.bg_color, fg=self.fg_color).grid(row=2, column=0, padx=5, pady=5)
        self.register_password = tk.Entry(frame, show='*')
        self.register_password.grid(row=2, column=1, padx=5, pady=5)
        tk.Button(frame, text="Submit", command=self.register, bg=self.btn_color).grid(row=3, column=0, columnspan=2, pady=10)
        tk.Button(frame, text="Back", command=self.create_main_menu, bg=self.btn_color).grid(row=4, column=0, columnspan=2, pady=5)

    def login_window(self):
        """Membuat jendela login."""
        self.clear_window()
        self.master.configure(bg=self.bg_color)

        frame = tk.Frame(self.master, bg=self.bg_color)
        frame.pack(expand=True)

        tk.Label(frame, text="Login", font=('Helvetica', 16), bg=self.bg_color, fg=self.fg_color).grid(row=0, column=0, columnspan=2, pady=10)

        tk.Label(frame, text="Username:", bg=self.bg_color, fg=self.fg_color).grid(row=1, column=0, padx=5, pady=5)
        self.login_username = tk.Entry(frame)
        self.login_username.grid(row=1, column=1, padx=5, pady=5)
        tk.Label(frame, text="Password:", bg=self.bg_color, fg=self.fg_color).grid(row=2, column=0, padx=5, pady=5)
        self.login_password = tk.Entry(frame, show='*')
        self.login_password.grid(row=2, column=1, padx=5, pady=5)
        tk.Button(frame, text="Submit", command=self.login, bg=self.btn_color).grid(row=3, column=0, columnspan=2, pady=10)
        tk.Button(frame, text="Back", command=self.create_main_menu, bg=self.btn_color).grid(row=4, column=0, columnspan=2, pady=5)

    def create_chatroom_window(self):
        """Membuat jendela untuk membuat chatroom."""
        self.clear_window()
        self.master.configure(bg=self.bg_color)

        frame = tk.Frame(self.master, bg=self.bg_color)
        frame.pack(expand=True)

        tk.Label(frame, text="Create Chatroom", font=('Helvetica', 16), bg=self.bg_color, fg=self.fg_color).grid(row=0, column=0, columnspan=2, pady=10)

        tk.Label(frame, text="Chatroom Name:", bg=self.bg_color, fg=self.fg_color).grid(row=1, column=0, padx=5, pady=5)
        self.create_chatroom_name = tk.Entry(frame)
        self.create_chatroom_name.grid(row=1, column=1, padx=5, pady=5)
        tk.Label(frame, text="Chatroom Password:", bg=self.bg_color, fg=self.fg_color).grid(row=2, column=0, padx=5, pady=5)
        self.create_chatroom_password = tk.Entry(frame, show='*')
        self.create_chatroom_password.grid(row=2, column=1, padx=5, pady=5)
        tk.Button(frame, text="Submit", command=self.create_chatroom, bg=self.btn_color).grid(row=3, column=0, columnspan=2, pady=10)
        tk.Button(frame, text="Back", command=self.create_main_menu, bg=self.btn_color).grid(row=4, column=0, columnspan=2, pady=5)

    def join_chatroom_window(self):
        """Membuat jendela untuk bergabung ke chatroom."""
        self.clear_window()
        self.master.configure(bg=self.bg_color)

        frame = tk.Frame(self.master, bg=self.bg_color)
        frame.pack(expand=True)

        tk.Label(frame, text="Join Chatroom", font=('Helvetica', 16), bg=self.bg_color, fg=self.fg_color).grid(row=0, column=0, columnspan=2, pady=10)

        tk.Label(frame, text="Chatroom Name:", bg=self.bg_color, fg=self.fg_color).grid(row=1, column=0, padx=5, pady=5)
        self.join_chatroom_name = tk.Entry(frame)
        self.join_chatroom_name.grid(row=1, column=1, padx=5, pady=5)
        tk.Label(frame, text="Chatroom Password:", bg=self.bg_color, fg=self.fg_color).grid(row=2, column=0, padx=5, pady=5)
        self.join_chatroom_password = tk.Entry(frame, show='*')
        self.join_chatroom_password.grid(row=2, column=1, padx=5, pady=5)
        tk.Button(frame, text="Submit", command=self.join_chatroom, bg=self.btn_color).grid(row=3, column=0, columnspan=2, pady=10)
        tk.Button(frame, text="Back", command=self.create_main_menu, bg=self.btn_color).grid(row=4, column=0, columnspan=2, pady=5)

    def chatroom_window(self):
        """Membuat jendela chatroom."""
        self.clear_window()
        self.master.configure(bg=self.bg_color)

        top_frame = tk.Frame(self.master, bg=self.bg_color)
        top_frame.pack(fill='x')

        tk.Label(top_frame, text=f"User: {self.username}", bg=self.bg_color, fg=self.fg_color, anchor='w').pack(side='left', padx=10)

        tk.Label(top_frame, text=f"Chatroom: {self.current_chatroom}", bg=self.bg_color, fg=self.fg_color, font=('Helvetica', 16)).pack(side='top', pady=5)

        main_frame = tk.Frame(self.master, bg=self.bg_color)
        main_frame.pack(expand=True, fill='both')

        self.chat_display = scrolledtext.ScrolledText(main_frame, state='disabled', bg='white', fg='black')
        self.chat_display.pack(expand=True, fill='both', padx=10, pady=5)
        self.message_entry = tk.Entry(self.master)
        self.message_entry.pack(fill='x', padx=10, pady=5)
        self.message_entry.bind("<Return>", self.send_chat_message)
        button_frame = tk.Frame(self.master, bg=self.bg_color)
        button_frame.pack()
        tk.Button(button_frame, text="Send", command=self.send_chat_message, bg=self.btn_color).pack(side='left', padx=5)
        tk.Button(button_frame, text="Back", command=self.leave_chatroom, bg=self.btn_color).pack(side='left', padx=5)

    def clear_window(self):
        """Menghapus semua widget di jendela."""
        for widget in self.master.winfo_children():
            widget.destroy()

    def receive_messages(self):
        """Menerima pesan dari server."""
        while True:
            data, addr = self.client_socket.recvfrom(65536)
            self.incoming_queue.put(data)

    def process_incoming_messages(self):
        """Memproses pesan yang diterima dari server."""
        while True:
            data = self.incoming_queue.get()
            try:
                decrypted_data = data.decode()
                encrypted_data_str, signature_str = decrypted_data.split('|')
                encrypted_data = bytes.fromhex(encrypted_data_str)
                signature = int(signature_str)
            except Exception as e:
                print("Format data yang diterima tidak valid.")
                continue

            # Dekripsi data menggunakan RC4
            decrypted_message = rc4(self.secret_key, encrypted_data).decode()

            # Verifikasi signature
            if not verify_signature(self.secret_key, decrypted_message, signature):
                messagebox.showerror("Error", "Verifikasi tanda tangan gagal untuk pesan yang diterima.")
                continue

            message = decrypted_message
            parts = message.split('|')
            command = parts[0]
            if command == 'REGISTER_SUCCESS':
                messagebox.showinfo("Success", "Registrasi berhasil")
                self.create_main_menu()
            elif command == 'REGISTER_FAILURE':
                messagebox.showerror("Error", f"Registrasi gagal: {parts[1]}")
            elif command == 'LOGIN_SUCCESS':
                self.username = self.login_username.get()
                messagebox.showinfo("Success", "Login berhasil")
                self.create_main_menu()
            elif command == 'LOGIN_FAILURE':
                messagebox.showerror("Error", f"Login gagal: {parts[1]}")
            elif command == 'CREATE_CHATROOM_SUCCESS':
                messagebox.showinfo("Success", "Chatroom berhasil dibuat")
                self.create_main_menu()
            elif command == 'CREATE_CHATROOM_FAILURE':
                messagebox.showerror("Error", f"Pembuatan chatroom gagal: {parts[1]}")
            elif command == 'JOIN_CHATROOM_SUCCESS':
                self.current_chatroom = self.join_chatroom_name.get()
                self.chatroom_window()
            elif command == 'JOIN_CHATROOM_FAILURE':
                messagebox.showerror("Error", f"Gagal bergabung ke chatroom: {parts[1]}")
            elif command == 'CHAT_HISTORY':
                self.chat_display.config(state='normal')
                self.chat_display.insert(tk.END, "Riwayat chat:\n")
                for msg in parts[1:]:
                    self.chat_display.insert(tk.END, msg + '\n')
                self.chat_display.config(state='disabled')
            elif command == 'LEAVE_CHATROOM_SUCCESS':
                self.current_chatroom = None
                messagebox.showinfo("Info", "Anda telah meninggalkan chatroom.")
                self.create_main_menu()
            elif command == 'MESSAGE':
                sender = parts[1]
                message_text = parts[2]
                self.chat_display.config(state='normal')
                self.chat_display.insert(tk.END, f"{sender}: {message_text}\n")
                self.chat_display.yview(tk.END)
                self.chat_display.config(state='disabled')
            elif command == 'ERROR':
                messagebox.showerror("Error", parts[1])
            elif command == 'LOGOUT_SUCCESS':
                self.username = None
                messagebox.showinfo("Info", "Berhasil logout")
                self.create_main_menu()
            else:
                print("Pesan tidak dikenal:", message)

    def send_messages(self):
        """Mengirim pesan ke server."""
        while True:
            message = self.outgoing_queue.get()
            encrypted_message = rc4(self.secret_key, message.encode()).hex()
            signature = sign_message(self.secret_key, message)
            data = f"{encrypted_message}|{signature}"
            self.client_socket.sendto(data.encode(), self.server_address)

    def register(self):
        """Fungsi untuk registrasi."""
        username = self.register_username.get()
        password = self.register_password.get()
        message = f'REGISTER|{username}|{password}'
        self.outgoing_queue.put(message)

    def login(self):
        """Fungsi untuk login."""
        username = self.login_username.get()
        password = self.login_password.get()
        message = f'LOGIN|{username}|{password}'
        self.outgoing_queue.put(message)

    def create_chatroom(self):
        """Fungsi untuk membuat chatroom."""
        chatroom_name = self.create_chatroom_name.get()
        chatroom_password = self.create_chatroom_password.get()
        message = f'CREATE_CHATROOM|{chatroom_name}|{chatroom_password}'
        self.outgoing_queue.put(message)

    def join_chatroom(self):
        """Fungsi untuk bergabung ke chatroom."""
        chatroom_name = self.join_chatroom_name.get()
        chatroom_password = self.join_chatroom_password.get()
        message = f'JOIN_CHATROOM|{chatroom_name}|{chatroom_password}'
        self.outgoing_queue.put(message)

    def leave_chatroom(self):
        """Fungsi untuk meninggalkan chatroom."""
        message = 'LEAVE_CHATROOM'
        self.outgoing_queue.put(message)

    def send_chat_message(self, event=None):
        """Mengirim pesan chat."""
        message_text = self.message_entry.get()
        if message_text.strip() == '':
            return
        message = f'MESSAGE|{message_text}'
        self.outgoing_queue.put(message)
        self.message_entry.delete(0, tk.END)

    def logout(self):
        """Fungsi untuk logout."""
        message = 'LOGOUT'
        self.outgoing_queue.put(message)
        self.username = None
        messagebox.showinfo("Info", "Anda telah logout.")
        self.create_main_menu()

if __name__ == '__main__':
    root = tk.Tk()
    client = ChatClient(root)
    root.mainloop()
