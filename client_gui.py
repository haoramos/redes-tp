# client_gui.py (ATUALIZADO - Interface com Explorer Visual)

import tkinter as tk
from tkinter import scrolledtext, messagebox
import tkinter.font as tkFont
import socket
import threading
import pickle
import queue
from pathlib import Path

# --- CONFIGURAÇÕES DO CLIENTE ---
BUFFER_SIZE = 1024
TIMEOUT = 5.0
RETRY_TIMEOUT = 1.0 
MAX_RETRIES = 5     


class MyFTPClient(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("MyFTP Client")
        self.geometry("1000x600")

        self.default_font = tkFont.Font(family="Helvetica", size=11)
        self.bold_font = tkFont.Font(family="Helvetica", size=11, weight="bold")
        
        self.sock = None
        self.server_address = None
        self.is_connected = False
        self.client_seq = 0 
        self.server_seq = 0
        
        self.queue = queue.Queue()
        # Estado para GET
        self.receiving_file_name = None
        self.received_file_data = bytearray()
        # Estado para PUT
        self.put_ack_event = threading.Event()
        self.put_operation_active = False
        self.put_transfer_success = False
        self.last_ack_received = -1

        self.create_widgets()
        self.protocol("WM_DELETE_WINDOW", self.on_closing)

    def create_widgets(self):
        self.grid_rowconfigure(2, weight=1)
        self.grid_columnconfigure(0, weight=1)

        # --- Frame de conexão ---
        self.conn_frame = tk.Frame(self, bd=2, relief=tk.GROOVE)
        self.conn_frame.grid(row=0, column=0, sticky="new", padx=10, pady=(10, 5))
        self.conn_frame.grid_columnconfigure(1, weight=1)
        self.conn_frame.grid_columnconfigure(3, weight=1)

        tk.Label(self.conn_frame, text="IP do Servidor:", font=self.default_font).grid(row=0, column=0, padx=(10, 5), pady=5, sticky="w")
        self.ip_entry = tk.Entry(self.conn_frame, font=self.default_font)
        self.ip_entry.grid(row=0, column=1, padx=5, pady=5, sticky="ew")
        self.ip_entry.insert(0, "127.0.0.1")

        tk.Label(self.conn_frame, text="Porta:", font=self.default_font).grid(row=0, column=2, padx=(10, 5), pady=5, sticky="w")
        self.port_entry = tk.Entry(self.conn_frame, font=self.default_font, width=10)
        self.port_entry.grid(row=0, column=3, padx=5, pady=5, sticky="w")
        self.port_entry.insert(0, "7891")

        tk.Label(self.conn_frame, text="Usuário:", font=self.default_font).grid(row=1, column=0, padx=(10, 5), pady=5, sticky="w")
        self.user_entry = tk.Entry(self.conn_frame, font=self.default_font)
        self.user_entry.grid(row=1, column=1, padx=5, pady=5, sticky="ew")
        self.user_entry.insert(0, "user")

        tk.Label(self.conn_frame, text="Senha:", font=self.default_font).grid(row=1, column=2, padx=(10, 5), pady=5, sticky="w")
        self.pass_entry = tk.Entry(self.conn_frame, show="*", font=self.default_font)
        self.pass_entry.grid(row=1, column=3, padx=5, pady=5, sticky="ew")
        self.pass_entry.insert(0, "123")

        self.connect_button = tk.Button(self.conn_frame, text="Conectar / Login", command=self.connect_login, font=self.bold_font, bg="#DDF0DD")
        self.connect_button.grid(row=0, column=4, rowspan=2, padx=10, pady=5, sticky="ns")

        # --- Novo frame para listagem de arquivos ---
        self.files_frame = tk.Frame(self)
        self.files_frame.grid(row=1, column=0, sticky="nsew", padx=10, pady=5)
        self.files_frame.grid_columnconfigure(0, weight=1)
        self.files_frame.grid_columnconfigure(2, weight=1)
        self.files_frame.grid_rowconfigure(1, weight=1)

        tk.Label(self.files_frame, text="Arquivos do Cliente", font=self.bold_font).grid(row=0, column=0)
        self.local_listbox = tk.Listbox(self.files_frame, selectmode=tk.SINGLE)
        self.local_listbox.grid(row=1, column=0, sticky="nsew", padx=5, pady=5)

        # Botões centrais
        self.actions_frame = tk.Frame(self.files_frame)
        self.actions_frame.grid(row=1, column=1, sticky="ns")
        self.upload_button = tk.Button(self.actions_frame, text="⬆️ Upload", command=self.upload_file)
        self.upload_button.pack(pady=5, fill="x")
        self.download_button = tk.Button(self.actions_frame, text="⬇️ Download", command=self.download_file)
        self.download_button.pack(pady=5, fill="x")
        self.refresh_button = tk.Button(self.actions_frame, text="🔄 Atualizar", command=self.refresh_lists)
        self.refresh_button.pack(pady=5, fill="x")

        tk.Label(self.files_frame, text="Arquivos do Servidor", font=self.bold_font).grid(row=0, column=2)
        self.server_listbox = tk.Listbox(self.files_frame, selectmode=tk.SINGLE)
        self.server_listbox.grid(row=1, column=2, sticky="nsew", padx=5, pady=5)

        # --- Log de saída ---
        self.log_console = scrolledtext.ScrolledText(self, width=80, height=10, state='disabled', font=("Courier New", 10))
        self.log_console.grid(row=2, column=0, sticky="nsew", padx=10, pady=0)

        # --- Frame de comandos ---
        self.cmd_frame = tk.Frame(self)
        self.cmd_frame.grid(row=3, column=0, sticky="sew", padx=10, pady=(5, 10))
        self.cmd_frame.columnconfigure(1, weight=1)
        tk.Label(self.cmd_frame, text="Comando:").grid(row=0, column=0)
        self.cmd_entry = tk.Entry(self.cmd_frame)
        self.cmd_entry.grid(row=0, column=1, sticky="ew", padx=5)
        self.cmd_entry.bind("<Return>", self.send_command_event)
        self.send_button = tk.Button(self.cmd_frame, text="Enviar", command=self.send_command)
        self.send_button.grid(row=0, column=2, padx=5)

    # ---------------- Lógica ----------------
    def log(self, message):
        self.log_console.config(state='normal')
        self.log_console.insert(tk.END, message + "\n")
        self.log_console.config(state='disabled')
        self.log_console.see(tk.END)

    def connect_login(self):
        if self.is_connected:
            self.log("Você já está conectado.")
            return
        ip = self.ip_entry.get()
        try:
            port = int(self.port_entry.get())
        except ValueError:
            self.log("Erro: A porta deve ser um número.")
            return
        self.server_address = (ip, port)
        user = self.user_entry.get()
        password = self.pass_entry.get()
        if not user or not password:
            self.log("Erro: Usuário e senha não podem ser vazios.")
            return
        self.connect_button.config(state="disabled", text="Conectando...")
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sock.settimeout(TIMEOUT)
            self.listener_thread = threading.Thread(target=self.listen_for_messages, daemon=True)
            self.listener_thread.start()
            command = f"login {user} {password}"
            self.send_packet("COMMAND", payload=command.encode('utf-8'))
            self.after(100, self.process_queue)
        except Exception as e:
            self.log(f"Erro ao conectar: {e}")
            self.connect_button.config(state="normal", text="Conectar / Login")

    def send_packet(self, pkt_type, payload=b'', ack_seq=None):
        if not self.sock:
            self.log("Erro: Não conectado.")
            return
        packet = { "seq": self.client_seq, "ack_seq": ack_seq if ack_seq is not None else self.server_seq, "type": pkt_type, "payload": payload }
        self.sock.sendto(pickle.dumps(packet), self.server_address)
        current_seq = self.client_seq
        self.client_seq += 1
        return current_seq

    def send_ack(self, ack_seq):
        self.send_packet("ACK", ack_seq=ack_seq)

    def listen_for_messages(self):
        while self.sock:
            try:
                data, _ = self.sock.recvfrom(BUFFER_SIZE)
                self.queue.put(pickle.loads(data))
            except (socket.timeout, ConnectionResetError, OSError):
                continue
            except Exception as e:
                self.log(f"Erro de rede: {e}")

    def process_queue(self):
        try:
            while not self.queue.empty():
                packet = self.queue.get_nowait()
                self.server_seq = packet.get('seq', 0)
                pkt_type = packet.get('type')
                payload = packet.get('payload', b'')
                
                if pkt_type == 'ACK':
                    if self.put_operation_active:
                        self.put_transfer_success = True
                        self.last_ack_received = packet.get('ack_seq', -1)
                        self.put_ack_event.set()
                    else:
                        if not self.is_connected:
                            self.is_connected = True
                            self.ip_entry.config(state="disabled")
                            self.port_entry.config(state="disabled")
                            self.user_entry.config(state="disabled")
                            self.pass_entry.config(state="disabled")
                            self.connect_button.config(text="Conectado")
                            self.refresh_lists()
                        if payload: self.log(f"Servidor: {payload.decode('utf-8', errors='ignore')}")
                elif pkt_type == 'ERROR':
                    self.log(f"ERRO do Servidor: {payload.decode('utf-8', errors='ignore')}")
                    if self.receiving_file_name:
                        self.log(f"Falha ao receber '{self.receiving_file_name}'.")
                        self.receiving_file_name = None
                        self.received_file_data.clear()
                    if self.put_operation_active:
                        self.put_transfer_success = False
                        self.put_ack_event.set()
                elif pkt_type == 'DATA':
                    if self.receiving_file_name:
                        self.received_file_data.extend(payload)
                        self.send_ack(self.server_seq)
                    else:
                        self.log(payload.decode('utf-8', errors='ignore'))
                        # Atualiza lista do servidor se for resposta ao ls
                        self.server_listbox.delete(0, tk.END)
                        for f in payload.decode('utf-8').splitlines():
                            self.server_listbox.insert(tk.END, f.strip())
                elif pkt_type == 'FIN':
                    if self.receiving_file_name:
                        try:
                            with open(self.receiving_file_name, "wb") as f:
                                f.write(self.received_file_data)
                            self.log(f"Arquivo '{self.receiving_file_name}' recebido e salvo com sucesso.")
                        except Exception as e:
                            self.log(f"Erro ao salvar arquivo '{self.receiving_file_name}': {e}")
                        finally:
                            self.receiving_file_name = None
                            self.received_file_data.clear()
                    if payload: self.log(f"Servidor: {payload.decode('utf-8', errors='ignore')}")
        finally:
            if self.sock:
                self.after(100, self.process_queue)

    def send_command_event(self, event): 
        self.send_command()

    def send_command(self):
        if not self.is_connected:
            self.log("Faça o login primeiro.")
            return
        command = self.cmd_entry.get()
        if not command:
            return
        self.log(f"> {command}")
        self.cmd_entry.delete(0, tk.END)
        parts = command.split()
        cmd = parts[0].lower()
        args = parts[1:]
        if cmd == 'put' and args:
            threading.Thread(target=self.handle_put, args=(args[0],), daemon=True).start()
        elif cmd == 'get' and args:
            self.handle_get(args[0])
        else:
            self.send_packet("COMMAND", payload=command.encode('utf-8'))

    def handle_get(self, filename):
        filepath = Path(filename)
        if filepath.is_file():
            self.log(f"Erro: Arquivo '{filename}' já existe no cliente.")
            return
        self.log(f"Requisitando arquivo '{filename}'...")
        self.received_file_data.clear()
        self.receiving_file_name = filename
        command = f"get {filename}"
        self.send_packet("COMMAND", payload=command.encode('utf-8'))

    def handle_put(self, filename):
        filepath = Path(filename)
        if not filepath.is_file():
            self.log(f"Erro local: Arquivo '{filename}' não encontrado.")
            return

        self.put_operation_active = True
        self.put_transfer_success = False
        self.log(f"Iniciando envio de '{filename}'...")
        
        try:
            self.send_packet("COMMAND", payload=f"put {filename}".encode('utf-8'))
            self.put_ack_event.clear()
            if not self.put_ack_event.wait(timeout=RETRY_TIMEOUT * 2):
                self.log("Erro: Servidor não respondeu ao comando de upload.")
                self.put_operation_active = False
                return
            
            if not self.put_transfer_success:
                self.log("Upload cancelado pelo servidor (arquivo pode já existir).")
                self.put_operation_active = False
                return

            with open(filepath, 'rb') as f:
                while True:
                    chunk = f.read(BUFFER_SIZE - 256)
                    if not chunk: break
                    ack_ok = False
                    for i in range(MAX_RETRIES):
                        data_seq = self.send_packet("DATA", payload=chunk)
                        self.put_ack_event.clear()
                        if self.put_ack_event.wait(timeout=RETRY_TIMEOUT):
                            if self.last_ack_received == data_seq:
                                ack_ok = True
                                break
                        self.log(f"Timeout esperando ACK para pacote de dados. Tentativa {i+1}/{MAX_RETRIES}")
                    if not ack_ok:
                        self.log("Falha no upload: Servidor parou de responder.")
                        self.put_operation_active = False
                        return

            self.send_packet("FIN")
            self.put_ack_event.clear()
            if self.put_ack_event.wait(timeout=RETRY_TIMEOUT * 2):
                 self.log(f"Arquivo '{filename}' enviado com sucesso.")
            else:
                 self.log(f"Envio concluído, mas não recebeu confirmação final do servidor.")
        except Exception as e:
            self.log(f"Erro durante o upload: {e}")
        finally:
            self.put_operation_active = False

    def refresh_lists(self):
        # Atualiza lista local
        self.local_listbox.delete(0, tk.END)
        for f in Path(".").iterdir():
            if f.is_file() and f.name not in ["server.py", "client_gui.py"]:
                self.local_listbox.insert(tk.END, f.name)

        # Atualiza lista do servidor
        if self.is_connected:
            self.send_packet("COMMAND", payload=b"ls")

    def upload_file(self):
        sel = self.local_listbox.get(tk.ACTIVE)
        if sel:
            threading.Thread(target=self.handle_put, args=(sel,), daemon=True).start()

    def download_file(self):
        sel = self.server_listbox.get(tk.ACTIVE)
        if sel:
            self.handle_get(sel)

    def on_closing(self):
        if self.sock:
            self.sock.close()
        self.destroy()


if __name__ == "__main__":
    try:
        from ctypes import windll
        windll.shcore.SetProcessDpiAwareness(1)
    except (ImportError, AttributeError): 
        pass
    app = MyFTPClient()
    app.mainloop()
