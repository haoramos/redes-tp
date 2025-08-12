# server.py (VERSÃO FINAL E CORRETA)

import socket
import os
import pickle
import time
from pathlib import Path

HOST = '127.0.0.1'
PORT = 7891
BUFFER_SIZE = 1024
SERVER_FILES_DIR = "server_files"
RETRY_TIMEOUT = 1.0 
MAX_RETRIES = 5     

USERS = { "user": "123", "aluno": "redes", "admin": "admin" }

def log(message):
    print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {message}")

class ClientHandler:
    def __init__(self, client_address, server_socket):
        self.client_address = client_address
        self.server_socket = server_socket
        self.is_logged_in = False
        self.current_path = Path(SERVER_FILES_DIR).resolve()
        self.server_root = Path(SERVER_FILES_DIR).resolve()
        self.client_seq = 0
        self.server_seq = 0

    def is_path_safe(self, path):
        try:
            return self.server_root in path.resolve().parents or self.server_root == path.resolve()
        except: return False

    def send_packet(self, pkt_type, payload=b'', ack_seq=None):
        if ack_seq is None: ack_seq = self.client_seq
        packet = {"seq": self.server_seq, "ack_seq": ack_seq, "type": pkt_type, "payload": payload}
        self.server_socket.sendto(pickle.dumps(packet), self.client_address)
        current_seq = self.server_seq
        self.server_seq += 1
        return current_seq

    def send_ack(self, ack_seq):
        self.send_packet("ACK", ack_seq=ack_seq)

    def send_error(self, message):
        log(f"Enviando erro para {self.client_address}: {message}")
        self.send_packet("ERROR", payload=message.encode('utf-8'))

    def process_packet(self, data):
        try:
            packet = pickle.loads(data)
            self.client_seq = packet.get('seq', 0)
            
            if packet.get('type') == 'COMMAND':
                command_str = packet.get('payload', b'').decode('utf-8')
                self.handle_command(command_str)
            elif packet.get('type') == 'ACK':
                pass
            elif packet.get('type') in ['DATA', 'FIN'] and self.is_logged_in:
                self.handle_put_data(packet)
            elif not self.is_logged_in:
                self.send_error("Erro: Você precisa fazer login primeiro.")
            else:
                 self.send_error("Tipo de pacote ou estado inválido.")
        except Exception as e:
            log(f"Erro ao processar pacote de {self.client_address}: {e}")

    def handle_command(self, command_str):
        parts = command_str.split()
        if not parts: return
        cmd = parts[0].lower()
        args = parts[1:]
        log(f"Comando '{command_str}' de {self.client_address}")
        
        command_map = {
            'ls': self.handle_ls, 'cd': self.handle_cd, 'cd..': self.handle_cd_up,
            'mkdir': self.handle_mkdir, 'rmdir': self.handle_rmdir,
            'get': self.handle_get, 'put': self.handle_put_setup
        }
        
        if cmd == 'login': return self.handle_login(args)
        if not self.is_logged_in: return self.send_error("Erro: Você precisa fazer login primeiro.")
        
        handler_func = command_map.get(cmd)
        if handler_func: handler_func(args)
        else: self.send_error(f"Comando desconhecido: {cmd}")

    def handle_login(self, args):
        if len(args) != 2: return self.send_error("Sintaxe: login <usuário> <senha>")
        user, password = args
        if USERS.get(user) == password:
            self.is_logged_in = True
            log(f"Cliente {self.client_address} logado como '{user}'.")
            self.send_packet("ACK", payload=f"Login bem-sucedido! Bem-vindo, {user}.".encode('utf-8'))
        else: self.send_error("Usuário ou senha incorretos.")

    def handle_ls(self, args):
        files = os.listdir(self.current_path)
        file_list = "\n".join(files) if files else "Diretório vazio."
        self.send_packet("DATA", payload=file_list.encode('utf-8'))

    def handle_cd(self, args):
        if not args: return self.send_error("Sintaxe: cd <pasta>")
        new_path = self.current_path / args[0]
        if not self.is_path_safe(new_path): return self.send_error("Acesso negado.")
        if new_path.is_dir():
            self.current_path = new_path.resolve()
            self.send_packet("ACK", payload=f"Diretório alterado para: {self.current_path.relative_to(self.server_root)}.".encode('utf-8'))
        else: self.send_error(f"Diretório não encontrado: {args[0]}")
    
    def handle_cd_up(self, args):
        if self.current_path == self.server_root: return self.send_error("Você já está no diretório raiz.")
        self.current_path = self.current_path.parent.resolve()
        self.send_packet("ACK", payload=f"Diretório alterado para: {self.current_path.relative_to(self.server_root)}.".encode('utf-8'))

    def handle_mkdir(self, args):
        if not args: return self.send_error("Sintaxe: mkdir <nome_da_pasta>")
        dir_path = self.current_path / args[0]
        if dir_path.exists(): return self.send_error("Diretório já existe.")
        dir_path.mkdir()
        self.send_packet("ACK", payload=f"Diretório '{args[0]}' criado.".encode('utf-8'))

    def handle_rmdir(self, args):
        if not args: return self.send_error("Sintaxe: rmdir <nome_da_pasta>")
        dir_path = self.current_path / args[0]
        if not dir_path.is_dir(): return self.send_error("Não é um diretório ou não existe.")
        if len(os.listdir(dir_path)) > 0: return self.send_error("O diretório não está vazio.")
        dir_path.rmdir()
        self.send_packet("ACK", payload=f"Diretório '{args[0]}' removido.".encode('utf-8'))

    def handle_get(self, args):
        if not args: return self.send_error("Sintaxe: get <arquivo>")
        file_path = self.current_path / args[0]
        if not file_path.is_file(): return self.send_error("Arquivo não encontrado.")
        log(f"Iniciando envio de '{args[0]}' para {self.client_address}")
        try:
            with open(file_path, 'rb') as f:
                while True:
                    chunk = f.read(BUFFER_SIZE - 256)
                    if not chunk: break
                    ack_received = False
                    for i in range(MAX_RETRIES):
                        current_seq = self.send_packet("DATA", payload=chunk)
                        try:
                            self.server_socket.settimeout(RETRY_TIMEOUT)
                            data, addr = self.server_socket.recvfrom(BUFFER_SIZE)
                            if addr == self.client_address:
                                ack_packet = pickle.loads(data)
                                if ack_packet.get('type') == 'ACK' and ack_packet.get('ack_seq') == current_seq:
                                    ack_received = True
                                    break
                        except socket.timeout:
                            log(f"Timeout esperando ACK para pacote {current_seq}. Tentativa {i+1}/{MAX_RETRIES}")
                            continue
                    if not ack_received:
                        self.send_error("Falha na transferência: cliente não respondeu.")
                        return
            self.send_packet("FIN", payload="Transferência concluída.".encode('utf-8'))
            log(f"Arquivo '{args[0]}' enviado com sucesso para {self.client_address}")
        finally:
            self.server_socket.settimeout(None)

    def handle_put_setup(self, args):
        if not args: return self.send_error("Sintaxe: put <arquivo>")
        self.receiving_file_path = self.current_path / Path(args[0]).name
        self.receiving_file_handle = open(self.receiving_file_path, 'wb')
        log(f"Pronto para receber arquivo '{args[0]}' de {self.client_address}")
        self.send_ack(self.client_seq)

    def handle_put_data(self, packet):
        if not hasattr(self, 'receiving_file_handle') or self.receiving_file_handle.closed: return
        if packet['type'] == 'DATA':
            self.receiving_file_handle.write(packet['payload'])
            self.send_ack(packet['seq'])
        elif packet['type'] == 'FIN':
            self.receiving_file_handle.close()
            log(f"Transferência de '{Path(self.receiving_file_path).name}' concluída.")
            self.send_packet("ACK", payload="Upload bem-sucedido.".encode('utf-8'), ack_seq=packet['seq'])
            del self.receiving_file_handle
            del self.receiving_file_path

def main():
    if not os.path.exists(SERVER_FILES_DIR): os.makedirs(SERVER_FILES_DIR)
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.bind((HOST, PORT))
    log(f"Servidor MyFTP iniciado em {HOST}:{PORT}")
    client_handlers = {}
    while True:
        try:
            data, client_address = server_socket.recvfrom(BUFFER_SIZE)
            if client_address not in client_handlers:
                log(f"Nova sessão para {client_address}")
                client_handlers[client_address] = ClientHandler(client_address, server_socket)
            handler = client_handlers[client_address]
            handler.process_packet(data)
        except Exception as e:
            log(f"Erro CRÍTICO no loop principal do servidor: {e}")

if __name__ == "__main__":
    main()