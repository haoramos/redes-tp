# Projeto MyFTP com Python e Interface Gráfica

Este projeto implementa um protocolo simples de transferência de arquivos (FTP) chamado MyFTP, utilizando sockets UDP em Python. O servidor é multi-cliente (usando threads) e o cliente possui uma interface gráfica (GUI) construída com Tkinter.

## Funcionalidades Implementadas

* **Protocolo sobre UDP**: Toda a comunicação é feita com datagramas UDP.
* **Confiabilidade**: Implementa um sistema de numeração de pacotes e ACKs (Agradecimentos) para garantir a entrega. Em caso de perda, o pacote é reenviado após um timeout.
* **Servidor Multi-Cliente**: O servidor usa threads para atender múltiplos clientes simultaneamente.
* **Interface Gráfica**: O cliente possui uma GUI intuitiva para interagir com o servidor.
* **Comandos Suportados**:
    * `login <usuário> <senha>`
    * `put <arquivo>`
    * `get <arquivo>`
    * `ls`
    * `cd <pasta>`
    * `cd..`
    * `mkdir <pasta>`
    * `rmdir <pasta>`
* **Segurança**: O servidor restringe o acesso dos clientes a um diretório raiz específico (`server_files`), impedindo o acesso a outras partes do sistema de arquivos.

## Como Executar

### Pré-requisitos
* Python 3.x

Nenhuma biblioteca externa é necessária, pois `socket`, `threading`, `os`, `pickle` e `tkinter` são parte da biblioteca padrão do Python.

### 1. Preparar o Ambiente do Servidor

1.  Crie uma pasta para o seu projeto.
2.  Dentro dela, salve os arquivos `server.py` e `client_gui.py`.
3.  Crie uma subpasta chamada `server_files`. **É aqui que todos os arquivos e pastas do servidor serão armazenados.**
    ```
    meu_projeto/
    ├── server.py
    ├── client_gui.py
    └── server_files/
        └── (coloque aqui alguns arquivos de teste para o comando 'get')
    ```

### 2. Iniciar o Servidor

Abra um terminal, navegue até a pasta do projeto e execute o seguinte comando:

```bash
python server.py
```

O servidor iniciará e ficará aguardando conexões de clientes na porta `7891`.

### 3. Iniciar o Cliente

Abra **outro** terminal, navegue até a pasta do projeto e execute o cliente:

```bash
python client_gui.py
```

Uma janela gráfica aparecerá.

### 4. Usando o Cliente

1.  Na interface gráfica, mantenha o IP (`127.0.0.1`) e a Porta (`7891`) se estiver executando na mesma máquina.
2.  Use um dos logins válidos definidos no `server.py` (ex: usuário `user`, senha `123`).
3.  Digite o usuário e a senha nos campos apropriados e clique em **"Conectar / Login"**.
4.  O console na parte inferior mostrará o status da conexão.
5.  Após o login bem-sucedido, você pode digitar os comandos (`ls`, `get teste.txt`, `put meu_arquivo.txt`, etc.) no campo de comando e clicar em **"Enviar Comando"**.
6.  Para transferir um arquivo do cliente para o servidor (`put`), o arquivo deve estar na mesma pasta que o `client_gui.py`.
7.  Para baixar um arquivo do servidor (`get`), ele será salvo na mesma pasta do `client_gui.py`.