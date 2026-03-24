# Encryped-chat-app
A secure peer-to-peer chat application with a centralized authentication server, combining multiple cryptographic techniques including RSA, AES, and Diffie-Hellman.

📌 Overview

This project implements a hybrid secure messaging system:

A central server handles:
User authentication (login/signup)
Online user management
Connection coordination between clients
A peer-to-peer (P2P) architecture handles:
Direct messaging between users
End-to-end encryption

The system allows switching between:

🔑 RSA-based key exchange
🔄 Diffie-Hellman key exchange
🧠 Key Features
🔐 End-to-end encrypted messaging (AES)
🔑 Secure key exchange (RSA / Diffie-Hellman)
👥 Multi-user support with live user list
💬 Real-time chat via P2P sockets
🧵 Multi-threaded server handling
🖥️ GUI client built with wxPython
📦 Persistent user storage (pickle + salted hashing)
🏗️ Project Structure
.
├── HybridClient.py       # GUI client application 
├── HybridServer.py       # Multi-threaded server 
├── TCP_AES.py            # AES encryption utilities 
├── TCP_RSA.py            # RSA encryption utilities 
├── tcp_by_size.py        # TCP framing protocol 
├── AsyncMessages.py      # Thread-safe message queue
├── crypto_utils.py       # (duplicate AES helpers)
├── Users.pkl             # Stored users (generated)
├── server_public.key     # Server RSA public key
├── server_private.key    # Server RSA private key
🔐 Encryption Architecture
1. Key Exchange Options
✅ RSA
Client sends public key
Server encrypts AES session key with RSA
Used for:
Client ↔ Server communication
Optional P2P setup
🔄 Diffie-Hellman
Shared secret generated dynamically
No key transmission required
Used for:
Secure session key derivation
2. Message Encryption (AES)

All actual messages are encrypted using AES-CBC:

Random IV per message
Key derived via SHA-256
Padding via PKCS#7

👉 Implemented in:

TCP_AES.py
3. Transport Protocol

Custom TCP framing:

Each message is prefixed with its size
Prevents partial reads

👉 Implemented in:

tcp_by_size.py
⚙️ How It Works
🔌 Connection Flow
Client connects to server
Key exchange (RSA or Diffie-Hellman)
User logs in / signs up
Server sends online users list
Client selects another user
Server coordinates P2P connection
Clients establish shared key
Secure chat begins
💬 Messaging Flow

Messages are sent via:

MSG@<text>
Encrypted with AES before transmission
Received and decrypted on the other side
🚀 Getting Started
1. Install Dependencies
pip install wxPython pycryptodome rsa sympy
2. Run the Server
python HybridServer.py
3. Run the Client
python HybridClient.py
4. Usage
Enter server IP (default: 127.0.0.1)
Choose key exchange method:
RSA
Diffie-Hellman
Sign up or log in
Select a user to start chatting
🔑 Security Notes
Passwords are:
Salted
Hashed using SHA-256
AES keys are:
Random or derived securely
RSA keys:
2048-bit
Diffie-Hellman:
Uses large prime generation (sympy)
