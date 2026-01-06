GridAdmin - Local Network Administration System

GridAdmin is an advanced Client-Server application, written in C, designed for the centralized administration of workstations within a local network. The system allows for remote shell command execution (SSH), workstation status monitoring (Online/Offline), power management (Wake-on-LAN / Shutdown), and utilizes a secure connection via AES-256 encryption.

Quick Installation and Compilation
The project includes an automated Makefile. Open a terminal in the project folder and follow these steps:
Step 1: Install Dependencies
```bash
        make setup
```
Step 2: Compile Server and Client
```bash
        make
```
Step 3: Start Server
```bash
        ./server <num_threads> <encryption_key>
```
Step 4: Start Client
```bash
        ./client <server_IP / local_IP> <server_PORT> <server_encryption_key>
```
PORT = 3670
Local_IP = 127.0.0.1

Application Usage
To access the administration functions, you must log in as an administrator.
    user: admin
    password: adminpass
