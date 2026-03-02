# 🛡️ GridAdmin - Local Network Administration System

![C](https://img.shields.io/badge/C-00599C?style=for-the-badge&logo=c&logoColor=white)
![Linux](https://img.shields.io/badge/Linux-FCC624?style=for-the-badge&logo=linux&logoColor=black)
![OpenSSL](https://img.shields.io/badge/OpenSSL-721412?style=for-the-badge&logo=openssl&logoColor=white)
![GTK3](https://img.shields.io/badge/GTK3-7FE719?style=for-the-badge&logo=gtk&logoColor=black)

## 📌 Overview
**GridAdmin** is an advanced, multithreaded Client-Server application written in C, designed for the centralized administration of workstations within a local area network (LAN). It establishes a secure communication channel using a custom TCP protocol and features a graphical user interface (GUI) built with GTK+3.

## ✨ Key Features
* 🔒 **Secure Communication:** All TCP traffic between the client and server is encrypted using **AES-256** (via OpenSSL).
* ⚡ **Multithreaded Architecture:** The server efficiently handles multiple concurrent client connections.
* 🖥️ **Remote Shell Execution:** Execute shell commands securely on remote workstations (SSH-like functionality).
* 🔌 **Power Management:** Features **Wake-on-LAN** (via UDP broadcasts) and remote shutdown capabilities.
* 📊 **Live Monitoring:** Real-time tracking of workstation status (Online/Offline) and network discovery using raw sockets.
* 🗄️ **Data Persistence:** Integrated **SQLite** for secure logging and data storage.

## 🛠️ Tech Stack
* **Language:** C
* **Networking:** TCP/UDP Sockets
* **Cryptography:** OpenSSL (AES-256)
* **GUI:** GTK+3
* **Database:** SQLite

---

## 🚀 Installation & Compilation

The project includes an automated `Makefile` for easy compilation. Open a terminal in the project directory and run:

**1. Install Dependencies:**
```bash
make setup
```
**2. Compile Server and Client:**
```bash
make
```
**3. Start the Server:**
```bash
./server <num_threads> <encryption_key>
```
**4. Start the Client:**
```bash
./client <server_IP> <server_PORT> <server_encryption_key>
```
**🔑 Default Credentials**
To access the administrative functions within the client GUI, use the following default credentials: 
```bash
    user: admin
    password: adminpass
```
