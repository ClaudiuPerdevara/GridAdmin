CC = gcc
CFLAGS = -Wall -Wextra -g

GTK_FLAGS = $(shell pkg-config --cflags gtk+-3.0)
GTK_LIBS  = $(shell pkg-config --libs gtk+-3.0)

SSL_LIBS  = -lssl -lcrypto

.PHONY: all clean setup

all: client server

client: client.c
	$(CC) $(CFLAGS) $(GTK_FLAGS) -o client client.c $(GTK_LIBS) $(SSL_LIBS)
	chmod +x client

server: server.c
	$(CC) $(CFLAGS) -o server server.c $(SSL_LIBS) -pthread -lsqlite3
	chmod +x server


setup:
	@echo "[INFO] Se actualizează lista de pachete..."
	sudo apt-get update
	@echo "[INFO] Se instalează bibliotecile necesare (Build, SSL, GTK, SQLite, SSHPass)..."
	sudo apt-get install -y build-essential \
							libssl-dev \
							libgtk-3-dev \
							libsqlite3-dev \
							sqlite3 \
							sshpass \
							gnome-terminal \
							pkg-config
	@echo "[SUCCESS] Toate dependințele au fost instalate! Acum poți rula 'make'."

clean:
	rm -f client server
