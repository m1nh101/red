#!/usr/bin/env python3

import socket
import threading

HOST = '0.0.0.0'
PORT = 31337

CLIENT_HOST = '10.0.0.2'

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((HOST, PORT))

def listen():
    while True:
        data, addr = sock.recvfrom(1024)
        if data.strip():
            print(f"[+] from {addr[0]}:{addr[1]}: {data.decode(errors='replace')}")
            break

if __name__ == "__main__":

    threading.Thread(target=listen, daemon=True).start()

    message = 'FLAG:10.0.0.1:31337'.encode()
    start_port = 0

    while True:
        try:
            start_port += 1
            sock.sendto(message, (CLIENT_HOST, start_port))

        except ConnectionError:
            continue
        except OverflowError:
            break