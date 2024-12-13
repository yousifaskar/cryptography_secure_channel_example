# echo-server.py

import socket
import sys
import os

# Add Cryptography to the system path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'cryptography')))

import util
import classes
import secure_channel_funcs as scf

HOST = "127.0.0.1"  # Standard loopback interface address (localhost)
PORT = 65432  # Port to listen on (non-privileged ports are > 1023)
SEED = 125793
KEY_SIZE_IN_BYTES = 32

key = util.generate_random_seq_from_seed(KEY_SIZE_IN_BYTES, SEED)
S = scf.initialize_secure_channel(key, classes.Role.SERVER)

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen()
    conn, addr = s.accept()
    with conn:
        print(f"Connected by {addr}")
        while True:
            data = conn.recv(1024)
            if not data:
                break  # Exit the loop if no data is received (client closed connection)
            print("SERVER: Data received -- ", data)
            x = "| Protocol: TCP/IP"
            decrypted_msg = scf.receive_message(S, data, x)
            print("Decrypted message: ", decrypted_msg)
            while True:
                user_input = input("Enter a response: ")
                if user_input.lower() == "":
                    print("You must send a message")
                else: break
            msg_to_send = scf.prepare_message(S, user_input, x)
            conn.sendall(msg_to_send)