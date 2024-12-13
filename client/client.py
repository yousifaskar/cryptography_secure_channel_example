# echo-client.py
import socket
import sys
import os

# Add Cryptography to the system path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'cryptography')))

import util
import classes
import secure_channel_funcs as scf

HOST = "127.0.0.1"  # The server's hostname or IP address
PORT = 65432  # The port used by the server
SEED = 125793
KEY_SIZE_IN_BYTES = 32

key = util.generate_random_seq_from_seed(KEY_SIZE_IN_BYTES, SEED)

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    while True:
        user_input = input("Enter a message (or 'exit' to quit): ")
        if user_input.lower() == 'exit':
            break
        elif user_input.lower() == "":
            print("You must send a message")
        else:
            # encrypt message
            x = "| Protocol: TCP/IP"
            S = scf.initialize_secure_channel(key, classes.Role.CLIENT)
            t = scf.prepare_message(S, user_input, x)
            s.sendall(t)
            data = s.recv(1024)
            response = scf.receive_message(S, data, x)
            print(f"Recieved {response}")