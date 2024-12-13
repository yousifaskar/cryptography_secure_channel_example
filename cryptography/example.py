#################################################
# Example function of sending a message. 
# Everything is represented in bytes form.

from secure_channel_funcs import *
from util import generate_random_seq_from_seed
from classes import Role

KEY_SIZE_IN_BYTES = 32
SEED = 125793

def main():
    K = generate_random_seq_from_seed(KEY_SIZE_IN_BYTES, SEED) # Key is 32 bytes (256 bits), in bytes type
    S = initialize_secure_channel(K, Role.CLIENT)
    m = b"hey cutie patootie"
    print("Original message: ", m.decode("utf-8"))
    x = b"Protocol: TCP/IP"
    t = prepare_message(S, m, x)
    print("Cipher (first 30):", t[:30])
    receive = receive_message(S, t, x).decode("utf-8")
    print("Received message: ", receive)
    
    

if __name__ == "__main__":
    main()