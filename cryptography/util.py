from hashlib import sha256
from classes import Type_Sizes
import hmac
import secrets
import struct
import math
import random
import Crypto.Cipher.AES as AES

def swap(a, b):
    return (b,a)

def convert_to_fixed_size(size: Type_Sizes, num: int) -> bytearray:
    """Converts an integer to either a 4 or 8 byte int (in bytearray format)
    
    Parameters:
    size: part of the Type_Sizes Enum, either FOUR or EIGHT
    num: the number to convert
    
    Returns:
    result: a bytearray of the specified number of bytes"""
    return struct.pack(size.value, num)

def HMAC_SHA_256(K: bytes, m: str | bytes):
    """Returns a MAC for a specific key, message combination. Uses SHA-256
    
    Parameters:
    k: key, 32 bytes in bytes form
    m: message, arbitary-length string

    Returns: 
    result: hashed result in hexadecimal form
    """
    return hmac.new(K, m, sha256).digest()

def generate_random_seq_from_seed(num_bytes: int, seed: int) -> bytes:
    """Generates a random sequence of bytes from a seed. Used for establishing a shared key.
    
    Parameters:
    num_bytes: number of bytes to generate
    seed: number to use
    
    Returns:
    result: random sequence of bytes"""
    # Set the seed for reproducibility
    random.seed(seed)
    
    # Generate num_bytes random bytes
    random_bytes = bytearray(random.getrandbits(8) for _ in range(num_bytes))
    
    return bytes(random_bytes)

def generate_random_seq(num_bytes: int) -> bytes:
    """Generates a random sequence of bytes. Can be used to establish a key. 
    
    Parameters:
    num_bytes: number of bytes to generate
    
    Returns:
    result: random sequence of bytes"""
    # Generate num_bytes secure random bytes
    secure_random_bytes = secrets.token_bytes(num_bytes)
    return secure_random_bytes

def generate_key_stream(K: bytes, msg_num: bytes, len_t: int) -> bytearray:
    """Generates a key stream for the XOR. Uses AES-256 as cipher. 
    Note, that AES-256 returns 128 bits (16 bytes) as output. 
    We want to return len_t bytes of output, so we will do ceil(len_t / 16)

    Parameters:
    K: the key
    msg_num: message number
    len_t: length of message to send

    Returns:
    key_stream: encrypted sequence of bytes
    """
    key_stream = bytearray()
    for i in range(math.ceil(len_t / 16)):
        curr = convert_to_fixed_size(Type_Sizes.FOUR, i) +\
               convert_to_fixed_size(Type_Sizes.FOUR, msg_num) +\
               convert_to_fixed_size(Type_Sizes.EIGHT, 0)
        cipher = AES.new(K, AES.MODE_CTR, nonce=convert_to_fixed_size(Type_Sizes.FOUR, i))
        key_stream += cipher.encrypt(curr)
    return key_stream

def xor_bytes(bytes1, bytes2) -> bytearray:
    """XORS two bytes or bytearrays
    
    Parameters:
    bytes1 & bytes2: the bytes you want to xor
    
    Returns:
    result: bytearray containing xor'ed result"""
    return bytearray(b1 ^ b2 for b1, b2 in zip(bytes1, bytes2))