from hashlib import sha256
from enum import Enum

class Channel_State:
    def __init__(self):
        self.KeySendEncryption = "" # key used to encrypt/decrypt messages sent from client to server
        self.KeyRecEncryption = ""  # key used to encrypt/decrypt messages sent from server to client
        self.KeySendAuth = ""       # key used to authenticate messages sent from client to server
        self.KeyRecAuth = ""        # key used to authenticate messages sent from server to client
        self.MsgCntSend = 0         # keeps track of most recent sent message
        self.MsgRecSend = 0         # keeps track of most recent received message
    
    def create_keys(self, K):
        self.KeySendEncryption = sha256(K + b"Enc Client to Server").digest()
        self.KeyRecEncryption = sha256(K + b"Enc Server to Client").digest()
        self.KeySendAuth = sha256(K + b"Auth Client to Server").digest()
        self.KeyRecAuth = sha256(K + b"Auth Server to Client").digest()

class Role(Enum):
    CLIENT = 0
    SERVER = 1

class Type_Sizes(Enum): # < implies least sig first
    FOUR = "<I"
    EIGHT = "<Q"