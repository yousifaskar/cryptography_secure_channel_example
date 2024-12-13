# Provides any functions necessary to implement a secure channel
from classes import Channel_State, Role, Type_Sizes
import util

def initialize_secure_channel(K: str, R: Role) -> Channel_State:
    """
    Initializes secure channel with keys and message counts
     
    Parameters:
    K: key string for channel, 256 bits
    R: Communication path (client to server, server to client)

    Returns: Channel_State with configured keys and message counts
    """
    # assert(util.is_256_bit_key(K))

    S = Channel_State()
    S.create_keys(K)
    
    # if server is sending message to client, swap keys (as they are initialized to from client to server)
    if R == Role.SERVER:
        S.KeySendEncryption, S.KeyRecEncryption = util.swap(S.KeySendEncryption, S.KeyRecEncryption)
        S.KeySendAuth, S.KeyRecAuth = util.swap(S.KeySendAuth, S.KeyRecAuth)
    
    return S

def prepare_message(S: Channel_State, m: str | bytes, x: str | bytes) -> bytes:
    """
        Prepares message through encryption and authentication, and updates message count
    
        Parameters:
        S: channel_state, includes keys and message count
        m: message to be sent
        x: additional data to be authenticated

        Returns:
        t: final message to be sent to receiver, includes msg, auth, and message count
    """
    # ensure we haven't reached msg limit, and increment msg
    assert(S.MsgCntSend < 2^32 - 1)
    S.MsgCntSend += 1
    i = S.MsgCntSend
    if type(m) == str:
        m = m.encode("utf-8")
    if type(x) == str:
        x = x.encode("utf-8")
    data = m + x

    # compute authentication using HMAC-SHA-256. Note, values l(x) and i are encoded in 4 bytes, least sig byte first. 
    a = util.HMAC_SHA_256(S.KeySendAuth, data)
    t = data + a # concatenate message + auth

    key_stream = util.generate_key_stream(S.KeySendEncryption, i, len(t))[:len(t)]
    t_xor = util.xor_bytes(t, key_stream)
    t = util.convert_to_fixed_size(Type_Sizes.FOUR, i) + t_xor

    return t

def receive_message(S: Channel_State, t: bytes, x: bytes) -> bytes:
    """Decrypts a message received. Checks authentication to see if MACs align, and discards otherwise.
    Also discards if message number is old.
    
    Parameters:
    S: Channel State, includes all keys and msg count numbers.
    t: received_msg
    x: extra information
    
    Returns:
    result: original message, in bytes"""
    assert(len(t) > 36)
    i = int.from_bytes((t[0:4]), byteorder="little") # i is always bytes
    t = t[4:] # remove i from t

    key_stream = util.generate_key_stream(S.KeyRecEncryption, i, len(t))[:len(t)] # generate same key stream
    t_xor = util.xor_bytes(t, key_stream) # get rid of cipher by xoring once again

    # structure of our message:
    # [m = len(m)][x = len(x)][a = 32 bytes]
    # process: we know len(x). Extract a, then x, then m. 
    
    a = t_xor[-32:] # get a, remember that a is 32 bytes
    t_xor = t_xor[:-32] # remove a
    x = t_xor[-(len(x)):] # get x
    t_xor = t_xor[:-(len(x))] # remove x
    m = t_xor # remaining message

    data = m + x # for consistency sake

    # recompute authentication
    a_prime = util.HMAC_SHA_256(S.KeyRecAuth, data)
    if (a_prime == a):
        print("Authentication confirmed!")
    else:
        print("not equal")
        print("a: ", a)
        print("a':", a_prime)
        return
    
    if i <= S.MsgRecSend:
        print("Message out of order")
        return 

    S.MsgCntRec = i
    return m
    



