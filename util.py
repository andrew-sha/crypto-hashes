import constants
from typing import List
import hashlib

'''
SUBROUTINES
'''

'''SHA256'''
def Ch(x, y, z):
    # if x then y else z
    return (x & y) ^ (~x & z)

def Maj(x, y, z):
    return (x & y) ^ (x & z) ^ (y & z)

def ROTR(x, n: int):
    # circular right shift
    return (x >> n) | (x << (32 - n))

def SIGMA_0(x):
    return ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22)

def SIGMA_1(x):
    return ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25)

def sigma_0(x):
    return ROTR(x, 7) ^ ROTR(x, 18) ^ (x >> 3)

def sigma_1(x):
    return ROTR(x, 17) ^ ROTR(x, 19) ^ (x >> 10)

'''MD5'''
def F(x, y, z):
    return (x & y) | (~x & z)

def G(x, y, z):
    return (x & z) | (y & ~z)

def H(x, y, z):
    return x ^ y ^ z

def I(x, y, z):
    return y ^ (x | ~z)


'''
PREPROCESSING
'''
def pad_message(m: str, byteorder: str) -> str:
    # pad message such that its length in bits is a multiple 512

    # get number of bits in original message
    original_length = len(m) * 8

    # append the byte-equivalent of '10000000' to the end of the message
    m += b'\x80'

    # append zeros until length of message in bits is equal to 448 mod 512
    while ((len(m) * 8) % 512) != 448:
        m += b'\x00'

    return (m + original_length.to_bytes(8, byteorder))

def parse_message(m: str, k: int) -> List[str]:
    # break a string (e.g. sequence of bytes) into blocks of size k
    N = int(len(m) / k)
    return [m[i * k: (i + 1) * k] for i in range(N)]

def generate_schedule_sha256(block: str) -> List[str]:
    # convert a 64 byte (512 bit) block into a schedule during one iteration of the hash computation
    schedule = []
    words = parse_message(block, 4)
    for t in range(64):
        if t <= 15:
            schedule.append(words[t])
        if t > 15:
            s0 = sigma_1(int.from_bytes(schedule[t-2], 'big')) 
            s1 = int.from_bytes(schedule[t-7], 'big')
            s2 = sigma_0(int.from_bytes(schedule[t-15], 'big'))
            s3 = int.from_bytes(schedule[t-16], 'big')
            s4 = (s0 + s1 + s2 + s3) % constants.MODULUS
            schedule.append(s4.to_bytes(4, 'big'))

    return schedule

'''
HASH COMPUTATIONS
'''
def compute_sha256(m: str) -> List[str]:
    # parse message into 64 byte (512 bit) blocks
    blocks = parse_message(pad_message(m, 'big'), 64)

    # initialize hash values
    hashes = constants.INITIAL_HASHES_SHA256

    # main loop
    for i in range(len(blocks)):
        # generate schedule
        schedule = generate_schedule_sha256(blocks[i])

        # initialize working variables
        [a, b, c, d, e, f, g, h] = [h for h in hashes]

        # update working variables
        for t in range(64):
            T_1 = (h + SIGMA_1(e) + Ch(e, f, g) + constants.CONSTANTS_SHA256[t] + int.from_bytes(schedule[t], 'big')) % constants.MODULUS
            T_2 = (SIGMA_0(a) + Maj(a, b, c)) % constants.MODULUS
            h = g
            g = f
            f = e
            e = (d + T_1) % constants.MODULUS
            d = c
            c = b
            b = a
            a = (T_1 + T_2) % constants.MODULUS
        
        # update hashes
        working_variables = [a, b, c, d, e, f, g, h]
        for j in range(len(hashes)):
            hashes[j] = (working_variables[j] + hashes[j]) % constants.MODULUS

    # return list of final hashes as bytes
    return [h.to_bytes(4, 'big') for h in hashes]

def compute_md5(m: str) -> List[str]:
    # parse message into 64 byte (512 bit) blocks
    blocks = parse_message(pad_message(m, 'little'), 64)

    # initialize hash values
    hashes = constants.INITIAL_HASHES_MD5

    # main loop
    for i in range(len(blocks)):
        # break block into 4-byte (32-bit) words
        schedule = parse_message(blocks[i], 4)

        # initialize working variables
        [A, B, C, D] = hashes
        
        # update working variables
        for j in range(64):
            if j in range(16):
                E = F(B, C, D)
                k = j
            elif j in range(16, 32):
                E = G(B, C, D)
                k = (j * 5 + 1) % 16
            elif j in range(32, 48):
                E = H(B, C, D)
                k = (j * 3 + 5) % 16
            elif j in range(48, 64):
                E = I(B, C, D)
                k = (j * 7) % 16
        
            E = (E + A + constants.CONSTANTS_MD5[j] + int.from_bytes(schedule[k], 'little')) % constants.MODULUS 
            A = D
            D = C
            C = B
            B = (B + ROTR(E, 32 - constants.SHIFTS_MD5[j])) % constants.MODULUS
        
        working_variables = [A, B, C, D]
        for p in range(len(hashes)):
            hashes[p] = (hashes[p] + working_variables[p]) % constants.MODULUS
    
    return [h.to_bytes(4, 'little') for h in hashes]


def SHA256(m: str) -> str:
    # encode message using unicode
    digest = compute_sha256(m.encode())    
    return b''.join(digest).hex()

def MD5(m: str) -> str:
    # encode message using unicode
    digest = compute_md5(m.encode())
    return b''.join(digest).hex()

if __name__ == '__main__':
    m = 'Lorem ipsum dolor sit amet'
    guess = str(MD5(m))
    answer = str(hashlib.md5(m.encode()).hexdigest())
    print(guess)
    print(answer)
    print(guess == answer)