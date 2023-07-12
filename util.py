import constants
from typing import List
import hashlib

# bit operations for bit strings
def AND(x: str, y: str) -> str:
    try:
        return ''.join([str(int(x[i]) & int(y[i])) for i in range(max(len(x), len(y)))])
    except IndexError:
        print('Inputs are of different length')

def OR(x: str, y: str) -> str:
    try:
        return ''.join([str(int(x[i]) | int(y[i])) for i in range(max(len(x), len(y)))])
    except IndexError:
        print('Inputs are of different length')

def XOR(x: str, y: str) -> str:
    try:
        return ''.join([str(int(x[i]) ^ int(y[i])) for i in range(max(len(x), len(y)))])
    except IndexError:
        print('Inputs are of different length')

def NOT(x: str) -> str:
    return ''.join([str((1 + int(i)) % 2) for i in x])

def lshift(x: str, n: int) -> str:
    # <<
    if n > len(x):
        return 'Shift amount exceeds string length'
    return x[n:] + ('0' * n)

def rshift(x: str, n: int) -> str:
    # >>
    if n > len(x):
        return 'Shift amount exceeds string length' 
    return ('0' * n) +  x[:len(x)-n]

def bitadd(x: str, y: str, p: int) -> str:
    # add the strings x and y modulo 2^p
    sum = (int(x, 2) + int(y, 2)) % (2 ** p)
    return bin(sum)[2:].zfill(len(x))


# subroutines used in SHA256
def Ch(x: str, y: str, z: str) -> str:
    return XOR(AND(x,y), AND(NOT(x), z)) 

def Maj(x: str, y: str, z: str) -> str:
    return XOR(XOR(AND(x,y), AND(x,z)), AND(y, z))

def ROTR(x: str, n: int) -> str:
    # circular right shift
    if len(x) <= n:
        return 'Shift amount exceeds string length'
    return OR(rshift(x, n), lshift(x, len(x) - n))

def SIGMA_0(x: str) -> str:
    return XOR(XOR(ROTR(x, 2), ROTR(x, 13)), ROTR(x, 22))

def SIGMA_1(x: str) -> str:
    return XOR(XOR(ROTR(x, 6), ROTR(x, 11)), ROTR(x, 25)) 

def sigma_0(x: str) -> str:
    return XOR(XOR(ROTR(x, 7), ROTR(x, 18)), rshift(x, 3))

def sigma_1(x: str) -> str:
    return XOR(XOR(ROTR(x, 17), ROTR(x, 19)), rshift(x, 10))

# functions for preprocessing message
def encode(m: str) -> str:
    # unicode message
    return ''.join([bin(ord(char))[2:].zfill(8) for char in m])

def pad_message(m: str) -> str:
    # convert the bit string m into a bit string whose length is a multiple of 512
    padded = m + '1'
    while (len(padded) % 512) != 448:
        padded += '0'
    return padded + bin(len(m))[2:].zfill(64)

def parse_message(m: str, k: int) -> List[str]:
    # break the bit string m into a list of N k-bit blocks
    N = int(len(m) / k)
    return [m[i * k: (i + 1) * k] for i in range(N)]


# functions for computing the hash
def generate_schedule(block: str) -> List[str]:
    # convert a 512 bit block into a schedule during one iteration of the hash computation
    schedule = []
    words = parse_message(block, 32)
    for t in range(64):
        if t <= 15:
            schedule.append(words[t])
        if t > 15:
            schedule.append(bitadd(bitadd(sigma_1(schedule[t-2]), schedule[t-7], 32), bitadd(sigma_0(schedule[t-15]), schedule[t-16], 32), 32))

    return schedule

def compute_hash(m: str) -> List[str]:
    # parse message into blocks
    blocks = parse_message(pad_message(m), 512)

    # initialize intermediate hash values
    hashes = [bin(h)[2:].zfill(32) for h in constants.INITIAL_HASHES]

    # main loop
    for i in range(len(blocks)):
        # generate schedule
        schedule = generate_schedule(blocks[i])

        # initialize working variables
        a = hashes[0]
        b = hashes[1]
        c = hashes[2]
        d = hashes[3]
        e = hashes[4]
        f = hashes[5]
        g = hashes[6]
        h = hashes[7]

        # update working variables
        for t in range(64):
            T_1 = bitadd(bitadd(bitadd(bitadd(h, SIGMA_1(e), 32), Ch(e, f, g), 32), bin(constants.CONSTANTS[t])[2:].zfill(32) , 32), schedule[t], 32)
            T_2 = bitadd(SIGMA_0(a), Maj(a, b, c), 32)
            h = g
            g = f
            f = e
            e = bitadd(d, T_1, 32)
            d = c
            c = b
            b = a
            a = bitadd(T_1, T_2, 32)
        
        # update intermediate hashes
        working_variables = [a, b, c, d, e, f, g, h]
        for j in range(len(hashes)):
            hashes[j] = bitadd(working_variables[j], hashes[j], 32)

    return hashes


def SHA256(m: str) -> str:
    # encode message using unicode
    digest = compute_hash(encode(m))
    
    # convert digest from sequence of 32-bit blocks to string of 64 hex characters
    for i in range(len(digest)):
        digest[i] = hex(int(digest[i], 2))[2:].zfill(8)
    
    return ''.join(digest)