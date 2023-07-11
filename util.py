import constants
import hashlib

# bit operations for bit strings
def AND(x, y):
    s = ''
    if len(x) != len(y):
        print('Bit strings are of different length.')
    else:
        for i in range(len(x)):
            s += str(int(x[i]) & int(y[i]))
        return(s)

def OR(x, y):
    s = ''
    if len(x) != len(y):
        print('Bit strings are of different length.')
    else:
        for i in range(len(x)):
            s += str(int(x[i]) | int(y[i]))
        return(s)

def XOR(x, y):
    s = ''
    if len(x) != len(y):
        print('Bit strings are of different length.')
    else:
        for i in range(len(x)):
            s += str(int(x[i]) ^ int(y[i]))
        return(s) 

def NOT(x):
    s = ''
    for i in x:
        s += str((1 + int(i)) % 2)
    return s

def lshift(x, n):
    # <<
    if n > len(x):
        return 'Shift amount exceeds string length'
    return x[n:] + ('0' * n)

def rshift(x, n):
    # >>
    if n > len(x):
        return 'Shift amount exceeds string length' 
    return ('0' * n) +  x[:len(x)-n]

def bitadd(x, y, p):
    # add the strings x and y modulo 2^p
    x_base_ten = int(x, 2)
    y_base_ten = int(y, 2)
    sum = (x_base_ten + y_base_ten) % (2 ** p)
    return '0' * (len(x)-len(bin(sum)[2:])) + bin(sum)[2:]

# subroutines used in SHA256
def Ch(x, y, z):
    return XOR(AND(x,y), AND(NOT(x), z)) 

def Maj(x, y, z):
    return XOR(XOR(AND(x,y), AND(x,z)), AND(y, z))

def ROTR(x, n):
    '''
    Circular right shift
    x is an w-bit word and n is an integer 0 <= n < w
    '''
    if len(x) <= n:
        return 'Shift amount exceeds string length'
    return OR(rshift(x, n), lshift(x, len(x) - n))

def SIGMA_0(x):
    return XOR(XOR(ROTR(x, 2), ROTR(x, 13)), ROTR(x, 22))

def SIGMA_1(x):
    return XOR(XOR(ROTR(x, 6), ROTR(x, 11)), ROTR(x, 25)) 

def sigma_0(x):
    return XOR(XOR(ROTR(x, 7), ROTR(x, 18)), rshift(x, 3))

def sigma_1(x):
    return XOR(XOR(ROTR(x, 17), ROTR(x, 19)), rshift(x, 10))

# functions for preprocessing message
def encode(m):
    '''
    unicode message
    '''
    encoded_message = ''
    for char in m:
        encoded_message += bin(ord(char))[2:].zfill(8)
    return encoded_message

def pad_message(m):
    '''
    m is a bit string 
    convert the string m into a bit string whose length is a multiple of 512
    '''
    padded = m + '1'
    while (len(padded) % 512) != 448:
        padded += '0'
    return padded + bin(len(m))[2:].zfill(64)


def parse_message(m, k):
    '''
    m is a padded bit string whose length is a multiple of k
    break the padded message into a list of N k-bit blocks
    '''
    N = int(len(m) / k)
    return [m[i * k: (i + 1) * k] for i in range(N)]


# functions for computing the hash
def generate_schedule(block):
    '''
    block is a 512-bit block that will be converted into a schedule during one iteration of the hash computation
    '''
    schedule = []
    words = parse_message(block, 32)
    for t in range(64):
        if t <= 15:
            schedule.append(words[t])
        if t > 15:
            schedule.append(bitadd(bitadd(sigma_1(schedule[t-2]), schedule[t-7], 32), bitadd(sigma_0(schedule[t-15]), schedule[t-16], 32), 32))

    return schedule

def compute_hash(m):
    '''
    m is the message to be hashed
    '''
    # initialize working variables for first iteration
    #working_variables = [bin(h)[2:].zfill(32)  for h in constants.INITIAL_HASHES]

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


def SHA256(m):
    # encode message using unicode
    digest = compute_hash(encode(m))
    
    # convert digest from sequence of 32-bit blocks to string of 64 hex characters
    for i in range(len(digest)):
        digest[i] = hex(int(digest[i], 2))[2:].zfill(8)
    
    return ''.join(digest)

if __name__ == '__main__':
    long = 'a' * 1000
    test_vectors = [
    'abc',
    '',
    'abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq',
    'abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu',
    long]
    for word in test_vectors:
        print(SHA256(word) == hashlib.sha256(word.encode()).hexdigest())
