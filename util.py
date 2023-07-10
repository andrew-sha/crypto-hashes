import constants

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
def pad_message(m):
    '''
    m is a bit string 
    convert the string m into a bit string whose length is a multiple of 512
    '''
    # number of zeros to append after the 1 
    num_zeros = 512 * (len(m) // 512) + 448  - (len(m) + 1) 
    # number of zeros to append to the binary representation of the message length
    num_zeros_binary = 64 - len(bin(len(m))[2:])

    # return padded string
    return m + '1' + (num_zeros * '0') + (num_zeros_binary * '0') + bin(len(m))[2:]

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
    working_variables = [bin(h)[2:].zfill(32)  for h in constants.INITIAL_HASHES]

    # parse message into blocks
    blocks = parse_message(pad_message(m), 512)

    # initialize intermediate hash values
    hashes = [bin(h)[2:].zfill(32)  for h in constants.INITIAL_HASHES]

    # main loop
    for i in range(len(blocks)):
        # generate schedule
        schedule = generate_schedule(blocks[i])

        # update working variables
        for t in range(64):
            T_1 = bitadd(bitadd(bitadd(bitadd(working_variables[7], SIGMA_1(working_variables[4]), 32), Ch(working_variables[4], working_variables[5], working_variables[6]), 32), bin(constants.CONSTANTS[t])[2:].zfill(32) , 32), schedule[t], 32)
            T_2 = bitadd(SIGMA_0(working_variables[0]), Maj(working_variables[0], working_variables[1], working_variables[2]), 32)
            working_variables[7] = working_variables[6]
            working_variables[6] = working_variables[5]
            working_variables[5] = working_variables[4]
            working_variables[4] = bitadd(working_variables[3], T_1, 32)
            working_variables[3] = working_variables[2]
            working_variables[2] = working_variables[1]
            working_variables[1] = working_variables[0]
            working_variables[0] = bitadd(T_1, T_2, 32)
        
        # update intermediate hashes
        for j in range(len(hashes)):
            hashes[j] = bitadd(working_variables[j], hashes[j], 32)

        return hashes


def SHA256(m: str):
    # encode message using unicode
    encoded_message = ''
    for char in m:
        encoded_message += bin(ord(char))[2:].zfill(8)
    
    digest = compute_hash(encoded_message)
    
    # convert digest from sequence of 32-bit blocks to string of 64 hex characters
    for i in range(len(digest)):
        digest[i] = hex(int(digest[i], 2))[2:].zfill(8)
    
    return ''.join(digest)

if __name__ == '__main__':
    print(SHA256('satoshi pays 10 bitcoin to andrew'))