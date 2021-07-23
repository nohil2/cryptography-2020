#Noah Hill 908200540
'''
input should be an ASCII text file called plaintext.txt
key should be 64 bit in hex in key.txt
output is hex in cyphertext.txt
reverse input/output for decryption
'''

def decrypt():
    with open('cyphertext.txt', 'r') as c:
        cyphertext = c.read()
    with open('key.txt', 'r') as k:
        key = k.read()
     
    p = open('plaintext.txt', 'w')
    
    #process key
    key = bin(int(key, 16))
    key = list(key)
    key = key[2:]
    
    cyphertext = cyphertext[2:]
    cyphertext = [cyphertext[x:x+16] for x in range(0, len(cyphertext), 16)] #divide ciphertext into 64-bit blocks
    
    for block in cyphertext:
        bwords = [block[x:x+4] for x in range(0, len(block), 4)] #divide block into 4 words
        temp = []
        temp_r0 = ""
        temp_r1 = ""
        
        #input whitening
        tempkey = [key[x:x+16] for x in range(0, len(key), 16)]
        r0 = int(bwords[0], 16) ^ int("".join(tempkey[0]), 2)
        r1 = int(bwords[1], 16) ^ int("".join(tempkey[1]), 2)
        r2 = hex(int(bwords[2], 16) ^ int("".join(tempkey[2]), 2))
        r3 = hex(int(bwords[3], 16) ^ int("".join(tempkey[3]), 2))
        
        for round in range(0, 16):
            #print("round ", round)
            #ensure that all r's inlcude preceding zeros; r2, r3 will always be strings
            r0 = hex(r0)
            r1 = hex(r1)
            while len(r0) != 6:
                r0 = r0[:2] + '0' + r0[2:]
            while len(r1) != 6:
                r1 = r1[:2] + '0' + r1[2:]
            while len(r2) != 6:
                r2 = r2[:2] + '0' + r2[2:]
            while len(r3) != 6:
                r3 = r3[:2] + '0' + r3[2:]
                
            temp = f_d(r0, r1, round+1, key)
            temp_r0 = r0
            temp_r1 = r1
            r0 = int(r2, 16) ^ temp[0]
            r1 = int(r3, 16) ^ temp[1]
            r2 = temp_r0
            r3 = temp_r1
        
        y0 = int(r2, 16)
        y1 = int(r3, 16)
        y2 = r0
        y3 = r1
        
        c0 = y0 ^ int("".join(tempkey[0]), 2)
        c1 = y1 ^ int("".join(tempkey[1]), 2)
        c2 = y2 ^ int("".join(tempkey[2]), 2)
        c3 = y3 ^ int("".join(tempkey[3]), 2)
        ptext = hex((c0 << 48) | (c1 & 0xFFFF) << 32 | (c2 & 0xFFFF) << 16 | (c3 & 0xFFFF))
        p.write(str(bytearray.fromhex(ptext[2:]).decode()))
        
    p.close()
    return 0

#f function for decrypting
def f_d(r0, r1, round, key):
    k12 = int("".join(key_sched_d(key, 4 * round + 3)), 2)
    k11 = int("".join(key_sched_d(key, 4 * round + 2)), 2)
    k10 = int("".join(key_sched_d(key, 4 * round + 1)), 2)
    k9 = int("".join(key_sched_d(key, 4 * round + 0)), 2)
    k8 = int("".join(key_sched_d(key, 4 * round + 3)), 2)
    k7 = int("".join(key_sched_d(key, 4 * round + 2)), 2)
    k6 = int("".join(key_sched_d(key, 4 * round + 1)), 2)
    k5 = int("".join(key_sched_d(key, 4 * round + 0)), 2)
    k4 = int("".join(key_sched_d(key, 4 * round + 3)), 2)
    k3 = int("".join(key_sched_d(key, 4 * round + 2)), 2)
    k2 = int("".join(key_sched_d(key, 4 * round + 1)), 2)
    k1 = int("".join(key_sched_d(key, 4 * round + 0)), 2)

    t0 = g_d(r0, round, k1, k2, k3, k4)
    t1 = g_d(r1, round, k5, k6, k7, k8)
    
    f0 = int(t0, 16) + 2 * int(t1, 16)
    
    concat = (k9 << 8) | (k10 & 0xFF)
    f0 = (f0 + concat) % 2**16

    f1 = 2 * int(t0, 16) + int(t1, 16)
    concat = (k11 << 8) | (k12 & 0xFF)
    f1 = (f1 + concat) % 2**16
    
    result = [f0, f1]
    return result

#g_permutation function for encrypting
def g_d(w, round, k1, k2, k3, k4):
    w = w[2:]
    w = [w[x:x+2] for x in range(0, len(w), 2)]
    g1 = int(w[0], 16)
    g2 = int(w[1], 16)
    
    g3 = int(ftable(hex(g2 ^ k1)), 16) ^ g1
    
    g4 = int(ftable(hex(g3 ^ k2)), 16) ^ g2

    g5 = int(ftable(hex(g4 ^ k3)), 16) ^ g3
    
    g6 = int(ftable(hex(g5 ^ k4)), 16) ^ g4
    
    #print(hex(g1), hex(g2), hex(g3), hex(g4), hex(g5), hex(g6))
    return hex((g5 << 8) | (g6 & 0xFF))


def key_sched_d(key, x):
    #pick byte of key based on x
    tempkey = [key[x:x+8] for x in range(0, len(key), 8)]
    key_byte = x % 8
    b = tempkey[len(tempkey) - key_byte - 1]
    
    #right rotate key
    temp = key[len(key) - 1]
    key.pop()
    key.insert(0, temp)
    #print(hex(int(("".join(b)),2)))
    return b



def encrypt():
    with open('plaintext.txt', 'r') as p:
        plaintext = p.read()
    with open('key.txt', 'r') as k:
        key = k.read()
    
    c = open('cyphertext.txt', 'w')
    c.write('0x')
    
    #process key
    key = bin(int(key, 16))
    key = list(key)
    key = key[2:]

    #process plaintext
    plaintext.replace(" ", "")
    plaintext = list(plaintext)
    plaintext = [plaintext[x:x+8] for x in range(0, len(plaintext), 8)] #divide plaintext into 64-bit blocks
    
    #for every 64-bit block
    for block in plaintext:
        bwords = [block[x:x+2] for x in range(0, len(block), 2)] #divide block into 4 words

        temp = []
        temp_r0 = ""
        temp_r1 = ""
        
        #input whitening
        key_chunk = 0
        r0 = input_whiten(bwords[0], key, key_chunk)   
        key_chunk += 1 #advance key_chunk for next word
        r1 = input_whiten(bwords[1], key, key_chunk)
        key_chunk += 1
        r2 = input_whiten(bwords[2], key, key_chunk)
        key_chunk += 1
        r3 = input_whiten(bwords[3], key, key_chunk)
        r2 = hex(r2)
        r3 = hex(r3)
        for round in range(0, 16):
            #print("round ", round)
            #ensure that all r's inlcude preceding zeros; r2, r3 will always be strings
            r0 = hex(r0)
            r1 = hex(r1)
            while len(r0) != 6:
                r0 = r0[:2] + '0' + r0[2:]
            while len(r1) != 6:
                r1 = r1[:2] + '0' + r1[2:]
            while len(r2) != 6:
                r2 = r2[:2] + '0' + r2[2:]
            while len(r3) != 6:
                r3 = r3[:2] + '0' + r3[2:]
                
            temp = f_e(r0, r1, round, key)
            temp_r0 = r0
            temp_r1 = r1
            r0 = int(r2, 16) ^ temp[0]
            r1 = int(r3, 16) ^ temp[1]
            r2 = temp_r0
            r3 = temp_r1
        
        y0 = int(r2, 16)
        y1 = int(r3, 16)
        y2 = r0
        y3 = r1
        
        tempkey = [key[x:x+16] for x in range(0, len(key), 16)]

        c0 = y0 ^ int("".join(tempkey[0]), 2)
        c1 = y1 ^ int("".join(tempkey[1]), 2)
        c2 = y2 ^ int("".join(tempkey[2]), 2)
        c3 = y3 ^ int("".join(tempkey[3]), 2)
        cyphertext = hex((c0 << 48) | (c1 & 0xFFFF) << 32 | (c2 & 0xFFFF) << 16 | (c3 & 0xFFFF))
        c.write(str(cyphertext)[2:])
    
    c.close()
    return 0


#f function for encrypting
def f_e(r0, r1, round, key):
    t0 = g_e(r0, round, key)
    t1 = g_e(r1, round, key)
    
    f0 = int(t0, 16) + 2 * int(t1, 16)
    temp = int("".join(key_sched_e(key, 4 * round)), 2)
    temp2 = int("".join(key_sched_e(key, 4 * round + 1)), 2)
    concat = (temp << 8) | (temp2 & 0xFF)
    f0 = (f0 + concat) % 2**16

    f1 = 2 * int(t0, 16) + int(t1, 16)
    temp = int("".join(key_sched_e(key, 4 * round + 2)), 2)
    temp2 = int("".join(key_sched_e(key, 4 * round + 3)), 2)
    concat = (temp << 8) | (temp2 & 0xFF)
    f1 = (f1 + concat) % 2**16
#    print('\n')
#    print("t0: ", t0, " t1: ", t1)
#    print("f0: ", hex(f0), " f1: ", hex(f1), '\n')
    result = [f0, f1]
    return result


#g_permutation function for encrypting
def g_e(w, round, key):
    #w = hex(w)
    w = w[2:]
    w = [w[x:x+2] for x in range(0, len(w), 2)]
    g1 = int(w[0], 16)
    g2 = int(w[1], 16)
    
    temp = int("".join(key_sched_e(key, 4 * round)), 2)
    g3 = int(ftable(hex(g2 ^ temp)), 16) ^ g1
    
    
    temp = int("".join(key_sched_e(key, 4 * round + 1)), 2) 
    g4 = int(ftable(hex(g3 ^ temp)), 16) ^ g2


    temp = int("".join(key_sched_e(key, 4 * round + 2)), 2) 
    g5 = int(ftable(hex(g4 ^ temp)), 16) ^ g3
    
    
    temp = int("".join(key_sched_e(key, 4 * round + 3)), 2) 
    g6 = int(ftable(hex(g5 ^ temp)), 16) ^ g4
    
    #print(hex(g1), hex(g2), hex(g3), hex(g4), hex(g5), hex(g6))
    return hex((g5 << 8) | (g6 & 0xFF))


def key_sched_e(key, x):
    #left rotate key
    temp = key[0]
    key.pop(0)
    key.append(temp)
    
    #temporary key separated into bytes
    tempkey = [key[x:x+8] for x in range(0, len(key), 8)]

    #pick byte of key based on x
    key_byte = x % 8
    #print(hex(int("".join(tempkey[len(tempkey) - key_byte - 1]), 2) ))
    return tempkey[len(tempkey) - key_byte - 1]



def input_whiten(word, key, kchunk):
    #process word into hex value
    a = word[0]
    b = word[1]
    a = ord(a)
    b = ord(b)
    y = hex((a << 8) | (b & 0xFF))

    #process key byte into hex
    tempkey = [key[x:x+16] for x in range(0, len(key), 16)]
    x = "".join(tempkey[kchunk])
    x = hex(int(x, 2))

    #return xor 
    return int(y, 16) ^ int(x, 16)

def ftable(byte):
    table = [[0xa3,0xd7,0x09,0x83,0xf8,0x48,0xf6,0xf4,0xb3,0x21,0x15,0x78,0x99,0xb1,0xaf,0xf9], 
             [0xe7,0x2d,0x4d,0x8a,0xce,0x4c,0xca,0x2e,0x52,0x95,0xd9,0x1e,0x4e,0x38,0x44,0x28], 
             [0x0a,0xdf,0x02,0xa0,0x17,0xf1,0x60,0x68,0x12,0xb7,0x7a,0xc3,0xe9,0xfa,0x3d,0x53], 
             [0x96,0x84,0x6b,0xba,0xf2,0x63,0x9a,0x19,0x7c,0xae,0xe5,0xf5,0xf7,0x16,0x6a,0xa2], 
             [0x39,0xb6,0x7b,0x0f,0xc1,0x93,0x81,0x1b,0xee,0xb4,0x1a,0xea,0xd0,0x91,0x2f,0xb8], 
             [0x55,0xb9,0xda,0x85,0x3f,0x41,0xbf,0xe0,0x5a,0x58,0x80,0x5f,0x66,0x0b,0xd8,0x90], 
             [0x35,0xd5,0xc0,0xa7,0x33,0x06,0x65,0x69,0x45,0x00,0x94,0x56,0x6d,0x98,0x9b,0x76], 
             [0x97,0xfc,0xb2,0xc2,0xb0,0xfe,0xdb,0x20,0xe1,0xeb,0xd6,0xe4,0xdd,0x47,0x4a,0x1d], 
             [0x42,0xed,0x9e,0x6e,0x49,0x3c,0xcd,0x43,0x27,0xd2,0x07,0xd4,0xde,0xc7,0x67,0x18], 
             [0x89,0xcb,0x30,0x1f,0x8d,0xc6,0x8f,0xaa,0xc8,0x74,0xdc,0xc9,0x5d,0x5c,0x31,0xa4], 
             [0x70,0x88,0x61,0x2c,0x9f,0x0d,0x2b,0x87,0x50,0x82,0x54,0x64,0x26,0x7d,0x03,0x40], 
             [0x34,0x4b,0x1c,0x73,0xd1,0xc4,0xfd,0x3b,0xcc,0xfb,0x7f,0xab,0xe6,0x3e,0x5b,0xa5], 
             [0xad,0x04,0x23,0x9c,0x14,0x51,0x22,0xf0,0x29,0x79,0x71,0x7e,0xff,0x8c,0x0e,0xe2], 
             [0x0c,0xef,0xbc,0x72,0x75,0x6f,0x37,0xa1,0xec,0xd3,0x8e,0x62,0x8b,0x86,0x10,0xe8], 
             [0x08,0x77,0x11,0xbe,0x92,0x4f,0x24,0xc5,0x32,0x36,0x9d,0xcf,0xf3,0xa6,0xbb,0xac], 
             [0x5e,0x6c,0xa9,0x13,0x57,0x25,0xb5,0xe3,0xbd,0xa8,0x3a,0x01,0x05,0x59,0x2a,0x46]]

    if len(byte) == 4:
        row = int(byte[2], 16)
        col = int(byte[3], 16)
    else:
        row = 0
        col = int(byte[2], 16)
    return hex(table[row][col])