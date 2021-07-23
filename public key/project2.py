#Noah Hill

import secrets as sec #python module for generating cryptographically strong random numbers


def main():
    #choose option based on user input
    run = True
    print("Project 2 by Noah Hill")
    while run:
        print("\nType k for key generation")
        print("Type e for encryption")
        print("Type d for decryption")
        print("Type f for encryption using default filenames")
        print("Type g for decryption using default filenames")
        print("Type q to exit")
        val = input("Enter an option: ")
        if val == "k":
            print("Generating a key pair...")
            key_gen()
        elif val == "e":
            file = input("Enter the name of a text file to encrypt: ")
            en(file)
        elif val == "d":
            file = input("Enter the name of a cipher text file to decrypt: ")
            de(file)
        elif val == "f":
            e()
        elif val == "g":
            d()
        elif val == "q":
            run = False
            print("Exiting")
        else:
            print("That is not a valid option.")
    return

#encryption tester
def e():
    with open('pubkey.txt', 'r') as pub:
        pubkey = pub.read()
        
    pubkey = pubkey.split(" ")
    encrypt('ptext.txt', pubkey[0], pubkey[1], pubkey[2])
    return

#decryption tester
def d():
    with open('prikey.txt', 'r') as priv:
        privkey = priv.read()
        
    privkey = privkey.split(" ")
    
    with open('ctext.txt', 'r') as c:
        ciphertxt = c.read()
    ciphertxt = ciphertxt.split(" ")
    ciphertxt.pop()
    
    with open("dtext.txt", 'w') as d:
        d.write("")
    
    for i in range(0, len(ciphertxt), 2):
        decrypt(privkey[2], privkey[0], ciphertxt[i], ciphertxt[i+1])
    return

#encrypt a given file
def en(file):
    with open('pubkey.txt', 'r') as pub:
        pubkey = pub.read()
        
    pubkey = pubkey.split(" ")
    encrypt(file, pubkey[0], pubkey[1], pubkey[2])
    return

#decrypt a given file
def de(file):
    with open('prikey.txt', 'r') as priv:
        privkey = priv.read()
        
    privkey = privkey.split(" ")
    
    with open(file, 'r') as c:
        ciphertxt = c.read()
    ciphertxt = ciphertxt.split(" ")
    ciphertxt.pop()
    
    with open("dtext.txt", 'w') as d:
        d.write("")
    
    for i in range(0, len(ciphertxt), 2):
        decrypt(privkey[2], privkey[0], ciphertxt[i], ciphertxt[i+1])
    return

#decryption algorithm
def decrypt(d, p, c1, c2):
    d = int(d)
    p = int(p)
    c1 = int(c1)
    c2 = int(c2)
    
    a = pow(c2, 1, p)
    b = pow(c1, (p - 1 - d), p)
    plain = pow((a * b), 1, p)
    
    plain = bin(plain)
    plain = plain[2:]
    while len(plain) < 32:
        plain = '0' + plain
    plain = [plain[x:x+8] for x in range(0, len(plain), 8)]
    
    text = ""
    for i in plain:
        text = text + "".join(chr(int(i, 2)))
    
    pt = open('dtext.txt', 'a')
    pt.write(text)
    pt.close()
    return

#encryption algorithm
def encrypt(pfile, p, g, e2):
    p = int(p)
    g = int(g)
    e2 = int(e2)

    with open(pfile, 'r') as plain:
        plaintxt = plain.read() 
    ciph = open('ctext.txt', 'w')
    plaintxt = list(plaintxt)
    plaintxt = [plaintxt[x:x+4] for x in range(0, len(plaintxt), 4)]
    
    #for every 32-bit block (treated as a 31-bit block)
    for block in plaintxt:
        while len(block) < 4:
            block.append('0')
        for x in range(len(block)):
            block[x] = format((ord(block[x])), '#010b')

        r = 1 + sec.randbelow(p - 1)
        c1 = pow(g, r, p)

        pint = int((block[0][3:] + block[1][2:] + block[2][2:] + block[3][2:]), 2)
        pint = pow(pint, 1, p)
        
        c2 = pow(e2, r, p)
        c2 = pow((c2 * pint), 1, p)
        
        ciph.write(str(c1) + " " +str(c2) + " ")
        
    ciph.close()
    return



#implementation of the Miller-Rabin algorithm
#takes an integer
#returns true if the integer is probably prime, false if composite
def miller_rabin(n):
    k = 12
    d = (n - 1)
    r = 0
    while pow(int(d), 1, 2) == 0:
        d /= 2
        r += 1   
    d = int(d)
    
    for m in range(0, k):
        a = 2 + sec.randbelow(n - 3)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        
        for l in range(0, (r - 1)):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        return False
    return True


#generates keys
#finds a prime fitting specifications and calculates d, e1, e2
#writes found values to text files
def key_gen():
    found = False
    q = 0
    
    while found == False:
        q = sec.randbits(31)
        if pow(q, 1, 12) == 5 and pow(q, 1, 2) == 1:
            if miller_rabin(q):
                if miller_rabin((2 * q) + 1):
                    found = True
    p = 2 * q + 1
    if len(bin(p)) != 34:
        key_gen() #if found prime isn't 32 bit, try again
        return
    
    d = 1 + sec.randbelow(p - 2)
    e1 = 2
    e2 = pow(e1, d, p)
    
    pub = open('pubkey.txt', 'w')
    pub.write(str(p) + " " + str(e1) + " " + str(e2))
    pub.close()
    
    priv = open('prikey.txt', 'w')
    priv.write(str(p) + " " + str(e1) + " " + str(d))
    
    return

