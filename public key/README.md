This project is a public-key cryptosystem written in Python3. The program can encrypt or decrypt a text file of any length. 

The program has three functions: key generation, encryption, and decryption. Key generation prompts for a seed, then generates a public-key (p g e2) and a private-key (p g d) in two files pubkey.txt and prikey.txt. Encryption takes a plaintext textfile (by default ptext.txt) and the public-key contained in pubkey.txt. The output is a text file ctext.txt containing a ciphertext as pairs of integers C1 and C2. Decryption takes a ciphertext file (by default ctext.txt) containing integer pairs C1 and C2 and a private-key contained in prikey.txt. The output is the decryption of the ciphertext into the text file dtext.txt.

More details about the algorithm used are in the project requirements pdf file.

