This project is a block-encryption alogrithm written in Python3. This program uses PSU-CRYPT, based on Twofish and SKIPJACK, with a 64 bit block size and a 64 bit key. 

The program can encrypt or decrypt an ASCII text file. To encrypt a plaintext file (by default plaintext.txt), the program uses the PSU-CRYPT alogrithm with a chosen 64 bit key in hexadecimal contained in a text file key.txt. To decrypt a ciphertext file (by default cyphertext.txt), the program performs the alogrithm in reverse with the chosen key. 

The details of the PSU-CRYPT algorithm are contained in the project requirements pdf file.