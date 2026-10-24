# CipherForge

A from-scratch implementation of the Data Encryption Standard (DES) in C.

## Current Progress

- [x] Bit extraction and permutation
- [x] 64-bit block loading and storing
- [x] DES PC-1 and PC-2 key permutations
- [x] 28-bit circular key rotations
- [x] Generation of all 16 DES round keys

## Next Steps

- [ ] DES expansion function
- [ ] XOR with round keys
- [ ] S-box substitution
- [ ] P permutation
- [ ] DES block encryption and decryption
- [ ] File encryption and decryption

## Build

Compile with GCC:

    gcc -std=c11 -O2 -Wall -Wextra 2200284.c -o 2200284.exe

## Disclaimer

Educational project only. DES is not secure for modern applications.
