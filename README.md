# CipherForge

**A from-scratch implementation of the Data Encryption Standard (DES) in C.**

CipherForge is an educational cryptography project that implements DES at the bit level without relying on external cryptographic libraries. The project explores the internal workings of a symmetric block cipher, including key scheduling, permutations, S-box substitution, Feistel rounds, and block encryption and decryption.

## Table of Contents

* [Overview](#overview)
* [Features](#features)
* [DES Implementation](#des-implementation)
* [Project Structure](#project-structure)
* [Requirements](#requirements)
* [Build and Run](#build-and-run)
* [Verification and Test Results](#verification-and-test-results)
* [Current Progress](#current-progress)
* [Roadmap](#roadmap)
* [Security Disclaimer](#security-disclaimer)

## Overview

The Data Encryption Standard (DES) is a symmetric-key block cipher that operates on 64-bit data blocks using a 64-bit key representation. Its effective key length is 56 bits, with the remaining 8 bits traditionally used for parity.

DES applies an initial permutation, 16 Feistel rounds, and a final permutation to transform plaintext into ciphertext. Decryption uses the same round structure but applies the round keys in reverse order.

This project implements the algorithm from scratch in C to provide a practical understanding of its internal operations.

## Features

* **Bit-level operations:** Extract and manipulate individual bits to implement DES permutations.
* **Initial and final permutations:** Implement the DES IP and FP transformations.
* **Key scheduling:** Generate all 16 round keys using PC-1, circular rotations, and PC-2.
* **Expansion permutation:** Expand the 32-bit right half into 48 bits.
* **Round-key mixing:** XOR the expanded data with the corresponding round key.
* **S-box substitution:** Apply all eight DES S-boxes to transform 48 bits into 32 bits.
* **P permutation:** Rearrange the S-box output bits.
* **Feistel network:** Execute all 16 DES rounds.
* **Encryption and decryption:** Process individual 64-bit blocks in both directions.
* **Built-in verification:** Test the implementation against five known DES test vectors.
* **Portable C implementation:** Designed to compile with GCC/MinGW using standard C facilities.

## DES Implementation

The implementation follows the standard DES encryption structure.

### 1. Initial Permutation

The 64-bit plaintext block passes through the Initial Permutation (IP), which rearranges its bits according to the DES permutation table.

The resulting block is divided into two 32-bit halves:

* `L0`: Left half
* `R0`: Right half

### 2. Key Schedule

The key schedule generates 16 round keys, each 48 bits wide.

The process consists of:

1. Applying Permuted Choice 1 (PC-1).
2. Splitting the resulting 56 bits into two 28-bit halves.
3. Performing circular left rotations according to the DES shift schedule.
4. Applying Permuted Choice 2 (PC-2) to generate each round key.

### 3. Feistel Rounds

Each of the 16 rounds updates the left and right halves using the Feistel structure:

`L(i) = R(i-1)`

`R(i) = L(i-1) XOR f(R(i-1), K(i))`

The round function `f` consists of four operations:

1. **Expansion:** Expand the 32-bit right half to 48 bits.
2. **XOR:** Combine the expanded result with the 48-bit round key.
3. **S-box substitution:** Convert the 48-bit result into 32 bits.
4. **P permutation:** Rearrange the resulting 32 bits.

### 4. Final Permutation

After 16 rounds, the right and left halves are combined in reversed order:

`R16 || L16`

The Final Permutation (FP), which is the inverse of IP, produces the resulting 64-bit ciphertext block.

### 5. Decryption

Decryption uses the same DES block-processing structure as encryption, but the round keys are applied in reverse order:

`K16, K15, ..., K1`

This allows the implementation to recover the original plaintext from a valid ciphertext block when the correct key is supplied.

## Project Structure

```text
CipherForge/
├── 2200284.c    # DES implementation and test harness
├── README.md    # Project documentation
├── LICENSE      # MIT License
└── .gitignore   # Git ignore rules
```

The implementation and current test harness are contained in a single C source file.

## Requirements

* GCC or MinGW
* A Windows, Linux, or other GCC-compatible development environment

No external cryptographic libraries are required.

## Build and Run

### Compile

From the project directory, run:

```bash
gcc -std=c11 -O2 -Wall -Wextra 2200284.c -o 2200284.exe
```

### Run the tests

On Windows PowerShell:

```powershell
.\2200284.exe
```

The current executable runs the built-in DES verification tests.

**Note:** The command-line file encryption and decryption interface is planned for a future development stage and is not yet part of the current implementation.

## Verification and Test Results

The implementation has been tested using five known DES test vectors.

| Test | Key                | Plaintext          | Expected Ciphertext |
| ---- | ------------------ | ------------------ | ------------------- |
| 1    | `133457799BBCDFF1` | `0123456789ABCDEF` | `85E813540F0AB405`  |
| 2    | `0000000000000000` | `0000000000000000` | `8CA64DE9C1B123A7`  |
| 3    | `FFFFFFFFFFFFFFFF` | `FFFFFFFFFFFFFFFF` | `7359B2163E4EDC58`  |
| 4    | `133457799BBCDFF1` | `0000000000000000` | `948A43F98A834F7E`  |
| 5    | `133457799BBCDFF1` | `FFFFFFFFFFFFFFFF` | `5A3DB304D64924FD`  |

**Current result: 5/5 test vectors passed.**

The tests cover different key and plaintext patterns, including all-zero and all-one inputs. The implementation also verifies decryption by recovering the original plaintext from the generated ciphertext.

## Current Progress

* [x] DES permutation and substitution tables
* [x] Bit extraction and permutation utilities
* [x] 64-bit block loading and storing
* [x] PC-1 and PC-2 key permutations
* [x] 28-bit circular key rotations
* [x] Generation of all 16 DES round keys
* [x] Expansion permutation
* [x] XOR with round keys
* [x] S-box substitution
* [x] P permutation
* [x] DES round function
* [x] 16-round block encryption
* [x] Block decryption using reversed round keys
* [x] Verification against five known test vectors

## Roadmap

The next development stages are:

* [ ] Read the DES key from an 8-byte binary key file.
* [ ] Add binary file input and output.
* [ ] Implement file encryption and decryption using ECB mode.
* [ ] Validate input sizes for 8-byte block processing without padding.
* [ ] Add command-line arguments for encryption and decryption.
* [ ] Test complete file encryption and decryption workflows.
* [ ] Improve error handling for file operations and invalid arguments.

## Security Disclaimer

**This project is for educational purposes only.**

DES is considered insecure for modern applications because its effective key length is only 56 bits, making exhaustive key search practical with modern computing resources.

Do not use this implementation to protect sensitive or real-world data. Modern applications should use established, secure cryptographic algorithms and libraries, such as AES-GCM.

## License

This project is distributed under the MIT License. See the `LICENSE` file for details.
