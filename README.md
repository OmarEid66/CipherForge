# CipherForge

**A from-scratch implementation of the Data Encryption Standard (DES) in C.**

CipherForge is an educational cryptography project that implements DES at the bit level without relying on external cryptographic libraries. It demonstrates the internal workings of a symmetric block cipher, including key scheduling, permutations, S-box substitution, Feistel rounds, block encryption/decryption, and binary file processing.

The project includes a command-line interface for encrypting and decrypting files, built-in DES known-answer tests, and support for processing large files in chunks. It also includes an automated Python verification suite for testing functional correctness and error handling.

> **Security warning:** DES is cryptographically obsolete and must not be used to protect sensitive data. CipherForge is intended for educational purposes and algorithm experimentation.

---

## Table of Contents

* [Overview](#overview)
* [Features](#features)
* [DES Architecture](#des-architecture)
* [DES Round Function](#des-round-function)
* [File Encryption and Decryption Workflow](#file-encryption-and-decryption-workflow)
* [Project Structure](#project-structure)
* [Requirements](#requirements)
* [Build and Run](#build-and-run)
* [Command-Line Usage](#command-line-usage)
* [Verification and Test Results](#verification-and-test-results)
* [Automated Verification Suite](#automated-verification-suite)
* [Performance Benchmark](#performance-benchmark)
* [Current Progress](#current-progress)
* [Limitations](#limitations)
* [Roadmap](#roadmap)
* [Security Disclaimer](#security-disclaimer)
* [License](#license)

---

## Overview

The Data Encryption Standard (DES) is a symmetric-key block cipher that operates on 64-bit data blocks. Its key representation is 64 bits long, but only 56 bits contribute to the effective encryption key; the remaining bits are traditionally used for parity.

DES processes each block through an initial permutation, 16 Feistel rounds, and a final permutation. Decryption uses the same block-processing structure with the round keys applied in reverse order.

CipherForge implements these operations from scratch in C and extends the block cipher implementation with binary file encryption and decryption.

### Technical Specifications

| Property                | Description                         |
| ----------------------- | ----------------------------------- |
| Algorithm               | Data Encryption Standard (DES)      |
| Block size              | 64 bits (8 bytes)                   |
| Key representation      | 64 bits (16 hexadecimal characters) |
| Effective key length    | 56 bits                             |
| Number of rounds        | 16                                  |
| Round-key size          | 48 bits                             |
| File processing         | Chunked binary I/O                  |
| File mode               | Electronic Codebook (ECB)           |
| Padding                 | None                                |
| Implementation language | C                                   |
| Built-in verification   | Five known-answer test vectors      |
| Automated verification  | 11 Python-based tests               |

---

## Features

* **From-scratch DES:** Implements the DES algorithm without external cryptographic libraries.
* **Bit-level operations:** Performs bit extraction, shifting, XOR, and permutation operations.
* **Initial and final permutations:** Implements the IP and FP transformations.
* **Key scheduling:** Generates 16 round keys using PC-1, circular rotations, and PC-2.
* **Expansion permutation:** Expands the 32-bit right half into 48 bits.
* **Round-key mixing:** XORs the expanded right half with the round key.
* **S-box substitution:** Uses all eight DES S-boxes to transform 48 bits into 32 bits.
* **P permutation:** Rearranges the S-box output bits.
* **Feistel network:** Executes the 16 DES rounds.
* **Block encryption and decryption:** Processes individual 64-bit blocks in both directions.
* **File encryption and decryption:** Reads binary input files and writes the transformed data to output files.
* **Chunked file processing:** Processes large files without loading the entire file into memory.
* **Input-size validation:** Rejects files whose sizes are not multiples of 8 bytes.
* **No padding:** Processes complete DES blocks without adding padding.
* **Command-line interface:** Selects encryption or decryption and specifies the key and file paths.
* **Built-in verification:** Includes five DES known-answer tests.
* **Automated verification:** Includes a Python test suite for functional behavior, input validation, and error handling.
* **Round-trip verification:** Checks whether decryption recovers the original file.
* **Repeatability testing:** Checks whether identical inputs and keys produce identical ciphertext under the tested operation.

---

## DES Architecture

DES operates on one 64-bit block at a time. The plaintext passes through an initial permutation, is divided into two 32-bit halves, and enters the 16-round Feistel network.

After the rounds, the halves are swapped and passed through the final permutation to produce the ciphertext.

```mermaid
flowchart TD
    A["64-bit Plaintext"] --> B["Initial Permutation (IP)"]
    B --> C["Split into L0 and R0"]
    C --> D["16 Feistel Rounds"]
    D --> E["Swap Halves: R16 || L16"]
    E --> F["Final Permutation (FP)"]
    F --> G["64-bit Ciphertext"]

    style A fill:#dbeafe,stroke:#2563eb,color:#111827
    style B fill:#e0f2fe,stroke:#0284c7,color:#111827
    style C fill:#dcfce7,stroke:#16a34a,color:#111827
    style D fill:#fef3c7,stroke:#d97706,color:#111827
    style E fill:#fce7f3,stroke:#db2777,color:#111827
    style F fill:#e0f2fe,stroke:#0284c7,color:#111827
    style G fill:#ddd6fe,stroke:#7c3aed,color:#111827
```

### DES Architecture Diagram

![DES Overall Architecture](docs/images/des-overall-architecture.png)

### Key Schedule

The DES key schedule generates 16 round keys, each 48 bits wide.

1. Apply Permuted Choice 1 (PC-1) to the 64-bit key representation, selecting 56 bits.
2. Divide the result into two 28-bit halves, `C0` and `D0`.
3. Perform circular left rotations according to the DES shift schedule.
4. Apply Permuted Choice 2 (PC-2) to generate each 48-bit round key.

```mermaid
flowchart TD
    A["64-bit Key"] --> B["PC-1"]
    B --> C["56-bit Result"]
    C --> D["C0: 28 bits"]
    C --> E["D0: 28 bits"]
    D --> F["Circular Left Shifts"]
    E --> F
    F --> G["PC-2"]
    G --> H["K1: 48 bits"]
    G --> I["K2: 48 bits"]
    G --> J["..."]
    G --> K["K16: 48 bits"]

    style A fill:#dbeafe,stroke:#2563eb,color:#111827
    style F fill:#fef3c7,stroke:#d97706,color:#111827
    style G fill:#e0f2fe,stroke:#0284c7,color:#111827
```

---

## DES Round Function

Each Feistel round uses the current right half and a 48-bit round key to calculate the next right half.

The round function `f(R, K)` consists of four operations:

1. **Expansion:** Expand the 32-bit right half to 48 bits.
2. **XOR:** Combine the expanded result with the 48-bit round key.
3. **S-box substitution:** Divide the 48-bit result into eight 6-bit groups. Each S-box maps one 6-bit group to 4 bits, producing 32 bits in total.
4. **P permutation:** Rearrange the resulting 32 bits.

```mermaid
flowchart LR
    A["R: 32 bits"] --> B["Expansion E<br/>32 to 48 bits"]
    B --> C["XOR with<br/>Round Key K"]
    D["K: 48 bits"] --> C
    C --> E["S-boxes<br/>48 to 32 bits"]
    E --> F["P Permutation"]
    F --> G["f(R, K)<br/>32 bits"]

    style A fill:#dcfce7,stroke:#16a34a,color:#111827
    style D fill:#fef3c7,stroke:#d97706,color:#111827
    style C fill:#dbeafe,stroke:#2563eb,color:#111827
    style E fill:#ffedd5,stroke:#ea580c,color:#111827
    style G fill:#ddd6fe,stroke:#7c3aed,color:#111827
```

For round `i`, the Feistel update is:

```text
L(i) = R(i-1)

R(i) = L(i-1) XOR f(R(i-1), K(i))
```

After the 16th round, the halves are combined in reversed order and passed through the final permutation.

### Decryption

DES decryption uses the same fundamental round structure as encryption. The difference is the order in which the round keys are applied:

```text
Encryption: K1, K2, ..., K16
Decryption: K16, K15, ..., K1
```

This allows the original plaintext block to be recovered when the correct key is supplied.

---

## File Encryption and Decryption Workflow

CipherForge accepts an operation, a DES key, an input file, and an output file.

The input is processed in complete 8-byte blocks. The file size must be a multiple of 8 bytes, and no padding is added.

```mermaid
flowchart TD
    A(["Start"]) --> B["Parse Command-Line Arguments"]
    B --> C["Validate Operation and Key"]
    C --> D["Open Input and Output Files"]
    D --> E["Validate Input File Size"]
    E --> F["Read File in Chunks"]
    F --> G["Process Each 8-Byte Block"]
    G --> H{"More Input?"}
    H -- Yes --> F
    H -- No --> I["Finish Writing Output"]
    I --> J["Close Files"]
    J --> K(["End"])

    style A fill:#dbeafe,stroke:#2563eb,color:#111827
    style C fill:#fef3c7,stroke:#d97706,color:#111827
    style E fill:#ffedd5,stroke:#ea580c,color:#111827
    style G fill:#dcfce7,stroke:#16a34a,color:#111827
    style K fill:#ddd6fe,stroke:#7c3aed,color:#111827
```

### File Processing Diagram

![File Encryption and Decryption Workflow](docs/images/file-encryption-decryption-workflow.png)

### File Processing Characteristics

* Input and output files are handled as binary data.
* Large files are processed in chunks rather than loaded entirely into memory.
* Every DES operation processes an 8-byte block.
* Input files that are not a multiple of 8 bytes are rejected.
* No padding is added or removed.
* The key must be supplied in the expected hexadecimal format.

**Important:** ECB mode encrypts each block independently. Identical plaintext blocks encrypted with the same key produce identical ciphertext blocks, which can reveal patterns in the original data. ECB is not appropriate for protecting sensitive real-world data.

---

## Project Structure

```text
CipherForge/
├── 2200284.c
├── README.md
├── LICENSE
├── .gitignore
├── tests/
│   ├── __init__.py
│   ├── run_tests.py
│   └── test_des.py
└── docs/
    └── images/
        ├── des-overall-architecture.png
        └── file-encryption-decryption-workflow.png
```

The DES implementation and built-in test harness are contained in a single C source file. The `tests/` directory contains the separate Python-based automated verification suite.

---

## Requirements

* GCC or MinGW-w64 with C11 support.
* Python 3 for the automated verification suite.
* Windows PowerShell for the commands shown below.
* Standard C library functionality.
* Input files whose sizes are multiples of 8 bytes.

No external cryptographic libraries are required.

The current file-processing implementation uses `_fseeki64()` and `_ftelli64()` for file-size validation. These are Microsoft-specific functions, so the current implementation should not be assumed to compile unchanged on every operating system or C library.

### Requirements for the Automated Test Suite

The automated suite uses Python's standard `unittest` framework and invokes the compiled C executable.

Make sure:

1. Python 3 is installed and accessible through the `python` command.
2. GCC is installed and accessible to the test runner.
3. The compiler configuration in `tests/run_tests.py` matches your environment.
4. You run the test command from the project root so the expected files and paths can be found.

The current Windows environment uses a configured GCC tool path because of an assembler compatibility issue. Other installations may not require this configuration.

---

## Build and Run

Open a terminal in the project directory.

### Compile

The following command is the build command verified in the current Windows environment:

```powershell
gcc -B"C:/msys64/ucrt64/bin/" -std=c11 -O2 -Wall -Wextra .\2200284.c -o .\2200284.exe
```

The `-B` option selects the specified tool directory for GCC's subordinate tools in the current environment.

If your GCC installation does not require this workaround, the following standard command may be sufficient:

```bash
gcc -std=c11 -O2 -Wall -Wextra 2200284.c -o 2200284
```

### Run the Built-In Tests

On Windows PowerShell:

```powershell
.\2200284.exe
```

The program runs the built-in DES verification tests and reports whether each known-answer test passes.

### Run the Automated Verification Suite

To compile the program and run all Python-based verification tests, execute:

```powershell
python .\tests\run_tests.py
```

This command performs both compilation and automated testing. See [Automated Verification Suite](#automated-verification-suite) for the test coverage and latest recorded results.

---

## Command-Line Usage

The file-processing interface accepts four arguments after the program name:

```text
program e <key> <input_file> <output_file>
program d <key> <input_file> <output_file>
```

Where:

| Argument        | Description                                      |
| --------------- | ------------------------------------------------ |
| `e`             | Encrypt the input file                           |
| `d`             | Decrypt the input file                           |
| `<key>`         | DES key represented by 16 hexadecimal characters |
| `<input_file>`  | Path to the source file                          |
| `<output_file>` | Path to the destination file                     |

### Encrypt a File

Example using the DES key `133457799BBCDFF1`:

```powershell
.\2200284.exe e 133457799BBCDFF1 plaintext.bin encrypted.bin
```

This reads `plaintext.bin` and writes the ciphertext to `encrypted.bin`.

### Decrypt a File

```powershell
.\2200284.exe d 133457799BBCDFF1 encrypted.bin decrypted.bin
```

This reads `encrypted.bin` and writes the recovered plaintext to `decrypted.bin`.

### Verify the Recovered File

Compare the original and decrypted files:

```powershell
fc.exe /b plaintext.bin decrypted.bin
```

If the files are identical, the output includes:

```text
FC: no differences encountered
```

### Input Size Requirements

DES processes 8-byte blocks. The input file size must therefore be divisible by 8.

For example:

* 8 bytes: valid
* 16 bytes: valid
* 100 MiB: valid
* 10 bytes: invalid

CipherForge does not add padding to incomplete blocks.

**Do not encrypt a file over itself unless the implementation explicitly guarantees safe in-place processing.** Use separate input and output paths for the examples above.

---

## Verification and Test Results

CipherForge includes five built-in known-answer tests that compare the computed ciphertext against expected DES results.

| Test | Key                | Plaintext          | Expected Ciphertext |
| ---- | ------------------ | ------------------ | ------------------- |
| 1    | `133457799BBCDFF1` | `0123456789ABCDEF` | `85E813540F0AB405`  |
| 2    | `0000000000000000` | `0000000000000000` | `8CA64DE9C1B123A7`  |
| 3    | `FFFFFFFFFFFFFFFF` | `FFFFFFFFFFFFFFFF` | `7359B2163E4EDC58`  |
| 4    | `133457799BBCDFF1` | `0000000000000000` | `948A43F98A834F7E`  |
| 5    | `133457799BBCDFF1` | `FFFFFFFFFFFFFFFF` | `5A3DB304D64924FD`  |

### Built-In Known-Answer Test Result

**Latest recorded result: 5/5 test vectors passed.**

The tests cover different key and plaintext patterns, including all-zero and all-one inputs. The built-in test harness also checks that decryption recovers the original plaintext.

### Large-File Round-Trip Test

A 100 MiB file was used to test file encryption and decryption.

| Check                    | Result                                 |
| ------------------------ | -------------------------------------- |
| Input file size          | 100 MiB                                |
| DES block size           | 8 bytes                                |
| Number of blocks         | 13,107,200                             |
| Encryption               | Completed                              |
| Decryption               | Completed                              |
| Byte-for-byte comparison | Passed for all three decrypted outputs |

The three decrypted files were compared against the original using Windows `fc.exe /b`. All three comparisons reported:

```text
FC: no differences encountered
```

These results establish successful round-trip processing for the tested file and key. They do not replace broader testing of malformed inputs, file errors, or other operating systems.

For the separate Python-based verification suite, see [Automated Verification Suite](#automated-verification-suite).

---

## Automated Verification Suite

CipherForge includes a Python-based automated verification suite in addition to the built-in DES known-answer tests. It checks functional correctness, encryption and decryption behavior, file handling, input validation, and selected error-handling scenarios.

### Test Suite Structure

```text
tests/
├── __init__.py
├── run_tests.py
└── test_des.py
```

* **`tests/run_tests.py`:** Compiles the C implementation and launches the Python test suite.
* **`tests/test_des.py`:** Contains the 11 automated test cases.
* **`tests/__init__.py`:** Enables Python package discovery for the test suite.

### How to Run the Tests

Open PowerShell in the project root directory and run:

```powershell
python .\tests\run_tests.py
```

The test runner performs the following operations:

1. Invokes the configured GCC compiler.
2. Compiles `2200284.c` into `2200284.exe`.
3. Stops and reports an error if compilation fails.
4. Runs the Python unittest suite.
5. Displays each test result and a final summary.

The test runner uses the compiler configuration in `tests/run_tests.py`. If the compiler or assembler is installed in a different location, the configuration may need to be adjusted.

### Verification Flow

```mermaid
flowchart TD
    A(["Start"]) --> B["Compile 2200284.c with GCC"]
    B --> C{"Compilation Successful?"}
    C -- No --> D["Report Compilation Error"]
    C -- Yes --> E["Run Built-In DES Tests"]
    E --> F["Run Python Verification Suite"]
    F --> G["Check Encryption and Decryption"]
    G --> H["Check Round-Trip File Processing"]
    H --> I["Check Invalid Inputs and Error Handling"]
    I --> J["Generate Test Summary"]
    D --> K(["End"])
    J --> K

    style A fill:#dbeafe,stroke:#2563eb,color:#111827
    style B fill:#e0f2fe,stroke:#0284c7,color:#111827
    style F fill:#fef3c7,stroke:#d97706,color:#111827
    style I fill:#dcfce7,stroke:#16a34a,color:#111827
    style K fill:#ddd6fe,stroke:#7c3aed,color:#111827
```

### Automated Test Coverage

The suite contains 11 tests.

| #  | Test                              | What It Verifies                                                                            |
| -- | --------------------------------- | ------------------------------------------------------------------------------------------- |
| 1  | Built-in known-answer tests       | The known-answer tests embedded in the C program pass.                                      |
| 2  | Encryption test vectors           | Encryption results match predefined expected ciphertexts.                                   |
| 3  | Decryption test vectors           | Decryption recovers the expected plaintext for predefined vectors.                          |
| 4  | Round-trip testing                | Encrypting and decrypting files of supported sizes recovers the original contents.          |
| 5  | Invalid file sizes                | Files whose sizes are not multiples of 8 bytes are rejected.                                |
| 6  | Malformed keys                    | Incorrectly formatted keys are rejected.                                                    |
| 7  | Missing input file                | Attempts to process nonexistent input files fail appropriately.                             |
| 8  | Output handling for missing input | A missing input file does not cause a new output file to be created in the tested scenario. |
| 9  | Invalid operation                 | Unsupported operation arguments are rejected.                                               |
| 10 | Missing command-line arguments    | Invoking the program without required arguments is handled appropriately.                   |
| 11 | Deterministic encryption          | The same input and key produce identical ciphertext under the tested operation.             |

### Latest Automated Test Results

The latest recorded automated run completed successfully on the `main` branch.

```text
Ran 11 tests in 52.613s

OK

SUMMARY: 11 tests; 0 failures; 0 errors; 0 skipped.
FINAL RESULT: ALL TESTS PASSED
```

| Metric         |         Result |
| -------------- | -------------: |
| Total tests    |             11 |
| Passed         |             11 |
| Failed         |              0 |
| Errors         |              0 |
| Skipped        |              0 |
| Execution time | 52.613 seconds |

**Final result: ALL TESTS PASSED.**

These results confirm that the program compiled successfully and passed all 11 tests in the tested environment.

### Testing Objectives

#### 1. DES Functional Correctness

Known-answer tests compare the implementation's output against predefined expected results. These tests help detect errors in encryption and decryption behavior.

#### 2. Round-Trip Verification

Round-trip tests encrypt and then decrypt files of supported sizes. The recovered file is compared against the original input.

```text
Original File
     |
     v
DES Encryption
     |
     v
Encrypted File
     |
     v
DES Decryption
     |
     v
Recovered File
     |
     v
Compare with Original
```

The objective is to verify that the recovered file matches the original bytes.

#### 3. Input Validation

The suite checks how the program responds to invalid conditions, including:

* File sizes that are not multiples of 8 bytes.
* Malformed keys.
* Missing input files.
* Unsupported operation arguments.
* Missing required command-line arguments.

These tests verify selected rejection and error-handling behaviors.

#### 4. File Handling

The suite checks the handling of a missing input file and verifies that the tested failure scenario does not create a new output file.

#### 5. Deterministic Behavior

The suite verifies that the same plaintext and key produce the same ciphertext when the same DES operation is performed under the tested conditions.

This checks repeatability; it is not a security guarantee.

### Scope and Limitations

The automated verification suite checks functional behavior and selected error-handling cases. Passing these tests does not prove that the implementation is free of every defect.

The current suite does not establish:

* Resistance to cryptanalysis or brute-force attacks.
* Memory safety for every possible input.
* Correct behavior on every operating system or compiler.
* Compliance with every possible DES test vector.
* Security of the surrounding application or file-handling environment.

DES has an effective key length of only 56 bits and is unsuitable for modern security applications. CipherForge is an educational project for studying DES and its implementation.

---

## Performance Benchmark

The following measurements were collected locally using a 100 MiB file and an optimized GCC build.

| Operation  |    Run 1 |    Run 2 |    Run 3 |  Average |
| ---------- | -------: | -------: | -------: | -------: |
| Encryption | 57.999 s | 56.520 s | 45.924 s | 53.481 s |
| Decryption | 25.694 s | 25.279 s | 25.331 s | 25.435 s |

Approximate average throughput:

| Operation  | Average throughput |
| ---------- | -----------------: |
| Encryption |         1.87 MiB/s |
| Decryption |         3.93 MiB/s |

These measurements are specific to the test machine, compiler, executable, and system conditions. They should be treated as preliminary results rather than universal performance figures.

Encryption and decryption have the same number of DES rounds, so the observed performance difference warrants further investigation with repeated controlled benchmarks.

---

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
* [x] Verification against five known-answer test vectors
* [x] Command-line file encryption and decryption
* [x] Input file size validation
* [x] Chunked binary file processing
* [x] Large-file round-trip verification
* [x] Python-based automated verification suite
* [x] Automated tests for invalid inputs and selected error-handling scenarios

---

## Limitations

* DES has an effective key length of only 56 bits and is vulnerable to exhaustive key search.
* ECB mode does not hide repeated plaintext blocks.
* Input files must be multiples of 8 bytes.
* No padding is applied.
* The current file-size validation uses Microsoft-specific file-position functions.
* The recorded performance results are specific to one local test environment.
* The current verification suite does not establish comprehensive security or robustness.

---

## Roadmap

Potential future improvements include:

* [ ] Add more published DES known-answer test vectors.
* [ ] Expand tests for empty files and additional file-size boundaries.
* [ ] Expand file I/O error-handling tests.
* [ ] Investigate the observed encryption/decryption performance difference.
* [ ] Improve portability across operating systems and C libraries.
* [ ] Add reproducible benchmarking instructions.
* [ ] Add a modern authenticated encryption implementation, such as AES-GCM, as a separate feature.
* [ ] Integrate automated regression testing into the development workflow.

---

## Security Disclaimer

**CipherForge is an educational project and is not suitable for protecting sensitive or real-world data.**

DES is considered insecure because its effective key length is only 56 bits. Additionally, ECB mode reveals patterns when plaintext contains repeated blocks.

For real applications, use a modern authenticated encryption scheme such as AES-GCM through a well-maintained cryptographic library. Do not use this DES implementation to protect passwords, personal information, financial data, or confidential files.

---

## License

This project is distributed under the MIT License. See the [LICENSE](LICENSE) file for details.
