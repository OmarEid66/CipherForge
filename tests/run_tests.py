import os
import random
import shutil
import subprocess
import tempfile
import unittest
import re
import time
from pathlib import Path

PROJECT_DIR = Path(__file__).resolve().parent.parent
EXECUTABLE = PROJECT_DIR / (
    "2200284.exe" if os.name == "nt" else "2200284"
)

SOURCE = PROJECT_DIR / "2200284.c"

KEY = "133457799BBCDFF1"
CHUNK_SIZE = 1024 * 1024

TEST_VECTORS = [
    ("133457799BBCDFF1", "0123456789ABCDEF", "85E813540F0AB405"),
    ("0000000000000000", "0000000000000000", "8CA64DE9C1B123A7"),
    ("FFFFFFFFFFFFFFFF", "FFFFFFFFFFFFFFFF", "7359B2163E4EDC58"),
    ("133457799BBCDFF1", "0000000000000000", "948A43F98A834F7E"),
    ("133457799BBCDFF1", "FFFFFFFFFFFFFFFF", "5A3DB304D64924FD"),
]

SEMI_WEAK_PAIRS = [
    ("011F011F010E010E", "1F011F010E010E01"),
    ("01E001E001F101F1", "E001E001F101F101"),
    ("01FE01FE01FE01FE", "FE01FE01FE01FE01"),
    ("1FE01FE00EF10EF1", "E01FE01FF10EF10E"),
    ("1FFE1FFE0EFE0EFE", "FE1FFE1FFE0EFE0E"),
    ("E0FEE0FEF1FEF1FE", "FEE0FEE0FEF1FEF1"),
]

VALID_SIZES = [
    0, 8, 16, 24, 64, 128, 1024, 4096,
    64 * 1024, 1024 * 1024, 10 * 1024 * 1024,
    100 * 1024 * 1024,
]

INVALID_SIZES = [1, 7, 9, 15, 17]


def write_pattern_file(path, size):
    """Create deterministic binary input of the requested size."""
    pattern = bytes(range(256))
    block = pattern * 4096  # 1 MiB

    with open(path, "wb") as f:
        full, rem = divmod(size, len(block))

        for _ in range(full):
            f.write(block)

        if rem:
            f.write(block[:rem])


def write_key_file(path, key_hex):
    """Write an 8-byte raw binary DES key (.bin)."""
    path.write_bytes(bytes.fromhex(key_hex))
    return path


def write_text_key_file(path, text):
    """Write an ASCII hexadecimal key file (.txt) for text-parser tests."""
    path.write_text(text, encoding="ascii")
    return path


def files_equal(path_a, path_b):
    """Compare two files in chunks without loading them entirely."""
    with open(path_a, "rb") as a, open(path_b, "rb") as b:
        while True:
            x = a.read(CHUNK_SIZE)
            y = b.read(CHUNK_SIZE)

            if x != y:
                return False

            if not x:
                return True


# ---------------------------------------------------------------------
# Independent reference DES (pure Python, table-driven, straight from
# FIPS 46-3). Slow, so only used on small inputs. It shares no code with
# the C program, which is the whole point: round-trip tests alone cannot
# detect a cipher that is consistently wrong.
# ---------------------------------------------------------------------
_IP = [58,50,42,34,26,18,10,2,60,52,44,36,28,20,12,4,62,54,46,38,30,22,14,6,
       64,56,48,40,32,24,16,8,57,49,41,33,25,17,9,1,59,51,43,35,27,19,11,3,
       61,53,45,37,29,21,13,5,63,55,47,39,31,23,15,7]
_FP = [40,8,48,16,56,24,64,32,39,7,47,15,55,23,63,31,38,6,46,14,54,22,62,30,
       37,5,45,13,53,21,61,29,36,4,44,12,52,20,60,28,35,3,43,11,51,19,59,27,
       34,2,42,10,50,18,58,26,33,1,41,9,49,17,57,25]
_E = [32,1,2,3,4,5,4,5,6,7,8,9,8,9,10,11,12,13,12,13,14,15,16,17,16,17,18,19,
      20,21,20,21,22,23,24,25,24,25,26,27,28,29,28,29,30,31,32,1]
_P = [16,7,20,21,29,12,28,17,1,15,23,26,5,18,31,10,2,8,24,14,32,27,3,9,19,13,
      30,6,22,11,4,25]
_PC1 = [57,49,41,33,25,17,9,1,58,50,42,34,26,18,10,2,59,51,43,35,27,19,11,3,
        60,52,44,36,63,55,47,39,31,23,15,7,62,54,46,38,30,22,14,6,61,53,45,
        37,29,21,13,5,28,20,12,4]
_PC2 = [14,17,11,24,1,5,3,28,15,6,21,10,23,19,12,4,26,8,16,7,27,20,13,2,41,52,
        31,37,47,55,30,40,51,45,33,48,44,49,39,56,34,53,46,42,50,36,29,32]
_SH = [1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1]
_S = [
 [14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7,0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8,
  4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0,15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13],
 [15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10,3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5,
  0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15,13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9],
 [10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8,13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1,
  13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7,1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12],
 [7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15,13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9,
  10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4,3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14],
 [2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9,14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6,
  4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14,11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3],
 [12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11,10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8,
  9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6,4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13],
 [4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1,13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6,
  1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2,6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12],
 [13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7,1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2,
  7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8,2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11],
]


def _perm(value, table, width):
    out = 0
    for pos in table:
        out = (out << 1) | ((value >> (width - pos)) & 1)
    return out


def ref_des_block(key64, block64, decrypt=False):
    cd = _perm(key64, _PC1, 64)
    c, d = cd >> 28, cd & 0xFFFFFFF
    subkeys = []
    for sh in _SH:
        c = ((c << sh) | (c >> (28 - sh))) & 0xFFFFFFF
        d = ((d << sh) | (d >> (28 - sh))) & 0xFFFFFFF
        subkeys.append(_perm((c << 28) | d, _PC2, 56))
    if decrypt:
        subkeys.reverse()
    x = _perm(block64, _IP, 64)
    l, r = x >> 32, x & 0xFFFFFFFF
    for k in subkeys:
        t = _perm(r, _E, 32) ^ k
        f = 0
        for i in range(8):
            six = (t >> (42 - 6 * i)) & 0x3F
            row = ((six >> 4) & 2) | (six & 1)
            col = (six >> 1) & 0xF
            f = (f << 4) | _S[i][row * 16 + col]
        l, r = r, l ^ _perm(f, _P, 32)
    return _perm((r << 32) | l, _FP, 64)


def ref_des_ecb(key_hex, data, decrypt=False):
    key = int(key_hex, 16)
    out = bytearray()
    for i in range(0, len(data), 8):
        blk = int.from_bytes(data[i:i + 8], "big")
        out += ref_des_block(key, blk, decrypt).to_bytes(8, "big")
    return bytes(out)


def random_bytes(size, seed):
    """Deterministic NON-periodic data (the 0..255 pattern repeats every
    32 blocks and can hide block-ordering bugs)."""
    return random.Random(seed).randbytes(size)


class CipherForgeVerification(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        # Never trust a stale binary: rebuild from source with the exact
        # command the instructor will use (gcc -O3 <src> -o <exe>).
        # Override with CC / EXTRA_CFLAGS if your toolchain needs it
        # (e.g. EXTRA_CFLAGS=-B"C:/msys64/ucrt64/bin/" on Windows).
        cc = os.environ.get("CC") or shutil.which("gcc")
        if cc and SOURCE.is_file():
            cmd = [cc, "-O3", *os.environ.get("EXTRA_CFLAGS", "").split(),
                   str(SOURCE), "-o", str(EXECUTABLE)]
            build = subprocess.run(cmd, capture_output=True, text=True)
            if build.returncode != 0:
                raise RuntimeError(
                    "COMPILE ERROR (instructor scores this 5/10):\n"
                    + " ".join(cmd) + "\n" + build.stderr
                )
        elif not EXECUTABLE.is_file():
            raise RuntimeError(
                f"No compiler found and no executable at {EXECUTABLE}."
            )

        cls.temp = tempfile.TemporaryDirectory(
            prefix="cipherforge_tests_"
        )
        cls.work = Path(cls.temp.name)

    @classmethod
    def tearDownClass(cls):
        if hasattr(cls, "temp"):
            cls.temp.cleanup()

    def run_program(self, *args, timeout=600):
        """Execute the compiled C program."""
        return subprocess.run(
            [str(EXECUTABLE), *map(str, args)],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )

    def make_key_file(self, filename, key_hex):
        stem = Path(filename).stem
        return write_key_file(self.work / f"{stem}.bin", key_hex)

    def make_text_key_file(self, filename, text):
        return write_text_key_file(self.work / filename, text)
    
    # ---------------------------------------------------------
    # Stage 1: Known-answer tests
    # ---------------------------------------------------------

    def test_02_known_answer_encryption_vectors(self):
        for i, (key, plain_hex, cipher_hex) in enumerate(
            TEST_VECTORS, 1
        ):
            with self.subTest(vector=i):
                key_file = self.make_key_file(
                    f"kat_{i}_key.txt", key
                )
                src = self.work / f"kat_{i}_in.bin"
                dst = self.work / f"kat_{i}_enc.bin"

                src.write_bytes(bytes.fromhex(plain_hex))

                result = self.run_program("e", key_file, src, dst)

                self.assertEqual(
                    result.returncode, 0,
                    result.stdout + result.stderr
                )
                self.assertTrue(
                    dst.is_file(), "Ciphertext output missing"
                )
                self.assertEqual(
                    dst.read_bytes().hex().upper(), cipher_hex
                )

    def test_03_known_answer_decryption_vectors(self):
        for i, (key, plain_hex, cipher_hex) in enumerate(
            TEST_VECTORS, 1
        ):
            with self.subTest(vector=i):
                key_file = self.make_key_file(
                    f"dec_kat_{i}_key.txt", key
                )
                src = self.work / f"dec_kat_{i}.bin"
                dst = self.work / f"dec_kat_{i}_out.bin"

                src.write_bytes(bytes.fromhex(cipher_hex))

                result = self.run_program("d", key_file, src, dst)

                self.assertEqual(
                    result.returncode, 0,
                    result.stdout + result.stderr
                )
                self.assertTrue(
                    dst.is_file(), "Decrypted output missing"
                )
                self.assertEqual(
                    dst.read_bytes().hex().upper(), plain_hex
                )

    # ---------------------------------------------------------
    # Stage 2: File sizes and round-trip verification
    # ---------------------------------------------------------

    def test_04_round_trip_all_valid_sizes(self):
        key_file = self.make_key_file(
            "round_trip_key.txt", KEY
        )

        for size in VALID_SIZES:
            with self.subTest(size_bytes=size):
                src = self.work / f"size_{size}_in.bin"
                enc = self.work / f"size_{size}_enc.bin"
                dec = self.work / f"size_{size}_dec.bin"

                write_pattern_file(src, size)

                # Encrypt
                result = self.run_program(
                    "e", key_file, src, enc
                )

                self.assertEqual(
                    result.returncode, 0,
                    f"Encryption failed for {size} bytes: "
                    f"{result.stdout} {result.stderr}"
                )

                self.assertTrue(enc.is_file())
                self.assertEqual(enc.stat().st_size, size)

                # Decrypt
                result = self.run_program(
                    "d", key_file, enc, dec
                )

                self.assertEqual(
                    result.returncode, 0,
                    f"Decryption failed for {size} bytes: "
                    f"{result.stdout} {result.stderr}"
                )

                self.assertTrue(dec.is_file())
                self.assertEqual(dec.stat().st_size, size)
                self.assertTrue(
                    files_equal(src, dec),
                    f"Round-trip mismatch at {size} bytes"
                )

    def test_05_non_aligned_sizes_are_rejected(self):
        key_file = self.make_key_file(
            "invalid_size_key.txt", KEY
        )

        for size in INVALID_SIZES:
            with self.subTest(size_bytes=size):
                src = self.work / f"bad_size_{size}.bin"
                dst = self.work / f"bad_size_{size}_out.bin"

                src.write_bytes(b"A" * size)

                if dst.exists():
                    dst.unlink()

                result = self.run_program(
                    "e", key_file, src, dst
                )

                self.assertNotEqual(
                    result.returncode, 0,
                    f"Accepted invalid input size: {size}"
                )

                self.assertFalse(
                    dst.exists(),
                    "Output was created for an invalid input size"
                )

    # ---------------------------------------------------------
    # Stage 3: Negative tests
    # ---------------------------------------------------------

    def test_06_malformed_keys_are_rejected(self):
        src = self.work / "bad_key_input.bin"
        src.write_bytes(b"12345678")

        malformed_keys = [
            "",
            "123",
            "133457799BBCDFF",
            "133457799BBCDFFGG",
            "ZZ3457799BBCDFF1",
        ]

        for i, key in enumerate(malformed_keys):
            with self.subTest(key=repr(key)):
                key_file = self.make_text_key_file(
                    f"malformed_key_{i}.txt", key
                )
                dst = self.work / f"bad_key_{i}_out.bin"

                if dst.exists():
                    dst.unlink()

                result = self.run_program(
                    "e", key_file, src, dst
                )

                self.assertNotEqual(
                    result.returncode, 0,
                    f"Accepted malformed key contents: {key!r}"
                )

                self.assertFalse(
                    dst.exists(),
                    "Output was created for a malformed key"
                )
        for n in (0, 1, 3, 7, 9, 12, 16, 17, 32):
            with self.subTest(raw_bin_len=n):
                key_file = self.work / f"malformed_bin_key_{n}.bin"
                key_file.write_bytes(b"\xAB" * n)
                dst = self.work / f"bad_bin_key_{n}_out.bin"
                if dst.exists():
                    dst.unlink()
                result = self.run_program("e", key_file, src, dst)
                self.assertNotEqual(result.returncode, 0, f"Accepted {n}-byte raw binary key")
                self.assertFalse(dst.exists())

    def test_07_missing_input_file_is_rejected(self):
        key_file = self.make_key_file(
            "missing_input_key.txt", KEY
        )
        src = self.work / "missing_input.bin"
        dst = self.work / "missing_input_out.bin"

        if src.exists():
            src.unlink()

        if dst.exists():
            dst.unlink()

        result = self.run_program(
            "e", key_file, src, dst
        )

        self.assertNotEqual(result.returncode, 0)

    def test_08_missing_input_does_not_create_new_output(self):
        key_file = self.make_key_file(
            "absent_input_key.txt", KEY
        )
        src = self.work / "absent_input.bin"
        dst = self.work / "must_not_exist.bin"

        if src.exists():
            src.unlink()

        if dst.exists():
            dst.unlink()

        result = self.run_program(
            "e", key_file, src, dst
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(
            dst.exists(),
            "Output was created despite missing input"
        )

    def test_09_invalid_operation_is_rejected(self):
        key_file = self.make_key_file(
            "invalid_operation_key.txt", KEY
        )
        src = self.work / "invalid_op_input.bin"
        dst = self.work / "invalid_op_out.bin"

        src.write_bytes(b"12345678")

        result = self.run_program(
            "x", key_file, src, dst
        )

        self.assertNotEqual(result.returncode, 0)

    def test_10_wrong_arg_counts_are_rejected(self):
        key_file = self.make_key_file("argcnt_key", KEY)
        src = self.work / "argcnt_in.bin"
        dst = self.work / "argcnt_out.bin"
        src.write_bytes(bytes(8))

        bad_invocations = [
            (),
            ("e",),
            ("e", key_file),
            ("e", key_file, src),
            ("e", key_file, src, dst, "extra"),
        ]
        for args in bad_invocations:
            with self.subTest(argc=len(args) + 1):
                if dst.exists():
                    dst.unlink()
                res = self.run_program(*args)
                self.assertNotEqual(res.returncode, 0)
                self.assertFalse(dst.exists())

    # ---------------------------------------------------------
    # Stage 4: Regression-style checks
    # ---------------------------------------------------------

    def test_11_same_input_and_key_produce_same_ciphertext(self):
        key_file = self.make_key_file(
            "repeat_key.txt", KEY
        )
        src = self.work / "repeat_input.bin"
        out1 = self.work / "repeat_a.bin"
        out2 = self.work / "repeat_b.bin"

        src.write_bytes(bytes(range(64)))

        r1 = self.run_program(
            "e", key_file, src, out1
        )
        r2 = self.run_program(
            "e", key_file, src, out2
        )

        self.assertEqual(
            r1.returncode, 0, r1.stdout + r1.stderr
        )
        self.assertEqual(
            r2.returncode, 0, r2.stdout + r2.stderr
        )
        self.assertEqual(
            out1.read_bytes(), out2.read_bytes()
        )

    # ---------------------------------------------------------
    # Stage 5: Autograder Edge Cases (The Devil's Advocate)
    # ---------------------------------------------------------

    def test_12_binary_key_format(self):
        """Test that exactly 8 raw bytes are parsed correctly as a key."""
        key_hex = "133457799BBCDFF1"
        key_bytes = bytes.fromhex(key_hex)
        
        # Write exactly 8 raw bytes to the key file
        key_file = self.work / "raw_key.bin"
        key_file.write_bytes(key_bytes)
        
        src = self.work / "bin_key_in.bin"
        dst = self.work / "bin_key_out.bin"
        src.write_bytes(bytes.fromhex("0123456789ABCDEF"))
        
        result = self.run_program("e", key_file, src, dst)
        self.assertEqual(
            result.returncode, 0, 
            f"Failed to use 8-byte raw binary key: {result.stderr}"
        )
        self.assertEqual(dst.read_bytes().hex().upper(), "85E813540F0AB405")

    def test_13_key_with_whitespace(self):
        """Test that the parser ignores newlines, tabs, and spaces in the key file."""
        # A violently dirty key file typical of copy-pasting TAs
        dirty_key = " \t 1334 \n 5779\t9BBC DFF1 \r\n "
        
        key_file = self.work / "dirty_key.txt"
        key_file.write_text(dirty_key, encoding="ascii")
        
        src = self.work / "dirty_key_in.bin"
        dst = self.work / "dirty_key_out.bin"
        src.write_bytes(bytes.fromhex("0123456789ABCDEF"))
        
        result = self.run_program("e", key_file, src, dst)
        self.assertEqual(
            result.returncode, 0, 
            f"Failed to ignore whitespace in key file: {result.stderr}"
        )
        self.assertEqual(dst.read_bytes().hex().upper(), "85E813540F0AB405")

    def test_15_too_many_arguments(self):
        """Test that providing extraneous arguments causes a failure."""
        res = self.run_program("e", "key.bin", "in.bin", "out.bin", "extra_arg")
        self.assertNotEqual(
            res.returncode, 0, 
            "Program accepted too many arguments instead of printing Usage."
        )

    def test_16_unwritable_output_path(self):
        key_file = self.make_key_file("unwritable_key", KEY)
        src = self.work / "valid_in.bin"
        src.write_bytes(b"A" * 8)
        dst = self.work / "nonexistent_dir_123" / "out.bin"
        res = self.run_program("e", key_file, src, dst)
        self.assertNotEqual(res.returncode, 0)

    # ---------------------------------------------------------
    # Stage 6: Build, independent-reference and boundary tests
    # (added after QA review - these cover what stages 1-5 miss)
    # ---------------------------------------------------------

    def encrypt_bytes(self, data, key_spec, tag, mode="e", text_key=False):
        """Helper: run the C program on in-memory bytes, return bytes."""
        key_file = (
            self.make_text_key_file(f"{tag}_key.txt", key_spec)
            if text_key
            else self.make_key_file(f"{tag}_key.bin", key_spec)
        )
        src = self.work / f"{tag}_in.bin"
        dst = self.work / f"{tag}_out.bin"
        src.write_bytes(data)
        if dst.exists():
            dst.unlink()
        res = self.run_program(mode, key_file, src, dst)
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        return dst.read_bytes()

    def test_17_compiles_with_o3_without_warnings(self):
        """Match TA's exact -O3 flag and fail on any warning."""
        cc = os.environ.get("CC") or shutil.which("gcc")
        if not cc:
            self.skipTest("gcc not available")
        out = self.work / "warn_check.out"
        res = subprocess.run(
            [cc, "-O3", "-Wall", "-Wextra", "-Werror",
             *os.environ.get("EXTRA_CFLAGS", "").split(),
             str(SOURCE), "-o", str(out)],
            capture_output=True, text=True)
        self.assertEqual(res.returncode, 0, res.stderr)

    def test_18_matches_independent_reference_on_random_data(self):
        """Random multi-block data, random keys, vs the pure-Python DES."""
        rng = random.Random(1234)
        for n_blocks in (1, 2, 3, 4, 5, 7, 8, 9, 33, 256):
            with self.subTest(blocks=n_blocks):
                key_hex = "%016X" % rng.getrandbits(64)
                data = random_bytes(n_blocks * 8, seed=n_blocks)
                got = self.encrypt_bytes(data, key_hex, f"ref_{n_blocks}")
                self.assertEqual(got, ref_des_ecb(key_hex, data))
                back = self.encrypt_bytes(got, key_hex, f"refd_{n_blocks}", "d")
                self.assertEqual(back, data)

    def test_19_block_count_not_multiple_of_unroll_width(self):
        """Optimised builds process several blocks per iteration; the tail
        (1..N-1 leftover blocks) is the classic place for off-by-one bugs."""
        key_hex = "0E329232EA6D0D73"
        for n_blocks in range(1, 18):
            with self.subTest(blocks=n_blocks):
                data = random_bytes(n_blocks * 8, seed=100 + n_blocks)
                self.assertEqual(
                    self.encrypt_bytes(data, key_hex, f"tail_{n_blocks}"),
                    ref_des_ecb(key_hex, data))

    def test_20_buffer_boundary_with_non_periodic_data(self):
        """The C buffer is 1 MiB. Test around that boundary with random data
        (the 0..255 pattern repeats every 256 B and would mask misordering).
        Spot-check first/boundary/last blocks against the reference."""
        MIB = 1024 * 1024
        key_hex = KEY
        for size in (MIB - 8, MIB + 8, 2 * MIB + 8):
            with self.subTest(size=size):
                data = random_bytes(size, seed=size)
                enc = self.encrypt_bytes(data, key_hex, f"bnd_{size}")
                self.assertEqual(len(enc), size)
                for blk in {0, MIB // 8 - 2, MIB // 8 - 1, MIB // 8,
                            size // 8 - 1}:
                    if 0 <= blk < size // 8:
                        a, b = blk * 8, blk * 8 + 8
                        self.assertEqual(
                            enc[a:b], ref_des_ecb(key_hex, data[a:b]),
                            f"block {blk} differs")
                back = self.encrypt_bytes(enc, key_hex, f"bndd_{size}", "d")
                self.assertEqual(back, data)

    def test_21_ecb_property_equal_blocks_equal_ciphertext(self):
        """ECB: identical plaintext blocks anywhere -> identical ciphertext
        blocks; different blocks -> different ciphertext blocks."""
        a, b = bytes(range(8)), bytes(range(8, 16))
        data = a + b + a + a + b + a * 5
        enc = self.encrypt_bytes(data, KEY, "ecb_prop")
        blocks = [enc[i:i + 8] for i in range(0, len(enc), 8)]
        self.assertEqual(blocks[0], blocks[2])
        self.assertEqual(blocks[0], blocks[3])
        self.assertEqual(blocks[1], blocks[4])
        self.assertNotEqual(blocks[0], blocks[1])

    def test_22_parity_bits_are_ignored(self):
        """DES ignores the LSB of each key byte (parity)."""
        k1 = "133457799BBCDFF1"
        k2 = "".join("%02X" % (int(k1[i:i + 2], 16) ^ 1) for i in range(0, 16, 2))
        data = random_bytes(64, seed=7)
        self.assertEqual(self.encrypt_bytes(data, k1, "par1"),
                         self.encrypt_bytes(data, k2, "par2"))

    def test_23_weak_keys_are_involutions(self):
        """For the 4 weak keys, encrypt == decrypt (E(E(x)) == x)."""
        data = random_bytes(64, seed=8)
        for i, k in enumerate(("0101010101010101", "FEFEFEFEFEFEFEFE",
                               "E0E0E0E0F1F1F1F1", "1F1F1F1F0E0E0E0E")):
            with self.subTest(key=k):
                once = self.encrypt_bytes(data, k, f"weak_{i}")
                twice = self.encrypt_bytes(once, k, f"weak2_{i}")
                self.assertEqual(twice, data)

    def test_24_complementation_property(self):
        """E_{~K}(~P) == ~E_K(P) - a structural DES property that needs no
        reference implementation."""
        inv = lambda bs: bytes(x ^ 0xFF for x in bs)
        data = random_bytes(128, seed=9)
        key = bytes.fromhex(KEY)
        c1 = self.encrypt_bytes(data, KEY, "comp1")
        c2 = self.encrypt_bytes(inv(data), inv(key).hex().upper(), "comp2")
        self.assertEqual(c2, inv(c1))

    def test_25_wrong_key_does_not_decrypt(self):
        data = random_bytes(64, seed=10)
        enc = self.encrypt_bytes(data, KEY, "wk1")
        wrong = self.encrypt_bytes(enc, "0123456789ABCDEF", "wk2", "d")
        self.assertNotEqual(wrong, data)

    def test_26_key_case_and_line_endings_equivalent(self):
        data = bytes.fromhex("0123456789ABCDEF")
        expect = bytes.fromhex("85E813540F0AB405")
        for i, text in enumerate(("133457799bbcdff1", "133457799BBCDFF1\n",
                                "133457799bbcdff1\r\n", "133457799BbCdFf1")):
            with self.subTest(key=repr(text)):
                self.assertEqual(self.encrypt_bytes(data, text, f"case_{i}", text_key=True), expect)

    def test_27_decrypt_rejects_non_aligned_input_too(self):
        key_file = self.make_key_file("dec_bad_key.txt", KEY)
        src = self.work / "dec_bad_in.bin"
        dst = self.work / "dec_bad_out.bin"
        src.write_bytes(b"A" * 13)
        if dst.exists():
            dst.unlink()
        res = self.run_program("d", key_file, src, dst)
        self.assertNotEqual(res.returncode, 0)
        self.assertFalse(dst.exists())

    def test_28_empty_file_decrypt(self):
        key_file = self.make_key_file("empty_dec_key.txt", KEY)
        src = self.work / "empty_in.bin"
        dst = self.work / "empty_out.bin"
        src.write_bytes(b"")
        res = self.run_program("d", key_file, src, dst)
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertEqual(dst.stat().st_size, 0)

    def test_29_existing_larger_output_is_truncated(self):
        key_file = self.make_key_file("trunc_key.txt", KEY)
        src = self.work / "trunc_in.bin"
        dst = self.work / "trunc_out.bin"
        src.write_bytes(bytes(8))
        dst.write_bytes(b"\xAA" * 4096)
        res = self.run_program("e", key_file, src, dst)
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertEqual(dst.stat().st_size, 8)
        self.assertEqual(dst.read_bytes(), ref_des_ecb(KEY, bytes(8)))

    def test_30_missing_key_file_is_rejected(self):
        src = self.work / "nokey_in.bin"
        dst = self.work / "nokey_out.bin"
        src.write_bytes(bytes(8))
        if dst.exists():
            dst.unlink()
        res = self.run_program("e", self.work / "does_not_exist.txt", src, dst)
        self.assertNotEqual(res.returncode, 0)
        self.assertFalse(dst.exists())

    def test_31_directory_as_input_is_rejected(self):
        key_file = self.make_key_file("dirin_key.txt", KEY)
        d = self.work / "a_directory"
        d.mkdir(exist_ok=True)
        dst = self.work / "dirin_out.bin"
        if dst.exists():
            dst.unlink()
        res = self.run_program("e", key_file, d, dst)
        self.assertNotEqual(res.returncode, 0)
        self.assertFalse(dst.exists())

    def test_32_paths_with_spaces(self):
        key_file = self.make_key_file("key with spaces.txt", KEY)
        src = self.work / "input with spaces.bin"
        dst = self.work / "output with spaces.bin"
        src.write_bytes(bytes.fromhex("0123456789ABCDEF"))
        res = self.run_program("e", key_file, src, dst)
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertEqual(dst.read_bytes().hex().upper(), "85E813540F0AB405")

    @unittest.skipUnless(os.path.exists("/dev/full"), "needs /dev/full (Linux)")
    def test_33_write_failure_returns_nonzero(self):
        """Disk-full / flush failure must not exit 0."""
        key_file = self.make_key_file("full_key.txt", KEY)
        src = self.work / "full_in.bin"
        src.write_bytes(bytes(8))
        res = self.run_program("e", key_file, src, "/dev/full")
        self.assertNotEqual(res.returncode, 0)

    def test_35_key_with_0x_prefix(self):
        """Test that hex keys starting with 0x or 0X are parsed cleanly."""
        data = bytes.fromhex("0123456789ABCDEF")
        expect = bytes.fromhex("85E813540F0AB405")
        for prefix in ("0x", "0X"):
            with self.subTest(prefix=prefix):
                key_text = f"{prefix}133457799BBCDFF1"
                got = self.encrypt_bytes(data, key_text, f"hex_prefix_{prefix}", text_key=True)
                self.assertEqual(got, expect)

    def test_36_key_with_extra_hex_digits_is_rejected(self):
        """Keys with more than 16 hex digits (e.g. 17 or 32 chars) must be rejected."""
        src = self.work / "extra_hex_in.bin"
        src.write_bytes(b"A" * 8)
        extra_keys = [
            "133457799BBCDFF1A",
            "133457799BBCDFF101234567",
            "133457799BBCDFF1133457799BBCDFF1",
        ]
        for i, bad_key in enumerate(extra_keys):
            with self.subTest(key=bad_key):
                key_file = self.make_text_key_file(f"extra_key_{i}.txt", bad_key)
                dst = self.work / f"extra_key_{i}_out.bin"
                if dst.exists():
                    dst.unlink()
                res = self.run_program("e", key_file, src, dst)
                self.assertNotEqual(res.returncode, 0, f"Accepted 16+ hex key: {bad_key}")
                self.assertFalse(dst.exists(), "Output was created for an oversized key")

    def test_37_key_with_trailing_garbage_is_rejected(self):
        """Keys followed by non-whitespace garbage must be rejected."""
        src = self.work / "garbage_key_in.bin"
        src.write_bytes(b"A" * 8)
        garbage_keys = [
            "133457799BBCDFF1 extra_notes",
            "133457799BBCDFF1_not_hex",
            "133457799BBCDFF1;",
        ]
        for i, bad_key in enumerate(garbage_keys):
            with self.subTest(key=bad_key):
                key_file = self.make_text_key_file(f"garbage_key_{i}.txt", bad_key)
                dst = self.work / f"garbage_key_{i}_out.bin"
                if dst.exists():
                    dst.unlink()
                res = self.run_program("e", key_file, src, dst)
                self.assertNotEqual(res.returncode, 0, f"Accepted key with trailing garbage: {bad_key}")
                self.assertFalse(dst.exists())

    def test_39_ecb_single_bit_flip_error_isolation(self):
        """ECB property: A corrupted byte in block 1 only corrupts decrypted block 1;
        blocks 0 and 2 must remain completely unaffected."""
        data = random_bytes(24, seed=42)  # 3 blocks
        enc = bytearray(self.encrypt_bytes(data, KEY, "ecb_iso_enc"))
        self.assertEqual(len(enc), 24)

        # Corrupt 1 bit in block 1 (byte offset 12)
        enc[12] ^= 0x01

        # Decrypt corrupted ciphertext
        corrupt_file = self.work / "corrupt_enc.bin"
        corrupt_out = self.work / "corrupt_out.bin"
        corrupt_file.write_bytes(enc)
        key_file = self.make_key_file("ecb_iso_key.txt", KEY)

        res = self.run_program("d", key_file, corrupt_file, corrupt_out)
        self.assertEqual(res.returncode, 0, res.stderr)
        recovered = corrupt_out.read_bytes()

        # Block 0 (bytes 0..8) must match original perfectly
        self.assertEqual(recovered[0:8], data[0:8], "ECB error propagated into block 0")
        # Block 1 (bytes 8..16) must be corrupted
        self.assertNotEqual(recovered[8:16], data[8:16], "Corrupted block was not altered")
        # Block 2 (bytes 16..24) must match original perfectly
        self.assertEqual(recovered[16:24], data[16:24], "ECB error propagated into block 2")

    def test_40_hostile_binary_keys_and_small_binary_inputs(self):
        """Catch text-mode fopen('r'/'w'), strlen/sscanf NUL truncation, and premature whitespace stripping."""
        hostile_keys = [
            bytes(8),                          # all 0x00 (NUL)
            b"\x1a\x0a\x0d\x09\x20\x00\xff\x1a", # Ctrl-Z, LF, CR, TAB, SPACE, NUL
            b"01234567",                       # 8 raw bytes that happen to be ASCII hex
            b"0x123456",                       # 8 raw bytes starting with '0x'
        ]
        # Also include 0x1A / 0x0A / 0x00 in an 8-byte plaintext
        plaintext = b"\x00\x1a\x0a\x0d\x09\x20\xfe\xff"

        for i, kbytes in enumerate(hostile_keys):
            with self.subTest(key=kbytes.hex()):
                kf = self.work / f"hostile_k_{i}.bin"
                src = self.work / f"hostile_in_{i}.bin"
                enc = self.work / f"hostile_enc_{i}.bin"
                dec = self.work / f"hostile_dec_{i}.bin"
                kf.write_bytes(kbytes)
                src.write_bytes(plaintext)

                r1 = self.run_program("e", kf, src, enc)
                self.assertEqual(r1.returncode, 0, r1.stderr)
                self.assertEqual(enc.read_bytes(), ref_des_ecb(kbytes.hex(), plaintext))

                r2 = self.run_program("d", kf, enc, dec)
                self.assertEqual(r2.returncode, 0, r2.stderr)
                self.assertEqual(dec.read_bytes(), plaintext)

    def test_41_semi_weak_keys_involutiveness(self):
        """Unlike weak keys, semi-weak keys test asymmetric C/D left-shift rotations in PC-1/PC-2."""
        data = random_bytes(64, seed=99)
        for i, (k1, k2) in enumerate(SEMI_WEAK_PAIRS):
            with self.subTest(k1=k1, k2=k2):
                c = self.encrypt_bytes(data, k1, f"sw1_{i}", "e")
                self.assertEqual(c, ref_des_ecb(k1, data))
                p = self.encrypt_bytes(c, k2, f"sw2_{i}", "e")  # E_k2(E_k1(P)) == P
                self.assertEqual(p, data)

    def test_42_walking_one_bits_and_full_sbox_coverage(self):
        """Verify every IP/FP plaintext bit, every PC1/PC2 key bit, and 100% of all 512 S-box entries."""
        # 1) Walking 1 across all 64 plaintext bits (tests every IP & FP wire)
        pt_walk = b"".join((1 << b).to_bytes(8, "big") for b in range(64))
        got = self.encrypt_bytes(pt_walk, KEY, "walk_pt")
        self.assertEqual(got, ref_des_ecb(KEY, pt_walk))

        # 2) Walking 1 across all 64 key bit positions (including parity bits)
        block = bytes.fromhex("0123456789ABCDEF")
        for b in range(64):
            k_hex = "%016X" % (1 << b)
            self.assertEqual(
                self.encrypt_bytes(block, k_hex, f"walk_k_{b}"),
                ref_des_ecb(k_hex, block),
            )

        # 3) Verify 100% of all 8*64 = 512 S-box lookups are exercised and match ref_des_ecb
        data = random_bytes(512 * 8, seed=2026)
        got = self.encrypt_bytes(data, KEY, "sbox_cov")
        self.assertEqual(got, ref_des_ecb(KEY, data))

        # Confirm our test data actually hit all 512 S-box entries
        hit = [set() for _ in range(8)]
        cd = _perm(int(KEY, 16), _PC1, 64)
        c, d = cd >> 28, cd & 0xFFFFFFF
        subkeys = []
        for sh in _SH:
            c = ((c << sh) | (c >> (28 - sh))) & 0xFFFFFFF
            d = ((d << sh) | (d >> (28 - sh))) & 0xFFFFFFF
            subkeys.append(_perm((c << 28) | d, _PC2, 56))
        for off in range(0, len(data), 8):
            x = _perm(int.from_bytes(data[off:off + 8], "big"), _IP, 64)
            l, r = x >> 32, x & 0xFFFFFFFF
            for k in subkeys:
                t = _perm(r, _E, 32) ^ k
                f = 0
                for i in range(8):
                    six = (t >> (42 - 6 * i)) & 0x3F
                    hit[i].add(six)
                    row = ((six >> 4) & 2) | (six & 1)
                    col = (six >> 1) & 0xF
                    f = (f << 4) | _S[i][row * 16 + col]
                l, r = r, l ^ _perm(f, _P, 32)
        for i in range(8):
            self.assertEqual(len(hit[i]), 64, f"S-box {i+1} missed entries")

    def test_43_large_message_speed_and_spot_verification(self):
        """Spec explicitly grades/measures speed on a large message; also verify large non-periodic ciphertext."""
        size = 64 * 1024 * 1024  # 64 MiB (adjust to 100 MiB if desired)
        key_file = self.make_key_file("bench_key", KEY)
        src = self.work / "bench_in.bin"
        enc = self.work / "bench_enc.bin"
        dec = self.work / "bench_dec.bin"

        # Fast deterministic non-periodic 64 MiB buffer (no 256-byte repeat)
        rng = random.Random(777)
        chunk = rng.randbytes(1024 * 1024)
        with open(src, "wb") as f:
            for i in range(size // len(chunk)):
                # XOR chunk index so every 1 MiB chunk is distinct
                f.write(bytes([chunk[0] ^ (i & 0xFF)]) + chunk[1:])

        t0 = time.perf_counter()
        r_enc = self.run_program("e", key_file, src, enc)
        t_enc = time.perf_counter() - t0
        self.assertEqual(r_enc.returncode, 0, r_enc.stderr)

        t1 = time.perf_counter()
        r_dec = self.run_program("d", key_file, enc, dec)
        t_dec = time.perf_counter() - t1
        self.assertEqual(r_dec.returncode, 0, r_dec.stderr)

        enc_mib_s = (size / (1024 * 1024)) / t_enc
        dec_mib_s = (size / (1024 * 1024)) / t_dec
        print(f"\n[SPEED] 64 MiB Encrypt: {t_enc:.3f}s ({enc_mib_s:.1f} MiB/s) | "
            f"Decrypt: {t_dec:.3f}s ({dec_mib_s:.1f} MiB/s)")

        self.assertTrue(files_equal(src, dec), "Large file round-trip mismatch")

        # Verify non-periodic chunks across the entire 64 MiB file against ref_des_ecb
        with open(src, "rb") as fs, open(enc, "rb") as fe:
            for mib in (0, 1, 15, 31, 63):
                off = mib * 1024 * 1024
                fs.seek(off)
                fe.seek(off)
                self.assertEqual(fe.read(64), ref_des_ecb(KEY, fs.read(64)),
                                f"Ciphertext mismatch at MiB {mib}")

        # Sanity floor: naive bit-by-bit DES (< 2 MiB/s) should fail a speed check
        self.assertGreater(enc_mib_s, 10.0, "Encryption too slow (< 10 MiB/s)")
        self.assertGreater(dec_mib_s, 10.0, "Decryption too slow (< 10 MiB/s)")

    def test_44_o3_warnings_and_sanitizers(self):
        """Test exact -O3 flag with warnings + ASan/UBSan against UB/strict-aliasing bugs."""
        cc = os.environ.get("CC") or shutil.which("gcc")
        if not cc:
            self.skipTest("gcc not available")

        o3_bin = self.work / "o3_warn_check"
        res = subprocess.run(
            [cc, "-O3", "-Wall", "-Wextra", "-Werror", str(SOURCE), "-o", str(o3_bin)],
            capture_output=True, text=True,
        )
        self.assertEqual(res.returncode, 0, "gcc -O3 warnings/errors:\n" + res.stderr)

        san_bin = self.work / "san_check"
        san_build = subprocess.run(
            [cc, "-O1", "-g", "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
            str(SOURCE), "-o", str(san_bin)],
            capture_output=True, text=True,
        )
        if san_build.returncode != 0:
            self.skipTest("ASan/UBSan runtime not supported by this toolchain")

        kf = self.make_key_file("san_key", KEY)
        src = self.work / "san_in.bin"
        enc = self.work / "san_enc.bin"
        dec = self.work / "san_dec.bin"
        data = random_bytes(4096, seed=314)
        src.write_bytes(data)

        for mode, a, b in (("e", src, enc), ("d", enc, dec)):
            r = subprocess.run([str(san_bin), mode, str(kf), str(a), str(b)],
                            capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, "Sanitizer failure:\n" + r.stderr)
        self.assertEqual(dec.read_bytes(), data)

    def test_45_directory_key_or_output_and_same_path_safety(self):
        """Directories as key/output must fail; same-path in==out must not silently destroy data."""
        kf = self.make_key_file("dir_test_key", KEY)
        d = self.work / "sub_dir"
        d.mkdir(exist_ok=True)
        src = self.work / "dir_test_in.bin"
        dst = self.work / "dir_test_out.bin"
        orig = bytes.fromhex("0123456789ABCDEF")
        src.write_bytes(orig)

        # Directory as key
        r_dk = self.run_program("e", d, src, dst)
        self.assertNotEqual(r_dk.returncode, 0)
        self.assertFalse(dst.exists())

        # Directory as output
        r_do = self.run_program("e", kf, src, d)
        self.assertNotEqual(r_do.returncode, 0)

        # Same-path in == out: must EITHER encrypt correctly OR fail without wiping src
        r_same = self.run_program("e", kf, src, src)
        if r_same.returncode == 0:
            self.assertEqual(src.read_bytes(), ref_des_ecb(KEY, orig))
        else:
            self.assertEqual(src.read_bytes(), orig, "Failed in-place call wiped input file!")

    def test_46_source_spec_compliance_audit(self):
        """Verify PDF constraints on 2200284.c: top comment, main signature, std headers, stdio API."""
        text = SOURCE.read_text(encoding="utf-8", errors="replace")
        head = "\n".join(text.splitlines()[:15])
        self.assertRegex(head, r"(/\*|//)", "Missing top comment with team names/IDs")
        self.assertRegex(text, r"int\s+main\s*\(\s*int\s+argc\s*,\s*char\s*\*\*\s*argv\s*\)",
                        "main signature does not match 'int main(int argc, char **argv)'")

        includes = re.findall(r'^\s*#\s*include\s*[<"]([^">]+)[">]', text, flags=re.MULTILINE)
        std_c = {"stdio.h", "stdlib.h", "stdint.h", "string.h", "ctype.h", "stdbool.h",
                "stddef.h", "limits.h", "errno.h", "inttypes.h", "time.h"}
        non_std = [h for h in includes if h not in std_c]
        self.assertEqual(non_std, [], f"Non-standard/external headers found: {non_std}")

        for fn in ("fopen", "fread", "fwrite", "fclose"):
            self.assertIn(fn, text, f"Required stdio function '{fn}' not used")
        self.assertNotRegex(text, r"\bfseek\s*\([^)]*SEEK_END\b",
                            "fseek(SEEK_END)/ftell risks 32-bit long overflow (>2 GiB) on Windows; use chunked fread")

if __name__ == "__main__":
    unittest.main(verbosity=2)