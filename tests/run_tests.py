import os
import subprocess
import tempfile
import unittest
from pathlib import Path

PROJECT_DIR = Path(__file__).resolve().parent.parent
EXECUTABLE = PROJECT_DIR / (
    "2200284.exe" if os.name == "nt" else "2200284"
)

KEY = "133457799BBCDFF1"
CHUNK_SIZE = 1024 * 1024

TEST_VECTORS = [
    ("133457799BBCDFF1", "0123456789ABCDEF", "85E813540F0AB405"),
    ("0000000000000000", "0000000000000000", "8CA64DE9C1B123A7"),
    ("FFFFFFFFFFFFFFFF", "FFFFFFFFFFFFFFFF", "7359B2163E4EDC58"),
    ("133457799BBCDFF1", "0000000000000000", "948A43F98A834F7E"),
    ("133457799BBCDFF1", "FFFFFFFFFFFFFFFF", "5A3DB304D64924FD"),
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
    """Write a hexadecimal DES key to a key file."""
    path.write_text(key_hex, encoding="ascii")
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


class CipherForgeVerification(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        if not EXECUTABLE.is_file():
            raise RuntimeError(
                f"Executable not found: {EXECUTABLE}. "
                "Run python tests/run_tests.py first."
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
        """Create a temporary key file for the C program."""
        return write_key_file(self.work / filename, key_hex)

    # ---------------------------------------------------------
    # Stage 1: Known-answer tests
    # ---------------------------------------------------------

    def test_01_builtin_known_answer_tests(self):
        result = self.run_program()

        self.assertEqual(
            result.returncode, 0, result.stdout + result.stderr
        )
        self.assertIn(
            "Results: 5/5 tests passed.", result.stdout
        )

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
                key_file = self.make_key_file(
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

    def test_10_missing_arguments_show_usage(self):
        result = self.run_program("e", KEY)

        self.assertIn(
            "Usage:", result.stdout + result.stderr
        )

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


if __name__ == "__main__":
    unittest.main(verbosity=2)
