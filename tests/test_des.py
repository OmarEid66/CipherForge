import subprocess
import tempfile
import unittest
from pathlib import Path

PROJECT_DIR = Path(__file__).resolve().parent.parent
EXECUTABLE = PROJECT_DIR / ("2200284.exe" if __import__("os").name == "nt" else "2200284")
KEY = "133457799BBCDFF1"
CHUNK_SIZE = 1024 * 1024

TEST_VECTORS = [
    ("133457799BBCDFF1", "0123456789ABCDEF", "85E813540F0AB405"),
    ("0000000000000000", "0000000000000000", "8CA64DE9C1B123A7"),
    ("FFFFFFFFFFFFFFFF", "FFFFFFFFFFFFFFFF", "7359B2163E4EDC58"),
    ("133457799BBCDFF1", "0000000000000000", "948A43F98A834F7E"),
    ("133457799BBCDFF1", "FFFFFFFFFFFFFFFF", "5A3DB304D64924FD"),
]
VALID_SIZES = [0, 8, 16, 24, 64, 128, 1024, 4096, 64*1024, 1024*1024, 10*1024*1024, 100*1024*1024]
INVALID_SIZES = [1, 7, 9, 15, 17]


def write_pattern_file(path, size):
    pattern = bytes(range(256))
    block = pattern * 4096  # 1 MiB deterministic data
    with open(path, "wb") as f:
        full, rem = divmod(size, len(block))
        for _ in range(full):
            f.write(block)
        if rem:
            f.write(block[:rem])


def files_equal(path_a, path_b):
    with open(path_a, "rb") as a, open(path_b, "rb") as b:
        while True:
            x, y = a.read(CHUNK_SIZE), b.read(CHUNK_SIZE)
            if x != y:
                return False
            if not x:
                return True


class CipherForgeVerification(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not EXECUTABLE.is_file():
            raise RuntimeError(f"Executable not found: {EXECUTABLE}. Run python tests/run_tests.py")
        cls.temp = tempfile.TemporaryDirectory(prefix="cipherforge_tests_")
        cls.work = Path(cls.temp.name)

    @classmethod
    def tearDownClass(cls):
        if hasattr(cls, "temp"):
            cls.temp.cleanup()

    def run_program(self, *args, timeout=600):
        return subprocess.run([str(EXECUTABLE), *map(str, args)],
                              capture_output=True, text=True,
                              timeout=timeout, check=False)

    # Stage 1: known-answer tests
    def test_01_builtin_known_answer_tests(self):
        result = self.run_program()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("Results: 5/5 tests passed.", result.stdout)

    def test_02_known_answer_encryption_vectors(self):
        for i, (key, plain_hex, cipher_hex) in enumerate(TEST_VECTORS, 1):
            with self.subTest(vector=i):
                src, dst = self.work / f"kat_{i}_in.bin", self.work / f"kat_{i}_enc.bin"
                src.write_bytes(bytes.fromhex(plain_hex))
                result = self.run_program("e", key, src, dst)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertTrue(dst.is_file(), "Ciphertext output missing")
                self.assertEqual(dst.read_bytes().hex().upper(), cipher_hex)

    def test_03_known_answer_decryption_vectors(self):
        for i, (key, plain_hex, cipher_hex) in enumerate(TEST_VECTORS, 1):
            with self.subTest(vector=i):
                src, dst = self.work / f"dec_kat_{i}.bin", self.work / f"dec_kat_{i}_out.bin"
                src.write_bytes(bytes.fromhex(cipher_hex))
                result = self.run_program("d", key, src, dst)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual(dst.read_bytes().hex().upper(), plain_hex)

    # Stage 2: sizes and round-trip
    def test_04_round_trip_all_valid_sizes(self):
        for size in VALID_SIZES:
            with self.subTest(size_bytes=size):
                src = self.work / f"size_{size}_in.bin"
                enc = self.work / f"size_{size}_enc.bin"
                dec = self.work / f"size_{size}_dec.bin"
                write_pattern_file(src, size)

                result = self.run_program("e", KEY, src, enc)
                self.assertEqual(result.returncode, 0,
                                 f"Encryption failed for {size} bytes: {result.stdout} {result.stderr}")
                self.assertTrue(enc.is_file())
                self.assertEqual(enc.stat().st_size, size)

                result = self.run_program("d", KEY, enc, dec)
                self.assertEqual(result.returncode, 0,
                                 f"Decryption failed for {size} bytes: {result.stdout} {result.stderr}")
                self.assertEqual(dec.stat().st_size, size)
                self.assertTrue(files_equal(src, dec), f"Round-trip mismatch at {size} bytes")

    def test_05_non_aligned_sizes_are_rejected(self):
        for size in INVALID_SIZES:
            with self.subTest(size_bytes=size):
                src, dst = self.work / f"bad_size_{size}.bin", self.work / f"bad_size_{size}_out.bin"
                src.write_bytes(b"A" * size)
                if dst.exists():
                    dst.unlink()
                result = self.run_program("e", KEY, src, dst)
                self.assertNotEqual(result.returncode, 0, f"Accepted invalid size {size}")

    # Stage 3: negative tests
    def test_06_malformed_keys_are_rejected(self):
        src = self.work / "bad_key_input.bin"
        src.write_bytes(b"12345678")
        keys = ["", "123", "133457799BBCDFF", "133457799BBCDFFGG", "ZZ3457799BBCDFF1"]
        for i, key in enumerate(keys):
            with self.subTest(key=repr(key)):
                dst = self.work / f"bad_key_{i}_out.bin"
                result = self.run_program("e", key, src, dst)
                self.assertNotEqual(result.returncode, 0, f"Accepted malformed key {key!r}")

    def test_07_missing_input_file_is_rejected(self):
        src, dst = self.work / "missing_input.bin", self.work / "missing_input_out.bin"
        if src.exists():
            src.unlink()
        result = self.run_program("e", KEY, src, dst)
        self.assertNotEqual(result.returncode, 0)

    def test_08_missing_input_does_not_create_new_output(self):
        src, dst = self.work / "absent_input.bin", self.work / "must_not_exist.bin"
        if dst.exists():
            dst.unlink()
        result = self.run_program("e", KEY, src, dst)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(dst.exists(), "Output was created despite missing input")

    def test_09_invalid_operation_is_rejected(self):
        src, dst = self.work / "invalid_op_input.bin", self.work / "invalid_op_out.bin"
        src.write_bytes(b"12345678")
        result = self.run_program("x", KEY, src, dst)
        self.assertNotEqual(result.returncode, 0)

    def test_10_missing_arguments_show_usage(self):
        result = self.run_program("e", KEY)
        self.assertIn("Usage:", result.stdout + result.stderr)

    # Stage 4: regression-style checks
    def test_11_same_input_and_key_produce_same_ciphertext(self):
        src = self.work / "repeat_input.bin"
        out1, out2 = self.work / "repeat_a.bin", self.work / "repeat_b.bin"
        src.write_bytes(bytes(range(64)))
        r1 = self.run_program("e", KEY, src, out1)
        r2 = self.run_program("e", KEY, src, out2)
        self.assertEqual(r1.returncode, 0, r1.stdout + r1.stderr)
        self.assertEqual(r2.returncode, 0, r2.stdout + r2.stderr)
        self.assertEqual(out1.read_bytes(), out2.read_bytes())


if __name__ == "__main__":
    unittest.main(verbosity=2)
