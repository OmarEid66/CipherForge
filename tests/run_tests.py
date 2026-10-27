import shutil
import subprocess
import sys
import unittest
from pathlib import Path

PROJECT_DIR = Path(__file__).resolve().parent.parent
SOURCE = PROJECT_DIR / "2200284.c"
TEST_DIR = PROJECT_DIR / "tests"
EXECUTABLE = PROJECT_DIR / (
    "2200284.exe" if sys.platform == "win32" else "2200284"
)


def compile_project():
    print("\n" + "=" * 68)
    print("STEP 1: COMPILE CIPHERFORGE")
    print("=" * 68, flush=True)

    if not SOURCE.is_file():
        print(f"ERROR: Source file not found: {SOURCE}")
        return False

    gcc = shutil.which("gcc")
    if gcc is None:
        print("ERROR: GCC not found on PATH.")
        return False

    command = [
    "gcc",
    "-B", r"C:\msys64\ucrt64\bin",
    "-std=c11",
    "-O2",
    "-Wall",
    "-Wextra",
    str(SOURCE),
    "-o",
    str(EXECUTABLE),
]

    print("Compiler:", gcc)

    try:
        result = subprocess.run(
            command,
            cwd=PROJECT_DIR,
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
    except (subprocess.TimeoutExpired, OSError) as exc:
        print(f"ERROR: Could not compile: {exc}")
        return False

    if result.stdout:
        print(result.stdout)
    if result.stderr:
        print(result.stderr)

    if result.returncode != 0:
        print(f"COMPILATION FAILED (exit code {result.returncode}).")
        return False

    if not EXECUTABLE.is_file():
        print("ERROR: Executable was not created.")
        return False

    print(f"Compilation successful: {EXECUTABLE}")
    return True


def run_tests():
    print("\n" + "=" * 68)
    print("STEP 2: RUN PYTHON VERIFICATION SUITE")
    print("=" * 68, flush=True)

    loader = unittest.TestLoader()
    suite = loader.discover(
        start_dir=str(TEST_DIR),
        pattern="test_des.py",
        top_level_dir=str(PROJECT_DIR),
    )

    if suite.countTestCases() == 0:
        print("ERROR: No tests discovered.")
        return False

    result = unittest.TextTestRunner(verbosity=2).run(suite)

    print(
        f"\nSUMMARY: {result.testsRun} tests; "
        f"{len(result.failures)} failures; "
        f"{len(result.errors)} errors; "
        f"{len(result.skipped)} skipped."
    )
    return result.wasSuccessful()


def main():
    print("CipherForge automated verification")
    print(f"Project: {PROJECT_DIR}")

    if not compile_project():
        print("FINAL RESULT: FAILED (compilation)")
        return 1

    if not run_tests():
        print("FINAL RESULT: FAILED (verification)")
        return 1

    print("\nFINAL RESULT: ALL TESTS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
