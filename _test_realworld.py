"""Real-world test file for Phase 7 production readiness.

Combines many production code shapes in one file. The obfuscator build with
--native-vm must produce an output that prints EXACTLY the same stdout as
running this file directly. Functions the VM can't compile (try/except, with,
async, class methods) fall back to the capsule runtime / plain Python; the VM
claims what it can (arithmetic, control flow, comprehensions, f-strings,
attribute access, subscripting).

Expected output (run directly first to capture):
  line 1: calculator: 57
  line 2: stats: mean=5.5 sum=55 count=10
  line 3: evens: [2, 4, 6, 8]
  line 4: primes: [2, 3, 5, 7, 11, 13]
  line 5: config: {'timeout': 30, 'retries': 3}
  line 6: safe: handled: division by zero
  line 7: file written ok
  line 8: points: [(0, 0), (1, 2), (3, 5)]
  line 9: result=42
"""
import os
import sys
import tempfile


# ---- VM-eligible: pure arithmetic + control flow -------------------------
def calculator(a, b, c):
    total = a + b * c
    if total > 50:
        total = total - 10
    else:
        total = total + 100
    while total > 60:
        total = total - 5
    return total


# ---- VM-eligible: list comprehension + nested calls ----------------------
def mean(values):
    return sum(values) / len(values)


def stats(values):
    m = mean(values)
    s = sum(values)
    n = len(values)
    return f"mean={m} sum={s} count={n}"


def evens_up_to(n):
    return [x for x in range(2, n) if x % 2 == 0]


def is_prime(n):
    if n < 2:
        return False
    if n < 4:
        return True
    if n % 2 == 0:
        return False
    i = 3
    while i * i <= n:
        if n % i == 0:
            return False
        i += 2
    return True


def primes_up_to(n):
    return [x for x in range(2, n) if is_prime(x)]


# ---- VM-eligible: dict building + f-strings ------------------------------
def build_config(timeout, retries):
    return {'timeout': timeout, 'retries': retries}


# ---- VM-ineligible: try/except (falls back to capsule/plain) --------------
def safe_divide(a, b):
    try:
        return a / b
    except ZeroDivisionError as e:
        return f"handled: {e}"


# ---- VM-ineligible: with statement (falls back to capsule/plain) ---------
def write_file():
    with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
        f.write("hello")
        return "file written ok"


# ---- VM-ineligible: class with methods (falls back) -----------------------
class Point:
    def __init__(self, x, y):
        self.x = x
        self.y = y

    def __repr__(self):
        return f"({self.x}, {self.y})"


def make_points():
    pts = [Point(0, 0), Point(1, 2), Point(3, 5)]
    return [repr(p) for p in pts]


# ---- VM-eligible: complex expression -------------------------------------
def complex_expr(a, b):
    return (a + b) * 2 - (a - b) if a > b else b - a


# ---- main: orchestrates all of the above --------------------------------
def main():
    print("calculator:", calculator(3, 7, 8))
    print("stats:", stats([1, 2, 3, 4, 5, 6, 7, 8, 9, 10]))
    print("evens:", evens_up_to(10))
    print("primes:", primes_up_to(15))
    print("config:", build_config(30, 3))
    print("safe:", safe_divide(10, 0))
    print(write_file())
    print("points:", make_points())
    print(f"result={complex_expr(20, 22)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
