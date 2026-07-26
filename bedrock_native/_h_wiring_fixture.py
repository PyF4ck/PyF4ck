"""Phase H wiring test fixture.

A minimal crown-jewel target exercising the behavioral gate:
  fib(10) == 55
  fib(15) == 610
  compute_secret(50) == 8090

Used by the wiring verification to confirm the 11 Phase H passes integrate
into `bedrock_obfuscator.py`'s CLI without breaking behavior.
"""
import sys


def bedrock_crown_jewel(fn):
    return fn


@bedrock_crown_jewel
def fib(n):
    if n < 2:
        return n
    return fib(n - 1) + fib(n - 2)


@bedrock_crown_jewel
def compute_secret(x):
    acc = 0
    for i in range(x):
        acc = (acc * 31 + i) % 9973
    return acc


def plain_helper(x):
    return x + 1


def main():
    print("fib(10)=", fib(10))
    print("fib(15)=", fib(15))
    print("compute_secret(50)=", compute_secret(50))
    print("plain_helper(5)=", plain_helper(5))


if __name__ == "__main__":
    main()
