import sys

def add(a, b):
    return a + b

def multiply(a, b):
    return a * b

def fib(n):
    if n < 2:
        return n
    a, b = 0, 1
    for _ in range(2, n + 1):
        a, b = b, a + b
    return b

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

def main():
    total = add(3, 4) + multiply(5, 6) + fib(10)
    primes = [n for n in range(2, 30) if is_prime(n)]
    final_result = total + sum(primes)
    print("primes 2-29:", primes)
    print("final_result:", final_result)
    return final_result

if __name__ == "__main__":
    main()
