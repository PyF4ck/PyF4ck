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
    print(fib(10))
    print(compute_secret(100))
    print(plain_helper(5))

if __name__ == "__main__":
    main()
