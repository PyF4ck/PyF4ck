import sys

async def fetch(n):
    return n * 2

def gen(n):
    for i in range(n):
        yield i

def kwargs_func(a, *, b, c=10):
    return a + b + c

def main():
    total = sum(gen(5))
    k = kwargs_func(1, b=2, c=3)
    print("async+yield+kwargs OK:", total, k)
    return total + k

if __name__ == "__main__":
    import asyncio
    r = asyncio.run(fetch(21))
    print("async result:", r)
    main()
