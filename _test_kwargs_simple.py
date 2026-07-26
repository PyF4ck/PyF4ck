def greet(name, *, greeting="Hello"):
    return greeting + ", " + name

def main():
    r1 = greet("World")
    r2 = greet("Bob", greeting="Hi")
    print("kwargs simple:", r1, r2)
    return r1 + r2

if __name__ == "__main__":
    main()
