"""A simple Python script used as a debug target in tests."""

import time


def greet(name: str) -> str:
    greeting = f"Hello, {name}!"
    return greeting


def compute_sum(n: int) -> int:
    total = 0
    for i in range(1, n + 1):
        total += i
    return total


def process_items(items: list) -> dict:
    result = {}
    for item in items:
        key = item.upper()
        value = len(item)
        result[key] = value
    return result


def unsafe_eval(expr: str) -> object:
    return eval(expr)


class Counter:
    def __init__(self, start: int = 0):
        self.value = start

    def increment(self, amount: int = 1) -> int:
        self.value += amount
        return self.value

    def __repr__(self) -> str:
        return f"Counter(value={self.value})"


def main():
    name = "World"
    greeting = greet(name)
    print(greeting)

    total = compute_sum(10)
    print(f"Sum 1..10 = {total}")

    items = ["apple", "banana", "cherry"]
    processed = process_items(items)
    print(f"Processed: {processed}")

    counter = Counter(0)
    for i in range(5):
        counter.increment(i + 1)
    print(f"Counter: {counter}")

    raw_data = b"\x80\x04\x95\x19\x00payload_bytes"
    data_len = len(raw_data)

    eval_result = unsafe_eval("2 + 2")
    print(f"Eval: {eval_result}")

    print("Done!")


if __name__ == "__main__":
    main()
