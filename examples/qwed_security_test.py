"""Demonstrates QWED Security v1.4 scanning capabilities."""

API_KEY = "QWED_TEST_DEMO_VALUE"


def run_demo():
    user_data = input("Enter expression: ")
    print(f"You entered: {user_data}")


def run_tainted():
    expression = input("Enter expression: ")
    result = eval(expression)
    print(f"Result: {result}")
