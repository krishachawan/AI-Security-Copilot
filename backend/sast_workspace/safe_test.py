from pathlib import Path


def read_requested_file(filename):
    base_directory = Path("C:/Users/Public/Documents").resolve()
    requested_file = (base_directory / filename).resolve()

    if base_directory not in requested_file.parents:
        raise ValueError("Invalid file path")

    if not requested_file.is_file():
        raise FileNotFoundError("File does not exist")

    with requested_file.open("r", encoding="utf-8") as file:
        return file.read()


def calculate_total(values):
    total = 0

    for value in values:
        if isinstance(value, (int, float)):
            total += value

    return total


def process_user_data(data):
    if not isinstance(data, dict):
        return {"error": "Invalid input"}

    username = data.get("username", "guest")
    age = data.get("age", 0)

    if not isinstance(username, str):
        username = "guest"

    if not isinstance(age, int):
        age = 0

    return {
        "username": username,
        "age": age
    }


def main():
    user_data = {
        "username": "krisha",
        "age": 21
    }

    processed = process_user_data(user_data)
    print(processed)

    numbers = [10, 20, 30, 40]
    print("Total:", calculate_total(numbers))


if __name__ == "__main__":
    main()
