def calculate_total(price, quantity):
    if price < 0 or quantity < 0:
        return 0
    return price * quantity


def main():
    total = calculate_total(100, 3)
    print(f'Total: {total}')


if __name__ == '__main__':
    main()
