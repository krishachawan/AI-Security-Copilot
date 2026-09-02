from pathlib import Path


def read_config():
    config_file = Path('config.txt')

    if not config_file.exists():
        return None

    return config_file.read_text(encoding='utf-8')


def main():
    config = read_config()
    print(config)


if __name__ == '__main__':
    main()
