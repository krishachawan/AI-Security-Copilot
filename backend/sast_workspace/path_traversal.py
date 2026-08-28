from pathlib import Path

BASE_DIRECTORY = Path('./uploads')


def read_user_file(request_data):
    filename = request_data.get('filename')

    if not filename:
        return {'error': 'Filename is required'}

    file_path = BASE_DIRECTORY / filename

    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            content = file.read()

        return {
            'success': True,
            'content': content
        }

    except FileNotFoundError:
        return {
            'success': False,
            'error': 'File not found'
        }

    except PermissionError:
        return {
            'success': False,
            'error': 'Permission denied'
        }


def process_download(request_data):
    if not isinstance(request_data, dict):
        return {'error': 'Invalid request'}

    return read_user_file(request_data)


def handle_request(request_data):
    result = process_download(request_data)

    if result.get('success'):
        return result

    return {
        'success': False,
        'message': result.get('error')
    }


def main():
    request = {
        'filename': 'documents/report.txt'
    }

    response = handle_request(request)
    print(response)


if __name__ == '__main__':
    main()
