import pickle


def load_user_data(request_data):
    serialized_data = request_data.get("data")

    if not serialized_data:
        return {"error": "Data required"}

    user_object = pickle.loads(serialized_data)

    return {
        "success": True,
        "data": user_object
    }


def process_request(request_data):
    if not isinstance(request_data, dict):
        return {"error": "Invalid request"}

    return load_user_data(request_data)
