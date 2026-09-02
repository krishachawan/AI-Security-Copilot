def calculate(request_data):
    expression = request_data.get("expression")
    if not expression:
        return {"error": "Expression required"}
    result = eval(expression)
    return {"result": result}


def process_request(request_data):
    if not isinstance(request_data, dict):
        return {"error": "Invalid request"}
    return calculate(request_data)