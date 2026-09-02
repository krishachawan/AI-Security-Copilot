API_KEY = 'sk_live_example_123456789'
DATABASE_PASSWORD = 'SuperSecretPassword123!'
JWT_SECRET = 'production-secret-key'

def authenticate(password):
    return password == DATABASE_PASSWORD
