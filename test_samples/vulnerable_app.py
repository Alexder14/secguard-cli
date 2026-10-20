# Archivo de prueba con vulnerabilidades simuladas

# 1. AWS Key expuesta
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# 2. Token de GitHub
GITHUB_TOKEN = "ghp_FakeTokenForTestingPurposes1234567890ABC"

# 3. OpenAI Key
OPENAI_KEY = "sk-proj-ThisIsAFakeOpenAiKeyUsedToTestTheScanner12345"

# 4. Cadena de conexion con password en texto plano
DATABASE_URL = "postgres://admin_user:P@ssw0rdSegura2026!@postgres.internal.net:5432/clients"

# 5. Token criptografico de alta entropia (sin prefijo conocido)
AUTH_SESSION_SECRET = "9f8e7d6c5b4a39281726354859607182"

def connect():
    print("Conectando a base de datos...")
