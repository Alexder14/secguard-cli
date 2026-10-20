import re

# Firmas de secretos reconocidos en la industria
SECRET_PATTERNS = [
    {
        "id": "SEC-001",
        "name": "AWS Access Key ID",
        "severity": "CRITICAL",
        "regex": re.compile(r"(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}")
    },
    {
        "id": "SEC-002",
        "name": "AWS Secret Access Key",
        "severity": "CRITICAL",
        "regex": re.compile(r"(?i)aws_secret_access_key\s*=\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?")
    },
    {
        "id": "SEC-003",
        "name": "GitHub Personal Access Token",
        "severity": "CRITICAL",
        "regex": re.compile(r"gh[pousr]_[A-Za-z0-9_]{36,255}|github_pat_[A-Za-z0-9_]{82}")
    },
    {
        "id": "SEC-004",
        "name": "Slack API Token",
        "severity": "HIGH",
        "regex": re.compile(r"xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*")
    },
    {
        "id": "SEC-005",
        "name": "OpenAI API Key",
        "severity": "HIGH",
        "regex": re.compile(r"sk-(?:proj-)?[A-Za-z0-9_-]{40,100}")
    },
    {
        "id": "SEC-006",
        "name": "Google Cloud API Key",
        "severity": "HIGH",
        "regex": re.compile(r"AIza[0-9A-Za-z\\-_]{35}")
    },
    {
        "id": "SEC-007",
        "name": "Clave Privada Criptográfica (RSA/SSH/EC)",
        "severity": "CRITICAL",
        "regex": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")
    },
    {
        "id": "SEC-008",
        "name": "Cadena de Conexión a Base de Datos con Credenciales",
        "severity": "HIGH",
        "regex": re.compile(r"(?:postgres|postgresql|mysql|mongodb|mongodb\+srv|redis)://[^:]+:[^@]+@[^/:]+")
    },
    {
        "id": "SEC-009",
        "name": "Asignación de Contraseña en Código",
        "severity": "MEDIUM",
        "regex": re.compile(r"(?i)(?:password|passwd|secret_key|api_secret)\s*[:=]\s*['\"]([^'\"]{8,})['\"]")
    }
]

# Carpetas y archivos a ignorar durante el escaneo para maximizar rendimiento
IGNORE_DIRS = {
    ".git", "node_modules", "venv", ".venv", "env", 
    "__pycache__", ".idea", ".vscode", "dist", "build", "target"
}

IGNORE_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".pdf", ".zip", 
    ".tar", ".gz", ".exe", ".bin", ".pyc", ".db", ".sqlite", ".sqlite3"
}
