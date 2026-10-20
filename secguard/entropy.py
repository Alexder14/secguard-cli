import math
from collections import Counter

def calculate_shannon_entropy(data: str) -> float:
    """
    Calcula la entropia de Shannon de una cadena.
    Una entropia alta (> 4.0) indica alta aleatoriedad, caracteristica tipica
    de contraseñas complejas, tokens de autenticacion y claves criptograficas.
    """
    if not data:
        return 0.0

    entropy = 0.0
    length = len(data)
    counts = Counter(data)

    for count in counts.values():
        probability = count / length
        entropy -= probability * math.log2(probability)

    return entropy

def is_high_entropy_string(token: str, threshold: float = 4.2) -> bool:
    """
    Evalua si un token sospechoso califica como secreto de alta entropia.
    Filtra palabras muy cortas para reducir falsos positivos.
    """
    # Descartar cadenas muy cortas o sin caracteres variados
    if len(token) < 16 or len(token) > 256:
        return False

    # Descartar si solo son letras o solo digitos
    if token.isalpha() or token.isdigit():
        return False

    return calculate_shannon_entropy(token) >= threshold
