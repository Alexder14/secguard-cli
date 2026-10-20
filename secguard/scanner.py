import os
import re
from typing import List, Dict, Any
from .rules import SECRET_PATTERNS, IGNORE_DIRS, IGNORE_EXTENSIONS
from .entropy import is_high_entropy_string

def mask_secret(secret: str) -> str:
    """Enmascara un secreto para mostrarlo de forma segura en los reportes."""
    if len(secret) <= 8:
        return "****"
    return f"{secret[:4]}...{secret[-4:]}"

def scan_file(file_path: str) -> List[Dict[str, Any]]:
    """Analiza un archivo individual linea por linea buscando secretos."""
    findings = []

    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            for line_num, line in enumerate(f, start=1):
                clean_line = line.strip()
                if not clean_line or clean_line.startswith("#") or clean_line.startswith("//"):
                    # Omitir comentarios obvios pero revisar si contienen secretos comentados
                    pass

                # 1. Escaneo mediante Reglas y Firmas Conocidas
                for rule in SECRET_PATTERNS:
                    match = rule["regex"].search(clean_line)
                    if match:
                        raw_match = match.group(0)
                        findings.append({
                            "type": "SECRET_SIGNATURE",
                            "rule_id": rule["id"],
                            "rule_name": rule["name"],
                            "severity": rule["severity"],
                            "file": file_path,
                            "line": line_num,
                            "match": mask_secret(raw_match),
                            "snippet": clean_line[:120]
                        })

                # 2. Escaneo mediante Entropia de Shannon (Detecta tokens desconocidos)
                tokens = re.findall(r"['\"]([A-Za-z0-9_\-+/=]{16,})['\"]", clean_line)
                for token in tokens:
                    if is_high_entropy_string(token):
                        # Evitar duplicar si ya fue capturado por una regla
                        already_captured = any(f["line"] == line_num and f["file"] == file_path for f in findings)
                        if not already_captured:
                            findings.append({
                                "type": "HIGH_ENTROPY_TOKEN",
                                "rule_id": "ENTROPY-001",
                                "rule_name": "Token Criptográfico de Alta Entropía",
                                "severity": "HIGH",
                                "file": file_path,
                                "line": line_num,
                                "match": mask_secret(token),
                                "snippet": clean_line[:120]
                            })

    except Exception:
        pass

    return findings

def scan_directory(target_dir: str) -> List[Dict[str, Any]]:
    """Recorre recursivamente un directorio omitiendo carpetas irrelevantes."""
    all_findings = []

    for root, dirs, files in os.walk(target_dir):
        # Filtrar directorios ignorados in-place
        dirs[:] = [d for d in dirs if d not in IGNORE_DIRS]

        for file in files:
            ext = os.path.splitext(file)[1].lower()
            if ext in IGNORE_EXTENSIONS:
                continue

            full_path = os.path.join(root, file)
            findings = scan_file(full_path)
            all_findings.extend(findings)

    return all_findings
