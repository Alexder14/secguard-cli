import json
from typing import List, Dict, Any

# Colores ANSI para terminal
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"

def print_banner():
    banner = f"""{CYAN}{BOLD}
   ____              ____                  _ 
  / ___|  ___  ___  / ___|_   _  __ _ _ __| |
  \\___ \\ / _ \\/ __|| |  _| | | |/ _` | '__| |
   ___) |  __/ (__ | |_| | |_| | (_| | |  |_|
  |____/ \\___|\\___| \\____|\\__,_|\\__,_|_|  (_)
    DevSecOps SAST & Secret Scanner v1.0.0
{RESET}"""
    print(banner)

def print_secret_findings(findings: List[Dict[str, Any]]):
    """Muestra el reporte de secretos en la consola."""
    if not findings:
        print(f"\n{GREEN}{BOLD}[✓] ¡Excelente! No se detectaron secretos ni credenciales expuestas.{RESET}\n")
        return

    print(f"\n{RED}{BOLD}[!] ALERTA DE SEGURIDAD: Se detectaron {len(findings)} secreto(s) expuesto(s):{RESET}\n")
    print("-" * 80)

    for idx, f in enumerate(findings, start=1):
        sev_color = RED if f["severity"] == "CRITICAL" else YELLOW
        print(f"{BOLD}#{idx} [{f['rule_id']}] {f['rule_name']}{RESET}")
        print(f"  {BOLD}Severidad:{RESET} {sev_color}{f['severity']}{RESET}")
        print(f"  {BOLD}Archivo:{RESET}   {f['file']}:{f['line']}")
        print(f"  {BOLD}Coincidencia:{RESET} {f['match']}")
        print(f"  {BOLD}Código:{RESET}    {f['snippet']}")
        print("-" * 80)

def print_header_audit(audit: Dict[str, Any]):
    """Muestra la auditoria de cabeceras en consola."""
    print(f"\n{BOLD}Auditoría de Cabeceras Web para:{RESET} {audit.get('url')}")
    print(f"{BOLD}Código HTTP:{RESET} {audit.get('status_code')}")
    print(f"{BOLD}Puntaje de Seguridad:{RESET} {audit.get('score')}/100\n")

    if audit.get("passed"):
        print(f"{GREEN}{BOLD}[+] Cabeceras de Protección Presentes ({len(audit['passed'])}):{RESET}")
        for p in audit["passed"]:
            print(f"  {GREEN}✓{RESET} {BOLD}{p['header']}{RESET}")

    if audit.get("missing"):
        print(f"\n{RED}{BOLD}[-] Cabeceras Faltantes / Vulnerables ({len(audit['missing'])}):{RESET}")
        for m in audit["missing"]:
            sev_color = RED if m["severity"] == "HIGH" else YELLOW
            print(f"  {RED}✗{RESET} {BOLD}{m['header']}{RESET} [{sev_color}{m['severity']}{RESET}]")
            print(f"    Riesgo: {m['description']}")

    print("\n" + "=" * 80)

def export_json(data: Any, filepath: str):
    """Exporta los hallazgos a formato JSON."""
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    print(f"\n{GREEN}[+] Reporte JSON guardado en: {filepath}{RESET}")

def export_html(findings: List[Dict[str, Any]], audit: Dict[str, Any], filepath: str):
    """Genera un reporte HTML visual para equipos de seguridad."""
    html_content = f"""<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <title>Reporte de Seguridad SecGuard</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0f172a; color: #f8fafc; padding: 30px; }}
        .container {{ max-width: 900px; margin: 0 auto; }}
        h1 {{ color: #38bdf8; border-bottom: 2px solid #334155; padding-bottom: 10px; }}
        .card {{ background: #1e293b; border-radius: 8px; padding: 20px; margin-bottom: 20px; border-left: 5px solid #ef4444; }}
        .CRITICAL {{ border-color: #ef4444; }}
        .HIGH {{ border-color: #f59e0b; }}
        .code {{ background: #020617; padding: 10px; border-radius: 4px; font-family: monospace; color: #a5f3fc; }}
        .badge {{ padding: 3px 8px; border-radius: 4px; font-size: 12px; font-weight: bold; background: #dc2626; color: white; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🛡️ Reporte de Auditoría SecGuard</h1>
        <p>Generado automáticamente durante el escaneo de seguridad SAST.</p>
        <h2>Hallazgos de Secretos ({len(findings)})</h2>
    """

    for f in findings:
        html_content += f"""
        <div class="card {f['severity']}">
            <h3>{f['rule_name']} <span class="badge">{f['severity']}</span></h3>
            <p><strong>Ubicación:</strong> {f['file']}:{f['line']}</p>
            <p><strong>Coincidencia Enmascarada:</strong> <code>{f['match']}</code></p>
            <div class="code">{f['snippet']}</div>
        </div>
        """

    html_content += """
    </div>
</body>
</html>"""

    with open(filepath, "w", encoding="utf-8") as f:
        f.write(html_content)
    print(f"\n{GREEN}[+] Reporte HTML guardado en: {filepath}{RESET}")
