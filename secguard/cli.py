import sys
import os
import argparse

from .scanner import scan_directory, scan_file
from .headers import audit_http_headers
from .reporter import (
    print_banner,
    print_secret_findings,
    print_header_audit,
    export_json,
    export_html
)

def main():
    parser = argparse.ArgumentParser(
        prog="secguard",
        description="🛡️ SecGuard CLI: Escáner DevSecOps de Secretos y Auditoría de Seguridad"
    )

    subparsers = parser.add_subparsers(dest="command", help="Comandos disponibles")

    # Comando 1: scan
    scan_parser = subparsers.add_parser("scan", help="Escanea un archivo o directorio en busca de secretos")
    scan_parser.add_argument("target", nargs="?", default=".", help="Ruta del archivo o directorio a escanear")
    scan_parser.add_argument("--json", dest="json_output", help="Ruta para exportar el reporte en JSON")
    scan_parser.add_argument("--html", dest="html_output", help="Ruta para exportar el reporte en HTML")
    scan_parser.add_argument("--fail-on-critical", action="store_true", help="Falla con código 1 si hay secretos CRÍTICOS (Ideal para CI/CD)")

    # Comando 2: audit-url
    url_parser = subparsers.add_parser("audit-url", help="Audita las cabeceras de seguridad HTTP de una URL")
    url_parser.add_argument("url", help="URL a auditar (ej. https://ejemplo.com)")
    url_parser.add_argument("--json", dest="json_output", help="Ruta para exportar el reporte en JSON")

    args = parser.parse_args()

    print_banner()

    if args.command == "scan":
        target = os.path.abspath(args.target)
        print(f"[*] Iniciando escaneo de seguridad en: {target}...")

        if os.path.isfile(target):
            findings = scan_file(target)
        else:
            findings = scan_directory(target)

        print_secret_findings(findings)

        if args.json_output:
            export_json(findings, args.json_output)
        if args.html_output:
            export_html(findings, {}, args.html_output)

        if args.fail_on_critical:
            has_critical = any(f["severity"] == "CRITICAL" for f in findings)
            if has_critical:
                print("\n[!] ALERTA CI/CD: Se encontraron secretos CRÍTICOS. Bloqueando pipeline.\n")
                sys.exit(1)

    elif args.command == "audit-url":
        print(f"[*] Auditando cabeceras de seguridad HTTP para: {args.url}...")
        audit = audit_http_headers(args.url)
        print_header_audit(audit)

        if args.json_output:
            export_json(audit, args.json_output)

    else:
        parser.print_help()

if __name__ == "__main__":
    main()
