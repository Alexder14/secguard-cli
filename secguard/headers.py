import urllib.request
import urllib.error
import ssl
from typing import Dict, Any

SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "severity": "HIGH",
        "description": "Fuerza el uso de HTTPS y previene ataques de Man-in-the-Middle (SSL Stripping)."
    },
    "Content-Security-Policy": {
        "severity": "HIGH",
        "description": "Previene ataques de Cross-Site Scripting (XSS) e inyeccion de datos al restringir fuentes de scripts."
    },
    "X-Frame-Options": {
        "severity": "MEDIUM",
        "description": "Protege a los usuarios contra ataques de Clickjacking impidiendo que la web sea embebida en iframes."
    },
    "X-Content-Type-Options": {
        "severity": "MEDIUM",
        "description": "Impide que el navegador interprete archivos con tipos MIME diferentes al declarado (MIME-Sniffing)."
    },
    "Referrer-Policy": {
        "severity": "LOW",
        "description": "Controla cuánta información de referencia (URLs previas) se envia en las cabeceras HTTP."
    },
    "Permissions-Policy": {
        "severity": "LOW",
        "description": "Restringe el acceso a características sensibles del navegador (cámara, micrófono, geolocalización)."
    }
}

def audit_http_headers(target_url: str) -> Dict[str, Any]:
    """
    Realiza una peticion HTTP a la URL objetivo y audita las cabeceras de seguridad.
    """
    if not target_url.startswith("http://") and not target_url.startswith("https://"):
        target_url = "https://" + target_url

    results = {
        "url": target_url,
        "status_code": None,
        "passed": [],
        "missing": [],
        "score": 0
    }

    # Contexto SSL seguro
    ctx = ssl.create_default_context()

    try:
        req = urllib.request.Request(
            target_url,
            headers={"User-Agent": "SecGuard-Security-Auditor/1.0"}
        )
        with urllib.request.urlopen(req, timeout=5, context=ctx) as response:
            results["status_code"] = response.getcode()
            headers = {k.title(): v for k, v in response.headers.items()}

            for header, info in SECURITY_HEADERS.items():
                if header.title() in headers:
                    results["passed"].append({
                        "header": header,
                        "value": headers[header.title()]
                    })
                else:
                    results["missing"].append({
                        "header": header,
                        "severity": info["severity"],
                        "description": info["description"]
                    })

    except urllib.error.HTTPError as e:
        results["status_code"] = e.code
    except Exception as e:
        results["error"] = str(e)
        return results

    # Calcular puntaje (0 a 100)
    total_headers = len(SECURITY_HEADERS)
    passed_count = len(results["passed"])
    results["score"] = int((passed_count / total_headers) * 100)

    return results
