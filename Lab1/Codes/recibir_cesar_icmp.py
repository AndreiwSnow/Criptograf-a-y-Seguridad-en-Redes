#!/usr/bin/env python3
# recibir_cesar_icmp.py
# Lee caracteres enviados en el campo data de ICMP Echo Request (uno por paquete),
# reconstruye la cadena y prueba todas las rotaciones César (0..25).
# Resalta en verde la opción con mayor puntaje según heurística en español.

import argparse
import re
import sys

try:
    from scapy.all import rdpcap, sniff, IP, ICMP
except Exception as e:
    print("Error importando scapy. Instala con: pip install scapy")
    raise

# --- Configuración de colores ANSI ---
GREEN = "\033[92m"
YELLOW = "\033[93m"
RESET = "\033[0m"

# --- Lista corta de palabras comunes en español para puntuar candidatas ---
SPANISH_COMMON_WORDS = [
    r"\bde\b", r"\bla\b", r"\bel\b", r"\by\b", r"\ben\b",
    r"\bque\b", r"\bpara\b", r"\bcon\b", r"\bpor\b", r"\buna\b",
    r"\bres\b", r"\bredes\b", r"\bseguridad\b", r"\bcriptograf", r"\bcriptografía\b"
]

def extraer_payloads_de_pcap(path_pcap):
    """Lee un pcap y devuelve la lista de bytes (payloads) de ICMP Echo Request en orden."""
    pkts = rdpcap(path_pcap)
    payload_bytes = []
    for p in pkts:
        if p.haslayer(ICMP) and p.haslayer(IP):
            # ICMP type 8 = Echo Request
            if int(p[ICMP].type) == 8:
                # p[ICMP].payload may be Raw or something; extraemos los bytes crudos
                raw = bytes(p[ICMP].payload)
                if len(raw) > 0:
                    # supondremos que cada paquete contiene exactamente 1 carácter en data
                    # si hay más de 1 byte, tomamos tal cual (ej. soporta multi-byte)
                    payload_bytes.append(raw)
    return payload_bytes

def extraer_payloads_en_vivo(timeout=None, count=None, iface=None):
    """
    Captura paquetes ICMP Echo Request en vivo y devuelve la lista de bytes payload.
    WARNING: requiere ejecutar como root y permiso para sniffing.
    """
    payload_bytes = []

    def procesar(p):
        if p.haslayer(ICMP) and p.haslayer(IP):
            if int(p[ICMP].type) == 8:
                raw = bytes(p[ICMP].payload)
                if len(raw) > 0:
                    payload_bytes.append(raw)

    # filtro BPF para ICMP echo requests
    bpf = "icmp and icmp[icmptype] == 8"
    sniff(filter=bpf, prn=procesar, timeout=timeout, count=count, iface=iface)
    return payload_bytes

def reconstruct_from_payloads(payload_bytes):
    """Concatena bytes en orden: intentaremos decodificar como latin-1 para mapear 1:1 bytes->caracter"""
    parts = []
    for b in payload_bytes:
        # b puede ser secuencia de bytes; convertimos conservando valores (latin-1)
        try:
            s = b.decode("latin-1")
        except:
            # si falla, iterar por bytes
            s = "".join(chr(x) for x in b)
        parts.append(s)
    return "".join(parts)

def caesar_shift(text, shift):
    """Aplica shift positivo (desplazar hacia la derecha). Para descifrar, usar shift negativo."""
    res = []
    for ch in text:
        if 'a' <= ch <= 'z':
            res.append(chr((ord(ch) - ord('a') + shift) % 26 + ord('a')))
        elif 'A' <= ch <= 'Z':
            res.append(chr((ord(ch) - ord('A') + shift) % 26 + ord('A')))
        else:
            res.append(ch)
    return "".join(res)

def score_spanish_candidate(candidate):
    """Cuenta coincidencias de palabras comunes (mayor = mejor). Añade pequeño bonus por vocales."""
    score = 0
    lc = candidate.lower()
    for pat in SPANISH_COMMON_WORDS:
        matches = re.findall(pat, lc)
        score += len(matches) * 10  # cada palabra común suma 10
    # bonus por porcentaje de vocales típico en español
    vowels = len(re.findall(r"[aeiouáéíóúü]", lc))
    total_letters = len(re.findall(r"[a-záéíóúüñ]", lc))
    if total_letters > 0:
        vowel_ratio = vowels / total_letters
        # ideal ratio (heurístico) ~0.4 -> acercarse suma más
        score += max(0, (0.4 - abs(0.4 - vowel_ratio)) * 5)
    return score

def generar_y_evaluar(cadena):
    """Genera todas las 26 rotaciones posibles (descifrado) y las puntúa."""
    candidates = []
    for shift in range(26):
        # Para probar una posible clave k (corrimiento usado en cifrado),
        # si texto fue cifrado con desplazamiento k (to right), entonces
        # para recuperar el original aplicamos desplazamiento -k.
        # Aquí definimos shift_decrypt = -k, pero al recorrer k 0..25
        # podemos calcular candidate = caesar_shift(cadena, -k)
        candidate = caesar_shift(cadena, -shift)
        s = score_spanish_candidate(candidate)
        candidates.append((shift, candidate, s))
    # ordenar por puntaje descendente
    candidates_sorted = sorted(candidates, key=lambda x: x[2], reverse=True)
    return candidates_sorted

def print_results(candidates_sorted):
    best_score = candidates_sorted[0][2]
    # puede haber empate; resaltamos todos los que empatan con la mejor puntuación
    bests = [c for c in candidates_sorted if abs(c[2] - best_score) < 1e-6]
    best_shifts = [c[0] for c in bests]

    print("\nTodas las opciones (shift usado en cifrado -> texto resultante):\n")
    for shift, text, score in candidates_sorted:
        prefix = f"[k={shift:2d}] "
        if shift in best_shifts:
            print(f"{GREEN}{prefix}{text}    (score={score:.2f}){RESET}")
        else:
            print(f"{prefix}{text}    (score={score:.2f})")

    print("\n" + "-"*60)
    print(f"{YELLOW}Opción(es) más probable(s) (resaltada(s) en verde). k considerado como el corrimiento original usado para cifrar.{RESET}")
    print("-"*60)
    for shift, text, score in bests:
        print(f"{GREEN}k={shift} -> {text} (score={score:.2f}){RESET}")

def main():
    parser = argparse.ArgumentParser(description="Recuperar mensaje enviado carácter-por-paquete ICMP y probar todas las rotaciones César.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--pcap", "-p", help="Archivo pcap que contiene los paquetes ICMP Echo Request (usado preferentemente).")
    group.add_argument("--live", "-l", action="store_true", help="Capturar paquetes ICMP en vivo (requiere sudo).")
    parser.add_argument("--timeout", "-t", type=int, default=10, help="Timeout para captura en vivo (segundos).")
    parser.add_argument("--count", "-c", type=int, default=0, help="Número de paquetes a capturar en vivo (0 = sin límite, usar timeout).")
    parser.add_argument("--iface", help="Interfaz para captura en vivo (opcional).")
    args = parser.parse_args()

    if args.pcap:
        print(f"Leyendo pcap: {args.pcap} ...")
        payloads = extraer_payloads_de_pcap(args.pcap)
        if not payloads:
            print("No se encontraron payloads ICMP Echo Request con datos en el pcap.")
            sys.exit(1)
    else:
        print("Capturando en vivo (Ctrl-C para detener si count=0). Requiere sudo/root.")
        payloads = extraer_payloads_en_vivo(timeout=args.timeout, count=(args.count or None), iface=args.iface)
        if not payloads:
            print("No se capturaron paquetes ICMP Echo Request con payload antes del timeout.")
            sys.exit(1)

    mensaje = reconstruct_from_payloads(payloads)
    print("\nMensaje reconstruido (raw):")
    print(repr(mensaje))
    print("\nProbando todas las rotaciones César (0..25)...")

    candidates_sorted = generar_y_evaluar(mensaje)
    print_results(candidates_sorted)

if __name__ == "__main__":
    main()
