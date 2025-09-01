from scapy.all import IP, ICMP, send

# --- Función Cifrado César ---
def cifrado_cesar(texto, desplazamiento):
    resultado = ""
    for caracter in texto:
        if 'a' <= caracter <= 'z':
            resultado += chr((ord(caracter) - ord('a') + desplazamiento) % 26 + ord('a'))
        elif 'A' <= caracter <= 'Z':
            resultado += chr((ord(caracter) - ord('A') + desplazamiento) % 26 + ord('A'))
        else:
            resultado += caracter
    return resultado

# --- Entrada del usuario ---
texto = input("Ingrese el texto a cifrar: ")
desplazamiento = int(input("Ingrese el número de desplazamientos: "))
destino = input("Ingrese la IP de destino: ")

# --- Cifrar el texto ---
texto_cifrado = cifrado_cesar(texto, desplazamiento)
print(f"\nTexto cifrado: {texto_cifrado}")

# --- Enviar un carácter por paquete ICMP ---
for caracter in texto_cifrado:
    paquete = IP(dst=destino) / ICMP(type=8) / caracter
    send(paquete, verbose=False)
    print(f"Enviado carácter '{caracter}' a {destino}")

print("\nTodos los caracteres fueron enviados.")
