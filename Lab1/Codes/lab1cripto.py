# Cifrado César en Python 3 con entrada por consola

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

# Pedir datos al usuario
texto = input("Ingrese el texto a cifrar: ")
desplazamiento = int(input("Ingrese el número de desplazamientos: "))

# Cifrar
texto_cifrado = cifrado_cesar(texto, desplazamiento)

# Mostrar resultado
print("\nTexto original :", texto)
print("Desplazamiento :", desplazamiento)
print("Texto cifrado  :", texto_cifrado)

