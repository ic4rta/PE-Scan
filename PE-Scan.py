import time
from pefile import PE
import os
import sys

banner = '''
██████  ███████       ███████  ██████  █████  ███    ██ 
██   ██ ██            ██      ██      ██   ██ ████   ██ 
██████  █████   █████ ███████ ██      ███████ ██ ██  ██ 
██      ██                 ██ ██      ██   ██ ██  ██ ██ 
██      ███████       ███████  ██████ ██   ██ ██   ████                                          
'''

class Colores: 
    verde = '\033[32m'
    blanco = '\033[37m'
    brillo = '\033[1m'
    rojo = '\033[31m'
    amarillo = '\033[33m'

print(Colores.brillo)
if len(sys.argv) != 2:
    print(Colores.amarillo + "Uso: python3 PE-Scan <ruta el PE>" + Colores.blanco)
    sys.exit(0)

if os.path.isfile(sys.argv[1]) == True:
    print(Colores.rojo + banner + Colores.blanco)
    print(Colores.verde + "[+] Cargando archivo\n" + Colores.blanco)
    time.sleep(2.4)
    pe = PE(sys.argv[1])
else:
	print(Colores.rojo + "[-] Error: Al parecer el archivo no existe" + Colores.blanco)

def headers():
	print(Colores.verde + "--> Firma/Signanure: " + Colores.blanco, hex(pe.NT_HEADERS.Signature))
	print(Colores.verde + "--> Magic: " + Colores.blanco, hex(pe.DOS_HEADER.e_magic))
	print(Colores.verde + "--> Image DOS Header: " + Colores.blanco)
	for i in pe.DOS_HEADER.dump():
		print("\t", i)
	print("-" * 70)

def estructuras():
	print(Colores.verde + "--> Esctrcturas de datos: " + Colores.blanco)
	for i in pe.OPTIONAL_HEADER.DATA_DIRECTORY:
		print("||t", i)
	print("-" * 70)

def dlls():
	print(Colores.verde + "--> DLLs utilizados: " + Colores.blanco)
	for i in pe.DIRECTORY_ENTRY_IMPORT:
		print("\t", i.dll.decode("utf-8"))
	print("-" * 70)

def arquitectura():
    if pe.FILE_HEADER.Machine == 0x014c:
        print(Colores.verde + "Arquitectura --> x86")
    if pe.FILE_HEADER.Machine == 0x8664:
        print(Colores.verde + "Arquitectura --> x64" + Colores.blanco)
    print("-" * 70)

def main():
    headers()
    estructuras()
    dlls()
    arquitectura()

if __name__ == "__main__":
    main()