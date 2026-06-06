from scapy.all import rdpcap, TCP, Raw
import sys

PALABRAS_CLAVE = ["user", "pass", "username", "password", "login", "pwd"]

def analizar_pcap(archivo):
    print(f"\nAnalizando el archivo de red: {archivo}...")
    print("-" * 50)

    try:
        paquetes = rdpcap(archivo)
    except FileNotFoundError:
        print(f"[ERROR] No se encontró el archivo: {archivo}")
        sys.exit(1)

    encontrados = 0

    for paquete in paquetes:
        if paquete.haslayer(TCP) and paquete.haslayer(Raw):
            contenido = paquete[Raw].load.decode(errors="ignore").lower()
            if any(palabra in contenido for palabra in PALABRAS_CLAVE):
                ip_origen  = paquete["IP"].src if paquete.haslayer("IP") else "Desconocida"
                ip_destino = paquete["IP"].dst if paquete.haslayer("IP") else "Desconocida"
                puerto_dst = paquete[TCP].dport
                if puerto_dst == 80 or puerto_dst == 8080:
                    protocolo = "HTTP"
                elif puerto_dst == 21:
                    protocolo = "FTP"
                else:
                    protocolo = f"TCP/{puerto_dst}"
                print(f"\n[!] Tráfico inseguro detectado ({protocolo})")
                print(f"[!] IP Origen: {ip_origen} -> IP Destino: {ip_destino}")
                print(f"[!] CREDENCIALES EXPUESTAS: {contenido.strip()[:120]}")
                encontrados += 1

    print("\n" + "-" * 50)
    if encontrados == 0:
        print("[OK] No se detectaron credenciales en texto plano.")
    else:
        print(f"[RESUMEN] Se encontraron {encontrados} paquete(s) sospechoso(s).")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Uso: py detector.py archivo.pcap")
        sys.exit(1)
    analizar_pcap(sys.argv[1])