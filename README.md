# Mini-IDS — Analizador de Tráfico de Red Local

Herramienta de ciberseguridad desarrollada en Python que analiza archivos de captura de red (.pcap) y detecta credenciales transmitidas en texto plano en protocolos HTTP y FTP.

**Autor:** Castro Ramos Mateo Rodolfo  
**Equipo:** Blue Team 🔵  
**Curso:** Proyecto Individual de Ciberseguridad  

---

## Descripción

Este script simula el trabajo de un analista de SOC (Security Operations Center), inspeccionando tráfico de red en busca de contraseñas y usuarios expuestos sin cifrado.

---

## Requisitos

- Python 3.x
- Librería Scapy

---

## Instalación

```bash
py -m pip install scapy
```

---

## Uso

```bash
py detector.py archivo.pcap
```

**Ejemplo:**
```bash
py detector.py http.cap
```

---

## Ejemplo de salida
Analizando el archivo de red: ftp_credenciales.pcap...
[!] Trafico inseguro detectado (FTP)
[!] IP Origen: 192.168.18.105 -> IP Destino: 172.16.0.10
[!] CREDENCIALES EXPUESTAS: Usuario: mateo_castro | Password: seg123cibernet
[RESUMEN] Se encontraron 1 paquete(s) sospechoso(s).

## Herramientas utilizadas

- Python 3.14
- Scapy 2.7.0
- Wireshark (verificación visual)
- Kali Linux (entorno de pruebas)
