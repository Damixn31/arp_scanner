```bash
   __   ____ ____    ___  ___   __   _  _ _  _ ____ ____ 
  /__\ (  _ (  _ \  / __)/ __) /__\ ( \( | \( | ___|  _ \
 /(__)\ )   /)___/  \__ ( (__ /(__)\ )  ( )  ( )__) )   /
(__)(__|_)\_|__)    (___/\___|__)(__|_)\_|_)\_|____|_)\_)

```

Herramienta en Python para escanear direcciones IP dentro dentro de una red y mostrar sus direcciones MAC junto con el fabricante del dispositivo (usando la OUI).

## 🚀 Características
- Escaneo de una IP o rango de IP usando paquetes ARP.
- Obtención de la dirección MAC de cada dispositivo.
- Identificación del fabricante mediante OUI.
- Uso sencillo desde la terminal.

## 📦 Requisitos
- Python 3.8+
- Librerías:
  - scapy
  - manuf
  - colorema
  - tabulate

## 🔧 Instalación
clonar el repositorio
```bash
git clone https://github.com/Damixn31/arp_scanner.git
cd arp_scanner
```
Instalar dependencias:
```bash
pip install -r requirements.txt
```
## 🔧 Uso
### **Ejecutar el script como `root`**
Escaneo IP especifica
```bash
python arp_scanner.py -t 192.168.0.77
```
Escaneo por rango
```bash
python arp_scanner.py -t 192.168.1.0/24
```
![](https://ibb.co/ZpN1BY1s)


