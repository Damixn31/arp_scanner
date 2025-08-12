#!/usr/bin/env python3

import scapy.all as scapy
import argparse
import sys 
import ipaddress
from tabulate import tabulate
from colorama import init, Fore
from manuf import manuf

init(autoreset=True)

def check_root():
    if not hasattr(sys, "real_prefix") and sys.platform != "win32":
        import os 
        if os.geteuid() != 0:
            print(Fore.RED +"\n[!] Este script debe ejecutarse como root.")
            sys.exit(1)

def get_arguments():
    parser = argparse.ArgumentParser(description="ARP Scanner - Escanea IPs y muestra la MAC")
    parser.add_argument("-t", "--target", required=True, dest="target", help="IP o rango de IP para escanear (ej: 192.168.1.1/24)" )
    args = parser.parse_args()
    return args.target

    try:
        ipaddress.ip_network(args.target)
    except ValueError:
        print(Fore.RED + "\n[!] Error: El objetivo debe ser una IP o un rango válido, por ejemplo 192.168.1.1/24")
        sys.exit(1)
    return args.target
                

def scan(ip):
    p = manuf.MacParser()
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request # esta barra es un operador de composicion que nos permite unir capas o protocolos de paquetes
    answered_list = scapy.srp(arp_request_broadcast, timeout=2, verbose=False)[0]

    clients = []
    for sent, received in answered_list:
        vendor = p.get_manuf(received.hwsrc) or "Desconocido"
        clients.append({'IP': received.psrc, 'MAC': received.hwsrc, 'Fabricante': vendor})
    return clients

def main():
    check_root()
    target_ip = get_arguments()
    clients = scan(target_ip)

    if clients:
        print(Fore.MAGENTA + "\n[*] Dispositivo encontrado\n")
        print(Fore.WHITE + "\tIP\t\tMAC\t\t\tFAB")
        for client in clients:
            print(Fore.GREEN + client['IP'] + "\t" + Fore.YELLOW + client['MAC'] + "\t" + " " + Fore.CYAN + client['Fabricante'])
    else:
        print(Fore.RED + "\n[!] No se encontraron dispositivos activos.")

if __name__ == '__main__':
    main()
