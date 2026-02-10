# DHCP-Spoofing-Attack
 Network Security Tool  
![Python](https://img.shields.io/badge/Python-3.7%2B-blue)

Herramienta automatizada para demostración de ataques DHCP Spoofing en entornos de laboratorio controlados

## 📋 Tabla de Contenidos
- [Objetivo del Script](#-objetivo)
- [Características Principales](#características)
- [Capturas de Pantalla](#-capturas-de-pantalla)
- [Topología de Red](#-topología-de-red)
- [Parámetros de Configuración](#parámetros-usados)
- [Uso y Ejemplos](#uso)
- [Medidas de Mitigación](#-medidas-de-mitigación)

## 🎯 Objetivo
El objetivo de este script es simular, en un entorno de laboratorio controlado, un ataque de **DHCP Spoofing** para interceptar peticiones DHCP legítimas y asignar configuraciones de red maliciosas a los clientes, posicionando al atacante como **Man-in-the-Middle**, con fines exclusivamente educativos y de análisis de seguridad.

## 🖼️ Capturas de Pantalla
Las capturas incluidas en este repositorio documentan el proceso completo del laboratorio:

- **Topología de red del escenario**
  
  ![Topología](screenshots/topologia.png)

- **Ejecución del ataque DHCP Spoofing**
  
  ![Ataque DHCP](screenshots/ataque_dhcp.png)

- **Servidor DHCP malicioso en ejecución**
  
  ![DHCP Rogue](screenshots/dhcp_rogue.png)

- **Tráfico DHCP interceptado**
  
  ![Wireshark](screenshots/wireshark_capture.png)

- **Cliente recibiendo configuración maliciosa**
  
  ![Cliente](screenshots/cliente_infectado.png)

## DHCP Spoofing - Rogue DHCP Server Attack
Script de Python que utiliza Scapy para realizar ataques de DHCP Spoofing mediante un servidor DHCP malicioso que intercepta y responde a solicitudes DHCP antes que el servidor legítimo.

### Requisitos
```bash
pip install scapy
```

### Uso
```bash
git clone https://github.com/tuusuario/DHCP-Spoofing.git
cd DHCP-Spoofing
chmod +x dhcp_spoofing.py
sudo python3 dhcp_spoofing.py
```

## Características
🎯 **DHCP Spoofing**: Servidor DHCP malicioso que intercepta peticiones  
🔄 **Asignación automática**: Asigna IPs falsas con gateway y DNS del atacante  
⚡ **Respuesta rápida**: Responde antes que el servidor DHCP legítimo  
✅ **IP Forwarding**: Habilita reenvío de paquetes automáticamente  
✅ **Monitoreo en tiempo real**: Muestra cada solicitud interceptada  
📊 **Logging detallado**: Registra todas las asignaciones DHCP  
🔧 **Configuración simple**: Variables fáciles de modificar

## 🔧 Configuración
Edita las siguientes variables según tu red:

```python
interface = "eth0"              # Interfaz de red
gateway_falso = "192.168.1.50"  # IP del atacante (gateway falso)
dns_falso = "192.168.1.50"      # DNS malicioso (IP del atacante)
pool_inicio = "192.168.1.100"   # Inicio del rango de IPs
pool_fin = "192.168.1.200"      # Fin del rango de IPs
lease_time = 3600               # Tiempo de concesión en segundos
```

## Notas
⚠️ **Advertencia**: Este script requiere privilegios de root para escuchar en el puerto 67 (DHCP).

⚠️ **Uso responsable**: Utiliza este script únicamente en entornos de prueba autorizados y con fines educativos.

⚠️ **Legal**: El uso no autorizado de este script puede ser ilegal. Asegúrate de tener permiso explícito.

## Cómo funciona
1. **Escucha peticiones DHCP**: Captura paquetes DHCP DISCOVER en la red
2. **Respuesta maliciosa**: Envía DHCP OFFER con configuración falsa
3. **Asignación de IP**: Proporciona IP, gateway y DNS controlados por el atacante
4. **Man-in-the-Middle**: Todo el tráfico del cliente pasa por el atacante
5. **Interceptación**: Permite capturar y manipular el tráfico de la víctima

## Detección
Este ataque puede ser detectado mediante:

- Monitoreo de múltiples servidores DHCP en la red
- DHCP Snooping en switches
- Detección de servidores DHCP no autorizados
- Análisis de logs de asignaciones DHCP
- IDS/IPS configurados

## Autor
**ALEXIS JAVIER CRUZ MINYETE**

---

## Reporte de Seguridad
Durante la ejecución del laboratorio se identificó que la red evaluada carece de mecanismos básicos de protección DHCP, lo que permitió la ejecución exitosa de un ataque de DHCP Spoofing. La ausencia de DHCP Snooping, validación de servidores autorizados y monitoreo de asignaciones representa un riesgo crítico para la integridad de la configuración de red.

El impacto principal del ataque es la capacidad de redirigir todo el tráfico de los clientes a través del atacante, permitiendo ataques Man-in-the-Middle, captura de credenciales y suplantación de servicios. En un entorno real, este tipo de vulnerabilidad podría facilitar el acceso no autorizado a información sensible y comprometer la seguridad de toda la red.

La implementación de controles como DHCP Snooping, Port Security, validación de servidores DHCP autorizados y monitoreo activo permitiría reducir considerablemente la superficie de ataque.

---

## 🌐 Topología de Red

### Diagrama de Topología

```
                            Cloud My House
                                  |
                   +--------------+---------------+
                   |                              |
                e1/0                            e0/1
          Kali Linux Atacante                 SW-Cloud
                e0/0                            e0/0
                   |                              |
                e1/0                            e0/1
                 SW-1 ----------PNET----------- R-SD DHCP
               (ARISTA)         (ISP)           e0/0
                e0/3 \                            |
                      \                         e1/0
                    e0/0                          |
                     SW-2                       SW-3
                   (ARISTA)   e0/2    e0/4    (ARISTA)
                    e0/2 \     |       |       / e1/2
                          \  e0/0    e0/0     /  e1/1
                           \  |       |      /   e1/3
                            USER    USER    USER
                                   (eth0)
```

**Elementos de la red:**
- **Cloud My House**: Conexión a Internet
- **Kali Linux Atacante**: Máquina atacante con servidor DHCP malicioso
- **SW-Cloud**: Switch de conexión a cloud
- **SW-1 (ARISTA)**: Switch principal izquierda
- **SW-2 (ARISTA)**: Switch segmento inferior izquierdo
- **SW-3 (ARISTA)**: Switch segmento derecho
- **R-SD DHCP**: Router con servidor DHCP legítimo
- **PNET**: Proveedor de Internet (ISP)
- **USER**: Clientes víctimas (3 dispositivos)

### Tabla de Interfaces

#### Kali Linux Atacante (DHCP Rogue Server)
| Interfaz | Dirección IP | Máscara | Descripción |
|----------|--------------|---------|-------------|
| e0 | DHCP (Falso) | /24 | Interfaz principal |
| e1 | Acceso Cloud | — | Conexión a Internet |

#### R-SD DHCP (Router con DHCP Legítimo)
| Interfaz | Dirección IP | Máscara | Descripción |
|----------|--------------|---------|-------------|
| e0/0 | IP Interna | /24 | Red interna |
| e0/1 | Conexión SW-Cloud | — | Uplink |
| e1/0 | Conexión SW-3 | — | Distribución |

#### SW-1 (ARISTA - Switch Principal)
| Interface | Tipo | Modo | Descripción |
|-----------|------|------|-------------|
| e0/0 | Ethernet | Access | Conexión Kali Atacante |
| e1/0 | Ethernet | Trunk | Uplink a Cloud |
| e0/3 | Ethernet | Access | Conexión SW-2 |

#### SW-2 (ARISTA - Switch Segmento Inferior)
| Interface | Tipo | Modo | Descripción |
|-----------|------|------|-------------|
| e0/0 | Ethernet | Trunk | Uplink SW-1 |
| e0/2 | Ethernet | Access | Usuario 1 |

#### SW-3 (ARISTA - Switch Segmento Derecho)
| Interface | Tipo | Modo | Descripción |
|-----------|------|------|-------------|
| e0/0 | Ethernet | Trunk | Uplink SW-Cloud |
| e0/2 | Ethernet | Trunk | Conexión PNET |
| e0/4 | Ethernet | Access | Usuario 2 |
| e1/0 | Ethernet | Trunk | Uplink R-SD |
| e1/1 | Ethernet | Access | Usuario 3 |
| e1/2 | Ethernet | Access | Usuario 3 (secundaria) |
| e1/3 | Ethernet | Access | Usuario 3 (terciaria) |

#### SW-Cloud (Switch de Acceso Cloud)
| Interface | Tipo | Modo | Descripción |
|-----------|------|------|-------------|
| e0/0 | Ethernet | Trunk | Downlink SW-3 |
| e0/1 | Ethernet | Trunk | Uplink Cloud My House |

#### Dispositivos Finales (USERS)
| Dispositivo | Interfaz | Configuración | Switch Conectado |
|-------------|----------|---------------|------------------|
| User 1 | eth0 | DHCP | SW-2 (e0/2) |
| User 2 | eth0 | DHCP | SW-3 (e0/4) |
| User 3 | eth0 | DHCP | SW-3 (e1/1, e1/2, e1/3) |

---

## Parámetros Usados

### Configuración de Red
| Parámetro | Valor | Descripción |
|-----------|-------|-------------|
| Red Clientes | 192.168.1.0/24 | VLAN 10 - Segmento objetivo |
| Red Servidores | 192.168.2.0/24 | VLAN 20 - Segmento administrativo |
| Enlace P2P | 10.0.0.0/30 | Conexión entre R1 y R2 |
| VLAN Nativa | 888 | VLAN para tráfico no etiquetado |

### Parámetros de Ataque

#### DHCP Spoofing
| Parámetro | Valor | Descripción |
|-----------|-------|-------------|
| Interfaz | eth0 | Interfaz de red del atacante |
| Gateway Falso | 192.168.1.50 | IP del atacante (gateway malicioso) |
| DNS Falso | 192.168.1.50 | Servidor DNS malicioso |
| Pool Inicio | 192.168.1.100 | Inicio del rango de IPs a asignar |
| Pool Fin | 192.168.1.200 | Fin del rango de IPs a asignar |
| Lease Time | 3600 segundos | Tiempo de concesión DHCP |
| Puerto DHCP | 67/68 | Puertos estándar DHCP |
| Protocolo | UDP | Protocolo de transporte |

---

### Dispositivos de Red Compatibles

#### Switches
| Fabricante | Modelos Soportados | Versión OS | Estado |
|------------|-------------------|------------|--------|
| **Arista** | **7050/7280/7500** | **EOS 4.x+** | **✅ Completo** |
| Cisco | Catalyst 2960/3560 | IOS 15.0+ | ✅ Completo |
| HP | ProCurve 2530/2920 | KB.16.x | ✅ Completo |

#### Routers
| Fabricante | Modelos Soportados | Versión OS | Estado |
|------------|-------------------|------------|--------|
| Cisco | ISR 1900/2900/4000 | IOS 15.0+ | ✅ Completo |
| Arista | 7500R/7280R | EOS 4.x+ | ✅ Completo |

### Conectividad Requerida
- ✅ Acceso SSH (puerto 22) a dispositivos de red
- ✅ Acceso físico a la red objetivo
- ⚠️ Acceso Telnet (puerto 23) - **NO RECOMENDADO** Solo para pruebas

---

## 🛡️ Medidas de Mitigación

### Análisis de Riesgos y Controles - DHCP Spoofing

| ID | Riesgo Identificado | Severidad | Probabilidad | Impacto | Medida de Mitigación Implementada |
|----|---------------------|-----------|--------------|---------|-----------------------------------|
| R-001 | DHCP Spoofing - Servidor DHCP malicioso | **CRÍTICO** | Alta | Crítico | • Implementación de **DHCP Snooping**<br>• Configurar puertos trust solo en servidores legítimos<br>• Rate limiting de paquetes DHCP<br>• Binding database para validación IP-MAC<br>• Alertas de servidores DHCP no autorizados |
| R-002 | Asignación de gateway falso | **CRÍTICO** | Alta | Crítico | • DHCP Snooping con validación de gateway<br>• Configuración estática en dispositivos críticos<br>• Monitoreo de tablas de ruteo<br>• Validación de gateway mediante ICMP |
| R-003 | Man-in-the-Middle (MitM) | **CRÍTICO** | Alta | Crítico | • Uso obligatorio de HTTPS/TLS<br>• Implementación de VPN para tráfico sensible<br>• DAI (Dynamic ARP Inspection)<br>• Detección de ataques MitM con IDS/IPS |
| R-004 | DNS Spoofing via DHCP | **ALTO** | Alta | Alto | • Configuración de DNS confiables<br>• DNSSEC para validación<br>• Servidores DNS corporativos protegidos<br>• Monitoreo de consultas DNS anómalas |
| R-005 | Agotamiento de pool DHCP | **ALTO** | Media | Alto | • Rate limiting de solicitudes DHCP<br>• Monitoreo de uso de pool<br>• Alertas de uso anormal de IPs<br>• Port Security en switches |
| R-006 | Acceso no autorizado a red | **ALTO** | Alta | Alto | • Autenticación 802.1X<br>• NAC (Network Access Control)<br>• Port Security con sticky MAC<br>• Autenticación RADIUS/TACACS+ |
| R-007 | Falta de detección de ataques | **ALTO** | Alta | Alto | • IDS/IPS (Snort, Suricata)<br>• SIEM para correlación de eventos<br>• Monitoreo de logs DHCP<br>• Alertas en tiempo real |
| R-008 | Propagación del ataque | **MEDIO** | Media | Alto | • Segmentación de VLANs<br>• ACLs entre segmentos<br>• Private VLANs<br>• Firewall interno |

---

### Controles Específicos - DHCP Spoofing

#### 1. DHCP Snooping
**Validación de mensajes DHCP y creación de binding database confiable**

```cisco
! Habilitar DHCP Snooping globalmente
Switch(config)# ip dhcp snooping

! Activar en VLANs específicas
Switch(config)# ip dhcp snooping vlan 10,20

! Configurar puerto trust (servidor DHCP legítimo)
Switch(config)# interface GigabitEthernet0/24
Switch(config-if)# ip dhcp snooping trust

! Configurar puertos untrust (clientes)
Switch(config)# interface range GigabitEthernet0/1-23
Switch(config-if-range)# ip dhcp snooping limit rate 10

! Habilitar Option-82
Switch(config)# ip dhcp snooping information option
```

#### 2. IP Source Guard
**Previene spoofing de direcciones IP basándose en DHCP Snooping**

```cisco
Switch(config)# interface range GigabitEthernet0/1-23
Switch(config-if-range)# ip verify source
Switch(config-if-range)# ip verify source port-security
```

#### 3. Port Security
**Limita direcciones MAC permitidas por puerto**

```cisco
Switch(config)# interface range GigabitEthernet0/1-23
Switch(config-if-range)# switchport port-security
Switch(config-if-range)# switchport port-security maximum 2
Switch(config-if-range)# switchport port-security violation restrict
Switch(config-if-range)# switchport port-security mac-address sticky
```

#### 4. Dynamic ARP Inspection (DAI)
**Previene envenenamiento ARP relacionado con DHCP Spoofing**

```cisco
Switch(config)# ip arp inspection vlan 10,20
Switch(config)# ip arp inspection validate src-mac dst-mac ip

! Puerto trust para gateway
Switch(config)# interface GigabitEthernet0/24
Switch(config-if)# ip arp inspection trust
```

#### 5. Autenticación 802.1X
**Control de acceso a nivel de puerto**

```cisco
! Habilitar AAA
Switch(config)# aaa new-model
Switch(config)# aaa authentication dot1x default group radius

! Configurar RADIUS
Switch(config)# radius server RADIUS-SERVER
Switch(config-radius-server)# address ipv4 192.168.1.10 auth-port 1812
Switch(config-radius-server)# key SecureKey123

! Habilitar 802.1X en puertos
Switch(config)# interface range GigabitEthernet0/1-23
Switch(config-if-range)# authentication port-control auto
Switch(config-if-range)# dot1x pae authenticator
```

---

### Monitoreo y Detección

| Herramienta | Propósito | Implementación |
|-------------|-----------|----------------|
| Wireshark/tcpdump | Análisis de tráfico DHCP | Captura de paquetes DHCP sospechosos |
| dhcp_probe | Detección DHCP Rogue | Identifica servidores DHCP no autorizados |
| Snort/Suricata | IDS/IPS | Reglas para detectar DHCP Spoofing |
| Syslog | Logging centralizado | Logs de DHCP Snooping violations |
| SIEM | Correlación de eventos | Alertas de múltiples servidores DHCP |
| Nagios/Zabbix | Monitoreo de red | Alertas de cambios en configuración DHCP |

---

### Plan de Respuesta a Incidentes

#### FASE 1: DETECCIÓN (0-15 minutos)
1. Sistema detecta servidor DHCP no autorizado
2. Alerta automática al equipo de seguridad
3. Revisión de logs DHCP Snooping
4. Identificación del puerto/dispositivo malicioso

#### FASE 2: CONTENCIÓN (15-30 minutos)
1. **Shutdown inmediato** del puerto afectado
2. Aislar segmento de red comprometido
3. Preservar evidencia (capturas de tráfico)
4. Revisar clientes que recibieron configuración falsa

#### FASE 3: ERRADICACIÓN (30-60 minutos)
1. Identificar y eliminar servidor DHCP malicioso
2. Liberar IPs asignadas incorrectamente
3. Forzar renovación DHCP en clientes afectados
4. Verificar configuraciones de red

#### FASE 4: RECUPERACIÓN (1-2 horas)
1. Restaurar configuración DHCP correcta en clientes
2. Verificar conectividad de todos los dispositivos
3. Confirmar que gateway y DNS son correctos
4. Monitoreo intensivo durante 24-48 horas

#### FASE 5: LECCIONES APRENDIDAS (1 semana)
1. Documentar el incidente completo
2. Revisar efectividad de controles DHCP Snooping
3. Actualizar políticas de seguridad
4. Capacitación al equipo técnico

---

**⚠️ Disclaimer de Responsabilidad**

Este proyecto es **exclusivamente para fines educativos y de investigación** en entornos de laboratorio controlados. El uso de estas técnicas en redes sin autorización explícita es **ilegal** y puede resultar en consecuencias legales graves.

El autor no se hace responsable del mal uso de esta herramienta. Al utilizar este código, aceptas usar este conocimiento de manera ética y legal.

---

**📚 Referencias**
- RFC 2131 - Dynamic Host Configuration Protocol
- RFC 3046 - DHCP Relay Agent Information Option
- Cisco DHCP Snooping Configuration Guide
- NIST Cybersecurity Framework

**📧 Contacto**
Para reportes de seguridad o consultas: [Tu Email]

---

*Última actualización: Febrero 2026*
