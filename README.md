# Metasploitable 2 — Puerto 22 (SSH)

Repositorio de análisis de seguridad sobre el servicio SSH de Metasploitable 2, una máquina virtual vulnerable diseñada para practicar técnicas de pentesting en entornos controlados.

---

## ¿Qué es Metasploitable 2?

Metasploitable 2 es una máquina virtual Linux intencionalmente vulnerable, desarrollada por Rapid7. Está pensada como objetivo de práctica para profesionales y estudiantes de ciberseguridad que quieren aprender a identificar y explotar vulnerabilidades en un entorno seguro y legal.

---

## Sobre este repositorio

Este repositorio documenta la explotación del puerto 22 (SSH) de Metasploitable 2. Se abordan dos enfoques distintos para llegar al mismo resultado, lo que permite comparar el nivel de control y automatización de cada método.

| | Descripción |
|---|---|
| **Servicio analizado** | SSH — OpenSSH 4.7p1 Debian 8ubuntu1 |
| **Puerto** | 22/tcp |
| **Vulnerabilidad** | Username Enumeration (OpenSSH 2.3 < 7.7) |
| **Métodos documentados** | Explotación manual + Metasploit Framework |

---

## Contenido

| Archivo | Descripción |
|---|---|
| `README.md` | Este archivo. Información general del proyecto. |
| `resolucion-port-22.md` | Writeup detallado con los dos métodos de explotación. |

---

## Herramientas utilizadas

- `nmap` — Descubrimiento de red y enumeración de servicios
- `searchsploit` — Búsqueda de exploits conocidos
- `ssh-enum.py` — Enumeración de usuarios válidos vía timing attack
- `medusa` — Ataque de fuerza bruta sobre SSH
- `john` — Crackeo de hashes extraídos del sistema
- `msfconsole` — Metasploit Framework (método alternativo)

---

## Advertencia

Este material es exclusivamente para uso en entornos de laboratorio controlados. Aplicar estas técnicas sobre sistemas sin autorización explícita es ilegal.
