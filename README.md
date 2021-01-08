NETWORK FREQUENCY ANALYSIS
==========================
This utility is designed to make frequency analysis of network traffic on local machine.
The utility uses Scapy library to capture traffic and then creates report about logged values in the fields of every packet.
Using this utility, you can:
- see what value in every field of PDU layer can be used by OS
- use the report as sampling values for statistical analysis and identifying patterns to match them with software/hardware parameters

Installation
------------
```
git clone https://github.com/treddis/network_frequency_analysis
```

Usage
-----
```
usage: freq_analyze_inet.py [-h] {counting}

sniffer for frequence analyze of traffic

positional arguments:
  {counting}  mode of working: counting - estimation of packets

optional arguments:
  -h, --help  show this help message and exit
```

**You must send Ctrl^C signal to program to stop capturing traffic**

Output example
--------------
Execution:
```
python freq_analyze_inet.py counting
```
**Be careful! Output on your machine may be much larger.**
You can redirect output to file to avoid data loss

Output format is field: value: frequency

Output:
```
[+] Result of working: Ethernet II
dst:
        17:37:03:2d:eb:dd : 18
        b1:4a:a0:96:1f:8a : 16
        86:f3:72:c8:4e:4c : 3
        ff:ff:ff:ff:ff:ff : 0
src:
        b1:4a:a0:96:1f:8a : 18
        17:37:03:2d:eb:dd : 16
        f4:73:52:9e:c9:2e : 4
type:
        2048 : 40

[+] Result of working: IP
options:
        () : 41
version:
        4 : 41
ihl:
        5 : 41
tos:
        0 : 41
dsf:
len:
        66 : 1
        70 : 1
        40 : 10
        79 : 4
        61 : 2
        77 : 1
        218 : 1
        201 : 4
        214 : 1
id:
        55485 : 1
        26892 : 1
        58121 : 1
        9780 : 1
        9796 : 1
        27103 : 1
        27104 : 1
        27105 : 1
        27106 : 1
        12192 : 1
flags:
        DF : 19
         : 22
frag:
        0 : 41
ttl:
        48 : 2
        128 : 18
        98 : 1
        51 : 2
        118 : 14
        1 : 4
proto:
        6 : 32
        17 : 9
chksum:
        45535 : 1
        53644 : 1
        45560 : 1
        38236 : 1
        50420 : 1
        38274 : 1
        35979 : 1
        53408 : 1
        39464 : 1
        39448 : 1
        40352 : 1
        40351 : 1
        40350 : 1
        40349 : 1
        34341 : 1
src:
        126.178.131.229 : 2
        192.168.0.10 : 17
        170.200.150.16 : 1
        8.8.8.8 : 2
        58.175.83.83 : 14
        192.168.0.4 : 5
dst:
        192.168.0.10 : 19
        126.178.131.229 : 1
        170.200.150.16 : 2
        8.8.8.8 : 2
        58.175.83.83 : 12
        239.255.255.250 : 4
        192.168.0.255 : 1

[+] Result of working: TCP
sport:
        443 : 17
        52988 : 1
        53038 : 2
        53102 : 12
dport:
        52988 : 2
        443 : 15
        53038 : 1
        53102 : 14
seq:
        379647177 : 1
        1786128300 : 1
        2555537897 : 1
        2555538075 : 1
        2555538114 : 2
ack:
        1786128300 : 1
        379647203 : 1
        2079225948 : 1
        0 : 1
        1747615299 : 1
        2555533126 : 2
        1747615816 : 4
        1747616976 : 1
dataofs:
        5 : 30
        8 : 2
reserved:
        0 : 32
flags:
        PA : 18
        A : 12
        S : 1
        SA : 1
window:
        73 : 2
        514 : 1
        511 : 2
        265 : 1
        273 : 7
        510 : 1
        509 : 2
chksum:
        14679 : 1
        9070 : 1
        33014 : 1
        8833 : 1
        26902 : 1
urgptr:
        0 : 32
options:
        () : 20
        (('MSS', 1460), ('NOP', None), ('WScale', 8), ('NOP', None), ('NOP', None), ('SAckOK', b'')) : 1
        (('MSS', 1430), ('NOP', None), ('NOP', None), ('SAckOK', b''), ('NOP', None), ('WScale', 8)) : 1
```
