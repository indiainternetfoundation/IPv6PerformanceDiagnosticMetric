# IPv6PerformanceDiagnosticMetric
rfc8250

## Protocol Server Essentials

```bash
# $ sudo apt install build-essential linux-headers-`uname -r` -y
# $ sudo apt install linux-generic -y
$ sudo apt install make gcc-13 -y
```


## Protocol DNS Client Essentials

```bash
$ sudo pip3 install scapy click
```

```bash
$ cd client
$ sudo python3 ./dns_client.py --q NS example.org
```