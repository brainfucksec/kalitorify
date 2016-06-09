## Kalitorify v1.2

### Bash script for transparent proxy through Tor
### Operative System: Kali Linux 

 
### Instructions 

#### 1 - Add these lines at /etc/tor/torrc
```
VirtualAddrNetworkIPv4 10.192.0.0/10
AutomapHostsOnResolve 1
TransPort 9040
SocksPort 9050
DNSPort 53
```

#### 2 - Chmod and run the program as a root
```bash
chmod +x kalitorify.sh

./kalitorify.sh start 
```
 
#### 3 - Use help argument or run the program without arguments for help menu'
```bash
./kalitorify.sh help
```



#### Note:
Kalitorify is KISS version of Parrot AnonSurf Module, developed by "Pirates' Crew" of FrozenBox - https://github.com/parrotsec/anonsurf
For informations about transparent proxy connections please read the official documentation: https://trac.torproject.org/projects/tor/wiki/doc/TransparentProxy
