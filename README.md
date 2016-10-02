## Kalitorify v1.4.0

### Transparent proxy trough Tor for Kali Linux

 
### Instructions 

#### 1 - Update system and install tor
```bash
sudo apt-get update && sudo apt-get upgrade -y
sudo apt-get dist-upgrade -y
sudo apt-get install -y tor
```

#### 2 - Modify /etc/tor/torrc file, add the follows:
```
VirtualAddrNetworkIPv4 10.192.0.0/10
AutomapHostsOnResolve 1
TransPort 9040
SocksPort 9050
DNSPort 53
RunAsDaemon 1
```

#### 2 - Chmod and run the program as a root
```bash
chmod +x kalitorify.sh

./kalitorify.sh --start 
```
 
#### 3 - Use help argument or run the program without arguments for help menu'
```bash
./kalitorify.sh --help
```



#### Note:
Kalitorify is KISS version of Parrot AnonSurf Module, developed by "Pirates' Crew" of FrozenBox - https://github.com/parrotsec/anonsurf

For informations about transparent proxy connections please read the official Tor Project documentation: https://trac.torproject.org/projects/tor/wiki/doc/TransparentProxy

Added the option for generate new Tor Entry Guards, this is usually something to avoid unless you know what you are doing, for more information please read here: 

https://www.whonix.org/wiki/Tor#Non-Persistent_Entry_Guards 

https://forums.whonix.org/t/persistent-tor-entry-guard-relays-can-make-you-trackable-across-different-physical-locations/2090
