## Kalitorify v1.6.0

### Transparent proxy trough Tor for Kali Linux OS

 
### Configuration

#### Update system and install tor:
```bash
sudo apt update && sudo apt full-upgrade -y
sudo apt install -y tor
```

#### Modify /etc/tor/torrc file, add the follows:
```
VirtualAddrNetworkIPv4 10.192.0.0/10
AutomapHostsOnResolve 1
TransPort 9040
SocksPort 9050
DNSPort 5353
```



### Start program

#### Use help argument or run the program without arguments for help menu':
```bash
./kalitorify.sh --help
...

└───╼ ./kalitorify --argument

Arguments:

--help      show this help message and exit
--start     start transparent proxy for tor
--stop      reset iptables and return to clear navigation
--status    check status of program and services
--restart   restart tor service and change IP
--version   display program and tor version then exit

```


#### Start Transparent Proxy with --start argument
```bash
./kalitorify.sh --start
...

:: Starting Transparent Proxy

```


 

#### NOTES:

Kalitorify is KISS version of Parrot AnonSurf Module, developed by "Pirates' Crew" of FrozenBox - https://github.com/parrotsec/anonsurf

Please note that this program isn't a final solution for a setup of anonimity at 100%, for more information about Tor configurations please read these docs:

Tor Project wiki about Transparent Proxy: https://trac.torproject.org/projects/tor/wiki/doc/TransparentProxy

Whonix wiki about Tor Entry Guards:

https://www.whonix.org/wiki/<Tor id="Non-Persistent_Entry_Guards"></Tor>

https://forums.whonix.org/t/persistent-tor-entry-guard-relays-can-make-you-trackable-across-different-physical-locations/2090


Whonix Do Not recommendations: https://www.whonix.org/wiki/DoNot
