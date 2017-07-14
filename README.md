## Kalitorify v1.8.0

### Transparent proxy through Tor for Kali Linux OS

 


### Install

#### Update system and run install.sh:
```bash
sudo apt-get update && sudo apt-get dist-upgrade -y

git clone https://github.com/brainfucksec/archtorify

cd kalitorify/
chmod +x install.sh
./install.sh
```




### Start program

#### Use help argument or run the program without arguments for help menu':
```bash
./kalitorify.sh --help
...

└───╼ ./kalitorify --argument

Arguments available:

--help      show this help message and exit
--start     start transparent proxy for tor
--stop      reset iptables and return to clear navigation
--status    check status of program and services
--checkip   check only public IP
--restart   restart tor service and change IP
--version   display program and tor version then exit

```


#### Start Transparent Proxy with --start argument
```bash
./kalitorify.sh --start
...

:: Starting Transparent Proxy

```


 

#### [ NOTES ]

##### Kalitorify is KISS version of Parrot AnonSurf Module, developed by "Pirates' Crew" of FrozenBox - https://github.com/parrotsec/anonsurf

##### Please note that this program isn't a final solution for a setup of anonimity at 100%, for more information about Tor configurations please read these docs:

**Tor Project wiki about Transparent Proxy:** 

https://trac.torproject.org/projects/tor/wiki/doc/TransparentProxy


**Whonix Do Not recommendations:**

https://www.whonix.org/wiki/DoNot


**Whonix wiki about Tor Entry Guards:**

https://www.whonix.org/wiki/<Tor id="Non-Persistent_Entry_Guards"></Tor>

https://forums.whonix.org/t/persistent-tor-entry-guard-relays-can-make-you-trackable-across-different-physical-locations/2090
