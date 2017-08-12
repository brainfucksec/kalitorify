## Kalitorify v1.9.0

### Transparent proxy through Tor for Kali Linux OS




### Installation

#### Install dependencies:
```bash
sudo apt-get update && sudo apt-get dist-upgrade -y

sudo apt-get install tor


#### Install kalitorify:
```bash
git clone https://github.com/brainfucksec/kalitorify

cd kalitorify/

sudo make install
```




### Start program

#### Use --help argument for help menu':
```bash
sudo kalitorify --help
...

└───╼ ./kalitorify --argument

Arguments available:
--------------------

--help      show this help message and exit
--start     start transparent proxy for tor
--stop      reset iptables and return to clear navigation
--status    check status of program and services
--checkip   check only public IP
--restart   restart tor service and change IP
--version   display program and tor version then exit
```


#### Start Transparent Proxy with --start argument:
```bash
sudo kalitorify --start
```




### Uninstall
```bash
cd kalitorify/

sudo make uninstall
```




#### [ NOTES ]

##### Kalitorify is KISS version of Parrot AnonSurf Module, developed by "Pirates' Crew" of FrozenBox - https://github.com/parrotsec/anonsurf

##### Please note that this program is not a final solution for a setup of anonimity at 100%, for more information about Tor configurations please read these docs:

**Tor Project wiki about Transparent Proxy:**

https://trac.torproject.org/projects/tor/wiki/doc/TransparentProxy


**Tor General FAQ**

https://www.torproject.org/docs/faq.html.en


**Whonix Do Not recommendations:**

https://www.whonix.org/wiki/DoNot
