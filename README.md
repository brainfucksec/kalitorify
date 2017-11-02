# Kalitorify v1.10.0

## Transparent proxy through Tor for Kali Linux OS


### Installation

#### Install dependencies:
```bash
sudo apt update && sudo apt full-upgrade -y

sudo apt install tor -y
```


#### Install kalitorify:
```bash
git clone https://github.com/brainfucksec/kalitorify

cd kalitorify/

sudo make install
```


### Run program

#### Simply start Transparent Proxy with --start option:
```bash
sudo kalitorify --start
```


### [ NOTES ]

#### Kalitorify is KISS version of Parrot AnonSurf Module, developed by "Pirates' Crew" of FrozenBox - https://github.com/parrotsec/anonsurf

#### Please note that this program is not a final solution for a setup of anonimity at 100%, for more information about Tor configurations please read these docs:

#### Tor Project wiki about Transparent Proxy:

https://trac.torproject.org/projects/tor/wiki/doc/TransparentProxy


#### Tor General FAQ**

https://www.torproject.org/docs/faq.html.en


#### Whonix Do Not recommendations:

https://www.whonix.org/wiki/DoNot
