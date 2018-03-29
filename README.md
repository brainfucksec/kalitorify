# kalitorify

# About kalitorify

kalitorify is a shell script for [Kali Linux](https://www.kali.org/) which use [iptables](https://www.netfilter.org/projects/iptables/index.html) settings for transparent proxy through Tor, the program also allows you to perform various checks like checking the external ip, or if Tor has been configured correctly.

## What is Transparent Proxy?

Also known as an intercepting proxy, inline proxy, or forced proxy, a transparent proxy intercepts normal communication at the network layer without requiring any special client configuration. Clients need not be aware of the existence of the proxy. A transparent proxy is normally located between the client and the Internet, with the proxy performing some of the functions of a gateway or router.

In the [Tor project wiki](https://trac.torproject.org/projects/tor/wiki/doc/TransparentProxy) you find an explanation of what is the "transparent proxy through tor" and related settings.

## Recommendations

kalitorify is produced independently from the Tor anonimity software and carries no guarantee from the Tor Project about quality, suitability or anything else, if you need more information about tor security plese read these docs:

[Tor General FAQ](https://www.torproject.org/docs/faq.html.en)

[Whonix Do Not recommendations](https://www.whonix.org/wiki/DoNot)


## Install

#### Install dependencies:
```bash
sudo apt update && sudo apt full-upgrade -y

sudo apt install tor -y
```

#### Install kalitorify and reboot:
```bash
git clone https://github.com/brainfucksec/kalitorify

cd kalitorify/

sudo make install

sudo reboot
```


## Usage

#### Simply start Transparent Proxy with --start option:
```bash
sudo kalitorify --start
```

#### Like any other unix like program use '--help' option for help menù:
```bash
sudo kalitorify --help
```

## Thanks

* kalitorify is KISS version of [Parrot AnonSurf Module](https://github.com/parrotsec/anonsurf), developed by "Pirates' Crew" of FrozenBox

* A special thanks goes also to the [Whonix](https://www.whonix.org/) Team and their [documentation](https://www.whonix.org/wiki/Documentation)
