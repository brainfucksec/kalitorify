# kalitorify

# About kalitorify

kalitorify is a shell script for [Kali Linux](https://www.kali.org/) which use [iptables](https://www.netfilter.org/projects/iptables/index.html) settings for transparent proxy through Tor, the program also allows you to perform various checks like checking the external ip, or if Tor has been configured correctly.

## What is Transparent Proxy?

Also known as an intercepting proxy, inline proxy, or forced proxy, a transparent proxy intercepts normal communication at the network layer without requiring any special client configuration. Clients need not be aware of the existence of the proxy. A transparent proxy is normally located between the client and the Internet, with the proxy performing some of the functions of a gateway or router.

Strictly speaking, with kalitorify you can redirect all traffic of your Kali Linux operating system through Tor.

In the [Tor project wiki](https://trac.torproject.org/projects/tor/wiki/doc/TransparentProxy) you find an explanation of what is the "transparent proxy through tor" and related settings.

## Recommendations

kalitorify is produced independently from the Tor anonimity software and carries no guarantee from the Tor Project about quality, suitability or anything else, **please read these documents to know how to use the Tor network safely:**

[Tor General FAQ](https://www.torproject.org/docs/faq.html.en)

[Whonix Do Not recommendations](https://www.whonix.org/wiki/DoNot)

kalitorify provides transparent proxy management on Tor but does not provide 100% anonymity.

From [Arch Linux Wiki](https://wiki.archlinux.org/index.php/Tor) about Transparent Torification: Using iptables to transparently torify a system affords comparatively strong leak protection, but it is not a substitute for virtualized torification applications such as Whonix, or TorVM.
Applications can still learn your computer's hostname, MAC address, serial number, timezone, etc. and those with root privileges can disable the firewall entirely. In other words, transparent torification with iptables protects against accidental connections and DNS leaks by misconfigured software, it is not sufficient to protect against malware or software with serious security vulnerabilities.

For this, you should change at least the hostname and the MAC address:

[Setting the Hostname on Debian](https://debian-handbook.info/browse/stable/sect.hostname-name-service.html)

[Changing MAC Address on Linux](https://en.wikibooks.org/wiki/Changing_Your_MAC_Address/Linux)


## Install

### Install dependencies:
```bash
sudo apt update && sudo apt full-upgrade -y

sudo apt install tor -y
```

### Install kalitorify and reboot:
```bash
git clone https://github.com/brainfucksec/kalitorify

cd kalitorify/

sudo make install

sudo reboot
```

## Usage

**kalitorify [option]**

### Options

**-t, --tor**

    start transparent proxy through tor

**-c, --clearnet**

    reset iptables and return to clearnet navigation

**-s, --status**

    check status of program and services

**-i, --ipinfo**

    show public IP

**-r, --restart**

    restart tor service and change IP

## Thanks

* kalitorify is KISS version of [Parrot AnonSurf Module](https://github.com/parrotsec/anonsurf), developed by [Parrot Project Team](https://docs.parrotsec.org/developers). Thank you guys for give me the way in developing this program.

* This program could not exist without the guides of the [Tor Project official website](https://www.torproject.org/)

* A special thanks goes also to the [Whonix](https://www.whonix.org/) Team and their [documentation](https://www.whonix.org/wiki/Documentation)

## Donations

This is a project made with a lot of motivation to collaborate in the computer security community, if you liked the features. I invite you to make a donation.

**BITCOIN:** 1B39SnAXcR2bkxNpNy3AuckgaTshqNc2ce
