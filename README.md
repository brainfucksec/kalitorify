<img src="logo.png" alt="kalitorify">

Transparent Proxy through Tor for Kali Linux

<a href="https://github.com/brainfucksec/kalitorify/releases"><img src="https://img.shields.io/badge/version-1.17.0-blue.svg"></a>
<a href="https://github.com/brainfucksec/kalitorify/commits/master"><img src="https://img.shields.io/badge/build-passing-brightgreen.svg"></a>
<a href="https://github.com/brainfucksec/kalitorify/blob/master/README.md"><img src="https://img.shields.io/badge/docs-passing-brightgreen.svg"></a>
<a href="https://github.com/brainfucksec/kalitorify/blob/master/LICENSE"><img src="https://img.shields.io/github/license/brainfucksec/kalitorify.svg"></a>
<a href="https://github.com/brainfucksec/kalitorify/network/members"><img src="https://img.shields.io/github/forks/brainfucksec/kalitorify.svg"></a>


## About kalitorify

**kalitorify** is a shell script for [Kali Linux](https://www.kali.org/) which use [iptables](https://www.netfilter.org/projects/iptables/index.html) settings to create a **Transparent Proxy through the Tor Network**, the program also allows you to perform various checks like checking the Tor Exit Node (i.e. your public IP when you are under Tor proxy), or if Tor has been configured correctly checking service and network settings.

In simple terms, with kalitorify you can redirect all traffic of your Kali Linux operating system through the Tor Network.

## What is Transparent Proxy through Tor?

Transparent proxy is an intermediary system that sit between a user and a content provider. When a user makes a request to a web server, the transparent proxy intercepts the request to perform various actions including caching, redirection and authentication.

![alt text](https://imgur.com/c9canu4.png)

Transparent proxy via Tor means that every network application will make its TCP connections through Tor; no application will be able to reveal your IP address by connecting directly.

In the [Tor project wiki](https://trac.torproject.org/projects/tor/wiki/doc/TransparentProxy) you find an explanation of what is the **"Transparent Proxy through Tor"** and related settings.
**Please read it if you want to use kalitorify safely.**

---

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

---

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

---

## Security

**kalitorify is produced independently from the Tor anonimity software and carries no guarantee from the Tor Project about quality, suitability or anything else,** please read these documents to know how to use the Tor network safely:

[Tor General FAQ](https://www.torproject.org/docs/faq.html.en)

[Whonix Do Not recommendations](https://www.whonix.org/wiki/DoNot)

**kalitorify provides transparent proxy management on Tor but does not provide 100% anonymity.**

From [Arch Linux Wiki](https://wiki.archlinux.org/index.php/Tor) about Transparent Torification: Using iptables to transparently torify a system affords comparatively strong leak protection, but it is not a substitute for virtualized torification applications such as Whonix, or TorVM.
Applications can still learn your computer's hostname, MAC address, serial number, timezone, etc. and those with root privileges can disable the firewall entirely. In other words, transparent torification with iptables protects against accidental connections and DNS leaks by misconfigured software, it is not sufficient to protect against malware or software with serious security vulnerabilities.

For this, you should change at least the hostname and the MAC address:

[Setting the Hostname on Debian](https://debian-handbook.info/browse/stable/sect.hostname-name-service.html)

[Changing MAC Address on Linux](https://en.wikibooks.org/wiki/Changing_Your_MAC_Address/Linux)

### Checking for leaks:

After starting kalitorify you can use [tcpdump](https://www.tcpdump.org/) to check if there are any internet activity other the Tor:

First, get your network interface:
```bash
ip -o addr
```

or

```bash
tcpdump -D
```

We'll assume its `eth0`.

Next you need to identify the Tor guard IP, you can use `ss`, `netstat` or `GETINFO entry-guards` through the tor controller to identify the guard IP.

Example with `ss`:
```bash
ss -ntp | grep $(cat /var/run/tor/tor.pid)
```

With the interface and guard IP at hand, we can now use `tcpdump` to check for possible non-tor leaks. Replace IP.TO.TOR.GUARD with the IP you got from the `ss` output.
```bash
tcpdump -n -f -p -i eth0 not arp and not host IP.TO.TOR.GUARD
```

You are not supposed to see any output other than the first two header lines. You can remove `and not host IP` to see how it would look like otherwise.

---

## Thanks

* kalitorify is KISS version of [Parrot AnonSurf Module](https://github.com/parrotsec/anonsurf), developed by [Parrot Project Team](https://docs.parrotsec.org/developers). Thank you guys for give me the way in developing this program.

* This program could not exist without the guides of the [Tor Project official website](https://www.torproject.org/)

* A special thanks goes also to the [Whonix](https://www.whonix.org/) Team and their [documentation](https://www.whonix.org/wiki/Documentation)

## Support kalitorify

Please consider donating to sustain this project

**BITCOIN:** 1B39SnAXcR2bkxNpNy3AuckgaTshqNc2ce
