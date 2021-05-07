<p align="center">
<img src="img/logo.png" alt="kalitorify">
</p>

<p align="center">
Transparent Proxy through Tor for Kali Linux
</p>

<p align="center">
<a href="https://github.com/brainfucksec/kalitorify/releases"><img src="https://img.shields.io/badge/version-1.26.1-blue"></a>
<a href="https://github.com/brainfucksec/kalitorify/commits/master"><img src="https://img.shields.io/badge/build-passing-brightgreen.svg"></a>
<a href="https://github.com/brainfucksec/kalitorify/blob/master/README.md"><img src="https://img.shields.io/badge/docs-passing-brightgreen.svg"></a>
<a href="https://github.com/brainfucksec/kalitorify/blob/master/LICENSE"><img src="https://img.shields.io/github/license/brainfucksec/kalitorify.svg"></a>
<a href="https://github.com/brainfucksec/kalitorify/network/members"><img src="https://img.shields.io/github/forks/brainfucksec/kalitorify.svg"></a>
</p>

## About kalitorify

**kalitorify** is a shell script for [Kali Linux](https://www.kali.org/) which use [iptables](https://www.netfilter.org/projects/iptables/index.html) settings to create a **Transparent Proxy through the Tor Network**, the program also allows you to perform various checks like checking the Tor Exit Node (i.e. your public IP address when you are under Tor proxy), or if Tor has been configured correctly checking service and network settings.

In simple terms, with kalitorify you can redirect all traffic of your Kali Linux operating system through the Tor Network.

**This program was created for the Kali Linux operating system (Kali Linux rolling 2021.x) , don't run on other Linux distributions if you're not sure what you're doing.**

### About Tor

if you don't know the Tor Network and the Tor Project (but even if you know them), I suggest you read the information from here:

Tor Anonimity Network on [Wikipedia](https://en.wikipedia.org/wiki/Tor_%28anonymity_network%29)

Tor Project [Website](https://www.torproject.org/)


### What is Transparent Proxy through Tor

Transparent proxy is an intermediary system that sit between a user and a content provider. When a user makes a request to a web server, the transparent proxy intercepts the request to perform various actions including caching, redirection and authentication.

![alt text](https://imgur.com/c9canu4.png)

Transparent proxy via Tor means that every network application will make its TCP connections through Tor; no application will be able to reveal your IP address by connecting directly.

For more information about the Transparent Proxy through Tor please read the [Tor project wiki](https://trac.torproject.org/projects/tor/wiki/doc/TransparentProxy)

---

## Install

### Download:

Download with `git`:
```bash
git clone https://github.com/brainfucksec/kalitorify
```

Download [release](https://github.com/brainfucksec/kalitorify/releases) (package of the latest git version)

### Install dependencies:
```bash
sudo apt-get update && sudo apt-get dist-upgrade -y

sudo apt-get install -y tor curl
```

### Install kalitorify:
```bash
cd kalitorify/

sudo make install
```

### Reboot:

Services and programs that use kalitorify (such as iptables) work at the kernel level, at the end of the installation reboot the operating system to avoid conflicts.

---

## Usage

**Before starting kalitorify:**

1 - Make sure you have read the [Security](#security) section.

2 - Disable your firewall if is active.

3 - Make a backup of the iptables rules if they are present, see: [iptables](https://wiki.debian.org/iptables)

### Commands:

**Start transparent proxy through Tor:**
```bash
kalitorify --tor
```

**Return to clearnet:**
```bash
kalitorify --clearnet
```

### Commands list:

**-h, --help**

    show this help message and exit

**-t, --tor**

    start transparent proxy through tor

**-c, --clearnet**

    reset iptables and return to clearnet navigation

**-s, --status**

    check status of program and services

**-i, --ipinfo**

    show public IP address

**-r, --restart**

    restart tor service and change IP address

---

## Security

### Please read this section carefully before starting kalitorify

**kalitorify is produced independently from the Tor anonimity software and carries no guarantee from the Tor Project about quality, suitability or anything else, please read these documents to know how to use the Tor network safely:**

[Tor General FAQ](https://www.torproject.org/docs/faq.html.en)

[Whonix Do Not recommendations](https://www.whonix.org/wiki/DoNot)

**kalitorify is a bash script to start a transparent proxy through Tor to be used for a safe navigation during communications, searches or other activities with Kali Linux, but does not guarantee 100% anonymity.**

About Transparent Torification, please read [Transparent Proxy Leaks](https://trac.torproject.org/projects/tor/wiki/doc/TransparentProxyLeaks) (mostly Microsoft Windows related) and/or consider an [Isolating Proxy](https://trac.torproject.org/projects/tor/wiki/doc/TorifyHOWTO/IsolatingProxy) as alternative.
See [Whonix](https://www.whonix.org/) for a complete, ready-made VM based solution (alternatively using multiple physical computers) built around the Isolating Proxy and Transparent Proxy [Anonymizing Middlebox design](https://trac.torproject.org/projects/tor/wiki/doc/TransparentProxy#AnonymizingMiddlebox).

Source: https://trac.torproject.org/projects/tor/wiki/doc/TransparentProxy#BriefNotes

---

###  Hostname and MAC Address security risks

Applications can still learn your computer's hostname, MAC address, serial number, timezone, etc. and those with root privileges can disable the firewall entirely. In other words, transparent torification with iptables protects against accidental connections and DNS leaks by misconfigured software, it is not sufficient to protect against malware or software with serious security vulnerabilities.

Source: https://wiki.archlinux.org/index.php/Tor

**Before run kalitorify you should change at least the hostname and the MAC address:**

[Setting the Hostname on Debian](https://debian-handbook.info/browse/stable/sect.hostname-name-service.html)

[Changing MAC Address on Linux](https://en.wikibooks.org/wiki/Changing_Your_MAC_Address/Linux)

---

### Transparent Proxy with kalitorify and Tor Browser

**Don't start Tor Browser when transparent browsing (kalitorify) is active, this to** [avoid Tor over Tor Scenarios](https://www.whonix.org/wiki/DoNot#Allow_Tor_over_Tor_Scenarios).

---

### Checking for leaks

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
ss -ntp | grep "$(cat /var/run/tor/tor.pid)"
```

With the interface and guard IP at hand, we can now use `tcpdump` to check for possible non-tor leaks. Replace IP.TO.TOR.GUARD with the IP you got from the `ss` output.
```bash
tcpdump -n -f -p -i eth0 not arp and not host IP.TO.TOR.GUARD
```

You are not supposed to see any output other than the first two header lines. You can remove `and not host IP` to see how it would look like otherwise.

Source: https://trac.torproject.org/projects/tor/wiki/doc/TransparentProxy#Checkingforleaks

---

## Demo

[![asciicast](https://asciinema.org/a/386518.svg)](https://asciinema.org/a/386518)

Warning: the example video might refer to an older version.

---

## Credits

* kalitorify is a KISS version of [Parrot AnonSurf Module](https://github.com/parrotsec/anonsurf), developed by [Parrot Project Team](https://docs.parrotsec.org/developers). Thank you guys for give me the way in developing this program.

* The realization of this program was possible only with:

    * The guides of the [Tor Project official website](https://www.torproject.org/)

    * The [Whonix](https://www.whonix.org/) Team and their [documentation](https://www.whonix.org/wiki/Documentation)

    * All the people who contribute: \[[Code Contributors](https://github.com/brainfucksec/kalitorify/graphs/contributors)\]

    * All users who with their reports help to improve this project.

* "KALI LINUX ™" is a trademark of Offensive Security. Please see: https://www.kali.org

* "Tor" is a trademark of The Tor Project, Inc.. Please see: https://www.torproject.org

---

## Donate

Support kalitorify by making a donation:

**Bitcoin**

![.](img/bitcoin.webp)

```
1B39SnAXcR2bkxNpNy3AuckgaTshqNc2ce
```

**Monero**

![.](img/monero.webp)

```
42HrxGUKPzNNJKFguPfFhXQajwNDnhLbogy6EWexWw9Sh5pTumVk7dkcD2PB4MuFgD1m8rnaR3pr1g852BWUTpXaTo9rQyr
```
