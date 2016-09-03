#!/bin/bash

# Program: kalitorify.sh
# Version: 1.3.0 - 01/09/2016
# Operative System: Kali Linux 
# Description: Transparent proxy trough Tor, simply.
# Dev: Brainfuck
# https://github.com/BrainfuckSec
# Dependencies: tor, wget
#
# Kalitorify is KISS version of Parrot AnonSurf Module, developed  
# by "Pirates' Crew" of FrozenBox - https://github.com/parrotsec/anonsurf

# GNU GENERAL PUBLIC LICENSE
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.


# program / version
program="kalitorify"
version="1.3.0"

# define colors
export red=$'\e[0;91m'
export green=$'\e[0;92m'
export blue=$'\e[0;94m'
export white=$'\e[0;97m'
export endc=$'\e[0m'
#export cyan=$'\e[0;36m'

# destinations you don't want routed through Tor
non_tor="192.168.1.0/24 192.168.0.0/24"

# UID --> 'ps -e | grep tor'
tor_uid="debian-tor"

# Tor TransPort
trans_port="9040"


# print banner
function banner {
printf "${white}
 _____     _ _ _           _ ___     
|  |  |___| |_| |_ ___ ___|_|  _|_ _ 
|    -| .'| | |  _| . |  _| |  _| | |
|__|__|__,|_|_|_| |___|_| |_|_| |_  |
                                |___|

Transparent proxy trough Tor, simply

Version: 1.3.0
Dev: Brainfuck${endc}\n"
}


# check if the program run as a root 
function check_root {
	if [ "$(id -u)" -ne 0 ]; then
		printf "${red}[!] Please run this program as a root!${endc}\n" >&2
		exit 1
	fi
}


# disable ufw (if is installed and active)
function disable_ufw {
	if ufw status | grep -q active$; then
		printf "${blue}::${endc} ${green}Firewall ufw is active, disabling...${endc}\n"
		ufw disable > /dev/null 2>&1
		printf "${blue}::${endc} ${green}ufw disabled${endc}\n"
		sleep 3
	else
		ufw status | grep -q inactive$;
		printf "${blue}::${endc} ${green}Firewall ufw is inactive, continue...${endc}\n"
	fi
}


# enable ufw 
function enable_ufw {
	if ufw status | grep -q inactive$; then
		printf "${blue}::${endc} ${green}Enabling firewall ufw${endc}\n"
		ufw enable > /dev/null 2>&1
		printf "${blue}::${endc} ${green}ufw enabled${endc}\n"
		sleep 3
	else
		printf "${blue}::${endc} ${green}Firewall ufw isn't installed, continue...${endc}\n"
	fi
}


# print public IP on the screen  
function check_ip {
	local ext_ip=$(wget -qO- ipinfo.io/ip)
	local city=$(wget -qO- ipinfo.io/city)
	printf "${blue}::${endc} ${green}Current public IP:${endc}\n"
	printf "${white}%s%s${endc}\n" "$ext_ip - $city"
}


# check default configurations
function check_default {
	# tor is installed?
	command -v tor > /dev/null 2>&1 ||
	{ printf "\n${red}[ failed ] tor isn't installed, exiting...${endc}"; exit 1; }

	# wget is installed?
	command -v wget > /dev/null 2>&1 ||
	{ printf "\n${red}[ failed ] wget isn't installed, exiting..${endc}\n"; exit 1; }

	# check file '/etc/tor/torrc'
	# 
	# VirtualAddrNetworkIPv4 10.192.0.0/10
        # AutomapHostsOnResolve 1
        # TransPort 9040
        # SocksPort 9050
        # DNSPort 53
        # RunAsDaemon 1
	grep -q -x 'VirtualAddrNetworkIPv4 10.192.0.0/10' /etc/tor/torrc
	VAR1=$?

	grep -q -x 'AutomapHostsOnResolve 1' /etc/tor/torrc
	VAR2=$?

	grep -q -x 'TransPort 9040' /etc/tor/torrc
	VAR3=$?

	grep -q -x 'SocksPort 9050' /etc/tor/torrc
	VAR4=$?

	grep -q -x 'DNSPort 53' /etc/tor/torrc
	VAR5=$?

	grep -q -x 'RunAsDaemon 1' /etc/tor/torrc
	VAR6=$?

	if [ $VAR1 -ne 0 ] || 
		[ $VAR2 -ne 0 ] || 
		[ $VAR3 -ne 0 ] || 
		[ $VAR4 -ne 0 ] || 
		[ $VAR5 -ne 0 ] ||
		[ $VAR6 -ne 0 ]; then
		printf "\n${red}[ failed ]${endc} ${green}To enable the transparent proxy add the following of /etc/tor/torrc file:${endc}\n" >&2
		printf "${white}VirtualAddrNetworkIPv4 10.192.0.0/10${endc}\n"
		printf "${white}AutomapHostsOnResolve 1${endc}\n"
		printf "${white}TransPort 9040${endc}\n"
		printf "${white}SocksPort 9050${endc}\n"
		printf "${white}DNSPort 53${endc}\n"
		printf "${white}RunAsDaemon 1${endc}\n"
	exit 1
	fi
}


# start program 
function start {
	banner
	check_root
	check_default

	# check status of tor.service and stop it is active
	if systemctl is-active tor.service > /dev/null 2>&1; then
		systemctl stop tor.service
	fi

	printf "\n${blue}::${endc} ${green}Starting Transparent Proxy${endc}\n"
	disable_ufw
	sleep 1

	# if you want, get fresh Tor entry guards by regenerating Tor state file
	# delete file: /var/lib/tor/state
	# when tor.service starting, a new file 'state' it's generated
	# when you connect to Tor network, a new Tor entry guards will be written
	# on this file.
	printf "${blue}::${endc} ${green}Get fresh Tor entry guards? [y/n]${endc}"
	read -p "${green}:${endc} " yn
	case $yn in
		[yY]|[y|Y] )
			rm -i -v /var/lib/tor/state
			printf "${blue}[ ok ]${endc} ${white}New Tor entry guards obtained${endc}\n"
			;;
		*)
			;;
	esac
	
	# start tor.service
	printf "${blue}::${endc} ${green}Start Tor service${endc}\n"
	systemctl start tor.service	
	sleep 6

	# save iptables 
	printf "${blue}::${endc} ${green}Backup iptables rules${endc}\n"
	iptables-save > /opt/iptables.backup
	sleep 2 

	# flush iptables
	printf "${blue}::${endc} ${green}Flush iptables rules${endc}\n"
	iptables -F
	iptables -t nat -F

	# configure system's DNS resolver to use Tor's DNSPort on the loopback interface 
	printf "${blue}::${endc} ${green}Configure system's DNS resolver to use Tor's DNSPort${endc}\n"
	cp /etc/resolv.conf /opt/resolv.conf.backup
	echo -e 'nameserver 127.0.0.1' > /etc/resolv.conf
	sleep 2
 	
 	# new iptables rules  
	printf "${blue}::${endc} ${green}Set new iptables rules${endc}\n"	
	
	# set iptables *nat
	iptables -t nat -A OUTPUT -m owner --uid-owner $tor_uid -j RETURN
	iptables -t nat -A OUTPUT -p udp --dport 53 -j REDIRECT --to-ports 53
	iptables -t nat -A OUTPUT -p tcp --dport 53 -j REDIRECT --to-ports 53
	iptables -t nat -A OUTPUT -p udp -m owner --uid-owner $tor_uid -m udp --dport 53 -j REDIRECT --to-ports 53
	
	iptables -t nat -A OUTPUT -p tcp -d 10.192.0.0/10 -j REDIRECT --to-ports $trans_port
	iptables -t nat -A OUTPUT -p udp -d 10.192.0.0/10 -j REDIRECT --to-ports $trans_port
	
	# allow clearnet access for hosts in $non_tor
	for clearnet in $non_tor 127.0.0.0/9 127.128.0.0/10; do
		iptables -t nat -A OUTPUT -d $clearnet -j RETURN
	done
	
	# redirect all other output to Tor TransPort	
	iptables -t nat -A OUTPUT -p tcp --syn -j REDIRECT --to-ports $trans_port
	iptables -t nat -A OUTPUT -p udp -j REDIRECT --to-ports $trans_port
	iptables -t nat -A OUTPUT -p icmp -j REDIRECT --to-ports $trans_port
	
	# set iptables *filter
	iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
	
	# allow clearnet access for hosts in $non_tor
	for clearnet in $non_tor 127.0.0.0/8; do
		iptables -A OUTPUT -d $clearnet -j ACCEPT
	done
	
	# allow only Tor output
	iptables -A OUTPUT -m owner --uid-owner $tor_uid -j ACCEPT
	iptables -A OUTPUT -j REJECT
	sleep 4

	printf "${blue}[ ok ]${endc} ${white}Transparent Proxy activated, your system is under Tor${endc}\n"
	printf "${blue}[ info ]${endc} ${green}use --checkip argument for print public IP${endc}\n"
}


# stop program and return to clearnet 
function stop {
	check_root

	printf "${blue}::${endc} ${green}Stopping Transparent Proxy${endc}\n"
	sleep 2

	# flush iptables
	printf "${blue}::${endc} ${green}Flush iptables rules${endc}\n"
	iptables -F
	iptables -t nat -F

	# restore iptables 
	printf "${blue}::${endc} ${green}Restore the default iptables rules${endc}\n"
	iptables-restore < /opt/iptables.backup
	sleep 2

	# stop tor.service
	printf "${blue}::${endc} ${green}Stop tor service${endc}\n"
	systemctl stop tor.service 
	sleep 4

	# restore /etc/resolv.conf --> default nameserver 
	printf "${blue}::${endc} ${green}Restore /etc/resolv.conf file with default DNS${endc}\n"
	rm /etc/resolv.conf
	cp /opt/resolv.conf.backup /etc/resolv.conf
	sleep 2

	enable_ufw
	printf "${blue}[-]${endc} ${white}Transparent Proxy stopped${endc}\n"
}


# check current status of tor.service 
function status {
	check_root
	printf "${blue}::${endc} ${green}Check current status of tor.service${endc}\n"
	if systemctl is-active tor.service > /dev/null 2>&1; then
		printf "${blue}[ ok ]${endc} ${white}Tor service is active${endc}\n"
	else
		printf "${red}[ failed ] Tor service is not running!${endc}\n"
	fi
}


# restart tor.service and change IP
function restart {
	check_root
	printf "${blue}::${endc} ${green}Restart Tor service and change IP${endc}\n"
	systemctl stop tor.service
	sleep 3
	systemctl start tor.service
	sleep 2
	# check tor.service again
	if systemctl is-active tor.service > /dev/null 2>&1; then
		printf "${blue}[ ok ]${endc} ${white}Tor service is active${endc}\n"
	else
		printf "${red}[ failed ] Tor service is not running!${endc}\n"
	fi
	sleep 4
	check_ip
}


# display version of: kalitorify.sh, tor daemon
function print_version {
	printf "${white}%s%s$program version $version${endc}\n"
	printf "${white}$(tor --version)${endc}\n"
	exit 0
}


# print help menu' 
function help_menu {
	banner	
	printf "\n${white}Usage:${endc}\n\n"
	printf "${white}┌─╼${endc} ${red}$USER${endc} $white╺─╸${endc} ${red}$(hostname)${endc}\n"
	printf "${white}└───╼${endc} ${green}./%s$program <--argument>${endc}\n"

	printf "\n${white}Arguments:${endc}\n\n"
	printf "${red}--help${endc}        ${green}show this help message and exit${endc}\n"
	printf "${red}--start${endc}       ${green}start transparent proxy for tor${endc}\n"
	printf "${red}--stop${endc}        ${green}reset iptables and return to clear navigation${endc}\n"
	printf "${red}--status${endc}      ${green}check program status${endc}\n"
	printf "${red}--restart${endc}     ${green}restart tor service and change IP${endc}\n"
	printf "${red}--checkip${endc}     ${green}print current public IP${endc}\n"
	printf "${red}--version${endc}     ${green}display program and tor version then exit${endc}\n"  
	exit 0
}


# cases user input
case "$1" in
	--start)
		start
		;;
	--stop)
		stop
		;;
	--restart)
		restart
		;;
	--status)
		status
		;;
	--checkip)
		check_ip
		;;
	--version)
		print_version
		;;
	--help)
		help_menu
		;;
	*)
help_menu
exit 1

esac
