#!/bin/bash

# Program: kalitorify.sh
# Version: 1.4.1
# Operating System: Kali Linux
# Description: Transparent proxy trough Tor
# Author: Brainfuck
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
version="1.4.1"

# define colors
export red=$'\e[0;91m'
export green=$'\e[0;92m'
export blue=$'\e[0;94m'
export white=$'\e[0;97m'
export endc=$'\e[0m'
export cyan=$'\e[0;36m'

# destinations you don't want routed through Tor
non_tor="192.168.1.0/24 192.168.0.0/24"

# UID --> 'ps -e | grep tor'
tor_uid="debian-tor"

# Tor TransPort
trans_port="9040"


# print banner
function banner {
printf "${white}
*****************************************
*                                       *
*  _____     _ _ _           _ ___      *
* |  |  |___| |_| |_ ___ ___|_|  _|_ _  *
* |    -| .'| | |  _| . |  _| |  _| | | *
* |__|__|__,|_|_|_| |___|_| |_|_| |_  | *
*                                 |___| *
*                                       *
*****************************************

Transparent proxy trough Tor for Kali Linux

Version: $version
Author: Brainfuck${endc}\n"
}


# check if the program run as a root
function check_root {
    if [ "$(id -u)" -ne 0 ]; then
        printf "${red}%s${endc}\n"  "[ failed ] Please run this program as a root!" >&2
        exit 1
    fi
}


# functions for firewall ufw
# check if ufw is installed and active, if not
# jump this function 
function disable_ufw {
	if hash ufw 2>/dev/null; then
    	if ufw status | grep -q active$; then
        	printf "${blue}%s${endc} ${green}%s${endc}\n" "::" "Firewall ufw is active. disabling..."
        	ufw disable > /dev/null 2>&1
        	printf "${blue}%s${endc} ${green}%s${endc}\n" "::" "ufw disabled"
        	sleep 3
    	else 
    		ufw status | grep -q inactive$; 
        	printf "${blue}%s${endc} ${green}%s${endc}\n" "::" "Firewall ufw is inactive, continue..."  
    	fi
    fi
}


# enable ufw 
# if ufw isn't installed, jump this function
function enable_ufw {
	if hash ufw 2>/dev/null; then
    	if ufw status | grep -q inactive$; then
        	printf "${blue}%s${endc} ${green}%s${endc}\n" "::" "Enabling firewall ufw"
        	ufw enable > /dev/null 2>&1
        	printf "${blue}%s${endc} ${green}%s${endc}\n" "::" "ufw enabled"
        	sleep 3
        fi
    fi
}


# check default configurations
# check if kalitorify is properly configured
function check_default {
    # check dependencies (tor, wget)
    command -v tor > /dev/null 2>&1 ||
    { printf >&2 "\n${red}%s${endc}\n" "[ failed ] tor isn't installed, exiting..."; exit 1; }

    command -v wget > /dev/null 2>&1 ||
    { printf >&2 "\n${red}%s${endc}\n" "[ failed ] wget isn't installed, exiting..."; exit 1; }

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
        printf "\n${red}%s${endc}\n" "[ failed ] To enable the transparent proxy add the following of /etc/tor/torrc file:" >&2
        printf "${white}%s${endc}\n" "VirtualAddrNetworkIPv4 10.192.0.0/10"
        printf "${white}%s${endc}\n" "AutomapHostsOnResolve 1"
        printf "${white}%s${endc}\n" "TransPort 9040"
        printf "${white}%s${endc}\n" "SocksPort 9050"
        printf "${white}%s${endc}\n" "DNSPort 53"
        printf "${white}%s${endc}\n" "RunAsDaemon 1"
    exit 1
    fi
}


# start transparent proxy
# start program
function start {
    banner
    check_root
    check_default

    # check status of tor.service and stop it if is active
    if systemctl is-active tor.service > /dev/null 2>&1; then
        systemctl stop tor.service
    fi

    printf "\n${blue}%s${endc} ${green}%s${endc}\n" "::" "Starting Transparent Proxy"
    disable_ufw
    sleep 3

    # Tor Entry Guards
    # delete file: /var/lib/tor/state
    # when tor.service starting, a new file 'state' it's generated
    # when you connect to Tor network, a new Tor entry guards will be written
    # on this file.
    printf "${blue}::${endc} ${green}Get fresh Tor entry guards? [y/n]${endc}"
	read -p "${green}:${endc} " yn
    case $yn in
        [yY]|[y|Y] )
            rm -v /var/lib/tor/state
            printf "${blue}%s${endc} ${white}%s${endc}\n" "[ ok ]" "When tor.service start, new Tor entry guards will obtained"
            ;;
        *)
            ;;
    esac

    # start tor.service
    printf "${blue}%s${endc} ${green}%s${endc}\n" "::" "Start Tor service"
    systemctl start tor.service
    sleep 6
   	printf "${blue}%s${endc} ${white}%s${endc}\n" "[ ok ]" "Tor service is active"

   	# iptables settings
   	###################	

    # save iptables
    printf "${blue}%s${endc} ${green}%s${endc}\n" "::" "Backup iptables rules"
    iptables-save > /opt/iptables.backup
    sleep 2

    # flush iptables
    printf "${blue}%s${endc} ${green}%s${endc}\n" "::" "Flush iptables rules"
    iptables -F
    iptables -t nat -F

    # configure system's DNS resolver to use Tor's DNSPort on the loopback interface
    printf "${blue}%s${endc} ${green}%s${endc}\n" "::" "Configure system's DNS resolver to use Tor's DNSPort"
    cp -vf /etc/resolv.conf /opt/resolv.conf.backup
    echo -e 'nameserver 127.0.0.1' > /etc/resolv.conf
    sleep 2

    # new iptables rules
    printf "${blue}%s${endc} ${green}%s${endc}\n" "::" "Set new iptables rules"

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

    printf "${blue}%s${endc} ${white}%s${endc}\n" "[ ok ]" "Transparent Proxy activated, your system is under Tor"
    printf "${blue}%s${endc} ${green}%s${endc}\n" "[ info ]" "Use --status argument for check the program status"
}


# stop function
# stop transparent proxy and return to clearnet
function stop {
    check_root

    printf "${blue}%s${endc} ${green}%s${endc}\n" "::" "Stopping Transparent Proxy"
    sleep 2

    # flush iptables
    printf "${blue}%s${endc} ${green}%s${endc}\n" "::" "Flush iptables rules"
    iptables -F
    iptables -t nat -F

    # restore iptables
    printf "${blue}%s${endc} ${green}%s${endc}\n" "::" "Restore the default iptables rules"
    iptables-restore < /opt/iptables.backup
    sleep 2

    # stop tor.service
    printf "${blue}%s${endc} ${green}%s${endc}\n" "::" "Stop tor service"
    systemctl stop tor.service
    sleep 4

    # restore /etc/resolv.conf --> default nameserver
    printf "${blue}%s${endc} ${green}%s${endc}\n" "::" "Restore /etc/resolv.conf file with default DNS"
    rm -v /etc/resolv.conf
    cp -vf /opt/resolv.conf.backup /etc/resolv.conf
    sleep 2

    enable_ufw
    printf "${blue}%s${endc} ${white}%s${endc}\n" "[-]" "Transparent Proxy stopped"
}


# check_status function
# function for check status of program and services:
# tor.service, check public IP, netstat for open door
function check_status {
    check_root

    # check status of tor.service
    printf "${blue}%s${endc} ${green}%s${endc}\n" "::" "Check current status of Tor service"
    if systemctl is-active tor.service > /dev/null 2>&1; then
        printf "${blue}%s${endc} ${white}%s${endc}\n" "[ ok ]" "Tor service is active"
    else
        printf "${red}%s${endc}\n" "[-] Tor service is not running!"
        exit 1
    fi

    # check current public IP
    printf "\n${blue}%s${endc} ${green}%s${endc}\n" "::" "Checking your public IP, please wait..."
    local ext_ip
    ext_ip=$(wget -qO- -t 1 --timeout=15 ipinfo.io/ip)
    local city
    city=$(wget -qO- -t 1 --timeout=15 ipinfo.io/city)
    
    printf "${blue}%s${endc} ${green}%s${endc}\n" "::" "Current public IP:"
    printf "${white}%s%s${endc}\n\n" "$ext_ip - $city"
    sleep 1

    # exec command "netstat -tulpn", check if there are open doors
    printf "${blue}%s${endc} ${green}%s${endc}\n" "::" "Check if there are open doors"
    printf "${blue}%s${endc} ${green}%s${endc}\n" "::" "run command 'netstat -tulpn'"
    sleep 5 &
    netstat -tulpn
    printf "\n${blue}%s${endc} ${green}%s${endc}\n" "[ info ]" "If your network security is ok, you have only 'tor' in listen"
    exit 0
}


# restart tor.service and change IP
function restart {
    check_root
    printf "${blue}%s${endc} ${green}%s${endc}\n" "::" "Restart Tor service and change IP"

    # systemctl restart or stop/start is the same?
    systemctl stop tor.service
    sleep 3
    systemctl start tor.service
    sleep 2
    # check tor.service after restart
    if systemctl is-active tor.service > /dev/null 2>&1; then
        printf "${blue}%s${endc} ${white}%s${endc}\n\n" "[ ok ]" "Tor service is active and your IP is changed"
        check_status
    else
        printf "${red}%s${endc}\n" "[-] Tor service is not running!" 
    fi
    sleep 4
}


# display program and tor version then exit
function print_version {
    printf "${white}%s${endc}\n" "$program version $version"
    printf "${white}%s${endc}\n" "$(tor --version)"
    exit 0
}


# print nice help message and exit
function help_menu {
	banner

    printf "\n${white}%s${endc}\n" "Usage:"
    printf "${white}%s${endc}\n\n"   "******"
    printf "${white}%s${endc} ${red}%s${endc} ${white}%s${endc} ${red}%s${endc}\n" "┌─╼" "$USER" "╺─╸" "$(hostname)"
    printf "${white}%s${endc} ${green}%s${endc}\n" "└───╼" "./$program --argument"

    printf "\n${white}%s${endc}\n\n" "Arguments:"
    printf "${green}%s${endc}\n" "--help      show this help message and exit"
    printf "${green}%s${endc}\n" "--start     start transparent proxy for tor"
    printf "${green}%s${endc}\n" "--stop      reset iptables and return to clear navigation"
    printf "${green}%s${endc}\n" "--status    check status of program and services"
    printf "${green}%s${endc}\n" "--restart   restart tor service and change IP"
    printf "${green}%s${endc}\n" "--version   display program and tor version then exit"
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
        check_status
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
