#!/usr/bin/env bash

# program: kalitorify.sh
# version: 1.9.0
# Operating System: Kali Linux
# Description: Transparent proxy through Tor
# Dependencies: tor
#
# Copyright (C) 2015-2017 Brainfuck
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


# program's informations
readonly program="kalitorify"
readonly version="1.9.0"
readonly author="Brainfuck"
readonly git_url="https://github.com/brainfucksec/kalitorify"

# define colors
export red=$'\e[0;91m'
export green=$'\e[0;92m'
export blue=$'\e[0;94m'
export white=$'\e[0;97m'
export cyan=$'\e[0;96m'
export endc=$'\e[0m'

## Network settings
# UID of tor, on Debian usually '109'
readonly tor_uid="109"

# Tor TransPort
readonly trans_port="9040"

# Tor DNSPort
readonly dns_port="5353"

# Tor VirtualAddrNetworkIPv4
readonly virtual_addr_net="10.192.0.0/10"

# LAN destinations that shouldn't be routed through Tor
readonly non_tor="127.0.0.0/8 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16"
## End of Network settings

# Directory where put backups of system default files
readonly backup_dir="/opt/kalitorify/backups"


# print banner
banner() {
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

version: "$version"
author: "$author"
$git_url${endc}\\n"
}


# check if the program run as a root
check_root() {
    if [[ "$(id -u)" -ne 0 ]]; then
        printf "\\n${red}%s${endc}\\n" \
            "[ failed ] Please run this program as a root!" 2>&-
        exit 1
    fi
}


# display program and Tor version then exit
print_version() {
    printf "${white}%s${endc}\\n" "$program version $version"
    printf "${white}%s${endc}\\n" "$(tor --version)"
	exit 0
}


## Functions for firewall ufw
# check ufw status:
# if installed and/or active disable it, if isn't installed, do nothing,
# don't display nothing to user and jump to next function
disable_ufw() {
	if hash ufw 2>/dev/null; then
    	if ufw status | grep -q active$; then
        	printf "${blue}%s${endc} ${green}%s${endc}\\n" \
                "::" "Firewall ufw is active. disabling... "
        	ufw disable
        	sleep 3
    	else
    		ufw status | grep -q inactive$;
        	printf "${blue}%s${endc} ${green}%s${endc}\\n" \
                "::" "Firewall ufw is inactive, continue..."
    	fi
    fi
}


## enable ufw:
# often, if ufw isn't installed, do nothing and jump to the next function
enable_ufw() {
	if hash ufw 2>/dev/null; then
    	if ufw status | grep -q inactive$; then
        	printf "${blue}%s${endc} ${green}%s${endc}\\n" \
                "::" "Enabling firewall ufw..."
        	ufw enable
        	sleep 3
        fi
    fi
}


## Check default configurations
# check if kalitorify is properly configured, begin ...
check_defaults() {
    # check dependencies (tor, macchanger)
    declare -a dependencies=("tor");
    for package in "${dependencies[@]}"; do
        if ! hash "$package" 2> /dev/null; then
            printf "${red}%s${endc}\\n" \
                "[ failed ] '$package' isn't installed, exit";
            exit 1
        fi
    done


    ## Check file "/etc/tor/torrc"
    grep -q -x 'VirtualAddrNetworkIPv4 10.192.0.0/10' /etc/tor/torrc
    VAR1=$?

    grep -q -x 'AutomapHostsOnResolve 1' /etc/tor/torrc
    VAR2=$?

    grep -q -x 'TransPort 9040' /etc/tor/torrc
    VAR3=$?

    grep -q -x 'SocksPort 9050' /etc/tor/torrc
    VAR4=$?

    grep -q -x 'DNSPort 5353' /etc/tor/torrc
    VAR5=$?

    # if this file is not already set, set it now
    if [[ $VAR1 -ne 0 ]] ||
       [[ $VAR2 -ne 0 ]] ||
       [[ $VAR3 -ne 0 ]] ||
       [[ $VAR4 -ne 0 ]] ||
       [[ $VAR5 -ne 0 ]]; then
        printf "\\n${blue}%s${endc} ${green}%s${endc}\\n" \
            "::" "Setting file: /etc/tor/torrc..."

        # backup original file
        cp -vf /etc/tor/torrc "$backup_dir/torrc.backup"

        # write new settings to file:
#-----------------------------------------------------------------------
        echo '## Configuration file for Tor
##
## See "man tor", or https://www.torproject.org/docs/tor-manual.html,
## for more options you can use in this file.
##
## Tor will look for this file in various places based on your platform:
## https://www.torproject.org/docs/faq#torrc

## Logs to /tmp to prevent digital evidence to be stored on disk
Log notice file /tmp/kalitorify.log

## Uncomment this to start the process in the background... or use
## --runasdaemon 1 on the command line. This is ignored on Windows;
## see the FAQ entry if you want Tor to run as an NT service.
#RunAsDaemon 1

## The directory for keeping all the keys/etc. By default, we store
## things in $HOME/.tor on Unix, and in Application Data\tor on Windows.
#DataDirectory /var/lib/tor

## Transparent Proxy settings
VirtualAddrNetworkIPv4 10.192.0.0/10
AutomapHostsOnResolve 1
TransPort 9040
SocksPort 9050
DNSPort 5353' > /etc/tor/torrc
#-----------------------------------------------------------------------
# EOF
    fi
}


## Start transparent proxy
main() {
    banner
    check_root
    check_defaults

    # check status of tor.service and stop it if is active
    if systemctl is-active tor.service > /dev/null 2>&1; then
        systemctl stop tor.service
    fi

    printf "\\n${blue}%s${endc} ${green}%s${endc}\\n" "::" "Starting Transparent Proxy"
    disable_ufw
    sleep 3

    # start tor.service
    printf "${blue}%s${endc} ${green}%s${endc}\n" "::" "Start Tor service... "
    if ! systemctl start tor.service 2>/dev/null; then
        printf "\\n${red}%s${endc}\\n" \
            "[ failed ] systemd error, exit!"
        exit 1
    fi
    sleep 6
   	printf "${cyan}%s${endc} ${green}%s${endc}\\n" "[ ok ]" "Tor service is active"


    ## Begin iptables settings
    # save current iptables rules
    printf "${blue}%s${endc} ${green}%s${endc}" "::" "Backup iptables rules... "
    iptables-save > "$backup_dir/iptables.backup"
    printf "${white}%s${endc}\\n" "Done"
    sleep 2

    # flush current iptables rules
    printf "${blue}%s${endc} ${green}%s${endc}" "::" "Flush iptables rules... "
    iptables -F
    iptables -t nat -F
    printf "${white}%s${endc}\\n" "Done"

    # configure system's DNS resolver to use Tor's DNSPort on the loopback interface
    # i.e. write nameserver 127.0.0.1 to 'etc/resolv.conf' file
    printf "${blue}%s${endc} ${green}%s${endc}\\n" \
        "::" "Configure system's DNS resolver to use Tor's DNSPort"
    cp -vf /etc/resolv.conf "$backup_dir/resolv.conf.backup"
    echo -e 'nameserver 127.0.0.1' > /etc/resolv.conf
    sleep 2

    # write new iptables rules
    printf "${blue}%s${endc} ${green}%s${endc}" "::" "Set new iptables rules... "
    #---------------------------------------------------------------------------
    # set iptables *nat
    iptables -t nat -A OUTPUT -m owner --uid-owner $tor_uid -j RETURN
    iptables -t nat -A OUTPUT -p udp --dport 53 -j REDIRECT --to-ports $dns_port
    iptables -t nat -A OUTPUT -p tcp --dport 53 -j REDIRECT --to-ports $dns_port
    iptables -t nat -A OUTPUT -p udp -m owner --uid-owner $tor_uid -m udp --dport 53 -j REDIRECT --to-ports $dns_port

    iptables -t nat -A OUTPUT -p tcp -d $virtual_addr_net -j REDIRECT --to-ports $trans_port
    iptables -t nat -A OUTPUT -p udp -d $virtual_addr_net -j REDIRECT --to-ports $trans_port

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
    #---------------------------------------------------------------------------
    ## End of iptables settings
    printf "${white}%s${endc}\\n" "Done"
    sleep 4

    printf "${cyan}%s${endc} ${green}%s${endc}\\n" \
    	"[ ok ]" "Transparent Proxy activated, your system is under Tor"
    printf "${cyan}%s${endc} ${green}%s${endc}\\n" \
    	"[ info ]" "Use --status argument for check the program status"
}


## Stop transparent proxy
stop() {
    check_root
    printf "${blue}%s${endc} ${green}%s${endc}\\n" "::" "Stopping Transparent Proxy"
    sleep 2

    ## Resets default settings
    # flush current iptables rules
    printf "${blue}%s${endc} ${green}%s${endc}" "::" "Flush iptables rules... "
    iptables -F
    iptables -t nat -F
    printf "${white}%s${endc}\\n" "Done"

    # restore iptables
    printf "${blue}%s${endc} ${green}%s${endc}" "::" "Restore the default iptables rules... "
    iptables-restore < "$backup_dir/iptables.backup"
    printf "${white}%s${endc}\\n" "Done"
    sleep 2

    # stop tor.service
    printf "${blue}%s${endc} ${green}%s${endc}" "::" "Stop tor service... "
    systemctl stop tor.service
    printf "${white}%s${endc}\\n" "Done"
    sleep 4

    # restore /etc/resolv.conf --> default nameserver
    printf "${blue}%s${endc} ${green}%s${endc}\\n" \
        "::" "Restore /etc/resolv.conf file with default DNS"
    rm -v /etc/resolv.conf
    cp -vf "$backup_dir/resolv.conf.backup" /etc/resolv.conf
    sleep 2

    # restore default /etc/tor/torrc file
    printf "${blue}%s${endc} ${green}%s${endc}\\n" \
        "::" "Restore default /etc/tor/torrc file"
    cp -vf "$backup_dir/torrc.backup" /etc/tor/torrc
    sleep 2

    # enable firewall ufw
    enable_ufw

    ## End
    printf "${cyan}%s${endc} ${green}%s${endc}\\n" "[-]" "Transparent Proxy stopped"
}


## Function for check public IP
check_ip() {
    printf "\\n${blue}%s${endc} ${green}%s${endc}\\n" \
        "::" "Checking your public IP, please wait..."

    # curl request: http://ipinfo.io/geo
    if ! external_ip="$(curl -s -m 10 ipinfo.io/geo)"; then
        printf "${red}%s${endc}\\n" "[ failed ] curl: HTTP request error!"
        exit 1
    fi

    # print output
    printf "${blue}%s${endc} ${green}%s${endc}\\n" "::" "IP Address Details:"
    printf "${white}%s${endc}\\n" "$external_ip" | tr -d '"{}' | sed 's/ //g'
}


## Check_status function
# function for check status of program and services:
# check --> tor.service
# check --> public IP
check_status() {
    check_root

    # check status of tor.service
    printf "${blue}%s${endc} ${green}%s${endc}\\n" \
        "::" "Check current status of Tor service"
    if systemctl is-active tor.service > /dev/null 2>&1; then
        printf "${cyan}%s${endc} ${green}%s${endc}\\n" "[ ok ]" "Tor service is active"
    else
        printf "${red}%s${endc}\\n" "[-] Tor service is not running!"
        exit 1
    fi

    # check current public IP
    check_ip
    exit 0
}


## Restart tor.service and change IP
restart() {
    check_root

    printf "${blue}%s${endc} ${green}%s${endc}\\n" "::" "Restart Tor service and change IP"
    ## why 'systemctl restart tor.service' not work any more?
    # avoid errors with old "service tor reload" command
    service tor reload
    sleep 3

    printf "${cyan}%s${endc} ${green}%s${endc}\\n" "[ ok ]" "Tor Exit Node changed"

    # check current public IP
    check_ip
}


# print nice "nerd" help menu
help_menu() {
	banner
    printf "\\n\\n${green}%s${endc}\\n" "Usage:"
    printf "${white}%s${endc}\\n\\n"   "------"
    printf "${white}%s${endc} ${red}%s${endc} ${white}%s${endc} ${red}%s${endc}\\n" \
        "┌─╼" "$USER" "╺─╸" "$(hostname)"
    printf "${white}%s${endc} ${green}%s${endc}\\n" "└───╼" "./$program --argument"

    printf "\\n${green}%s${endc}\\n" "Arguments available:"
    printf "${white}%s${endc}\\n\\n" "--------------------"

    printf "${white}%-12s${endc} ${green}%s${endc}\\n" "--help"      "show this help message and exit"
    printf "${white}%-12s${endc} ${green}%s${endc}\\n" "--start"     "start transparent proxy through tor"
    printf "${white}%-12s${endc} ${green}%s${endc}\\n" "--stop"      "reset iptables and return to clear navigation"
    printf "${white}%-12s${endc} ${green}%s${endc}\\n" "--status"    "check status of program and services"
    printf "${white}%-12s${endc} ${green}%s${endc}\\n" "--checkip"   "check only public IP"
    printf "${white}%-12s${endc} ${green}%s${endc}\\n" "--restart"   "restart tor service and change IP"
    printf "${white}%-12s${endc} ${green}%s${endc}\\n" "--version"   "display program and tor version then exit"
    exit 0
}


## cases user input
case "$1" in
    --start)
        main
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
