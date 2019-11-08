#!/usr/bin/env bash

# ===================================================================
#
# kalitorify.sh
#
# Kali Linux - Transparent proxy through Tor
#
# Copyright (C) 2015-2019 Brainfuck
#
# Kalitorify is KISS version of Parrot AnonSurf Module, developed
# by "Pirates' Crew" of FrozenBox - https://github.com/parrotsec/anonsurf
#
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
#
# ===================================================================


# ===================================================================
# General settings
# ===================================================================

# Program information
readonly prog_name="kalitorify"
readonly version="1.20.0"
readonly signature="Copyright (C) 2015-2019 Brainfuck"
readonly git_url="https://github.com/brainfucksec/kalitorify"

# Colors for terminal output
export red=$'\e[0;91m'
export green=$'\e[0;92m'
export blue=$'\e[0;94m'
export white=$'\e[0;97m'
export cyan=$'\e[0;96m'
export endc=$'\e[0m'

# b = bold
export bgreen=$'\e[1;92m'
export bblue=$'\e[1;94m'
export bwhite=$'\e[1;97m'
export bcyan=$'\e[1;96m'
export byellow=$'\e[1;96m'


# ===================================================================
# Set program's directories and files
# ===================================================================

# Configuration files: /usr/share/kalitorify/data
# Backup files: /usr/share/kalitorify/backups
readonly config_dir="/usr/share/kalitorify/data"
readonly backup_dir="/usr/share/kalitorify/backups"


# ===================================================================
# Network settings
# ===================================================================

# The UID that Tor runs as (varies from system to system)
#`id -u debian-tor` #Debian/Ubuntu
readonly tor_uid="$(id -u debian-tor)"

# Tor TransPort
readonly trans_port="9040"

# Tor DNSPort
readonly dns_port="5353"

# Tor VirtualAddrNetworkIPv4
readonly virtual_addr_net="10.192.0.0/10"

# LAN destinations that shouldn't be routed through Tor
readonly non_tor="127.0.0.0/8 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16"

# End settings
# ===================================================================


# ===================================================================
# Show program banner
# ===================================================================
banner() {
printf "${bwhite}
 _____     _ _ _           _ ___
|  |  |___| |_| |_ ___ ___|_|  _|_ _
|    -| .'| | |  _| . |  _| |  _| | |
|__|__|__,|_|_|_| |___|_| |_|_| |_  |
                                |___| v$version

=[ Transparent proxy through Tor
=[ BrainfuckSec
${endc}\\n\\n"
}


# ===================================================================
# Print a message and exit with (1) when an error occurs
# ===================================================================
die() {
    printf "${red}%s${endc}\\n" "$@" >&2
    exit 1
}


# ===================================================================
# Check if the program run as a root
# ===================================================================
check_root() {
    if [[ "$(id -u)" -ne 0 ]]; then
        die "[ failed ] Please run this program as a root!"
    fi
}


# ===================================================================
# Display program version
# ===================================================================
print_version() {
    printf "%s\\n" "$prog_name $version"
	exit 0
}


# ===================================================================
# Check default settings
# ===================================================================

# Check:
# -> required dependencies (tor, curl)
# -> program folders
# -> tor `torrc` configuration file
check_defaults() {
    printf "${bcyan}%s${endc} ${bgreen}%s${endc}\\n" \
           "::" "Check program settings"

    # Check: dependencies
    # ===================
    declare -a dependencies=('tor' 'curl')

    for package in "${dependencies[@]}"; do
        if ! hash "${package}" 2>/dev/null; then
            die "[ failed ] '${package}' isn't installed, exit"
        fi
    done

    # Check: default directories
    # ==========================
    if [ ! -d "$backup_dir" ]; then
        die "[ failed ] directory '$backup_dir' not exist, run makefile first!"
    fi

    if [ ! -d "$config_dir" ]; then
        die "[ failed ] directory '$config_dir' not exist, run makefile first!"
    fi

    # Check: file `/etc/tor/torrc`
    # ============================
    #
    # reference file: `/usr/share/kalitorify/data/torrc`
    #
    # if torrc not exists copy from reference file
    if [[ ! -f /etc/tor/torrc ]]; then

        printf "${bblue}%s${endc} ${bgreen}%s${endc}\\n" \
               "==>" "Copy file: /etc/tor/torrc"

        if ! cp -vf "$config_dir/torrc" /etc/tor/torrc; then
            die "[ failed ] can't setup '/etc/tor/torrc'"
        fi
    else
        # grep required strings from existing file
        grep -q -x 'VirtualAddrNetworkIPv4 10.192.0.0/10' /etc/tor/torrc
        local string1=$?

        grep -q -x 'AutomapHostsOnResolve 1' /etc/tor/torrc
        local string2=$?

        grep -q -x 'TransPort 9040 IsolateClientAddr IsolateClientProtocol IsolateDestAddr IsolateDestPort' /etc/tor/torrc
        local string3=$?

        grep -q -x 'SocksPort 9050' /etc/tor/torrc
        local string4=$?

        grep -q -x 'DNSPort 5353' /etc/tor/torrc
        local string5=$?

        # if required strings does not exists replace original
        # `/etc/tor/torrc` file
        if [[ "$string1" -ne 0 ]] ||
           [[ "$string2" -ne 0 ]] ||
           [[ "$string3" -ne 0 ]] ||
           [[ "$string4" -ne 0 ]] ||
           [[ "$string5" -ne 0 ]]; then

            printf "${bblue}%s${endc} ${bgreen}%s${endc}\\n" \
                   "==>" "Setting file: /etc/tor/torrc"

            # backup original tor `/etc/tor/torrc` file
            # in the backup directory
            if ! cp -vf /etc/tor/torrc "$backup_dir/torrc.backup"; then
                die "[ failed ] can't copy original tor 'torrc' file in the backup directory"
            fi

            # copy new `torrc` file with settings for kalitorify
            if ! cp -vf "$config_dir/torrc" /etc/tor/torrc; then
                die "[ failed ] can't setup '/etc/tor/torrc'"
            fi
        fi
    fi
}


# ===================================================================
# Check public IP
# ===================================================================
check_ip() {
    printf "${bcyan}%s${endc} ${bgreen}%s${endc}\\n" \
           "::" "Checking your public IP, please wait..."

    # url list for curl requests
    url_list=(
        'http://ip-api.com/'
        'https://ipinfo.io/'
        'https://api.myip.com'
    )

    # if the first request fails try with the next
    for url in "${url_list[@]}"; do
        request="$(curl -s "$url")"
        response="$?"

        if [[ "$response" -ne 0 ]]; then
            continue
        fi

        printf "${bblue}%s${endc} ${bgreen}%s${endc}\\n" "==>" "IP Address Details:"
        printf "${white}%s${endc}\\n" "$request"
        break
    done
}


# ===================================================================
# Check status of program and services
# ===================================================================

# Check:
# -> tor.service
# -> tor settings
# -> public IP
check_status() {
    check_root

    # Check status of tor.service
    # ===========================
    printf "${bcyan}%s${endc} ${bgreen}%s${endc}\\n" \
           "::" "Check current status of Tor service"

    if systemctl is-active tor.service >/dev/null 2>&1; then
        printf "${bcyan}%s${endc} ${bgreen}%s${endc}\\n\\n" \
               "[ ok ]" "Tor service is active"
    else
        die "[-] Tor service is not running! exit"
    fi

    # Check tor network settings
    # ==========================
    #
    # make http request with curl at: https://check.torproject.org/
    # and grep the necessary strings from the html page to test connection
    # with tor
    printf "${bcyan}%s${endc} ${bgreen}%s${endc}\\n" \
           "::" "Check Tor network settings"

    # hostport = curl socks5 settings:
    #   --socks5 <host[:port]> SOCKS5 proxy on given host + port
    #   --socks5-hostname <host[:port]> SOCKS5 proxy, pass host name to proxy
    local hostport="localhost:9050"
    local url="https://check.torproject.org/"

    # curl: `-L` and `tac` for avoid error: (23) Failed writing body
    # https://github.com/kubernetes/helm/issues/2802
    # https://stackoverflow.com/questions/16703647/why-curl-return-and-error-23-failed-writing-body
    if curl -s -m 10 --socks5 "$hostport" --socks5-hostname "$hostport" -L "$url" \
        | cat | tac | grep -q 'Congratulations'; then
        printf "${bcyan}%s${endc} ${bgreen}%s${endc}\\n\\n" \
               "[ ok ]" "Your system is configured to use Tor"
    else
        printf "${red}%s${endc}\\n\\n" "[!] Your system is not using Tor"
        printf "%s\\n" "try another Tor circuit with '$prog_name --restart'"
        exit 1
    fi

    # Check current public IP
    check_ip
}


# ===================================================================
# iptables settings
# ===================================================================

# Setup new iptables rules
setup_iptables() {
    printf "\\n${bblue}%s${endc} ${bgreen}%s${endc}\\n" "==>" "Setup new iptables rules"

    # Backup current iptables rules
    iptables-save > "$backup_dir/iptables.backup"

    # Flush current iptables rules
    iptables -F
    iptables -t nat -F

    # set iptables *nat
    iptables -t nat -A OUTPUT -m owner --uid-owner $tor_uid -j RETURN
    iptables -t nat -A OUTPUT -p udp --dport 53 -j REDIRECT --to-ports $dns_port
    iptables -t nat -A OUTPUT -p tcp --dport 53 -j REDIRECT --to-ports $dns_port
    iptables -t nat -A OUTPUT -p udp -m owner --uid-owner $tor_uid -m udp --dport 53 -j REDIRECT --to-ports $dns_port

    iptables -t nat -A OUTPUT -p tcp -d $virtual_addr_net -j REDIRECT --to-ports $trans_port
    iptables -t nat -A OUTPUT -p udp -d $virtual_addr_net -j REDIRECT --to-ports $trans_port

    # allow lan access for hosts in $non_tor (local ip addresses)
    for lan in $non_tor 127.0.0.0/9 127.128.0.0/10; do
        iptables -t nat -A OUTPUT -d "$lan" -j RETURN
        iptables -A OUTPUT -d "$lan" -j ACCEPT
    done

    # redirect all other output to Tor TransPort
    iptables -t nat -A OUTPUT -p tcp --syn -j REDIRECT --to-ports $trans_port
    iptables -t nat -A OUTPUT -p udp -j REDIRECT --to-ports $trans_port
    iptables -t nat -A OUTPUT -p icmp -j REDIRECT --to-ports $trans_port

    # set iptables *filter
    iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

    # allow only Tor output
    iptables -A OUTPUT -m owner --uid-owner $tor_uid -j ACCEPT
    iptables -A OUTPUT -j REJECT

    printf "${bcyan}%s${endc} ${bgreen}%s${endc}\\n" \
        "[ ok ]" "iptables rules set"
}


# ===================================================================
# Start transparent proxy
# ===================================================================
start() {
    banner
    check_root
    sleep 2
    check_defaults

    # stop tor.service before changing tor settings
    if systemctl is-active tor.service >/dev/null 2>&1; then
        systemctl stop tor.service
    fi

    printf "\\n${bcyan}%s${endc} ${bgreen}%s${endc}\\n" \
           "::" "Starting Transparent Proxy"

    # DNS settings: `/etc/resolv.conf`:
    # =================================
    #
    # Configure system's DNS resolver to use Tor's DNSPort
    # on the loopback interface, i.e. write nameserver 127.0.0.1
    # to `/etc/resolv.conf` file
    printf "${bblue}%s${endc} ${bgreen}%s${endc}\\n" \
           "==>" "Configure system's DNS resolver to use Tor's DNSPort"

    # backup current resolv.conf
    if ! cp -vf /etc/resolv.conf "$backup_dir/resolv.conf.backup"; then
        die "[ failed ] can't copy resolv.conf to the backup directory"
    fi

    # write new nameserver
    printf "%s\\n" "nameserver 127.0.0.1" > /etc/resolv.conf
    sleep 1

    # Disable IPv6 with sysctl
    # ========================
    printf "\\n${bblue}%s${endc} ${bgreen}%s${endc}\\n" "==>" "Disable IPv6 with sysctl"

    sysctl -w net.ipv6.conf.all.disable_ipv6=1
    sysctl -w net.ipv6.conf.default.disable_ipv6=1

    # Start tor.service for new configuration
    # =======================================
    printf "\\n${bblue}%s${endc} ${bgreen}%s${endc}\\n" "==>" "Start Tor service"

    if systemctl start tor.service 2>/dev/null; then
        printf "${bcyan}%s${endc} ${bgreen}%s${endc}\\n" \
               "[ ok ]" "Tor service started"
    else
        die "[ failed ] systemd error, exit!"
    fi

    # set iptables rules
    setup_iptables
    printf "\\n"

    # check program status
    check_status

    printf "\\n${bcyan}%s${endc} ${bgreen}%s${endc}\\n" \
    	    "[ ok ]" "Transparent Proxy activated, your system is under Tor"
}


# ===================================================================
# Stop transparent proxy
# ===================================================================

# Stop connection with Tor Network and return to clearnet navigation
stop() {
    check_root

    printf "${bcyan}%s${endc} ${bgreen}%s${endc}\\n" \
           "::" "Stopping Transparent Proxy"
    sleep 2

    # Restore default iptables rules:
    # ===============================
    #
    printf "${bblue}%s${endc} ${bgreen}%s${endc}\\n" "==>" "Restore default iptables rules"

    # Flush iptables rules
    iptables -F
    iptables -t nat -F

    # Restore iptables from backup
    iptables-restore < "${backup_dir}/iptables.backup"

    printf "${bcyan}%s${endc} ${bgreen}%s${endc}\\n" \
        "[ ok ]" "iptables rules restored"

    # Stop tor.service
    printf "\\n${bblue}%s${endc} ${bgreen}%s${endc}\\n" "==>" "Stop tor service"
    systemctl stop tor.service

    printf "${bcyan}%s${endc} ${bgreen}%s${endc}\\n" \
        "[ ok ]" "Tor service stopped"

    # Restore `/etc/resolv.conf`
    # ==========================
    printf "\\n${bblue}%s${endc} ${bgreen}%s${endc}\\n" \
           "==>" "Restore /etc/resolv.conf file with default DNS"

    # restore file with `resolvconf` program if exists
    # otherwise copy the original file from backup directory
    if hash resolvconf 2>/dev/null; then
        resolvconf -u
        printf "${bcyan}%s${endc} ${bgreen}%s${endc}\\n " \
               "[ ok ]" "update '/etc/resolv.conf'"
    else
        cp -vf "$backup_dir/resolv.conf.backup" /etc/resolv.conf
    fi
    sleep 1

    # Re-enable IPv6
    # ==============
    printf "\\n${bblue}%s${endc} ${bgreen}%s${endc}\\n" "==>" "Enable IPv6"
    sysctl -w net.ipv6.conf.all.disable_ipv6=0
    sysctl -w net.ipv6.conf.default.disable_ipv6=0

    # Restore default `/etc/tor/torrc`
    # ================================
    printf "\\n${bblue}%s${endc} ${bgreen}%s${endc}\\n" \
           "==>" "Restore '/etc/tor/torrc' file with default tor settings"

    cp -vf "$backup_dir/torrc.backup" /etc/tor/torrc


    printf "\\n${bcyan}%s${endc} ${bgreen}%s${endc}\\n" \
           "[-]" "Transparent Proxy stopped"
}


# ===================================================================
# Restart tor.service and change public IP (i.e. new Tor exit node)
# ===================================================================
restart() {
    check_root

    printf "${bcyan}%s${endc} ${bgreen}%s${endc}\\n" \
           "::" "Restart Tor service and change IP"

    systemctl restart tor.service
    sleep 3

    printf "${bcyan}%s${endc} ${bgreen}%s${endc}\\n\\n" \
           "[ ok ]" "Tor Exit Node changed"

    # Check current public IP
    check_ip
    exit 0
}


# ===================================================================
# Show help menù
# ===================================================================
usage() {
    printf "${blue}%s${endc}\\n" "$prog_name $version"
    printf "${white}%s${endc}\\n" "Kali Linux - Transparent proxy through Tor"
    printf "${white}%s${endc}\\n\\n" "$signature"

    printf "${green}%s${endc}\\n\\n" "Usage:"

    printf "${white}%s${endc} ${red}%s${endc} ${white}%s${endc} ${red}%s${endc}\\n" \
        "┌─╼" "$USER" "╺─╸" "$(hostname)"
    printf "${white}%s${endc} ${green}%s${endc}\\n\\n" "└───╼" "$prog_name [option]"

    printf "${green}%s${endc}\\n\\n" "Options:"

    printf "${white}%s${endc}\\n" \
           "-h, --help      show this help message and exit"

    printf "${white}%s${endc}\\n" \
           "-t, --tor       start transparent proxy through tor"

    printf "${white}%s${endc}\\n" \
           "-c, --clearnet  reset iptables and return to clearnet navigation"

    printf "${white}%s${endc}\\n" \
           "-s, --status    check status of program and services"

    printf "${white}%s${endc}\\n" \
           "-i, --ipinfo    show public IP"

    printf "${white}%s${endc}\\n" \
           "-r, --restart   restart tor service and change Tor exit node"

    printf "${white}%s${endc}\\n\\n" \
           "-v, --version   display program version and exit"

    printf "${green}%s${endc} ${white}%s${endc}\\n" "Project URL:" "$git_url"
    printf "${green}%s${endc} ${white}%s${endc}\\n" "Report bugs:" "$git_url/issues"
    exit 0
}


# ===================================================================
# Main function
# ===================================================================

# Parse command line arguments and start program
main() {
    if [[ "$#" -eq 0 ]]; then
        printf "%s\\n" "$prog_name: Argument required"
        printf "%s\\n" "Try '$prog_name --help' for more information."
        exit 1
    fi

    while [[ "$#" -gt 0 ]]; do
        case "$1" in
            -t | --tor)
                start
                shift
                ;;
            -c | --clearnet)
                stop
                ;;
            -r | --restart)
                restart
                ;;
            -s | --status)
                check_status
                ;;
            -i | --ipinfo)
                check_ip
                ;;
            -v | --version)
                print_version
                ;;
            -h | --help)
                usage
                exit 0
                ;;
            -- | -* | *)
                printf "%s\\n" "$prog_name: Invalid option '$1'"
                printf "%s\\n" "Try '$prog_name --help' for more information."
                exit 1
                ;;
        esac
        shift
    done
}


main "$@"
