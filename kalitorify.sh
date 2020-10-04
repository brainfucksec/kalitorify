#!/usr/bin/env bash

# ===================================================================
# kalitorify.sh
#
# Kali Linux - Transparent proxy through Tor
#
# Copyright (C) 2015-2020 Brainfuck
#
# Kalitorify is KISS version of Parrot AnonSurf Module, developed
# by "Pirates' Crew" of FrozenBox - https://github.com/parrotsec/anonsurf
#
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
# ===================================================================


# ===================================================================
# General settings
# ===================================================================
#
# Program information
readonly prog_name="kalitorify"
readonly version="1.24.0"
readonly signature="Copyright (C) 2015-2020 Brainfuck"
readonly git_url="https://github.com/brainfucksec/kalitorify"

# Set colors for terminal output
export red="$(tput setaf 1)"
export green="$(tput setaf 2)"
export yellow="$(tput setaf 3)"
export blue="$(tput setaf 4)"
export magenta="$(tput setaf 5)"
export cyan="$(tput setaf 6)"
export white="$(tput setaf 7)"
export b="$(tput bold)"
export reset="$(tput sgr0)"


# ===================================================================
# Set program's directories and files
# ===================================================================
#
# Configuration files:
readonly config_dir="/usr/share/kalitorify/data"
# Backup files:
readonly backup_dir="/usr/share/kalitorify/backups"


# ===================================================================
# Network settings
# ===================================================================
#
# The UID that Tor runs as (varies from system to system)
#`id -u debian-tor` #Debian/Ubuntu
readonly tor_uid="$(id -u debian-tor)"

# Tor TransPort
readonly trans_port="9040"

# Tor DNSPort
readonly dns_port="5353"

# Tor VirtualAddrNetworkIPv4
readonly virtual_address="10.192.0.0/10"

# LAN destinations that shouldn't be routed through Tor
readonly non_tor="127.0.0.0/8 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16"


# ===================================================================
# Show program banner
# ===================================================================
#
# Thanks to: https://github.com/dylanaraps/neofetch
# for the Kali Linux ASCII logo
banner() {

printf "${b}${white}
 _____     _ _ _           _ ___
|  |  |___| |_| |_ ___ ___|_|  _|_ _
|    -| .'| | |  _| . |  _| |  _| | |
|__|__|__,|_|_|_| |___|_| |_|_| |_  |
                                |___| v${version}

=[ Transparent proxy through Tor
=[ brainfucksec
${reset}\\n\\n"
}


# ===================================================================
# Print a message and exit with (1) when an error occurs
# ===================================================================
die() {
    printf "${b}${red}%s${reset}\\n" "$@" >&2
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
    printf "%s\\n" "${prog_name} ${version}"
	exit 0
}


# ===================================================================
# Check program settings
# ===================================================================
#
# - required packages: tor, curl
# - program folders, see: $backup_dir, $config_dir
# - tor configuration file: /etc/tor/torrc
check_settings() {
    printf "${b}${cyan}%s${reset} ${b}%s${reset}\\n" "::" "Check program settings"

    # Check: dependencies
    declare -a dependencies=('tor' 'curl')
    for package in "${dependencies[@]}"; do
        if ! hash "${package}" 2>/dev/null; then
            die "[ failed ] '${package}' isn't installed, exit"
        fi
    done

    # Check: default directories
    if [ ! -d "${backup_dir}" ]; then
        die "[ failed ] directory '${backup_dir}' not exist, run makefile first!"
    fi

    if [ ! -d "${config_dir}" ]; then
        die "[ failed ] directory '${config_dir}' not exist, run makefile first!"
    fi

    # Check: file `/etc/tor/torrc`
    #
    # if /etc/tor/torrc not exists copy the file from ${config_dir}/torrc
    if [[ ! -f /etc/tor/torrc ]]; then

        printf "${b}${green}%s${reset} %s\\n" "==>" "Copy file: /etc/tor/torrc"

        if ! cp "${config_dir}/torrc" /etc/tor/torrc; then
            die "[ failed ] can't modify '/etc/tor/torrc'"
        fi
    # else if exists check if have the required strings
    else
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

        # if required strings does not exists copy the file $config_dir/torrc
        if [[ "$string1" -ne 0 ]] ||
           [[ "$string2" -ne 0 ]] ||
           [[ "$string3" -ne 0 ]] ||
           [[ "$string4" -ne 0 ]] ||
           [[ "$string5" -ne 0 ]]; then

            printf "${b}${green}%s${reset} %s\\n" "==>" "Setting file: /etc/tor/torrc"

            # backup original file
            if ! cp /etc/tor/torrc "${backup_dir}/torrc.backup"; then
                die "[ failed ] can't copy original tor 'torrc' file in the backup directory"
            fi

            # copy new torrc file
            if ! cp "${config_dir}/torrc" /etc/tor/torrc; then
                die "[ failed ] can't modify '/etc/tor/torrc'"
            fi
        fi
    fi

    # reload systemd daemons
    printf "\\n${b}${green}%s${reset} %s\\n" "==>" "Reload systemd daemons"
    systemctl --system daemon-reload
    printf "${b}${green}%s${reset} ${b}%s${reset}\\n" \
            "[ ok ]" "systemd daemons reloaded"
}


# ===================================================================
# iptables settings
# ===================================================================
#
# Setup iptables rules.  This function is used for give the arguments in
# start() and stop() functions.
#
# Arguments:
# tor_proxy -> set rules for Tor transparent proxy
# default   -> restore default rules
setup_iptables() {
    case "$1" in
        tor_proxy)
            printf "${b}${green}%s${reset} %s\\n" "==>" "Setup new iptables rules"

            ## Flush current iptables rules
            iptables -F
            iptables -X
            iptables -t nat -F
            iptables -t nat -X

            ## *nat OUTPUT (For local redirection)
            #
            # nat .onion addresses
            iptables -t nat -A OUTPUT -d $virtual_address -p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK SYN -j REDIRECT --to-ports $trans_port

            # nat dns requests to Tor
            iptables -t nat -A OUTPUT -d 127.0.0.1/32 -p udp -m udp --dport 53 -j REDIRECT --to-ports $dns_port

            # Don't nat the Tor process, the loopback, or the local network
            iptables -t nat -A OUTPUT -m owner --uid-owner $tor_uid -j RETURN
            iptables -t nat -A OUTPUT -o lo -j RETURN

            # Allow lan access for hosts in $non_tor
            for lan in $non_tor; do
                iptables -t nat -A OUTPUT -d $lan -j RETURN
            done

            # Redirects all other pre-routing and output to Tor's TransPort
            iptables -t nat -A OUTPUT -p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK SYN -j REDIRECT --to-ports $trans_port

            ## *filter INPUT
            iptables -A INPUT -m state --state ESTABLISHED -j ACCEPT
            iptables -A INPUT -i lo -j ACCEPT

            # Drop everything else
            iptables -A INPUT -j DROP

            ## *filter FORWARD
            iptables -A FORWARD -j DROP

            ## *filter OUTPUT
            #
            # Fix for potential kernel transproxy packet leaks
            # see: https://lists.torproject.org/pipermail/tor-talk/2014-March/032507.html
            iptables -A OUTPUT -m conntrack --ctstate INVALID -j DROP

            iptables -A OUTPUT -m state --state INVALID -j DROP
            iptables -A OUTPUT -m state --state ESTABLISHED -j ACCEPT

            # Allow Tor process output
            iptables -A OUTPUT -m owner --uid-owner $tor_uid -p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK SYN -m state --state NEW -j ACCEPT

            # Allow loopback output
            iptables -A OUTPUT -d 127.0.0.1/32 -o lo -j ACCEPT

            # Tor transproxy magic
            iptables -A OUTPUT -d 127.0.0.1/32 -p tcp -m tcp --dport $trans_port --tcp-flags FIN,SYN,RST,ACK SYN -j ACCEPT

            # Drop everything else
            iptables -A OUTPUT -j DROP

            ## Set default policies to DROP
            iptables -P INPUT DROP
            iptables -P FORWARD DROP
            iptables -P OUTPUT DROP
        ;;

        default)
            printf "${b}${green}%s${reset} %s\\n" \
                    "==>" "Restore default iptables rules"

            # Flush iptables rules
            iptables -F
            iptables -X
            iptables -t nat -F
            iptables -t nat -X
            iptables -P INPUT ACCEPT
            iptables -P FORWARD ACCEPT
            iptables -P OUTPUT ACCEPT
        ;;
    esac
}


# ===================================================================
# Check public IP
# ===================================================================
check_ip() {
    printf "${b}${cyan}%s${reset} ${b}%s${reset}\\n" "::" \
            "Checking your public IP..."

    # url list for curl requests
    local url_list=(
        'http://ip-api.com/'
        'https://ipleak.net/json/'
        'https://ipinfo.io/'
        'https://api.myip.com/'
    )

    # if the first request fails try with the next
    for url in "${url_list[@]}"; do
        local request="$(curl -s "$url")"
        local response="$?"

        if [[ "$response" -ne 0 ]]; then
            continue
        fi

        printf "${b}${green}%s${reset} ${b}%s${reset}\n" "[!]" "IP Address details:"
        printf "%s\\n" "${request}"
        break
    done
}


# ===================================================================
# Check status of program and services
# ===================================================================
#
# - tor.service
# - tor settings
# - public IP
check_status() {
    # Check status of tor.service
    printf "${b}${cyan}%s${reset} ${b}%s${reset}\\n" \
            "::" "Check current status of Tor service"

    if systemctl is-active tor.service >/dev/null 2>&1; then
        printf "${b}${green}%s${reset} ${b}%s${reset}\\n\\n" \
                "[ ok ]" "Tor service is active"
    else
        die "[-] Tor service is not running! exit"
    fi

    # Check tor network settings
    #
    # make http request with curl at: https://check.torproject.org/
    # and grep the necessary strings from the html page to test connection
    # with tor
    printf "${b}${cyan}%s${reset} ${b}%s${reset}\\n" \
                "::" "Check Tor network settings"

    # curl options details:
    #   --socks5 <host[:port]> SOCKS5 proxy on given host + port
    #   --socks5-hostname <host[:port]> SOCKS5 proxy, pass host name to proxy
    #
    #   `-L` and `tac` options for avoid error: "(23) Failed writing body"
    #   https://github.com/kubernetes/helm/issues/2802
    #   https://stackoverflow.com/questions/16703647/why-curl-return-and-error-23-failed-writing-body
    local hostport="localhost:9050"
    local url="https://check.torproject.org/"

    if curl -s -m 10 --socks5 "${hostport}" --socks5-hostname "${hostport}" -L "${url}" \
        | cat | tac | grep -q 'Congratulations'; then
        printf "${b}${green}%s${reset} ${b}%s${reset}\\n\\n" \
                "[ ok ]" "Your system is configured to use Tor"
    else
        printf "${b}${red}%s${reset}\\n\\n" "[!] Your system is not using Tor"
        printf "%s\\n" "try another Tor circuit with '${prog_name} --restart'"
        exit 1
    fi

    # Check current public IP
    check_ip
}


# ===================================================================
# Start transparent proxy
# ===================================================================
start() {
    banner
    check_root
    sleep 2
    check_settings

    # stop tor.service before changing tor settings
    if systemctl is-active tor.service >/dev/null 2>&1; then
        systemctl stop tor.service
    fi

    printf "\\n${b}${cyan}%s${reset} ${b}%s${reset}\\n" \
            "::" "Starting Transparent Proxy"

    # DNS settings: /etc/resolv.conf:
    #
    # Configure system's DNS resolver to use Tor's DNSPort
    # on the loopback interface, i.e. write nameserver 127.0.0.1
    # to `/etc/resolv.conf` file
    printf "${b}${green}%s${reset} %s\\n" "==>" "Configure DNS to use Tor's DNSPort"

    # backup current resolv.conf
    if ! cp /etc/resolv.conf "${backup_dir}/resolv.conf.backup"; then
        die "[ failed ] can't modify /etc/resolv.conf"
    fi

    # write new nameserver
    printf "%s\\n" "nameserver 127.0.0.1" > /etc/resolv.conf


    # Disable IPv6 with sysctl
    printf "${b}${green}%s${reset} %s\\n" "==>" "Disable IPv6 with sysctl"
    sysctl -w net.ipv6.conf.all.disable_ipv6=1 >/dev/null 2>&1
    sysctl -w net.ipv6.conf.default.disable_ipv6=1 >/dev/null 2>&1

    # Start tor.service for new configuration
    printf "${b}${green}%s${reset} %s\\n" "==>" "Start Tor service"

    if ! systemctl start tor.service >/dev/null 2>&1; then
        die "[ failed ] systemd error, exit!"
    fi

    # Set new iptables rules
    setup_iptables tor_proxy
    printf "\\n"

    # check program status
    check_status

    printf "\\n${b}${green}%s${reset} ${b}%s${endc}\\n" \
    	   "[ ok ]" "Transparent Proxy activated, your system is under Tor"
}


# ===================================================================
# Stop transparent proxy
# ===================================================================
#
# Stop connection with Tor Network and return to clearnet navigation
stop() {
    banner
    check_root

    printf "${b}${cyan}%s${reset} ${b}%s${reset}\\n" \
            "::" "Stopping Transparent Proxy"

    # Resets default iptables rules
    setup_iptables default

    # Stop tor.service
    printf "${b}${green}%s${reset} %s\\n" "==>" "Stop tor service"
    systemctl stop tor.service

    # Restore `/etc/resolv.conf`:
    #
    # restore file with `resolvconf` program if exists
    # otherwise copy the original file from backup directory
    printf "${b}${green}%s${reset} %s\\n" \
            "==>" "Restore /etc/resolv.conf file with default DNS"

    if hash resolvconf 2>/dev/null; then
        resolvconf -u
    else
        cp "${backup_dir}/resolv.conf.backup" /etc/resolv.conf
    fi

    # Enable IPv6
    printf "${b}${green}%s${reset} %s\\n" "==>" "Enable IPv6"
    sysctl -w net.ipv6.conf.all.disable_ipv6=0 >/dev/null 2>&1
    sysctl -w net.ipv6.conf.default.disable_ipv6=0 >/dev/null 2>&1

    # Restore default `/etc/tor/torrc`
    printf "${b}${green}%s${reset} %s\\n" "==>" "Restore default '/etc/tor/torrc'"
    cp "${backup_dir}/torrc.backup" /etc/tor/torrc

    printf "\\n${b}${green}%s${reset} ${b}%s${reset}\\n" \
            "[-]" "Transparent Proxy stopped"
}


# ===================================================================
# Restart tor.service and change public IP (i.e. new Tor exit node)
# ===================================================================
restart() {
    check_root

    if systemctl is-active tor.service >/dev/null 2>&1; then
        printf "${b}${cyan}%s${reset} ${b}%s${reset}\\n" \
                "::" "Restart Tor service and change IP"

        systemctl restart tor.service
        sleep 1

        printf "${b}${green}%s${reset} ${b}%s${reset}\\n\\n" \
                "[ ok ]" "Tor Exit Node changed"

        # Check current public IP
        check_ip
        exit 0
    else
        die "[-] Tor service is not running! exit"
    fi
}


# ===================================================================
# Show help menù
# ===================================================================
usage() {
    printf "%s\\n" "${prog_name} ${version}"
    printf "%s\\n" "Kali Linux - Transparent proxy through Tor"
    printf "%s\\n\\n" "${signature}"

    printf "%s\\n\\n" "Usage: ${prog_name} [option]"

    printf "%s\\n\\n" "Options:"

    printf "%s\\n" "-h, --help      show this help message and exit"
    printf "%s\\n" "-t, --tor       start transparent proxy through tor"
    printf "%s\\n" "-c, --clearnet  reset iptables and return to clearnet navigation"
    printf "%s\\n" "-s, --status    check status of program and services"
    printf "%s\\n" "-i, --ipinfo    show public IP"
    printf "%s\\n" "-r, --restart   restart tor service and change Tor exit node"
    printf "%s\\n\\n" "-v, --version   display program version and exit"

    printf "%s\\n" "Project URL: ${git_url}"
    printf "%s\\n" "Report bugs: ${git_url}/issues"

    exit 0
}


# ===================================================================
# Main function
# ===================================================================
#
# Parse command line arguments and start program
main() {
    if [[ "$#" -eq 0 ]]; then
        printf "%s\\n" "${prog_name}: Argument required"
        printf "%s\\n" "Try '${prog_name} --help' for more information."
        exit 1
    fi

    while [[ "$#" -gt 0 ]]; do
        case "$1" in
            -t | --tor)
                start
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
                printf "%s\\n" "${prog_name}: Invalid option '$1'"
                printf "%s\\n" "Try '${prog_name} --help' for more information."
                exit 1
                ;;
        esac
        shift
    done
}

main "$@"
