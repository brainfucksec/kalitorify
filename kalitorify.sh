#!/usr/bin/env bash

################################################################################
#                                                                              #
# kalitorify.sh                                                                #
#                                                                              #
# version: 1.26.1                                                              #
#                                                                              #
# Kali Linux - Transparent proxy through Tor                                   #
#                                                                              #
# Copyright (C) 2015-2021 Brainfuck                                            #
#                                                                              #
# Kalitorify is KISS version of Parrot AnonSurf Module, developed              #
# by "Pirates' Crew" of FrozenBox - https://github.com/parrotsec/anonsurf      #
#                                                                              #
#                                                                              #
# GNU GENERAL PUBLIC LICENSE                                                   #
#                                                                              #
# This program is free software: you can redistribute it and/or modify         #
# it under the terms of the GNU General Public License as published by         #
# the Free Software Foundation, either version 3 of the License, or            #
# (at your option) any later version.                                          #
#                                                                              #
# This program is distributed in the hope that it will be useful,              #
# but WITHOUT ANY WARRANTY; without even the implied warranty of               #
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the                #
# GNU General Public License for more details.                                 #
#                                                                              #
# You should have received a copy of the GNU General Public License            #
# along with this program.  If not, see <http://www.gnu.org/licenses/>.        #
#                                                                              #
################################################################################


## General
#
# program information
readonly prog_name="kalitorify"
readonly version="1.26.1"
readonly signature="Copyright (C) 2021 Brainfuck"
readonly git_url="https://github.com/brainfucksec/kalitorify"

# set colors for stdout
export red="$(tput setaf 1)"
export green="$(tput setaf 2)"
export yellow="$(tput setaf 3)"
export blue="$(tput setaf 4)"
export magenta="$(tput setaf 5)"
export cyan="$(tput setaf 6)"
export white="$(tput setaf 7)"
export b="$(tput bold)"
export reset="$(tput sgr0)"


## Directories
#
# config files:
readonly config_dir="/usr/share/kalitorify/data"
# backups:
readonly backup_dir="/usr/share/kalitorify/backups"

## Network settings
#
# the UID that Tor runs as (varies from system to system)
# $(id -u debian-tor) #Debian/Ubuntu
readonly tor_uid="$(id -u debian-tor)"

# Tor TransPort
readonly trans_port="9040"

# Tor DNSPort
readonly dns_port="5353"

# Tor VirtualAddrNetworkIPv4
readonly virtual_address="10.192.0.0/10"

# LAN destinations that shouldn't be routed through Tor
readonly non_tor="127.0.0.0/8 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16"


## Show program banner
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


## Print a message and exit with (1) when an error occurs
die() {
    printf "${red}%s${reset}\\n" "[ERROR] $@" >&2
    exit 1
}


## Print information
info() {
    printf "${b}${blue}%s${reset} ${b}%s${reset}\\n" "::" "${@}"

}


## Print `OK` messages
msg() {
    printf "${b}${green}%s${reset} %s\\n\\n" "[OK]" "${@}"
}


## Check if the program run as a root
check_root() {
    if [[ "${UID}" -ne 0 ]]; then
        die "Please run this program as a root!"
    fi
}


## Display program version and License
print_version() {
    printf "%s\\n" "${prog_name} ${version}"
    printf "%s\\n" "${signature}"
    printf "%s\\n" "License GNU GPL version 3 or later <https://gnu.org/licenses/gpl.html>"
    printf "%s\\n" "This is free software: you are free to change and redistribute it."
    printf "%s\\n" "There is NO WARRANTY, to the extent permitted by law."
    exit 0
}


## Check program settings
#
# - required packages: tor, curl
# - program folders, see: ${backup_dir}, ${config_dir}
# - tor configuration file: /etc/tor/torrc
check_settings() {
    info "Check program settings"

    declare -a dependencies=('tor' 'curl')
    for package in "${dependencies[@]}"; do
        if ! hash "${package}" 2>/dev/null; then
            die "'${package}' isn't installed, exit"
        fi
    done

    if [[ ! -d "${backup_dir}" ]]; then
        die "directory '${backup_dir}' not exist, run makefile first!"
    fi

    if [[ ! -d "${config_dir}" ]]; then
        die "directory '${config_dir}' not exist, run makefile first!"
    fi

    if [[ ! -f /etc/tor/torrc ]]; then
        die "/etc/tor/torrc file not exist, check Tor configuration"
    fi

    # check torrc settings
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

    # if required strings does not exists copy file from /usr/share/kalitorify
    if [[ "$string1" -ne 0 ]] ||
       [[ "$string2" -ne 0 ]] ||
       [[ "$string3" -ne 0 ]] ||
       [[ "$string4" -ne 0 ]] ||
       [[ "$string5" -ne 0 ]]; then

        printf "%s\\n" "Set /etc/tor/torrc"

        if ! cp -f /etc/tor/torrc "${backup_dir}/torrc.backup"; then
            die "can't backup '/etc/tor/torrc'"
        fi

        if ! cp -f "${config_dir}/torrc" /etc/tor/torrc; then
            die "can't copy new '/etc/tor/torrc'"
        fi
    fi

    # reload systemd daemons
    printf "%s\\n" "Reload systemd daemons"
    systemctl --system daemon-reload
}


## iptables settings
#
# This function is used with args in start() and stop()
# for set/restore iptables.
#
# Args:
#   tor_proxy -> set rules for Tor transparent proxy
#   default   -> restore default rules
setup_iptables() {
    case "$1" in
        tor_proxy)
            printf "%s\\n" "Set iptables rules"

            ## Flush current iptables rules
            iptables -F
            iptables -X
            iptables -t nat -F
            iptables -t nat -X
            iptables -P INPUT ACCEPT
            iptables -P FORWARD ACCEPT
            iptables -P OUTPUT ACCEPT

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
            printf "%s\\n" "Restore default iptables rules"

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


## Check public IP address
#
# Make an HTTP request to the URL in the list, if the first request fails try
# with the next, then print the IP address.
check_ip() {
    info "Check public IP address"

    local url_list=(
        'https://ipleak.net/json/'
        'https://api.myip.com/'
        'https://ipinfo.io/'
        'http://ip-api.com/'
    )

    for url in "${url_list[@]}"; do
        local request="$(curl -s "$url")"
        local response="$?"

        if [[ "$response" -ne 0 ]]; then
            continue
        fi

        printf "%s\\n" "${request}"
        break
    done
}


## Check status of program and services
#
# - tor.service
# - tor settings (check if Tor works correctly)
# - public IP Address
check_status() {
    info "Check current status of Tor service"

    if systemctl is-active tor.service >/dev/null 2>&1; then
        msg "Tor service is active"
    else
        die "Tor service is not running! exit"
    fi

    # make an HTTP request with curl at: https://check.torproject.org/
    # and grep the necessary strings from the HTML page to test connection
    # with Tor
    info "Check Tor network settings"

    # curl option details:
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
        msg "Your system is configured to use Tor"
    else
        printf "${red}%s${reset}\\n\\n" "[!] Your system is not using Tor"
        printf "%s\\n" "try another Tor circuit with '${prog_name} --restart'"
        exit 1
    fi

    check_ip
}


## Start transparent proxy through Tor
start() {
    check_root

    # Exit if tor.service is already active
    if systemctl is-active tor.service >/dev/null 2>&1; then
        die "Tor service is already active, stop it first"
    fi

    banner
    sleep 2
    check_settings

    printf "\\n"
    info "Starting Transparent Proxy"

    # DNS settings: /etc/resolv.conf:
    #
    # write nameserver 127.0.0.1 to `/etc/resolv.conf` file
    # i.e. use Tor DNSPort (see: /etc/tor/torrc)
    printf "%s\\n" "Configure resolv.conf file to use Tor DNSPort"

    # backup current resolv.conf
    if ! cp /etc/resolv.conf "${backup_dir}/resolv.conf.backup"; then
        die "can't backup '/etc/resolv.conf'"
    fi

    # write new nameserver
    printf "%s\\n" "nameserver 127.0.0.1" > /etc/resolv.conf

    # disable IPv6 with sysctl
    printf "%s\\n" "Disable IPv6 with sysctl"
    sysctl -w net.ipv6.conf.all.disable_ipv6=1 >/dev/null 2>&1
    sysctl -w net.ipv6.conf.default.disable_ipv6=1 >/dev/null 2>&1

    # start tor.service
    printf "%s\\n" "Start Tor service"

    if ! systemctl start tor.service >/dev/null 2>&1; then
        die "can't start tor service, exit!"
    fi

    # set new iptables rules
    setup_iptables tor_proxy

    # check program status
    printf "\\n"
    check_status

    printf "\\n${b}${green}%s${reset} %s\\n" \
            "[OK]" "Transparent Proxy activated, your system is under Tor"
}


## Stop transparent proxy
#
# stop connection with Tor Network and return to clearnet navigation
stop() {
    check_root

    # don't run function if tor.service is NOT running!
    if systemctl is-active tor.service >/dev/null 2>&1; then
        info "Stopping Transparent Proxy"

        # resets default iptables rules
        setup_iptables default

        printf "%s\\n" "Stop tor service"
        systemctl stop tor.service

        # restore /etc/resolv.conf:
        #
        # restore file with resolvconf program if exists
        # otherwise copy the original file from backup directory
        printf "%s\\n" "Restore default DNS"

        if hash resolvconf 2>/dev/null; then
            resolvconf -u
        else
            cp "${backup_dir}/resolv.conf.backup" /etc/resolv.conf
        fi

        # enable IPv6
        printf "%s\\n" "Enable IPv6"
        sysctl -w net.ipv6.conf.all.disable_ipv6=0 >/dev/null 2>&1
        sysctl -w net.ipv6.conf.default.disable_ipv6=0 >/dev/null 2>&1

        # restore default `/etc/tor/torrc`
        printf "%s\\n" "Restore default /etc/tor/torrc"
        cp "${backup_dir}/torrc.backup" /etc/tor/torrc

        printf "\\n${b}${green}%s${reset} %s\\n" \
                "[-]" "Transparent Proxy stopped"
        exit 0
    else
        die "Tor service is not running! exit"
    fi
}


## Restart
#
# restart tor.service (i.e. get new Tor exit node) and change public IP Address
restart() {
    check_root

    if systemctl is-active tor.service >/dev/null 2>&1; then
        info "Change IP address"

        systemctl restart tor.service
        sleep 1

        msg "IP address changed"
        check_ip
        exit 0
    else
        die "Tor service is not running! exit"
    fi
}


## Show help menù
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
    printf "%s\\n" "-i, --ipinfo    show public IP address"
    printf "%s\\n" "-r, --restart   restart tor service and change IP address"
    printf "%s\\n\\n" "-v, --version   display program version and exit"

    printf "%s\\n" "Project URL: ${git_url}"
    printf "%s\\n" "Report bugs: ${git_url}/issues"

    exit 0
}


## Main function
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


# Call main
main "${@}"

