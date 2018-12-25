#!/usr/bin/env bash

# kalitorify.sh
#
# Kali Linux - Transparent proxy through Tor
#
# Copyright (C) 2015-2018 Brainfuck
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


# ===================================================================
# General settings
# ===================================================================

# Program information
readonly prog_name="kalitorify"
readonly version="1.14.0"
readonly author="Brainfuck"
readonly git_url="https://github.com/brainfucksec/kalitorify"

# URL for bug reports
readonly report_url="https://github.com/brainfucksec/kalitorify/issues"

# Colors for terminal output
export red=$'\e[0;91m'
export green=$'\e[0;92m'
export blue=$'\e[0;94m'
export white=$'\e[0;97m'
export bold_white=$'\e[1;97m'
export cyan=$'\e[0;96m'
export endc=$'\e[0m'


# ===================================================================
# Set program's directories and files
# ===================================================================

# Configuration files: /usr/share/kalitorify/data
# Backup files: /opt/kalitorify/backups
readonly config_dir="/usr/share/kalitorify/data"
readonly backup_dir="/opt/kalitorify/backups"


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
printf "${bold_white}
#####################################

 _____     _ _ _           _ ___
|  |  |___| |_| |_ ___ ___|_|  _|_ _
|    -| .'| | |  _| . |  _| |  _| | |
|__|__|__,|_|_|_| |___|_| |_|_| |_  |
                                |___|

#####################################

=[ Kali Linux
=[ Transparent proxy through Tor${endc}\\n"

printf "${white}
Version: $version
Author: $author
$git_url${endc}\\n\\n"
}


# ===================================================================
# Check if the program run as a root
# ===================================================================
check_root() {
    if [[ "$(id -u)" -ne 0 ]]; then
        printf "\\n${red}%s${endc}\\n" \
               "[ failed ] Please run this program as a root!" 2>&1
        exit 1
    fi
}


# ===================================================================
# Display program and Tor version
# ===================================================================
print_version() {
    printf "%s\\n" "$prog_name version $version"
    printf "%s\\n" "$(tor --version)"
	exit 0
}


# ===================================================================
# Disable firewall ufw
# ===================================================================

# See: https://wiki.ubuntu.com/UncomplicatedFirewall
#
# If ufw is installed and/or active, disable it, if isn't installed,
# do nothing, don't display nothing to user, just jump to the next function
disable_ufw() {
	if hash ufw 2>/dev/null; then
    	if ufw status | grep -q active$; then
        	printf "${blue}%s${endc} ${green}%s${endc}\\n" \
                   "::" "Disabling firewall ufw, please wait..."
        	ufw disable
    	else
    		ufw status | grep -q inactive$;
        	printf "${blue}%s${endc} ${green}%s${endc}\\n" \
                   "::" "Firewall ufw is inactive, continue..."
    	fi
    fi
}


# ===================================================================
# Enable ufw
# ===================================================================

# Often, if ufw isn't installed, again, do nothing
# and jump to the next function
enable_ufw() {
	if hash ufw 2>/dev/null; then
    	if ufw status | grep -q inactive$; then
        	printf "\\n${blue}%s${endc} ${green}%s${endc}\\n" \
                   "::" "Enabling firewall ufw, please wait..."
        	ufw enable
        fi
    fi
}


# ===================================================================
# Check default settings
# ===================================================================

# Check:
# -> required dependencies (tor, curl)
# -> program folders
# -> tor `torrc` configuration file
check_defaults() {
    # Check: dependencies
    # ===================
    declare -a dependencies=('tor' 'curl');

    for package in "${dependencies[@]}"; do
        if ! hash "$package" 2>/dev/null; then
            printf "\\n${red}%s${endc}\\n" \
                   "[ failed ] '$package' isn't installed, exit";
            exit 1
        fi
    done

    # Check: program's default directories
    # ====================================
    #
    # bash `-d`: test if the given directory exists or not.
    if [ ! -d "$backup_dir" ]; then
        printf "\\n${red}%s${endc}\\n" \
               "[ failed ] directory '$backup_dir' not exist, run makefile first!";
        exit 1
    fi

    if [ ! -d "$config_dir" ]; then
        printf "\\n${red}%s${endc}\\n" \
               "[ failed ] directory '$config_dir' not exist, run makefile first!";
        exit 1
    fi

    # Check: file `/etc/tor/torrc`
    # ============================
    #
    # reference file: `/usr/share/kalitorify/data/torrc`
    #
    # if torrc not exists copy from reference file
    if [[ ! -f /etc/tor/torrc ]]; then
        printf "\\n${blue}%s${endc} ${green}%s${endc}\\n" \
               "::" "Setting file: /etc/tor/torrc..."

        if ! cp -vf "$config_dir/torrc" /etc/tor/torrc; then
            printf "\\n${red}%s${endc}\\n" "[ failed ] can't set '/etc/tor/torrc'"
            printf "${red}%s${endc}\\n" "Please report bugs at: $report_url"
            exit 1
        fi
    else
        # grep required strings from existing file
        grep -q -x 'VirtualAddrNetworkIPv4 10.192.0.0/10' /etc/tor/torrc
        VAR1=$?

        grep -q -x 'AutomapHostsOnResolve 1' /etc/tor/torrc
        VAR2=$?

        grep -q -x 'TransPort 9040 IsolateClientAddr IsolateClientProtocol IsolateDestAddr IsolateDestPort' /etc/tor/torrc
        VAR3=$?

        grep -q -x 'SocksPort 9050' /etc/tor/torrc
        VAR4=$?

        grep -q -x 'DNSPort 5353' /etc/tor/torrc
        VAR5=$?

        # if required strings does not exists replace original
        # `/etc/tor/torrc` file
        if [[ $VAR1 -ne 0 ]] ||
           [[ $VAR2 -ne 0 ]] ||
           [[ $VAR3 -ne 0 ]] ||
           [[ $VAR4 -ne 0 ]] ||
           [[ $VAR5 -ne 0 ]]; then
            printf "\\n${blue}%s${endc} ${green}%s${endc}\\n" \
                   "::" "Setting file: /etc/tor/torrc..."

            # backup original tor `/etc/tor/torrc` file
            # in the backup directory
            if ! cp -vf /etc/tor/torrc "$backup_dir/torrc.backup"; then
                printf "\\n${red}%s${endc}\\n" \
                       "[ failed ] can't copy original tor 'torrc' file in the backup directory"

                printf "${red}%s${endc}\\n" "Please report bugs at: $report_url"
                exit 1
            fi

            # copy new `torrc` file with settings for kalitorify
            if ! cp -vf "$config_dir/torrc" /etc/tor/torrc; then
                printf "\\n${red}%s${endc}\\n" "[ failed ] can't set '/etc/tor/torrc'"
                printf "${red}%s${endc}\\n" "Please report bugs at: $report_url"
                exit 1
            fi
        fi
    fi
}


# ===================================================================
# Start transparent proxy
# ===================================================================
main() {
    banner
    check_root
    sleep 1
    check_defaults

    # Stop tor.service
    # ================
    if systemctl is-active tor.service >/dev/null 2>&1; then
        systemctl stop tor.service
    fi

    printf "\\n${cyan}%s${endc} ${green}%s${endc}\\n" \
           "==>" "Starting Transparent Proxy"

    sleep 2
    disable_ufw

    # DNS settings: `/etc/resolv.conf`:
    # =================================
    #
    # Configure system's DNS resolver to use Tor's DNSPort
    # on the loopback interface, i.e. write nameserver 127.0.0.1
    # to `/etc/resolv.conf` file
    printf "\\n${blue}%s${endc} ${green}%s${endc}\\n" \
           "::" "Configure system's DNS resolver to use Tor's DNSPort"

    # backup current resolv.conf
    if ! cp -vf /etc/resolv.conf "$backup_dir/resolv.conf.backup"; then
        printf "${red}%s${endc}\\n" \
               "[ failed ] can't copy resolv.conf to the backup directory"

        printf "${red}%s${endc}\\n" "Please report bugs at: $report_url"
        exit 1
    fi

    # write new nameserver
    printf "%s\\n" "nameserver 127.0.0.1" > /etc/resolv.conf
    sleep 1

    # Start tor.service for new configuration
    # =======================================
    printf "\\n${blue}%s${endc} ${green}%s${endc}\\n" "::" "Start Tor service"
    if systemctl start tor.service 2>/dev/null; then
        printf "${cyan}%s${endc} ${green}%s${endc}\\n" \
               "[ ok ]" "Tor service started"
    else
        printf "${red}%s${endc}\\n" "[ failed ] systemd error, exit!"
        exit 1
    fi
    sleep 2

    # iptables settings
    # =================
    #
    # Save current iptables rules
    printf "\\n${blue}%s${endc} ${green}%s${endc}" "::" "Backup iptables... "
    iptables-save > "$backup_dir/iptables.backup"
    printf "%s\\n" "Done"

    # Flush current iptables rules
    printf "${blue}%s${endc} ${green}%s${endc}" "::" "Flush current iptables... "
    iptables -F
    iptables -t nat -F
    printf "%s\\n" "Done"

    # Set new iptables rules
    # ======================
    printf "${blue}%s${endc} ${green}%s${endc}" "::" "Set new iptables rules... "

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

    printf "%s\\n\\n" "Done"

    # check program status
    check_status

    printf "${cyan}%s${endc} ${green}%s${endc}\\n" \
    	    "[ ok ]" "Transparent Proxy activated, your system is under Tor"
}


# ===================================================================
# Stop transparent proxy
# ===================================================================

# Stop connection with Tor Network and return to clearnet navigation
stop() {
    check_root

    printf "${cyan}%s${endc} ${green}%s${endc}\\n" \
           "==>" "Stopping Transparent Proxy"
    sleep 2

    # Resets default settings:
    # ========================
    #
    # Flush current iptables rules
    printf "${blue}%s${endc} ${green}%s${endc}" "::" "Flush iptables rules... "
    iptables -F
    iptables -t nat -F
    printf "%s\\n" "Done"

    # Restore iptables
    printf "${blue}%s${endc} ${green}%s${endc}" \
           "::" "Restore the default iptables rules... "

    iptables-restore < "$backup_dir/iptables.backup"
    printf "%s\\n" "Done"

    # Stop tor.service
    printf "${blue}%s${endc} ${green}%s${endc}" "::" "Stop tor service... "
    systemctl stop tor.service
    printf "%s\\n" "Done"

    # Restore `/etc/resolv.conf`
    # ==========================
    printf "\\n${blue}%s${endc} ${green}%s${endc}\\n" \
           "::" "Restore /etc/resolv.conf file with default DNS"

    # delete current `/etc/resolv.conf` file
    rm -v /etc/resolv.conf

    # restore file with `resolvconf` program if exists
    # otherwise copy the original file from backup directory
    if hash resolvconf 2>/dev/null; then
        resolvconf -u
    else
        cp -vf "$backup_dir/resolv.conf.backup" /etc/resolv.conf
    fi
    sleep 1

    # Restore default `/etc/tor/torrc`
    # ================================
    printf "\\n${blue}%s${endc} ${green}%s${endc}\\n" \
           "::" "Restore '/etc/tor/torrc' file with default tor settings"

    cp -vf "$backup_dir/torrc.backup" /etc/tor/torrc

    # Enable firewall ufw
    enable_ufw

    # == End program
    printf "\\n${cyan}%s${endc} ${green}%s${endc}\\n" \
           "[-]" "Transparent Proxy stopped"
}


# ===================================================================
# Check public IP
# ===================================================================
check_ip() {
    check_root

    printf "${cyan}%s${endc} ${green}%s${endc}\\n" \
           "==>" "Checking your public IP, please wait..."

    # curl request: http://ipinfo.io/geo
    if ! external_ip="$(curl -s -m 10 ipinfo.io/geo)"; then
        printf "${red}%s${endc}\\n" "[ failed ] curl: HTTP request error!"
        printf "${red}%s${endc}\\n" "Please check your network settings."
        exit 1
    fi

    # Print output
    printf "${blue}%s${endc} ${green}%s${endc}\\n" "::" "IP Address Details:"
    printf "${white}%s${endc}\\n" "$external_ip" | tr -d '"{}' | sed 's/ //g'
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
    printf "${cyan}%s${endc} ${green}%s${endc}\\n" \
           "==>" "Check current status of Tor service"

    if systemctl is-active tor.service > /dev/null 2>&1; then
        printf "${cyan}%s${endc} ${green}%s${endc}\\n\\n" \
               "[ ok ]" "Tor service is active"
    else
        printf "${red}%s${endc}\\n" "[-] Tor service is not running! exit"
        exit 1
    fi

    # Check tor network settings
    # ==========================
    #
    # make http request with curl at: https://check.torproject.org/
    # and grep the necessary strings from the html page to test connection
    # with tor
    printf "${cyan}%s${endc} ${green}%s${endc}\\n" \
           "==>" "Check Tor network settings"

    # curl option: --socks5 <host[:port]> SOCKS5 proxy on given host + port
    local hostport="localhost:9050"
    # destination url
    local url="https://check.torproject.org/"

    # curl: `-L` and `tac` for avoid error: (23) Failed writing body
    # https://github.com/kubernetes/helm/issues/2802
    # https://stackoverflow.com/questions/16703647/why-curl-return-and-error-23-failed-writing-body
    if curl -m 15 --socks5 "$hostport" --socks5-hostname "$hostport" -sL "$url" \
        | cat | tac | grep -q 'Congratulations'; then
        printf "${cyan}%s${endc} ${green}%s${endc}\\n\\n" \
               "[ ok ]" "Your system is configured to use Tor"
    else
        printf "${red}%s${endc}\\n" "Your system is not using Tor:"
        printf "%s\\n" "try restarting the program with '$prog_name --restart'"
        printf "%s\\n" "or report bug at: $report_url"
        exit 1
    fi

    # Check current public IP
    check_ip
}


# ===================================================================
# Restart tor.service and change public IP (i.e. newtor exit node)
# ===================================================================
restart() {
    check_root

    printf "${cyan}%s${endc} ${green}%s${endc}\\n" \
           "==>" "Restart Tor service and change IP"

    service tor reload
    sleep 3

    printf "${cyan}%s${endc} ${green}%s${endc}\\n\\n" \
           "[ ok ]" "Tor Exit Node changed"

    # Check current public IP
    check_ip
    exit 0
}


# ===================================================================
# Show help menù
# ===================================================================
usage() {
    printf "${green}%s${endc}\\n" "$prog_name $version"

    printf "${green}%s${endc}\\n\\n" "Kali Linux - Transparent proxy through Tor"

    printf "${white}%s${endc}\\n\\n" "Usage:"

    printf "${white}%s${endc} ${red}%s${endc} ${white}%s${endc} ${red}%s${endc}\\n" \
        "┌─╼" "$USER" "╺─╸" "$(hostname)"
    printf "${white}%s${endc} ${green}%s${endc}\\n\\n" "└───╼" "$prog_name [option]"

    printf "${white}%s${endc}\\n\\n" "Options:"

    printf "${green}%s${endc}\\n" \
           "-h, --help      show this help message and exit"

    printf "${green}%s${endc}\\n" \
           "-t, --tor       start transparent proxy through tor"

    printf "${green}%s${endc}\\n" \
           "-c, --clearnet  reset iptables and return to clearnet navigation"

    printf "${green}%s${endc}\\n" \
           "-s, --status    check status of program and services"

    printf "${green}%s${endc}\\n" \
           "-i, --ipinfo    show public IP"

    printf "${green}%s${endc}\\n" \
           "-r, --restart   restart tor service and change IP"

    printf "${green}%s${endc}\\n" \
           "-v, --version   print version number of program and tor package"
    exit 0
}


# ===================================================================
# Parse command line options
# ===================================================================
if [ "$#" -eq 0 ]; then
    printf "%s\\n" "$prog_name: Argument required"
    printf "%s\\n" "Try '$prog_name --help' for more information."
    exit 1
fi

while [ "$#" -gt 0 ]; do
    case "$1" in
        -t | --tor)
            main
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
