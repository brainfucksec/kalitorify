#!/bin/bash

# install.sh - kalitorify installer
# Copyright (C) 2015 Brainfuck
#
# This file is part of Kalitorify
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

# program informations
_PROGRAM="install.sh"
_VERSION="0.1"
_AUTHOR="Brainfuck"

# define colors
export red=$'\e[0;91m'
export green=$'\e[0;92m'
export blue=$'\e[0;94m'
export cyan=$'\e[0;96m'
export white=$'\e[0;97m'
export endc=$'\e[0m'


# banner
banner () {
printf "${red}
####################################
#
# :: "$_PROGRAM"
# :: Version: "$_VERSION"
# :: Installer script for kalitorify
# :: Author: "$_AUTHOR"
# 
####################################${endc}\n\n"
}


# check if the program run as a root
check_root () {
    if [ "$(id -u)" -ne 0 ]; then
        printf "\n${red}%s${endc}\n" "[ FAILED ] Please run this program as a root!" >&2
        exit 1
    fi
}


# check dependencies (tor, curl)
check_required () {
    printf "\n${blue}%s${endc} ${green}%s${endc}\n" "==>" "Check dependencies"
    printf "${blue}%s${endc} ${green}%s${endc}\n" "==>" "Check tor"
    if ! hash tor 2>/dev/null; then
        printf "${blue}%s${endc} ${green}%s${endc}\n" "==>" "Installing tor..."
        apt-get update && apt-get install -y tor
        printf "${cyan}%s${endc} ${green}%s${endc}\n" "[ OK ]" "tor installed"
    else
        printf "${cyan}%s${endc} ${green}%s${endc}\n" "[ OK ]" "tor already installed"
    fi

    printf "${blue}%s${endc} ${green}%s${endc}\n" "==>" "Check curl"
    if ! hash curl 2>/dev/null; then
        printf "${blue}%s${endc} ${green}%s${endc}" "==>" "Installing curl..."
        apt-get update && apt-get install -y curl
        printf "${cyan}%s${endc} ${green}%s${endc}\n" "[ OK ]" "curl installed"
    else
        printf "${cyan}%s${endc} ${green}%s${endc}\n" "[ OK ]" "curl already installed"
    fi
}


# Set file and folders
install_program () {
    printf "${blue}%s${endc} ${green}%s${endc}\n" "==>" "Install kalitorify..."
    # copy program files on /usr/share/
    install -d -m644 "/usr/share/kalitorify/cfg"
    install -D -m644 "cfg/torrc" "/usr/share/kalitorify/cfg/torrc"
    install -D -m644 "LICENSE" "/usr/share/kalitorify/LICENSE"
    install -D -m644 "README.md" "/usr/share/kalitorify/README.md"
    
    # copy executable file on /usr/local/bin
    install -D -m755 "kalitorify.sh" "/usr/local/bin/kalitorify"

    # check if program run correctly
    if hash kalitorify 2>/dev/null; then
        printf "${cyan}%s${endc} ${green}%s${endc}\n" "[ OK ]" "kalitorify succesfully installed"
        printf "${green}%s${endc}\n" "run command 'kalitorify --start for start program"
    else
        printf "${red}%s${endc}\n" "[ FAILED ] kalitorify cannot start :("
        printf "${green}%s${endc}\n" "If you are in trouble read NOTES on file README"
        printf "${green}%s${endc}\n" "Report issues at: https://github.com/brainfucksec/kalitorify/issues"
    fi
}


# Main function
main () {
    banner
    check_root
    printf "${blue}%s${endc}" "==> " 
        read -n 1 -s -p "${green}Press any key to install kalitorify${endc} "    
    check_required
    install_program
}

main
