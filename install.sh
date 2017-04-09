#!/bin/bash

# install.sh - kalitorify installer
# Copyright (C) 2015, 2017 Brainfuck
#
# This file is part of kalitorify
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
PROGRAM="install.sh"
VERSION="0.3.0"
AUTHOR="Brainfuck"

# define colors
export red=$'\e[0;91m'
export green=$'\e[0;92m'
export blue=$'\e[0;94m'
export cyan=$'\e[0;96m'
export white=$'\e[0;97m'
export endc=$'\e[0m'


# banner
banner() {
printf "${red}
####################################
#
# :: "$PROGRAM"
# :: Version: "$VERSION"
# :: Installer script for kalitorify
# :: Author: "$AUTHOR"
# 
####################################${endc}\n\n"
}


# check if the program run as a root
check_root() {
    if [[ "$(id -u)" -ne 0 ]]; then
        printf "\n${red}%s${endc}\n" "[ FAILED ] Please run this program as a root!" 2>&-
        exit 1
    fi
}


## Check dependencies
# only tor is required, but use this function for future additions
check_required() {
    printf "\n${blue}%s${endc} ${green}%s${endc}\n" "==>" "Check dependencies"
    
    declare -a dependencies=("tor");
    
    for package in "${dependencies[@]}"; do
    	if ! hash "$package" 2>/dev/null; then
        	printf "${blue}%s${endc} ${green}%s${endc}\n" "==>" "Installing "$package" ..."
        	apt-get update && apt-get install -y "$package"
        	printf "${cyan}%s${endc} ${green}%s${endc}\n" "[ OK ]" ""$package" installed"
    	else
        	printf "${cyan}%s${endc} ${green}%s${endc}\n" \
                "[ OK ]" ""$package" already installed"
    	fi
    done
}


## Install program files
# with 'install' command create directories and copy files
install_program() {
    printf "${blue}%s${endc} ${green}%s${endc}\n" "==>" "Install kalitorify..."
    
    # copy program files on /usr/share/*
    install -Dm644 "LICENSE" "/usr/share/license/kalitorify/LICENSE"
    install -Dm644 "README.md" "/usr/share/doc/kalitorify/README.md"
    
    # copy executable file on /usr/local/bin
    install -Dm755 "kalitorify.sh" "/usr/local/bin/kalitorify"

    # check if program run correctly
    if hash kalitorify 2>/dev/null; then
        printf "${cyan}%s${endc} ${green}%s${endc}\n" \
            "[ OK ]" "kalitorify succesfully installed"
        printf "${green}%s${endc}\n" "run command 'kalitorify --start for start program"
    else
        printf "${red}%s${endc}\n" "[ FAILED ] kalitorify cannot start :("
        printf "${green}%s${endc}\n" "If you are in trouble read NOTES on file README"
        printf "${green}%s${endc}\n" \ 
            "Report issues at: https://github.com/brainfucksec/kalitorify/issues"
    fi
}


# Main function
main() {
    banner
    check_root
    printf "${blue}%s${endc}" "==> " 
        read -n 1 -s -p "${green}Press any key to install kalitorify${endc} "    
    check_required
    install_program
}

main
