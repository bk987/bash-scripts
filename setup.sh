#!/bin/bash

function main() {
    set +o history

    normal="\033[0m"
    red="\033[1;91m"
    green="\033[1;92m"
    blue="\033[1;94m"
    cyan="\033[1;96m"
    overwrite="\r\033[0K"
    failure="${overwrite} [${red} FAILURE ${normal}] :"
    success="${overwrite} [${green} SUCCESS ${normal}] :"
    working="${overwrite} [${blue} WORKING ${normal}] :"
    details="[${cyan} DETAILS ${normal}] :"

    files="$(dirname "$(readlink -f "$0")")/conf_files"
    sshd_conf="/etc/ssh/sshd_config"
    fs_tab="/etc/fstab"

    if [[ $EUID -ne 0 ]]; then
        echo -e " ${failure} This script must be run as root! " >&2
        exit 1
    elif fuser /var/lib/dpkg/lock /var/lib/apt/lists/lock /var/cache/apt/archives/lock >/dev/null 2>&1; then
        echo -e " ${failure} Another process is using the package management system! " >&2
        exit 1
    fi

    clear
    echo ""
    
    while :; do
        read -rp " Enter username for new non-root user: " input
        if [[ "$input" =~ ^[a-z_]([a-z0-9_-]{0,31}|[a-z0-9_-]{0,30}\$)$ ]]; then
            inp_user_name="$input"
            break
        else
            echo " ... Invalid username "
        fi
    done

    while :; do
        read -rp " Disable SSH Password Authentication? [y/n]: " input
        if [[ "$input" =~ ^[yYnN]$ ]]; then
    		inp_disable_password="$input"
    		break
    	fi
    done

    if [[ "$inp_disable_password" =~ ^[yY]$ ]]; then
        while :; do
            read -rp " Paste public SSH key for user ${inp_user_name}: " input
            if [[ -n "$input" ]]; then
                inp_ssh_key="$input"
                break
            fi
        done
    fi

    while :; do
        read -rp " Set timezone and locale? [y/n]: " input
        if [[ "$input" =~ ^[yYnN]$ ]]; then
            inp_set_timezone_locale="$input"
            break
        fi
    done

    while :; do
        read -rp " Add swap space? [y/n]: " input
        if [[ "$input" =~ ^[yYnN]$ ]]; then
            inp_add_swap="$input"
            break
        fi
    done

    while :; do
        read -rp " Enable automatic updates? [y/n]: " input
        if [[ "$input" =~ ^[yYnN]$ ]]; then
            inp_enable_updates="$input"
            break
        fi
    done

    while :; do
        read -rp " Install frequently used packages? [y/n]: " input
        if [[ "$input" =~ ^[yYnN]$ ]]; then
            inp_install_packages="$input"
            break
        fi
    done

    cd ~
    clear
    echo " $(date "+%Y-%m-%d %H:%M:%S") "

    upgrade_pkgs
    add_user
    if [[ "$inp_disable_password" =~ ^[yY]$ ]] && [[ -n "$inp_ssh_key" ]]; then
        disable_password
    fi
    if [[ "$inp_set_timezone_locale" =~ ^[yY]$ ]]; then
        set_timezone_locale
    fi
    harden_server
    if [[ "$inp_add_swap" =~ ^[yY]$ ]]; then
        add_swap
    fi
    if [[ "$inp_enable_updates" =~ ^[yY]$ ]]; then
        automatic_updates
    fi
    if [[ "$inp_install_packages" =~ ^[yY]$ ]]; then
        install_packages
    fi
    misc_tweaks

    echo ""
    set -o history
}

function upgrade_pkgs() {
	title "UPGRADE"
    echo -ne " ${working} Upgrading packages "
    sleep 1
    apt_fn update && 
    apt_fn upgrade && 
    apt_fn autoremove
    if [[ $? -eq 0 ]]; then
        echo -e " ${success} Installed packages have been upgraded to newest versions "
        return 0
    else
        echo -e " ${failure} Unable to upgrade packages " >&2
        return 1
    fi
}

function add_user() {
    title "USER SETUP"
    echo -ne " ${working} Adding new non-root user "
    sleep 1
	if grep -q "$inp_user_name" /etc/passwd; then
        echo -e " ${failure} User already exists " >&2
        return 1
    else
        user_password="$(< /dev/urandom tr -dc 'A-Za-z0-9_~@#%^' | head -c32)" &&
        useradd -m -p "$(openssl passwd -6 ${user_password})" -s /bin/bash "${inp_user_name}" &&
        usermod -aG sudo "${inp_user_name}"
        if [[ $? -eq 0 ]]; then
            echo -e " ${success} User has been created and added to the sudo group "
            echo -e " ${details} Username: ${inp_user_name} Password: ${user_password} "
            return 0
        else
            echo -e " ${failure} Unable to create new user " >&2
            return 1
        fi
    fi
}

function disable_password() {
    echo -ne " ${working} Adding SSH key for the new user "
    sleep 1
	local ssh_dir="/home/${inp_user_name}/.ssh"
    local keys="authorized_keys"
    {
        if [[ ! -d $ssh_dir ]]; then
            mkdir $ssh_dir && chmod 700 $ssh_dir
        fi
        if [[ ! -f "${ssh_dir}/${keys}" ]]; then
            touch "${ssh_dir}/${keys}" && chmod 600 "${ssh_dir}/${keys}"
        fi
        chown -R "${inp_user_name}:" $ssh_dir
        echo "${inp_ssh_key}" >> "${ssh_dir}/${keys}"
    } >/dev/null 2>&1
    if [[ $? -eq 0 ]]; then
        echo -e " ${success} SSH key has been added for user ${inp_user_name} "
        echo -ne " ${working} Updating SSH configuration "
        sleep 1
        cp $sshd_conf "${sshd_conf}.$(date +%m_%d_%Y_%H_%M_%S).bak" &&
        {
            sed -i -E '/^#?ChallengeResponseAuthentication /c\ChallengeResponseAuthentication no' $sshd_conf
            sed -i -E '/^#?UsePAM /c\UsePAM no' $sshd_conf
            sed -i -E '/^#?PubkeyAuthentication /c\PubkeyAuthentication yes' $sshd_conf
            sed -i -E '/^#?PasswordAuthentication /c\PasswordAuthentication no' $sshd_conf
        } >/dev/null 2>&1
        if [[ $? -eq 0 ]]; then
            echo -e " ${success} Password Authentication has been disabled "
            return 0
        else 
            echo -e " ${failure} Unable to disable Password Authentication " >&2
            return 1
        fi
    else
        echo -e " ${failure} Unable to add the SSH key for user ${inp_user_name} " >&2
        return 1
    fi
}

function set_timezone_locale() {
    title "TIMEZONE & LOCALE"
    echo -ne " ${working} Fetching timezone from geolocation "
    sleep 1
    local current_timezone="$(timedatectl status | grep 'Time zone' | awk '{print $3}')"
    local suggested_timezone="$(curl -s 'geoip.ubuntu.com/lookup' | sed -n -e 's/.*<TimeZone>\(.*\)<\/TimeZone>.*/\1/p')"
    if [[ -n "$suggested_timezone" ]]; then
        if [[ "$suggested_timezone" != "$current_timezone" ]]; then
            echo -ne " ${working} Updating timezone "
            sleep 1
            timedatectl set-timezone $suggested_timezone >/dev/null 2>&1
            if [[ $? -eq 0 ]]; then
                echo -e " ${success} Timezone has been changed from ${current_timezone} to ${suggested_timezone} "
            else
                echo -e " ${failure} Unable to set timezone " >&2
            fi
        else
            echo -e " ${failure} Timezone is already set to ${suggested_timezone} " >&2
        fi
    else
        echo -e " ${failure} Unable to fetch timezone from geolocation " >&2
    fi
    
    echo -ne " ${working} Generating localisation files "
    sleep 1
    locale-gen en_US en_US.UTF-8 >/dev/null 2>&1
    if [[ $? -eq 0 ]]; then
        echo -ne " ${working} Updating locale "
        sleep 1
        {
            update-locale LANG="en_US.UTF-8" LANGUAGE="en_US.UTF-8" LC_ALL="en_US.UTF-8"
            dpkg-reconfigure --frontend=noninteractive locales
        }  >/dev/null 2>&1
        if [[ $? -eq 0 ]]; then
            echo -e " ${success} Locale has been set to 'en_US.UTF-8', reboot for changes to take effect "
        else
            echo -e " ${failure} Unable to set locale " >&2
        fi
    else
        echo -e " ${failure} Unable to generate localisation files " >&2
    fi
}

function harden_server() {
    title "SERVER HARDENING"
    secure_ssh_fn
    install_ufw && configure_ufw && install_f2b && configure_f2b
    secure_shared_mem
    configure_sysctl
    disable_ipv6
}

function secure_ssh_fn() {
    local banner_issue="/etc/issue.net"
    if [[ "$inp_disable_password" =~ ^[nN]$ ]]; then
        cp $sshd_conf "${sshd_conf}.$(date +%m_%d_%Y_%H_%M_%S).bak"
    fi
    echo -ne " ${working} Reading local port range "
    sleep 1
    read lower_port upper_port < /proc/sys/net/ipv4/ip_local_port_range 2>/dev/null
    if [[ $? -ne 0 ]]; then
        echo -e " ${failure} Unable to read local port range from procfs "
        return 1
    fi
    while :; do
        ssh_port="$(shuf -i ${lower_port}-${upper_port} -n 1)"
        ss -lpn | grep -q ":${ssh_port} " || break
    done
    if [[ ! $ssh_port =~ ^[0-9]+$ ]]; then
        echo -e " ${failure} Unable to generate valid port number for SSH " >&2
        return 1
    fi
    echo -ne " ${working} Updating SSH configuration "
    sleep 1
    {
        if grep -q "AllowUsers" $sshd_conf; then
            sed -i "s/AllowUsers.*/& ${inp_user_name}/" $sshd_conf
        else
            sed -i "/# Authentication:/a AllowUsers ${inp_user_name}" $sshd_conf
        fi
        cp -f "${files}${banner_issue}" $banner_issue &&
        chmod 644 $banner_issue &&
        sed -i -E "/^#?Banner /c\Banner ${banner_issue}" $sshd_conf
        sed -i -E "/^#?LogLevel /c\LogLevel VERBOSE" $sshd_conf &&
        sed -i -E "/^#?PermitRootLogin /c\PermitRootLogin no" $sshd_conf &&
        sed -i -E "/^#?LoginGraceTime /c\LoginGraceTime 20" $sshd_conf &&
        sed -i -E "/^#?MaxAuthTries /c\MaxAuthTries 3" $sshd_conf &&
        sed -i -E "/^#?PermitEmptyPasswords /c\PermitEmptyPasswords no" $sshd_conf &&
        sed -i -E "/^#?X11Forwarding /c\X11Forwarding no" $sshd_conf &&
        sed -i -E "/^#?Port /c\Port ${ssh_port}" $sshd_conf
    } >/dev/null 2>&1
    if [[ $? -eq 0 ]] && sshd -t -q; then
        echo -ne " ${working} Restarting SSH server "
        sleep 1
        service ssh restart >/dev/null 2>&1
        if [[ $? -eq 0 ]]; then
            echo -e " ${success} SSH has been secured. "
            echo -e " ${details} Randomized SSH port number: ${ssh_port} "
            return 0
        else
            echo -e " ${failure} Unable to restart SSH server " >&2
            return 1
        fi
	else 
		echo -e " ${failure} Unable to configure SSH properly " >&2
        return 1
	fi
}

function install_ufw() {
    echo -ne " ${working} Installing UFW "
    sleep 1
    if apt_fn install ufw; then
        echo -e " ${success} UFW has been installed "
        return 0
    else
        echo -e " ${failure} Unable to install UFW " >&2
        return 1
    fi
}

function configure_ufw() {
    if ! dpkg -l | grep -q ufw; then
        echo -e " ${failure} UFW has not been installed properly " >&2
        return 1
    fi
    echo -ne " ${working} Creating UFW app for custom SSH port "
    sleep 1
    local ufw_app="/etc/ufw/applications.d/customssh"
    {
        cp "${files}${ufw_app}" $ufw_app &&
        chmod 644 $ufw_app
    } >/dev/null 2>&1
    if [[ $? -ne 0 ]]; then
        echo -e " ${failure} Unable to copy UFW app file " >&2
        return 1
    fi
    sed -i "s|^ports=$|ports=${ssh_port}/tcp|" $ufw_app >/dev/null 2>&1
    if [[ $? -ne 0 ]]; then
        echo -e " ${failure} Unable to modify UFW app file " >&2
        return 1
    fi
    {
        ufw limit CustomSSH &&
        ufw --force enable
    } >/dev/null 2>&1
    if [[ $? -eq 0 ]]; then
        echo -e " ${success} UFW has been configured "
        return 0
    else
        echo -e " ${failure} Unable to configure UFW properly " >&2
        return 1
    fi
}

function install_f2b() {
    echo -ne " ${working} Installing Fail2Ban "
    sleep 1
    if apt_fn install fail2ban; then
        echo -e " ${success} Fail2Ban has been installed "
        return 0
    else
        echo -e " ${failure} Unable to install Fail2Ban " >&2
        return 1
    fi
}

function configure_f2b() {
    if ! dpkg -l | grep -q fail2ban; then
        echo -e " ${failure} Fail2Ban has not been installed properly " >&2
        return 1
    fi
    if [[ ! -f "/etc/fail2ban/action.d/ufw.conf" ]]; then
        echo -e " ${failure} Fail2Ban action for UFW does not exist " >&2
        return 1
    fi
    echo -ne " ${working} Setting up Fail2Ban jail for SSH "
    sleep 1
    local f2b_local="/etc/fail2ban/jail.local"
    {
        cp "${files}${f2b_local}" $f2b_local &&
        chmod 644 $f2b_local
    } >/dev/null 2>&1
    if [[ $? -ne 0 ]]; then
        echo -e " ${failure} Unable to copy jail.local file " >&2
        return 1
    fi
    sed -i "s/^port = ssh$/port = ${ssh_port}/" $f2b_local >/dev/null 2>&1
    if [[ $? -ne 0 ]]; then
        echo -e " ${failure} Unable to modify jail.local file " >&2
        return 1
    fi
    {
        fail2ban-client -t &&
        fail2ban-client reload sshd
    } >/dev/null 2>&1
    if [[ $? -eq 0 ]]; then
        echo -e " ${success} Fail2Ban has been configured "
        return 0
    else
        echo -e " ${failure} Unable to configure Fail2Ban properly " >&2
        return 1
    fi
}

function secure_shared_mem() {
    grep -q '/run/shm' $fs_tab
    if [[ $? -ne 0 ]]; then
        echo -ne " ${working} Securing shared memory "
        sleep 1
        cp $fs_tab "${fs_tab}.$(date +%m_%d_%Y_%H_%M_%S).bak" &&
        echo 'none	/run/shm	tmpfs	defaults,ro	0	0' >> $fs_tab
        if [[ $? -eq 0 ]]; then
            echo -e " ${success} Shared memory has been secured, reboot after the setup "
            return 0
        else
            echo -e " ${failure} Unable to secure shared memory " >&2
            return 1
        fi
    fi
}

function configure_sysctl() {
    if virt_ovz; then
        echo -e " ${failure} Unable to modify kernel configuration on OpenVZ " >&2
        return 1
    fi
    echo -ne " ${working} Updating SYSCTL configuration "
    sleep 1
    local sysctl_conf="/etc/sysctl.conf"
    {
        cp $sysctl_conf "${sysctl_conf}.$(date +%m_%d_%Y_%H_%M_%S).bak" &&
        cp -f "${files}${sysctl_conf}" $sysctl_conf &&
        chmod 644 $sysctl_conf &&
        sysctl -p -q
    } >/dev/null 2>&1
    if [[ $? -eq 0 ]]; then
        echo -e " ${success} SYSCTL has been configured "
        return 0
    else
        echo -e " ${failure} Unable to modify SYSCTL configuration " >&2
        return 1
    fi
}

function disable_ipv6() {
    if virt_ovz; then
        echo -e " ${failure} Unable to modify GRUB configuration on OpenVZ " >&2
        return 1
    fi
    local errors=0
    echo -ne " ${working} Updating SYSCTL configuration "
    sleep 1
    local sysctl_conf="/etc/sysctl.conf"
    if ! grep -q 'disable_ipv6' $sysctl_conf; then
        {
            cat "${files}/snippets/disable_ipv6" >> $sysctl_conf &&
            sysctl -p -q
        } >/dev/null 2>&1
        if [[ $? -eq 0 ]]; then
            echo -e " ${success} IPv6 has been disabled in the SYSCTL configuration "
        else
            echo -e " ${failure} Unable to modify SYSCTL configuration " >&2
            ((errors++))
        fi
    else
        echo -e " ${failure} SYSCTL configuration already contains disable_ipv6 key, check manually " >&2
        ((errors++))
    fi
    echo -ne " ${working} Updating GRUB configuration "
    sleep 1
    local grub_conf="/etc/default/grub"
    if ! grep -q 'ipv6.disable=1' $grub_conf; then
        {
            cp $grub_conf "${grub_conf}.$(date +%m_%d_%Y_%H_%M_%S).bak" &&
            sed -i 's/GRUB_CMDLINE_LINUX_DEFAULT="[^"]*/& ipv6.disable=1/' $grub_conf &&
            sed -i -e '/^GRUB_CMDLINE_LINUX=/{s/=""/="ipv6.disable=1"/;t;s/"$/ ipv6.disable=1&/;}' $grub_conf &&
            update-grub
        } >/dev/null 2>&1
        if [[ $? -eq 0 ]]; then
            echo -e " ${success} IPv6 has been disabled in the GRUB configuration "
        else
            echo -e " ${failure} Unable to edit GRUB configuration " >&2
            ((errors++))
        fi
    else
        echo -e " ${failure} GRUB configuration already contains ipv6.disable, check manually " >&2
        ((errors++))
    fi

    if [[ $errors -eq 0 ]]; then
        return 0
    else
        return 1
    fi
}

function add_swap() {
    local mem_total=$(free | awk '/Mem:/ {print $2}')
    local swap_total=$(free | awk '/Swap:/ {print $2}')
    if [[ -z "$swap_total" || -z "$mem_total" ]]; then
        echo -e " ${failure} Unable to check memory info " >&2
        return 1
    fi
    echo -ne " ${working} Calculating optimal swap size "
    sleep 1
    if [[ $mem_total -lt 1048576 ]]; then
        local swap_size_mb=$(awk "BEGIN {printf \"%.0f\", (${mem_total}/1024)}")
    else
        local swap_size_gb=$(awk "BEGIN {printf \"%.0f\", sqrt(${mem_total}/1024/1024)}")
        local swap_size_mb=$((${swap_size_gb}*1024))
    fi
    if [[ ! $swap_size_mb =~ ^[0-9]+$ ]]; then
        echo -e " ${failure} Unable to calculate optimal swap size " >&2
        return 1
    fi
    echo -ne " ${working} Checking FSTAB for existing swap space "
    sleep 1
    cp $fs_tab "${fs_tab}.$(date +%m_%d_%Y_%H_%M_%S).bak" &&
    grep swap $fs_tab | awk '{print $1}' | while read -r file ; do
        if [[ -f $file ]]; then
            {
                swapoff $file && 
                sed -i "\|^$file|d" $fs_tab && 
                rm -f $file
            } >/dev/null 2>&1
            if [[ $? -eq 0 ]]; then
                echo -e " ${success} Existing swap space has been removed from ${file} "
            fi
        fi
    done
    echo -ne " ${working} Creating swap file "
    sleep 1
    local swap_file="/swap.img"
    fallocate -l "${swap_size_mb}MiB" $swap_file >/dev/null 2>&1
    if [[ $? -ne 0 ]]; then
        dd if=/dev/zero of=$swap_file bs=1M count=$swap_size_mb >/dev/null 2>&1
    fi
    if [[ $? -eq 0 ]]; then
        echo -ne " ${working} Setting up swap "
        sleep 1
        {
            chmod 600 $swap_file && 
            mkswap $swap_file && 
            swapon $swap_file &&
            echo "${swap_file}	none	swap	sw	0	0" >> $fs_tab
        } >/dev/null 2>&1
        if [[ $? -eq 0 ]]; then
            echo -e " ${success} ${swap_size_mb}M swap space has been added at ${swap_file} "
            return 0
        else
            echo -e " ${failure} Unable to set up swap properly " >&2
            return 1
        fi
    fi
}

function automatic_updates() {
    if ! dpkg -l | grep -q unattended-upgrades; then
        echo -ne " ${working} Installing Unattended-Upgrades "
        sleep 1
        apt_fn install unattended-upgrades
    fi
    echo -ne " ${working} Updating Unattended-Upgrades configuration "
    sleep 1
    local ua_conf="/etc/apt/apt.conf.d/50unattended-upgrades"
    local au_conf="/etc/apt/apt.conf.d/20auto-upgrades"
    {
        cp $ua_conf "${ua_conf}.$(date +%m_%d_%Y_%H_%M_%S).bak" &&
        cp $au_conf "${au_conf}.$(date +%m_%d_%Y_%H_%M_%S).bak" &&
        cp -f "${files}${ua_conf}" $ua_conf &&
        cp -f "${files}${au_conf}" $au_conf &&
        chmod 644 $ua_conf &&
        chmod 644 $au_conf
    } >/dev/null 2>&1
    if [[ $? -eq 0 ]]; then
        echo -e " ${success} Unattended-Upgrades has been configured "
        return 0
    else
        echo -e " ${failure} Unable to configure Unattended-Upgrades properly " >&2
        return 1
    fi
}

function install_packages() {
    title "FREQUENTLY USED PACKAGES"
    echo -ne " ${working} Installing frequently used packages "
    sleep 1
    apt_fn install htop glances nload nethogs zip unzip software-properties-common secure-delete build-essential
    if [[ $? -eq 0 ]]; then
        echo -e " ${success} Frequently used packages have been installed "
        return 0
    else
        echo -e " ${failure} Unable to install frequently used packages " >&2
        return 1
    fi
}

function misc_tweaks() {
    title "MISC. TWEAKS"
    echo -ne " ${working} Adding bash aliases "
    sleep 1
    local aliases="/etc/profile.d/00-aliases.sh"
    {
        cp -f "${files}${aliases}" "$aliases" &&
        chmod 644 "$aliases"
    } >/dev/null 2>&1
    if [[ $? -eq 0 ]]; then
        echo -e " ${success} Bash aliases have been added "
    else
        echo -e " ${failure} Unable to add bash aliases " >&2
    fi
    echo -ne " ${working} Customizing the prompt "
    sleep 1
    local dirs=(/etc/skel/ /root/ /home/*/)
    local prompt='. "$HOME"/.custom_prompt'
    {
        for dir in "${dirs[@]}"; do
            cp -f "${files}/misc/.custom_prompt" "$dir" &&
            chmod 644 "${dir}/.custom_prompt" &&
            { grep custom_prompt "${dir}/.bashrc" || echo -e "\n${prompt}" >> "${dir}/.bashrc"; }
        done
    } >/dev/null 2>&1
    if [[ $? -eq 0 ]]; then
        echo -e " ${success} Bash prompt has been customized "
    else
        echo -e " ${failure} Unable to customize bash prompt " >&2
    fi
}

function title() {
    echo -e "\n ${blue}------------- ${@:1}${normal} \n"
}

function apt_fn() {
    apt-get -qq -o Acquire::ForceIPv4=true ${@:1} < /dev/null >/dev/null 2>&1
}

function virt_ovz() {
    local virtualization="$(hostnamectl status | grep 'Virtualization' | awk '{print $2}')"
    if [ "$virtualization" == "openvz" ]; then
        return 0
    else
        return 1
    fi
}


main