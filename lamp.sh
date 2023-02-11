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

    if [[ $EUID -ne 0 ]]; then
        echo -e " ${failure} This script must be run as root! " >&2
        exit 1
    elif fuser /var/lib/dpkg/lock /var/lib/apt/lists/lock /var/cache/apt/archives/lock >/dev/null 2>&1; then
        echo -e " ${failure} Another process is using the package management system! " >&2
        exit 1
    fi

    clear
    echo ""

    if ! amp_installed; then
        while :; do
            read -rp " Enter a FQDN to be used as the hostname: " input
            if [[ -n "$input" ]]; then
                inp_hostname="$input"
                break
            fi
        done
    fi

    while :; do
        read -rp " Create a new site? [y/n]: " input
        if [[ "$input" =~ ^[yYnN]$ ]]; then
            local inp_create_site="$input"
            break
        fi
    done

    if [[ "$inp_create_site" =~ ^[yY]$ ]]; then
        while :; do
            read -rp " System user under which the site will be created? : " input
            if [[ "$input" =~ ^[a-z_]([a-z0-9_-]{0,31}|[a-z0-9_-]{0,30}\$)$ ]]; then
                inp_user_name="$input"
				break
            else
                echo " ... Invalid username "
            fi
        done

        while :; do
            read -rp " Enter domain name : " input
            if [[ -n "$input" ]]; then
                inp_domain_name="$input"
                break
            fi
        done

        while :; do
            read -rp " Create a database for this site? [y/n]: " input
            if [[ "$input" =~ ^[yYnN]$ ]]; then
                inp_create_database="$input"
                break
            fi
        done
    fi

    cd ~
    clear
    echo " $(date "+%Y-%m-%d %H:%M:%S") "

    if ! amp_installed; then
        upgrade_pkgs
        if [[ -n "$inp_hostname" ]]; then
            set_hostname
        fi
        install_amp && configure_amp
        install_additional
    fi

    if [[ "$inp_create_site" =~ ^[yY]$ ]]; then
        create_site
    fi

    echo ""
    set -o history
}

function upgrade_pkgs() {
	title 'UPGRADE'
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

function set_hostname() {
    title 'HOSTNAME'
    echo -ne " ${working} Setting hostname "
    sleep 1
    local hosts_conf="/etc/hosts"
    hostnamectl set-hostname "$inp_hostname" && \
    cp $hosts_conf "${hosts_conf}.$(date +%m_%d_%Y_%H_%M_%S).bak" && \
    sed -i "s/^127.0.1.1 .*/127.0.1.1 ${inp_hostname}/" $hosts_conf
    if [[ $? -eq 0 ]]; then
        echo -e " ${success} Hostname has been set to ${inp_hostname} "
        return 0
    else 
        echo -e " ${failure} Unable to set hostname " >&2
        return 1
    fi
}

function install_amp() {
    title 'INSTALLATION'
    echo -ne " ${working} Installing necessary packages "
    sleep 1
    apt_fn install software-properties-common &&
    add-apt-repository -y ppa:ondrej/php >/dev/null 2>&1 &&
    apt_fn update &&
    apt_fn install apache2 apachetop php8.1-fpm php8.1-common php8.1-cli php8.1-dev php8.1-mysql \
        php8.1-curl php8.1-gd php8.1-imagick php8.1-imap php8.1-mbstring php8.1-intl php8.1-bcmath \
        php8.1-xml php8.1-xmlrpc php8.1-soap php8.1-zip libapache2-mod-php8.1 mariadb-server \
		debconf-utils build-essential
    if [[ $? -eq 0 ]]; then
        echo -e " ${success} Necessary packages have been installed "
        return 0
    else
        echo -e " ${failure} Unable to install all the necessary packages " >&2
        return 1
    fi
}

function configure_amp() {
    title 'CONFIGURATION'
    configure_apache
    configure_php
    configure_mariadb
}

function configure_apache() {
    service apache2 status >/dev/null 2>&1
    if [[ $? -ne 0 ]]; then
        echo -e " ${failure} Apache has not been installed properly " >&2
        return 1
    fi
    echo -ne " ${working} Configuring Apache "
    sleep 1
	{
        a2enmod expires headers rewrite ssl alias proxy proxy_fcgi setenvif &&
        a2enconf php8.1-fpm &&
        > /var/www/html/index.html &&
        service apache2 restart
    } >/dev/null 2>&1
    if [[ $? -eq 0 ]]; then
        echo -e " ${success} Apache has been configured "
        return 0
    else
        echo -e " ${failure} Unable to configure Apache " >&2
        return 1
    fi
}

function configure_php() {
    service php8.1-fpm status >/dev/null 2>&1
    if [[ $? -ne 0 ]]; then
        echo -e " ${failure} PHP-FPM has not been installed properly " >&2
        return 1
    fi
    echo -ne " ${working} Configuring PHP-FPM "
    sleep 1
    local php_fpm="/etc/php/8.1/fpm/php-fpm.conf"
    cp $php_fpm "${php_fpm}.$(date +%m_%d_%Y_%H_%M_%S).bak" &&
    {
        service php8.1-fpm restart
    } >/dev/null 2>&1
    if [[ $? -eq 0 ]]; then
        echo -e " ${success} PHP-FPM has been configured "
        return 0
    else
        echo -e " ${failure} Unable to configure PHP-FPM " >&2
        return 1
    fi
}

function configure_mariadb() {
    # Check MariaDB status
    service mariadb status >/dev/null 2>&1
    if [[ $? -ne 0 ]]; then
        echo -e " ${failure} MariaDB has not been installed properly " >&2
        return 1
    fi
    echo -ne " ${working} Configuring MariaDB "
    sleep 1
    # Generate random 32 character password for MariaDB admin
    local admin_user="mysql_admin"
    local admin_pass="$(< /dev/urandom tr -dc 'A-Za-z0-9_~@#%^' | head -c32)"
    # Remove anonymous users
    mysql -se "DELETE FROM mysql.user WHERE User='';"
    # Disallow root login remotely
    mysql -se "DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1');"
    # Remove test database and access to it
    mysql -se "DROP DATABASE IF EXISTS test;"
    # Remove privileges on test database
    mysql -se "DELETE FROM mysql.db WHERE Db='test' OR Db='test\\_%'"
    # Create an admin user
    mysql -se "CREATE USER '${admin_user}'@'localhost' IDENTIFIED BY '${admin_pass}';" &&
    # Allow access to all databases
    mysql -se "GRANT ALL PRIVILEGES ON *.* TO '${admin_user}'@'localhost' WITH GRANT OPTION;"
    if [[ $? -eq 0 ]]; then
        echo -e " ${success} MariaDB admin user has been created "
        echo -e " ${details} Username: ${admin_user} Password: ${admin_pass} "
    else
        echo -e " ${failure} Unable to create MariaDB admin user " >&2
        return 1
    fi
    # Reload privilege tables
    mysql -se "FLUSH PRIVILEGES;"
    # Restart MariaDB service
    service mariadb restart >/dev/null 2>&1
    if [[ $? -eq 0 ]]; then
        echo -e " ${success} MariaDB has been configured "
        return 0
    else
        echo -e " ${failure} Unable to configure MariaDB " >&2
        return 1
    fi
}

function install_additional() {
    title "ADDITIONAL SOFTWARE"
    # Install Composer
    echo -ne " ${working} Installing Composer "
    sleep 1
    {
        curl -sS https://getcomposer.org/installer -o composer-setup.php &&
        curl -sS https://composer.github.io/installer.sha384sum -o installer.sha384sum
    } >/dev/null 2>&1
    if [[ $? -eq 0 ]]; then
        sha384sum -c installer.sha384sum 2>&1 | grep -q OK
        if [[ $? -eq 0 ]]; then
            php composer-setup.php --install-dir=/usr/local/bin --filename=composer >/dev/null 2>&1
            if [[ $? -eq 0 ]]; then
                echo -e " ${success} Composer has been installed "
                rm composer-setup.php installer.sha384sum >/dev/null 2>&1
            else
                echo -e " ${failure} Unable to install Composer " >&2
            fi
        else
            echo -e " ${failure} Composer installer corrupt " >&2
            rm composer-setup.php installer.sha384sum >/dev/null 2>&1
        fi
    else
        echo -e " ${failure} Unable to download Composer " >&2
    fi
    # Install Node.js
    echo -ne " ${working} Installing Node.js "
    sleep 1
    {
        curl -sL https://deb.nodesource.com/setup_18.x | bash - &&
        apt-get install -y nodejs
    } >/dev/null 2>&1
    if [[ $? -eq 0 ]]; then
        echo -e " ${success} Node.js has been installed "
    else 
        echo -e " ${failure} Unable to install Node.js " >&2
    fi
}

function create_site() {
    title 'SITE SETUP'
    create_user && 
    create_directory && 
    create_fpm_pool && 
    create_virtual_host && 
    { [[ "$inp_create_database" =~ ^[yY]$ ]] && create_database || :; } &&
    { [[ "$inp_enable_sftp" =~ ^[yY]$ ]] && enable_sftp || :; }
    if [[ $? -eq 0 ]]; then
        echo -e " ${success} ${inp_domain_name} site has been created "
        return 0
    else
        echo -e " ${failure} Unable to create new site " >&2
        return 1
    fi
}

function create_user() {
    # Check if the user exists, otherwise create user with a random password
    id -u "$inp_user_name" >/dev/null 2>&1
    if [[ $? -ne 0 ]] ; then
        echo -ne " ${working} Creating new user "
        sleep 1
        user_password="$(< /dev/urandom tr -dc 'A-Za-z0-9_~@#%^' | head -c32)" &&
        useradd -m -p "$(openssl passwd -6 ${user_password})" -s /usr/sbin/nologin "$inp_user_name"
        if [[ $? -eq 0 ]]; then
            echo -e " ${success} New user has been created "
            echo -e " ${details} Username: ${inp_user_name} Password: ${user_password} "
            return 0
        else
            echo -e " ${failure} Unable to create new user " >&2
            return 1
        fi
    fi
}

function create_directory() {
    # Create directories for site files
    echo -ne " ${working} Creating site directory structure "
    sleep 1
    srv_user="/srv/${inp_user_name}"
    site_dir="${srv_user}/${inp_domain_name}"
    if [[ ! -d "${site_dir}" ]]; then
        mkdir -p ${site_dir}/{backup,logs,www/public} &&
        printf "%s\n" "<?php echo \"${inp_domain_name}\"; ?>" > ${site_dir}/www/public/index.php &&
        touch ${site_dir}/logs/{error,access}.log &&
        chown "${inp_user_name}:${inp_user_name}" $srv_user &&
        chown -R "${inp_user_name}:" $site_dir
        if [[ $? -eq 0 ]]; then
            echo -e " ${success} Site directory has been created "
            return 0
        else
            echo -e " ${failure} Unable to create site directory at ${site_dir} " >&2
            return 1
        fi
    fi
}

function create_fpm_pool() {
    # Configure PHP-FPM pool for the user
    echo -ne " ${working} Setting up new PHP-FPM pool "
    sleep 1
    {
        printf "%s\n" \
            "[${inp_user_name}]" \
            "user = ${inp_user_name}" \
            "group = ${inp_user_name}" \
            "listen = /run/php/php8.1-fpm.${inp_user_name}.sock" \
            "listen.owner = www-data" \
            "listen.group = www-data" \
            "pm = dynamic" \
            "pm.max_children = 5" \
            "pm.start_servers = 2" \
            "pm.min_spare_servers = 1" \
            "pm.max_spare_servers = 3" \
            > /etc/php/8.1/fpm/pool.d/${inp_user_name}.conf &&
        # Reload PHP-FPM
        service php8.1-fpm reload
    } >/dev/null 2>&1
    if [[ $? -eq 0 ]]; then
        echo -e " ${success} PHP-FPM pool has been set up "
        return 0
    else
        echo -e " ${failure} Unable to set up PHP-FPM pool " >&2
        return 1
    fi
}

function create_virtual_host() {
    # Create Apache virtual host for http
    echo -ne " ${working} Creating Apache virtual host for http "
    sleep 1
    {
        {
            printf "%s\n" \
                "<VirtualHost *:80>" \
                "    ServerName ${inp_domain_name}" \
                "    ServerAlias www.${inp_domain_name}" \
                "    ServerAdmin admin@${inp_domain_name}" \
                "    " \
                "    DirectoryIndex index.html index.php" \
                "    DocumentRoot ${site_dir}/www/public" \
                "    " \
                "    ErrorLog ${site_dir}/logs/error.log" \
                "    CustomLog ${site_dir}/logs/access.log combined" \
                "    " \
                "    <Directory ${site_dir}/www/public>" \
                "        Options -Indexes +FollowSymLinks +MultiViews" \
                "        AllowOverride All" \
                "        Require all granted" \
                "    </Directory>" \
                "    <FilesMatch \.php$>" \
                "        SetHandler \"proxy:unix:/run/php/php8.1-fpm.${inp_user_name}.sock|fcgi://localhost/\"" \
                "    </FilesMatch>" \
                "</VirtualHost>" \
                > /etc/apache2/sites-available/${inp_domain_name}.conf
        } &&
        # Enable the site
        a2ensite ${inp_domain_name} &&
        # Reload Apache if config is OK
        apache2ctl configtest &&
        service apache2 reload
    } >/dev/null 2>&1
    if [[ $? -eq 0 ]]; then
        echo -e " ${success} Apache virtual host has been set up "
        return 0
    else
        echo -e " ${failure} Unable to set up Apache virtual host " >&2
        return 1
    fi
    # Test Apache config and reload
    apache2ctl configtest &&
    service apache2 reload
    if [[ $? -eq 0 ]]; then
        return 0
    else
        echo -e " ${failure} Unable to reload Apache " >&2
        return 1
    fi
}

function create_database() {
    # Create database if needed
    if [[ "$inp_create_database" =~ ^[yY]$ ]]; then
        echo -ne " ${working} Creating database "
        sleep 1
        local db_name="$(< /dev/urandom tr -dc 'A-Za-z0-9' | head -c6)_$(echo ${inp_domain_name} | sed 's/[^A-Za-z0-9]/_/g')" &&
        local db_user="$(< /dev/urandom tr -dc 'A-Za-z0-9' | head -c6)_${inp_user_name}" &&
        local db_pass="$(< /dev/urandom tr -dc 'A-Za-z0-9_~@#%^' | head -c32)" &&
        mysql -se "CREATE USER \"${db_user}\"@\"localhost\" IDENTIFIED BY \"${db_pass}\";" &&
        mysql -se "CREATE DATABASE \`${db_name}\`;" &&
        mysql -se "GRANT ALL PRIVILEGES ON \`${db_name}\`.* TO \"${db_user}\"@\"localhost\";" &&
        mysql -se "FLUSH PRIVILEGES;"
        if [[ $? -eq 0 ]]; then
            echo -e " ${success} Database has been created "
            echo -e " ${details} Database: ${db_name} User: ${db_user} Password: ${db_pass} "
            return 0
        else
            echo -e " ${failure} Unable to set up database " >&2
            return 1
        fi
    fi
}

function misc_tweaks() {
    title "MISC. TWEAKS"
    echo -ne " ${working} Adding bash aliases "
    sleep 1
    local aliases="/etc/profile.d/00-aliases.sh"
    {
        if [[ ! -f "$aliases" ]]; then
            touch "$aliases"
        fi
        for als in "$(cat ${files}/snippets/amp_aliases)"; do
            grep "$als" "$aliases" || echo "$als" >> $aliases
        done
        source $aliases
    } >/dev/null 2>&1
    if [[ $? -eq 0 ]]; then
        echo -e " ${success} Bash aliases have been added "
    else
        echo -e " ${failure} Unable to add bash aliases " >&2
    fi
}

function amp_installed() {
    dpkg -l | grep -q apache2 &&
    dpkg -l | grep -q php8.1-fpm &&
    dpkg -l | grep -q mariadb
}

function title() {
    echo -e "\n ${blue}------------- ${@:1}${normal} \n"
}

function apt_fn() {
    apt-get -qq -o Acquire::ForceIPv4=true ${@:1} < /dev/null >/dev/null 2>&1
}


main