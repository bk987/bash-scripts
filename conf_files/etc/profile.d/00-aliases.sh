function cdl() {
    DIR="$*";
    if [ $# -lt 1 ]; then
        DIR=$HOME;
    fi;
    \cd "${DIR}" &&
    ls -AF
}
function mkcd() {
    \mkdir -pv "$1" &&
    \cd "$1"
}

alias ..="cd .."
alias cd..="cd .."
alias ...='cd ../../'
alias ....='cd ../../../'
alias cp='sudo cp -iv'
alias mv='sudo mv -iv'
alias ln='sudo ln -v'
alias rm='sudo rm -I --preserve-root'
alias chown='sudo chown --preserve-root'
alias chmod='sudo chmod --preserve-root'
alias chgrp='sudo chgrp --preserve-root'
alias mkdir="sudo mkdir -pv"
alias ax="sudo chmod a+x"

alias update='sudo apt-get update && sudo apt-get upgrade'
alias subb='sudo su -s /bin/bash -'
alias ports='netstat -tulanp'
alias psag="ps aux | grep"
alias topcpu='top -o %CPU'
alias topmem='top -o %MEM'

alias aptsr='apt-cache search'
alias aptsh='apt-cache show'
alias npmi="npm install"
alias npmis="npm install --save"
alias npmid="npm install --save-dev"
alias npmig="npm install --global"
