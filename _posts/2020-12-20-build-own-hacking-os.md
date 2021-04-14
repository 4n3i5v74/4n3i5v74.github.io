---
title: Building own Hacking OS
author: 4n3i5v74
date: 2020-12-20 00:00:00 +0530
categories: [HackingOS, Debian, CyberSecurity]
tags: [hackingos, debian, build, cybersecurity]
pin: true
---


## Introduction

If you ask security professionals, on what is the best platform to be used for hacking, they would suggest to build own OS and add the tools manually.

I myself was using kali and Parrot OS, and came across [this awesome video](https://www.youtube.com/watch?v=zTpuYI9TPJw){:target="_blank"}, by Zaid from ZSecurity, who explains how to build a custom hacking OS from scratch. There could be lots of other resources, but this video was complete and I built my OS on the first run.

The following is my experience based on the video mentioned above.


## OS Install

I will be explaining the steps post initial OS installation.
However, the following is the configuration I used.

- OS - Debian latest
- CPU - 2 (minimum)
- RAM - 4GB (minimum)
- DISK - 20GB (for OS - LVM), 100GB (for data - LVM)
- NIC - 1 NIC with internet enabled
- SOFTWARES - ssh server, gnome (for GUI)

Debian installation requires internet, so make sure to have NIC card with internet enabled during installation.
I will use 100GB disk as LVM partition under /data, and will install/configure additional packages, scripts and tools in that location.


## OS Basic Configuration

After OS is installed, set hostname and dns.
{% capture code %}{% raw %}hostnamectl set-hostname --static <fqdn>{% endraw %}{% endcapture %} {% include code.html code=code %}
{% capture code %}{% raw %}Set DNS to 1.1.1.1 and 1.0.0.1 for more security.{% endraw %}{% endcapture %} {% include code.html code=code %}

During OS installation, a regular user would have been created.
For the user to switch to root without password, make the following changes.
{% capture code %}{% raw %}visudo{% endraw %}{% endcapture %} {% include code.html code=code %}
{% capture code %}{% raw %}%sudo   ALL=(ALL:ALL) NOPASSWD: ALL{% endraw %}{% endcapture %} {% include code.html code=code %}

Edit the following line in `/etc/group` file.
{% capture code %}{% raw %}sudo:x:27:lab{% endraw %}{% endcapture %} {% include code.html code=code %}


## Latest Kernel and updates

In order to install latest 5.X kernel, backports channel should be enabled in the file `/etc/apt/sources.list`.
{% capture code %}{% raw %}deb https://deb.debian.org/debian buster-backports main contrib non-free{% endraw %}{% endcapture %} {% include code.html code=code %}

Perform an `apt update` to refresh the sources and download available updates.

Install the latest kernel.
{% capture code %}{% raw %}apt -t buster-backports install linux-image-amd64 linux-headers-amd64{% endraw %}{% endcapture %} {% include code.html code=code %}

Perform a full OS update.
{% capture code %}{% raw %}apt clean ; apt autoclean ; apt update ; apt upgrade -y ; apt dist-upgrade -y ; apt full-upgrade -y ; apt autoremove ; apt autoclean ; apt clean ; apt-file update{% endraw %}{% endcapture %} {% include code.html code=code %}

Perform a `reboot` at this stage to boot from new kernel.


## Packages and Services required

Install required basic packages for hacking.
{% capture code %}{% raw %}apt install linux-headers-$(uname -r) apt-file build-essential dkms vim bash-completion net-tools telnet lsof wget curl dnsutils strace ltrace jq zip unzip screen git tcpdump smbclient ftp python-pip python3-pip golang yasm pkg-config openmpi-bin flex cmake bison aircrack-ng nmap zenmap xsltproc sqlmap wireshark dirb bleachbit socat torbrowser-launcher ocl-icd-libopencl1 opencl-headers clinfo hashid openvpn nfs-common tmux fcrackzip tesseract-ocr zlib1g-dev libbz2-dev libimage-exiftool-perl libssl-dev libssh-dev libidn11-dev libpcre3-dev libgtk2.0-dev libmariadbclient-dev libpq-dev libsvn-dev firebird-dev libmemcached-dev libgpg-error-dev libgcrypt20-dev libpcap-dev libusb-1.0-0-dev libnetfilter-queue-dev libnetfilter-queue1 libssl-dev libgmp-dev libpcap-dev libnss3-dev libkrb5-dev libopenmpi-dev{% endraw %}{% endcapture %} {% include code.html code=code %}

As I run my Hacking OS as a VM inside VMware, I will be enabling open-vm-tools for seemless host-guest functionality. Make sure to install/enable corresponding virtualization guest package.
{% capture code %}{% raw %}systemctl enable --now open-vm-tools{% endraw %}{% endcapture %} {% include code.html code=code %}

Disable services which are not required at the moment.
{% capture code %}{% raw %}systemctl disable --now avahi-daemon nmbd smbd tor{% endraw %}{% endcapture %} {% include code.html code=code %}

## Bash customization

Add the following lines in `/etc/bash.bashrc` file for nice looking prompt, better history management and needed aliases.
{% capture code %}{% raw %}export HISTTIMEFORMAT='%F %T  '
export HISTSIZE=1000000
export HISTFILESIZE=1000000
export HISTCONTROL=ignoredups
shopt -s histappend

export PS1="\[\033[01;34m\]\t \[\033[01;32m\]\u@\h \[\033[01;91m\]\w \[\033[01;32m\]\! $ \[\033[0m\]"
export PROMPT_COMMAND="history -a; history -c; history -r; $PROMPT_COMMAND"

export DISPLAY=<ip>:0.0

export LS_OPTIONS='--color=auto'
eval "`dircolors`"

alias ls='ls $LS_OPTIONS'
alias ll='ls $LS_OPTIONS -l'

export GOROOT=/usr/local/go
export PATH=$PATH:$GOROOT/bin{% endraw %}{% endcapture %} {% include code.html code=code %}

Make the change apply for current session `source /etc/bash.bashrc`.


## VIM customization

Since I am in favor of vim, I will set up vim as default text editor.
{% capture code %}{% raw %}update-alternatives --set editor /usr/bin/vim.basic{% endraw %}{% endcapture %} {% include code.html code=code %}
This can also be set via command `/usr/bin/select-editor`.


Use the custom vimrc file for quick editing and syntax highlighting, in `/root/.vimrc` file.
{% capture code %}{% raw %}" Custom vimrc file to work easily with yaml and py files
" Save the file as .vimrc under home directory

set nocompatible

filetype off
filetype plugin indent on

set ttyfast
set laststatus=2
set encoding=utf-8
set autoread
set autoindent
set backspace=indent,eol,start
set incsearch
set hlsearch

" Basic vim settings
set hidden
set visualbell
set number
set nobackup
set noswapfile
set noshowmode

" Set the terminal's title
set title

" Global tab width.
set tabstop=2
set shiftwidth=2
set softtabstop=2
set expandtab

" Set to show invisibles (tabs & trailing spaces) & their highlight color
set list listchars=tab:»\ ,trail:·

" enable syntax highlighting
syntax enable

" show a visual line under the cursor's current line
" set cursorline

" show the matching part of the pair for [] {} and ()
set showmatch

" enable all Python syntax highlighting features
let python_highlight_all = 1

" Configure spell checking
nmap <silent> <leader>p :set spell!<CR>
set spelllang=en_us

" Set leader to comma
let mapleader = ","

" Default to magic mode when using substitution
cnoremap %s/ %s/\v
cnoremap \>s/ \>s/\v

" Capture current file path into clipboard
function! CaptureFile()
  let @+ = expand('%')
endfunction
map <leader>f :call CaptureFile()<cr>

" Rename current file
function! RenameFile()
  let old_name = expand('%')
  let new_name = input('New file name: ', expand('%'))
  if new_name != '' && new_name != old_name
    exec ':saveas ' . new_name
    exec ':silent !rm ' . old_name
    redraw!
  endif
endfunction
map <leader>n :call RenameFile()<cr>

" Strip whitespace on save
fun! <SID>StripTrailingWhitespaces()
  " Preparation: save last search, and cursor position.
  let _s=@/
  let l = line(".")
  let c = col(".")
  " Do the business:
  %s/\s\+$//e
  " Clean up: restore previous search history, and cursor position
  let @/=_s
  call cursor(l, c)
endfun
command -nargs=0 Stripwhitespace :call <SID>StripTrailingWhitespaces()

" Fix indentation in file
map <leader>i mmgg=G`m<CR>

" Toggle highlighting of search results
nnoremap <leader><space> :nohlsearch<cr>

" Unsmart Quotes
nnoremap guq :%s/\v[“”]/"/g<cr>
if has("autocmd")
  " StripTrailingWhitespaces
  autocmd BufWritePre * Stripwhitespace

" To spell check all git commit messages
  au BufNewFile,BufRead COMMIT_EDITMSG set spell nonumber nolist wrap linebreak
  " Set filetype tab settings
  autocmd FileType python,doctest set ai ts=4 sw=4 sts=4 et
  autocmd BufReadPost *
  \ if line("'\"") > 1 && line("'\"") <= line("$") |
  \   exe "normal! g`\"" |
  \ endif
endif{% endraw %}{% endcapture %} {% include code.html code=code %}


## Initialize GIT
{% capture code %}{% raw %}git config --global user.email <mail>
git config --global user.name <name>{% endraw %}{% endcapture %} {% include code.html code=code %}


## Wordlists


### Wordlists - RockYou

Download RockYou wordlist which is most widely used.
{% capture code %}{% raw %}curl -# -o /tmp/rockyou.txt.gz https://gitlab.com/kalilinux/packages/wordlists/-/raw/kali/master/rockyou.txt.gz ; mkdir /data/wordlists/ ; gunzip -c /tmp/rockyou.txt.gz > /data/wordlists/rockyou.txt{% endraw %}{% endcapture %} {% include code.html code=code %}


### Wordlists - SecLists

Download SecLists wordlist which is available by default in Kali, and also widely used.
{% capture code %}{% raw %}git clone --depth 1 https://github.com/danielmiessler/SecLists.git /data/wordlists/SecLists{% endraw %}{% endcapture %} {% include code.html code=code %}


### Wordlists - Dirb

We could copy wordlists from dirb, so all dictionaries will be available at a single location.
{% capture code %}{% raw %}mkdir /data/wordlists/dirb ; cp -ar /usr/share/dirb/wordlists/* /data/wordlists/dirb/{% endraw %}{% endcapture %} {% include code.html code=code %}


## Tools

The tools mentioned below need not be installed altogether. Whenever needed, install and use specific tool/module.

Create directory for manually installing/configuring tools `mkdir -p /data/tools/wireshark`.


### Install Burpsuite

{% capture code %}{% raw %}curl -# -o /tmp/burpsuite-community.sh "https://portswigger.net/burp/releases/download?product=community&version=2020.12.1&type=Linux" ; chmod 777 /tmp/burpsuite-community.sh ; /tmp/burpsuite-community.sh
chown root:root /data/tools/BurpSuiteCommunity/burpbrowser/87.0.4280.88/chrome-sandbox && chmod u+s /data/tools/BurpSuiteCommunity/burpbrowser/87.0.4280.88/chrome-sandbox{% endraw %}{% endcapture %} {% include code.html code=code %}


### Configure Burpsuite

Download jython, a requirement for extensions.
{% capture code %}{% raw %}curl -# -o /data/tools/jython-standalone-2.7.2.jar https://repo1.maven.org/maven2/org/python/jython-standalone/2.7.2/jython-standalone-2.7.2.jar{% endraw %}{% endcapture %} {% include code.html code=code %}


### Install Metasploit

{% capture code %}{% raw %}curl -# -o /tmp/msfinstall https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb ; chmod 755 /tmp/msfinstall ; /tmp/msfinstall{% endraw %}{% endcapture %} {% include code.html code=code %}


### Configure Metasploit

Metasploit is intended to be run as regular user. Hence perform the following steps as regular user.
Initialize metasploit db using `msfdb init`. Note down the metasploit web service username, password and API token.
There will also be a manual database connect command. This will not be necessary, but worth noting down.
Check the status of database connection from `msfconsole` using `db_status`.


### Install Gobuster

{% capture code %}{% raw %}cd ~ ; go get -u github.com/OJ/gobuster ; cp go/bin/gobuster /usr/bin{% endraw %}{% endcapture %} {% include code.html code=code %}


### Install dirsearch

{% capture code %}{% raw %}cd ~ ; git clone https://github.com/maurosoria/dirsearch.git /data/tools/dirsearch ; pip3 install -r /data/tools/dirsearch/requirements.txt{% endraw %}{% endcapture %} {% include code.html code=code %}


### Install Bettercap

{% capture code %}{% raw %}cd ~ ; go get -u github.com/bettercap/bettercap ; cp go/bin/bettercap /usr/bin{% endraw %}{% endcapture %} {% include code.html code=code %}


### Install theHarvester

{% capture code %}{% raw %}git clone https://github.com/laramies/theHarvester.git /data/tools/theHarvester ; pip3 install -r /data/tools/theHarvester/requirements/base.txt ; mkdir /etc/theHarvester ; cp /data/tools/theHarvester/proxies.yaml /etc/theHarvester{% endraw %}{% endcapture %} {% include code.html code=code %}


### Install Nikto

{% capture code %}{% raw %}git clone https://github.com/sullo/nikto /data/tools/nikto{% endraw %}{% endcapture %} {% include code.html code=code %}


### Identifying Hashes

Online tools like [Dcode](https://www.dcode.fr/cipher-identifier){:target="_blank"} or [Hashes](https://hashes.com/en/tools/hash_identifier){:target="_blank"} can be used for identifying hashes.

Offline tools like [hash-id.py](https://gitlab.com/kalilinux/packages/hash-identifier){:target="_blank"} or `hashid` can also be used.


### Install Hashcat

{% capture code %}{% raw %}git clone https://github.com/hashcat/hashcat.git /data/tools/hashcat ; cd /data/tools/hashcat ; make ; make install ; cd ~{% endraw %}{% endcapture %} {% include code.html code=code %}

To install in windows, download the binary [here](https://github.com/openwall/john-packages/releases/tag/jumbo-dev){:target="_blank"}


### Check compatability for running hashcat

{% capture code %}{% raw %}clinfo
/data/tools/hashcat/hashcat --benchmark --force{% endraw %}{% endcapture %} {% include code.html code=code %}


### Install John the Ripper

{% capture code %}{% raw %}git clone https://github.com/openwall/john -b bleeding-jumbo /data/tools/john ; cd /data/tools/john/src/ ; ./configure && make -s clean && make -sj4 ; cd ~{% endraw %}{% endcapture %} {% include code.html code=code %}

To install in windows, download the binary from [here](https://github.com/openwall/john-packages/releases/tag/jumbo-dev){:target="_blank"} or [here](https://download.openwall.net/pub/projects/john/contrib/windows/){:target="_blank"}


### Install smbmap

{% capture code %}{% raw %}git clone https://salsa.debian.org/pkg-security-team/smbmap.git /data/tools/smbmap ; pip3 install -r /data/tools/smbmap/requirements.txt{% endraw %}{% endcapture %} {% include code.html code=code %}


### Install hydra

{% capture code %}{% raw %}git clone https://github.com/vanhauser-thc/thc-hydra.git /data/tools/hydra ; cd /data/tools/hydra ; ./configure ; make ; make install ; cd ~{% endraw %}{% endcapture %} {% include code.html code=code %}


### Install impacket

{% capture code %}{% raw %}git clone https://github.com/SecureAuthCorp/impacket.git /data/tools/impacket ; pip3 install -r /data/tools/impacket/requirements.txt{% endraw %}{% endcapture %} {% include code.html code=code %}


### Install enum4linux

{% capture code %}{% raw %}git clone https://github.com/portcullislabs/enum4linux /data/tools/enum4linux{% endraw %}{% endcapture %} {% include code.html code=code %}


## OpenVPN

### OpenVPN - TryHackMe

If using openvpn, the easiest way to configure is to put the openvpn config file to `/etc/openvpn`, as `tryhackme.conf`, and to configure the service.
{% capture code %}{% raw %}systemctl start openvpn@tryhackme{% endraw %}{% endcapture %} {% include code.html code=code %}


### OpenVPN - VPNBook

Similar setup for VPNBook openvpn.
{% capture code %}{% raw %}mkdir /data/vpnbook

wget https://www.vpnbook.com/free-openvpn-account/VPNBook.com-OpenVPN-FR8.zip -O /data/vpnbook/VPNBook.com-OpenVPN-FR8.zip ; unzip /data/vpnbook/VPNBook.com-OpenVPN-FR8.zip -d /data/vpnbook ; sed -i "s/^auth-user-pass.$/auth-user-pass\t\/data\/vpnbook\/auth.conf/g" /data/vpnbook/vpnbook-fr8-tcp443.ovpn

wget https://www.vpnbook.com/free-openvpn-account/VPNBook.com-OpenVPN-DE4.zip -O /data/vpnbook/VPNBook.com-OpenVPN-DE4.zip ; unzip /data/vpnbook/VPNBook.com-OpenVPN-DE4.zip -d /data/vpnbook ; sed -i "s/^auth-user-pass.$/auth-user-pass\t\/data\/vpnbook\/auth.conf/g" /data/vpnbook/vpnbook-de4-tcp443.ovpn

touch /data/vpnbook/auth.conf

cp /data/vpnbook/vpnbook-fr8-tcp443.ovpn /etc/openvpn/vpnbook1.conf
cp /data/vpnbook/vpnbook-de4-tcp443.ovpn /etc/openvpn/vpnbook2.conf

chmod 600 /data/vpnbook/auth.conf && curl -s "https://www.vpnbook.com" | grep -A 1 "Username: vpnbook" | tail -n 2 | cut -f2 -d " " | cut -f1 -d '<' | awk 'NF>0' >/data/vpnbook/auth.conf 2>/dev/null && curl -s -X POST --header "apikey: <api-key>" -F "url=https://www.vpnbook.com/$( curl -s "https://www.vpnbook.com/freevpn" | grep -m2 "Password:" | tail -n1 | cut -d \" -f2 )" -F 'language=eng' -F 'isOverlayRequired=true' -F 'FileType=.Auto' -F 'IsCreateSearchablePDF=false' -F 'isSearchablePdfHideTextLayer=true' -F 'scale=true' -F 'detectOrientation=false' -F 'isTable=false' "https://api.ocr.space/parse/image" 2>/dev/null | jq -r ".ParsedResults[].ParsedText" 2>/dev/null | awk 'NF>0' >>/data/vpnbook/auth.conf && chmod 400 /data/vpnbook/auth.conf && systemctl start openvpn@vpnbook1{% endraw %}{% endcapture %} {% include code.html code=code %}


## Bleachbit

Initialize bleachbit as regular user for first time, select the cleanup modules required and preview first. It will generate a config file under home directory.
Copy the file to root directory to use bleachbit in command line.
{% capture code %}{% raw %}mkdir -p /root/.config/bleachbit ; cp /home/<user>/.config/bleachbit/bleachbit.ini /root/.config/bleachbit/{% endraw %}{% endcapture %} {% include code.html code=code %}

Use `bleachbit -p --preset` to preview using the generated config file, and `bleachbit -c --preset` to perform the cleanup.


## Update Bash alias

Create alias for custom built tools in `/etc/bash.bashrc` file.
{% capture code %}{% raw %}export XDG_RUNTIME_DIR="/data/tools/wireshark/"

alias theHarvester="python3 /data/tools/theHarvester/theHarvester.py"
alias nikto="perl /data/tools/nikto/program/nikto.pl"
alias hashcat="/data/tools/hashcat/hashcat"
alias john="/data/tools/john/run/john"
alias smbmap="python3 /data/tools/smbmap/smbmap.py"
alias hydra="/data/tools/hydra/hydra"
alias burp="/data/tools/BurpSuiteCommunity/BurpSuiteCommunity"
alias enum4linux="perl /data/tools/enum4linux/enum4linux.pl"
alias ovb="systemctl start openvpn@4n3i5v74"
alias ove="systemctl stop openvpn@4n3i5v74"
alias ovv1b='chmod 600 /data/vpnbook/auth.conf && curl -s "https://www.vpnbook.com" | grep -A 1 "Username: vpnbook" | tail -n 2 | cut -f2 -d " " | cut -f1 -d "<" | awk "NF>0" >/data/vpnbook/auth.conf 2>/dev/null && curl -s -X POST --header "apikey: <api-key>" -F "url=https://www.vpnbook.com/$( curl -s "https://www.vpnbook.com/freevpn" | grep -m2 "Password:" | tail -n1 | cut -d \" -f2 )" -F "language=eng" -F "isOverlayRequired=true" -F "FileType=.Auto" -F "IsCreateSearchablePDF=false" -F "isSearchablePdfHideTextLayer=true" -F "scale=true" -F "detectOrientation=false" -F "isTable=false" "https://api.ocr.space/parse/image" 2>/dev/null | jq -r ".ParsedResults[].ParsedText" 2>/dev/null | awk "NF>0" >>/data/vpnbook/auth.conf && chmod 400 /data/vpnbook/auth.conf && systemctl start openvpn@vpnbook1'
alias ovv1e='systemctl stop openvpn@vpnbook1'
alias ovv2b='chmod 600 /data/vpnbook/auth.conf && curl -s "https://www.vpnbook.com" | grep -A 1 "Username: vpnbook" | tail -n 2 | cut -f2 -d " " | cut -f1 -d "<" | awk "NF>0" >/data/vpnbook/auth.conf 2>/dev/null && curl -s -X POST --header "apikey: <api-key>" -F "url=https://www.vpnbook.com/$( curl -s "https://www.vpnbook.com/freevpn" | grep -m2 "Password:" | tail -n1 | cut -d \" -f2 )" -F "language=eng" -F "isOverlayRequired=true" -F "FileType=.Auto" -F "IsCreateSearchablePDF=false" -F "isSearchablePdfHideTextLayer=true" -F "scale=true" -F "detectOrientation=false" -F "isTable=false" "https://api.ocr.space/parse/image" 2>/dev/null | jq -r ".ParsedResults[].ParsedText" 2>/dev/null | awk "NF>0" >>/data/vpnbook/auth.conf && chmod 400 /data/vpnbook/auth.conf && systemctl start openvpn@vpnbook2'
alias ovv2e='systemctl stop openvpn@vpnbook2'
alias nts="netstat -tunlap"
alias bclean="bleachbit -c --preset"{% endraw %}{% endcapture %} {% include code.html code=code %}

Make the change apply for current session `source /etc/bash.bashrc`.


## Tips for searching packages

{% capture code %}{% raw %}apt-cache search <package>
apt search <package>
apt-file search <file>{% endraw %}{% endcapture %} {% include code.html code=code %}

Search [Kali Package Tracker](http://pkg.kali.org){:target="_blank"} for packages, and use source github to build and use the tool, which is not available for debian by default.
Searcg [Kali Gitlab](https://gitlab.com/kalilinux/packages){:target="_blank"} for packages and install / build and use the tool, which is not available for debian by default.

