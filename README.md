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
- [Looting for password](#looting-for-password)
    *
	*
	*

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

for find hostname 
```
$ hostname 
```

print all system information
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
list all task and process of system 
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

keep track many program read input from the user a line at a time
```
$ history 

$ cat ~/.bash_history
``` 

## Network enumeration

see what is ipv4/6  address of system
``` 
$ ifconfig 
$ ip a 
```

network route and ip address 
```
$ route 
$ ip route 
```

arp packet that send 
```
$ arp -a 
$ ip neigh
```

all quistion that command can tell it answare to you : 
  - what port are open?
  - who i communicate with?
  - who is out there network ? 
  - and more
```
$ netstat -ano 
```

## password hunting

search in the all file in linux system that contin PASSWORD key
```
$ grep --color=auto -rnw '/' -ie "PASSWORD" --color=always 2> /dev/null 
```

find all tools in the system that have pass key as the  file name 
```
$ locate pass  | less 
```

find id_rsa file to public and private key 
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
grep --color=auto -rnw '/' -ie "PASSWORD" --color=always 2> /dev/null
find . -type -f -exec grep -i -I "PASSWORD" {} /dev/null \;
```

File that were edited in the last 10 minutes 
```
find / -mmin -19 2>/dev/null | grep -Ev "^/proc"
```

in history command 
```
cat .bash_history | grep -i "password"
```
in memory passwords 
```
strings /dev/mem -n10 | grep -i PASS
```
check permision of shadow file and if you have read permision LUKY LUK so use this command and read hash password 
```
cat /etc/shadow 
```
We can crack the password using join the ripper :
```
unshadow passwd shadow > unshadowd.txt
join --rules --wordlist=/path/to/wordlist/file.txt unshadowed.txt
```

## ssh keys 

```
find / -name authorized_keys 2> /dev/null
find / -name id_rsa 2> /dev/null
```

search within history strings that cnotain ssh / telnet / mysql
```
grep ^ssh /home/*/.hist
grep ^telnet /home/*/.hist
grep ^mysql /home/*/.hist
```


# ETC

-
-
-
