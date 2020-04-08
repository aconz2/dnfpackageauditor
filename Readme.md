# Libaudit example

I wanted to get a list of all packages installed on my system that I haven't used in a while so I could remove them. This means collecting information on when a program is actually run.

I initially looked into just using auditd as it is already builtin, but then thought I would hook in directly and then I could do some custom processing online to dedup, count, etc. I had some issues finding any documentation on using libaudit, but between two stack overflow questions and reading headers and auditd source, I hacked together a working example.

In the end, I just configured the regular auditd daemon to do this in the background and I will examine the logs there. But this is a nice program for figuring out all the things going on in your system

# Instructions
```
# trying to stop auditd with systemctl fails; why its a service i don't know
# auditd has to be closed AFAIK b/c only one PID can receive events from the kernel
sudo service auditd stop
sudo auditctl -s  # check status, pid should be 0

sudo dnf install audit-libs audit-libs-devel libev libev-devel
make
sudo ./audit
```

# Usage
```
-r will output the entire message and its type (in this case we only print EXECVE events)
-t will print the process ancestry like `/usr/bin/esmtp(24937) -- /usr/bin/bash(20837) -- /usr/lib/systemd/systemd(1) --`
-c will include the /proc/[pid]/cmdline (skipping the first arg) in either the default format (tsv) or the tree format
No flags will output a tsv with fields ppid, pid, and exe (any of these can be thee output `(null)`)
```

## Example Output

In another terminal I have a loop running

```
while true; do git status; clear; sleep 1; done
```

## Default
```
sudo ./audit | head -n2

```

```
4470	7837	/usr/bin/git
4470	7838	/usr/bin/clear
```

## Ancestry Tree
```
sudo ./audit -t | head -n2

```

```
git(12261) -- /bin/bash(4470) -- alacritty(4451)
clear(12262) -- /bin/bash(4470) -- alacritty(4451)
```

## Ancestry Tree + Arguments
```
sudo ./audit -t | head -n2

```

```
git(3174)[status] -- /bin/bash(4470)[] -- alacritty(4451)[]
clear(3175)[] -- /bin/bash(4470)[] -- alacritty(4451)[]
```

## Raw Message
```
sudo ./audit -t | head -n4

```

```
audit(1586373889.003:160226): argc=2 a0="git" a1="status"ccess=yes exit=0 a0=55a2e6b00150 a1=55a2e6b00030 a2=55a2e6ae4a20 a3=8 items=2 ppid=4470 pid=21424 auid=1000 uid=1000 gid=1000 euid=1000 suid=1000 fsuid=1000 egid=1000 sgid=1000 fsgid=1000 tty=pts0 ses=2 comm="git" exe="/usr/bin/git" subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=(null)
4470	21424	/usr/bin/git
audit(1586373889.008:160227): argc=1 a0="clear"call=59 success=yes exit=0 a0=55a2e6a369d0 a1=55a2e6aff2b0 a2=55a2e6ae4a20 a3=8 items=2 ppid=4470 pid=21425 auid=1000 uid=1000 gid=1000 euid=1000 suid=1000 fsuid=1000 egid=1000 sgid=1000 fsgid=1000 tty=pts0 ses=2 comm="clear" exe="/usr/bin/clear" subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=(null)
4470	21425	/usr/bin/clear
```

# Warnings

Seeing how much stuff is running on your computer may make your head explode. Some of its there for a good reason, but please tell me why there are hundreds of alternating calls between `esmtp` and `expr`

# TODO

I will follow up later with the code to analayze the auditd log and comapare it with the list of binaries provided by user installed packages and figure out which ones aren't being used anymore

# Links
- <https://stackoverflow.com/questions/56252499/how-to-use-libaudit>
- <https://stackoverflow.com/questions/57534297/how-to-use-audit-in-linux-to-monitor-a-file-using-libaudit>
- <https://www.digitalocean.com/community/tutorials/how-to-write-custom-system-audit-rules-on-centos-7>
- <https://github.com/linux-audit/audit-documentation/wiki>
