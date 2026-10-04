Fail2Ban scans log files resp. journals (using specified regular expressions also known as filter-rules) and executes configured actions to ban failures having too many attempts (matched specified filter-rules). It does this e. g. by updating system firewall rules to reject new connections from those IP addresses, for a configurable amount of time.
But you can write resp. configure your own action to [ban something other as host/IP, like user or e-mail](How-to-ban-something-other-as-host-(IP-address),-like-user-or-mail,-etc.).

Fail2Ban comes out-of-the-box ready to read many standard log files, such as those for sshd and Apache, and is easy to configure to read any log file you choose, for any error you choose.

**But fail2ban is just a tool, so it should be [properly configured](Proper-fail2ban-configuration).**

***
**[Q]** Fail2ban does not detect some authentication failures or ban doesn't occur
<details><summary>Answer</summary>

**[A]** Fail2ban is monitoring log-files or journals and searching for matches corresponding `failregex` or `filter` rules specified in jail. Every found match will be logged (in `fail2ban.log` or its journal), for example `[jail] Found 192.0.2.25`. After several attempts (`maxretry` failures within a time windows of `findtime` seconds) from the same intruder it will be banned and every ban will be also logged, for example `[jail] Ban 192.0.2.25`.

If there are `Ban` messages in fail2ban log, but the intruder is still able to connect or continue an attack, then rather take a look for the answer to next question.

If there is no such `Found` or `Ban` messages logged:
- corresponding jail for scanning the log file or systemd journal is not enabled (or idle). See [here](Proper-fail2ban-configuration) how the jail can be enabled.
- the proper parameter `backend` (for example `auto` for log files or `systemd` for journal), proper path to the log files (parameter `logpath`) or proper journal control parameter `journalmatch` should be set for this jail.
- the IP goes to ban if it makes at least `maxretry` failures within `findtime` seconds. So if you've configured `maxretry=5` and `findtime=10m` (default values) then it needs at least 5 failures (5 attempts) within 10 minutes to ban an IP.<br/>
Each failure (attempt) will be logged in `fail2ban.log` as:<br/>
`  INFO    [jail] Found 192.0.2.25`<br/>
First if you'll see at least 5 such lines with this IP address within 10 minutes, the IP goes banned and you should see:<br/>
`  NOTICE  [jail] Ban 192.0.2.25`<br/>
If there are some `Found` but no `Ban` messages for an IP, the solution could be to increase `findtime` or decrease `maxretry`. Just note that the larger `findtime` and smaller `maxretry` the higher may be the probability of false positives (mistaken bans of legitimate users);
- no matching date-time pattern or wrong date-time pattern specified for the jail resp. filter via `datepattern`, thus it does not match the log-line at all;
- be careful with `%` character in fail2ban configurations (because of the python-config, it should be dual-escaped `%%`);
- note the time of values that fail2ban recognizes from the log-file will be converted using the system time zone (if not specified different) - be sure that the times, written from the corresponding service into the log, are not too old for the fail2ban;
- each failure should match a regular expressions (from stock fail2ban or local customized in jail.local, some filter from `/etc/fail2ban/filter.d`, etc). It may be, that the expression or some part of it is not good enough.
You can use another fail2ban tool `fail2ban-regex` to check resp. build your own `failregex`.
Note: fail2ban tries to search the match not the original string - the datetime value (matched `datepattern`) will be cut out from it before searching.
</details>
<details><summary>Examine interpolated configuration (dump)</summary>
<br/>

You can use `fail2ban-client -d` to see interpolated configuration of all your configs (stock, distribution and local merged together) to check it is valid (no syntactical errors) and to clarify certain issues described above.

For example start with this one (replace `sshd` with your jail name):
```bash
fail2ban-client -d | grep ", 'sshd'" | grep -E "'((add)?(logpath|journalmatch)|start|add)'"
# or with that:
jail=sshd; fail2ban-client -d | grep -E "($jail.*\b(add)?(logpath|journalmatch)\b)|(\b(start|add)\b.*$jail)"
```
to examine that your jail (here `sshd`) is enabled, uses proper `backend` (`auto`, `polling`, `pyinotify` for file- and `systemd` for journal-related monitoring, respectively) as well as the `logpath` (for file) and `journalmatch` (for systemd-journal) are also correct for you.

You should then see something like that:
```
['add', 'sshd', 'auto']
['set', 'sshd', 'addjournalmatch', '_SYSTEMD_UNIT=sshd.service', '+', '_COMM=sshd']
['set', 'sshd', 'addlogpath', '/var/log/auth.log', 'head']
['start', 'sshd']
```
</details>


***
**[Q]** Ban takes place but does not work, the intruder is still able to connect and continues an attack
<details><summary>Answer</summary>

**[A]** If there are `Ban` messages in fail2ban log for the jail, but the banning seems not to work, so the intruder is able to continue an attack.<br/>
Mostly you'd also see too many notices like `[jail] 192.0.2.25 already banned` in the fail2ban log (also several minutes after ban occurred).

It could have many reasons:
- there is no banning action (mostly set as parameter `banaction`) or the action is not suitable to ban this ticket: for instance cannot ban this IP family (such as not IPv6 capable), or trying to ban not IP-based ticket (like user or session-ID) with IP-based action, etc<br/>
  Or something going wrong by execution of the ban-action - firstly check for errors in fail2ban log immediately after ban and at start of fail2ban.<br/>
  Also make sure that action creates expected tables, chains and rules in the related net-filter subsystem, for example if some iptables action used, one can verify it by checking of iptables entries (with `iptables -nL`), where one should find the fail2ban jail name (prefixed with `f2b-`) as chain and the rule corresponding the IP address.
- firewall or net-filter based action does not work at all or for some constellation:
  * port-based action gets wrong port, for instance service `sshd` listening to port 2222, but in jail the `port` is still set default value 22<br/>
    (solution is to specify `port = 2222` for this jail or to switch to all-ports banning action, like `banaction = iptables-allports`);
  * multiport action doesn't cover all ports the service is listening for, e. g. service `nginx` listening to port 80 and 443 but also 8080 for some reason, but in jail the `port` is still set default value 80,443<br/>
    (solution is to extend port `port = 80,443,8080` for this jail or to switch to all-ports banning action, like `banaction = iptables-allports`);
  * your action bans only TCP protocol, but the failures are generated by UDP connection (incoming UDP packets are bypassing net-filter rules for TCP traffic);
  * firewall or net-filter the action is based on does not work (for instance action uses kernel module which is unsupported on the system, or some feature is unsupported or not properly configured in container or virtual environment);
  * firewall or net-filter subsystem has some configuration preventing fail2ban ban properly e. g. ignores already established connections, so intruder is able to continue over established keep-alive socket unless it timeouts (or server/client closes the connection)
  (solution is to remove such whitelisting firewall rules for established connection or to extend action with some special handling dropping or rejecting the active established connection of intruder, using something like `tcpkill`, `killcx`, `ss`, etc);<br/>
  a good illustration of such ruleset listing for iptables with a bypass for established connection provided by ufw may be found in [#2545](https://github.com/fail2ban/fail2ban/issues/2545#issuecomment-543347684);
  * there are some other firewalls/net-filters yet or even some white-listing rules with higher precedence than fail2ban, allowing banned connections or forwarding them somewhere (e. g. to docker container) before fail2ban rules would have an effect;<br/>
  (check all native tables and chains of lowest level net-filter sub-system, e. g. `iptables -Ln`, `nft list`, etc and resolve possible conflicts, e. g. remove rules allowing banned connections or reorder them below the fail2ban tables or chains, or switch to another banning action using net-filter better suitable for your system)
  * if you are using docker, the docker FORWARD rule may take precedence, configure the chain as discussed in [#2376](https://github.com/fail2ban/fail2ban/issues/2376); also consider [wiki :: Fail2Ban and Docker](https://github.com/fail2ban/fail2ban/wiki/Fail2Ban-and-Docker)
- everything is correct with banning action, but there are no rules in chains or tables of net-filter at some point:
  * some service or tool may remove fail2ban tables or flush its chains accidently (for instance using `iptables-restore` without `-n` or `--noflush`) etc;
  * your net-filter sub-system is not multi-processing safe, for example changing of some tables from two processes i. e. fail2ban and some service simultaneously loses modification of fail2ban (last wins);
- there are `Unban` messages in fail2ban log immediately or short time after the intruder gets banned (so it gets unbanned too early):
  * either your `bantime` is too small (increase this value);
  * or the fail2ban or the monitored service are affected by the time-zone issue (times are different in those logs);
</details>


***
**[Q]** Fail2ban detects resp. incorrectly blocks some authentication attempts as failure (e. g. bans my IP address)
<details><summary>Answer</summary>

**[A]** It may be, that the expression is not good enough or the matching just occurs in pre-authentication step (e. g. by handshake) and so even per success login you have one failure (in sense of your configuration of fail2ban), so normally for the "fix" in this case, it will be enough to increase `maxretry` resp. to decrease `findtime` for this jail.

Why this IP was banned you can find in the `fail2ban.log` (search for lines before `[affected-jail-name] Found <IP>`) if your log-level more precise as INFO.<br/>
Otherwise take a look in the corresponding log file on the time from which fail2ban logged the failure.

Or try to use `fail2ban-regex` with log-file and filter-file as arguments.<br/>
E. g. if you want to see why the IP-address was banned in sshd jail:
```
# auth.log:
fail2ban-regex --print-all-matched /var/log/auth.log /etc/fail2ban/filter.d/sshd | grep 192.0.2.25
# or systemd journal:
fail2ban-regex --print-all-matched systemd-journal /etc/fail2ban/filter.d/sshd | grep 192.0.2.25
```

If your fail2ban version is larger as 0.9 and database was not disabled, you can quick find there corresponding log-matches for this IP, e. g. by executing of following script:
``` bash
# set your IP and db-path ...
?sudo? python -c "ip='192.0.2.25'; db='/var/lib/fail2ban/fail2ban.sqlite3';  import sys, logging; logging.basicConfig(stream=sys.stdout, level=logging.ERROR); from fail2ban.server.database import Fail2BanDb; db = Fail2BanDb(db); t = db.getBansMerged(ip=ip); print(('%d attempts, matches:\n  %s' % (t.getAttempt(), '\n  '.join(t.getMatches())) ) if t else 'NOT FOUND')"
```
Following script shows all failures of all IPs across all jails:
```bash
?sudo? python -c "db='/var/lib/fail2ban/fail2ban.sqlite3';  import sys, logging; logging.basicConfig(stream=sys.stdout, level=logging.ERROR); from fail2ban.server.database import Fail2BanDb; db = Fail2BanDb(db); t = db.getBansMerged(); print('\n'.join((('%s - %d attempts, matches:\n  %s' % (t.getIP(), t.getAttempt(), '\n  '.join(t.getMatches())) ) for t in t)))"
```
</details>

***
**[Q]** Fail2ban does not ban and logs include `iptables v...: unknown option "-w"`
<details><summary>Answer</summary>

**[A]** Default configuration of Fail2Ban requires iptables with locking support (`-w` option).  If you run on a system with older iptables (before `1.4.20`), you need to disable locking option by e.g. providing   `/etc/fail2ban/action.d/iptables.local` file with

```
[Init]
lockingopt =
```
</details>

***
**[Q]** After Fail2ban starts, I'm not seeing the filter chains I expect as per my configuration
<details><summary>Answer</summary>

**[A]** Fail2ban will create the filter chains on demand, i.e. as the first bans actually happen. This behaviour was changed in fail2ban 0.10 - prior to that version empty chains were created directly at startup (see also [this SO answer](https://stackoverflow.com/a/68622588/1529709) and [#1742](https://github.com/fail2ban/fail2ban/pull/1742)).
</details>