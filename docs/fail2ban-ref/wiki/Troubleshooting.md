Please read [proper fail2ban configuration](Proper-fail2ban-configuration) carefully before and follow the instructions there.<br/>
Many issues are configuration-related and can be relative easy rectified by the adjustment of the configuration.

***
**[Q]** I messed up Fail2Ban during Testing and blocked out my own IP address, how do I completely reset Fail2Ban to get it off to a clean start?<br/>
**[A]** In newer versions of Fail2Ban you can simply run the command<br/>
`?sudo? fail2ban-client unban <IP> ... <IP>`<br/>
Which will remove all entries for that IP from your firewall system (using banning actions) and from fail2ban database file `fail2ban.sqlite3` for all jails.<br/>
But fail2ban still holds the offsets of already processed log-lines in the database (so this entries will be bypassed if fail2ban should be restarted later).

**[A]** Up to version 0.10 you can do it only per jail:<br/>
`?sudo? fail2ban-client set <JAIL> unbanip <IP>`

**[A]** To reset fail2ban completely and start off fresh **(not to be recommended)**<br/>
Should you ever want to completely clear and reset the Fail2Ban log file and SQLite database for whatever reason you can do the following:
- Stop Fail2Ban<br/>
`?sudo? service fail2ban stop`
- Empty the Fail2Ban LogFile<br/>
`?sudo? truncate -s 0 /var/log/fail2ban.log`
- Delete the Fail2Ban SQLite Database File<br/>
`?sudo? rm /var/lib/fail2ban/fail2ban.sqlite3`
- Restart Fail2Ban<br/>
`?sudo? service fail2ban restart`

If you delete fail2ban database, also consider deleting any of your Apache, Nginx or Auth log files or just the entries that may contain your own IP address used during testing, as once Fail2Ban starts again, depending on your jail settings, it will just block you again.
***
**[Q]** Fail2Ban will not start and is giving me the following error message "Job for fail2ban.service failed. See 'systemctl status fail2ban.service' and 'journalctl -xn' for details." but checking those does not help me trace where my error is.</span><br/>
**[A]** First take a look in journal log of fail2ban.service by running<br/>
`journalctl -ru fail2ban`<br/>

Your fail2ban.log file in `/var/log/fail2ban.log` is also a very good place to keep a check for errors.<br/>

If you find and fix your error then reload fail2ban using:<br/>
- Reload (works only since 0.10):<br/>
`?sudo? service fail2ban reload`<br/>
- Or more aggressive (using restart).<br/>
`?sudo? service fail2ban restart`<br/>
Please note: all banned IPs will be unbanned and banned again after restart.<br/>

***
**[Q]** I'm trying to block connections on a service hosted in a docker container. Fail2ban logs says it has banned some IPs, but I still see some connections from banned adresses in the service logs?<br/>
**[A]** fail2ban uses the INPUT iptables chain by default to block incoming traffic for the local server. docker uses FORWARD chain to send traffic to your containers, so the rules in the INPUT chain will have no effect. You need to change the default iptables chain to DOCKER-USER (which is called by FORWARD chain) in your jail config file, so that the blocking rule can block traffic destinated to services hosted in docker containers:

```
[FILTERNAME]
enabled = true
chain = DOCKER-USER
```
See [#2292](https://github.com/fail2ban/fail2ban/issues/2292) for more details.


**For Heavy Debugging Users**<br/>
You can run the Fail2Ban-Client in a very verbose mode using the following commands which will show you all output when Fail2Ban is loading, this is also a useful method for tracing errors in jails, filters and actions.<br/><br/> 
Stop the Failban Server by running<br/>
`?sudo? service fail2ban stop`<br/><br/>
Make sure the Fail2Ban client is also not running by running the following<br/>
`?sudo? fail2ban-client -vvv -x stop`<br/><br/>
Then start the Fail2Ban client in verbose mode as follows<br/>
`?sudo? fail2ban-client -vvv -x start`<br/><br/>
This will show you exactly in which jail, filter or action your error lies.
Once you can start the fail2ban-client successfully using `?sudo? fail2ban-client -vvv -x start`<br/><br/>
Then stop it again using <br/>
`?sudo? fail2ban-client -vvv -x stop`<br/><br/>
and then start the Fail2Ban Server<br/>
`?sudo? service fail2ban restart`<br/><br/>