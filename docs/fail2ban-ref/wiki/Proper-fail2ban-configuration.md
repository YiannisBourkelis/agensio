If not configured manually, Fail2ban will load configuration files from the directory `/etc/fail2ban`. You can find many files called `*.conf` there.<br/>
Before you start the fail2ban service for the first time, you should do some configuration appropriate to your system. The least would be to enable jails for the services that you want to protect with fail2ban.

***
**[Q]** Should I make my configuration directly in `jail.conf` and `fail2ban.conf`?<br/>
**[A]** No. You should avoid to change `.conf` files, created by fail2ban installation. Instead, you should create new files with a `.local` extension.
<details>

Since these stock files may be overwritten by the package upgrades, or because your changes may be incompatible with some future versions, you shouldn't edit it in-place.<br/>
So to set your jail configuration, don't change `jail.conf`. To customize some filter configuration, don't change `filter.conf`. Instead, create a new file with a `.local` extension and insert only the settings you want to override or the settings you want to append to the default configuration. For example any values defined in `jail.local` will override those in `jail.conf` in the same sections (e. g. `[DEFAULT]`).

So for example if original `.conf` file contains:
```ini
[DEFAULT]
logpath = /path/to/log

[section1]
logpath = /other/path
enabled = true

[section2]
enabled = true
```
And you'll create a `.local` file contains:
```ini
[DEFAULT]
logpath = /my-path/to/log
```
The value of parameter `logpath` in `section1` will be still `/other/path`.<br/>
But value of parameter `logpath` in `section2` will be changed to `/my-path/to/log` (because it was not specified in the section itself, so the new default value will be used).
</details>

***
**[Q]** What configuration is necessary to let fail2ban protect a service?
<details><summary>Answer</summary>

**[A]** You should create a `jail.local` file and at least enable the corresponding jails (all jails are disabled by default) or overwrite the default settings which you want to change, or even create your own jails (and/or) filters, that are not available in the default configuration of fail2ban.

For example if your intention is to monitor authorization failures occurring in sshd and nginx, but the `error.log` of your your nginx-instance is configured as `/var/log/my-nginx/error.log` you should set the `logpath` parameter appropriately additionally to `enabled` in section `[nginx]`.

So your `jail.local` looks like:
```ini
[nginx]
logpath = /var/log/my-nginx/error.log
enabled = true

[sshd]
enabled = true
```

If you use another version of fail2ban as provided by the maintainers of your distribution, you should check other parameters (that may be normally specified in some distribution config files), like:
- several path-parameters of fail2ban service itself (specified in `fail2ban.conf` or includes):
```ini
[Definition]
logtarget = /var/log/fail2ban.log
socket =    /var/run/fail2ban/fail2ban.sock
pidfile =   /var/run/fail2ban/fail2ban.pid
dbfile =    /var/run/fail2ban/fail2ban.sqlite3
```
- other jail parameters (`jail.conf` or includes) like `backend` (e. g. usage of systemd journals expected `systemd` backend), `action` resp. `banaction` (e. g. you can't use `iptables` if your system does not support it), `logpath`, etc.

You can also control resp. configure another optional configurations parameters, like `ignoreip`, etc.
</details>

***
**[Q]** How I can see the current (merged) configuration, that fail2ban will use
<details><summary>Answer</summary>

**[A]** You can dump your current configuration (all the parameters that fail2ban loads on startup) with the following commands:
```bash
# dump parameters:
fail2ban-client -d
# verbose: output config files will be loaded and dump parameters:
fail2ban-client -vd
fail2ban-client -vvd
```
</details>

***
**[Q]** How I can notify fail2ban, that the configuration was changed

<details><summary>Answer</summary>

**[A]** You should execute `fail2ban-client reload` (in previous versions before 0.10 `fail2ban-client restart`).<br/> 

You can also get and set parameters individually during runtime, using the fail2ban client-server communication protocol. For example:
```bash
fail2ban-client set pam-generic logencoding UTF-8
fail2ban-client set nginx findtime 10m
```
</details>

***
**[Q]** How should I correctly modify log file locations other than in the jail settings or messing with master .conf files?
<details><summary>Answer</summary>

**[A]** To make a modification to the default log file locations you should create a .local file of paths-common.conf or paths-debian.conf (whichever you are using in jail.local) and make changes only in your .local files which keeps it nicely structured for your jail(s) settings and avoids problems when Fail2Ban is updated<br/>

To create your .local file<br/>

Please don't copy it:<br/>
<s>`cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local`</s><br/>
<s>`cp /etc/fail2ban/paths-common.conf /etc/fail2ban/paths-common.local`</s><br/>
Just create and edit it with your preferred editor.

Now if you want for example an Nginx filter to read all your Nginx Access Logs for multiple web sites<br/>

- Either do it in `jail.local`:<br/>
`[nginx]`<br/>
`logpath = /var/log/nginx/*access*.log`<br/>
`enabled = true`<br/>
- Or instead of using in your jail:<br/>
Edit the line in `paths-common.local` or `paths-debian.local` (whichever you are using) and add the entry with `nginx_access_log` line as follows<br/>
`[DEFAULT]`<br/>
`nginx_access_log = /var/log/nginx/*access*.log`<br/>
Then in your jail you would rather use<br/>
`logpath = %(nginx_access_log)s`<br/>
</details>
