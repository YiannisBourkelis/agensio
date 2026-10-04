If you are using [WP-Fail2Ban](https://wordpress.org/plugins/wp-fail2ban/), [WP Fail2Ban Redux](https://wordpress.org/plugins/wp-fail2ban-redux/), their equivalents on Drupal and Joomla, or various other third-party filters then these may stop working after upgrading from an earlier 0.10.x release of Fail2ban.

As noted in the [change log](https://github.com/fail2ban/fail2ban/blob/0.10.5/ChangeLog), the default flag for the systemd backend was changed to SYSTEM_ONLY(4) in order to ignore user session files that could prevent "Too many open files" errors on a lot of user sessions. As a consequence anything that writes its log output as a non-root user may no longer be visible to Fail2ban by default.  Web applications like WordPress usually write their log outputs as a non-root user!

The fix is to change this line in either the relevant [jail_name] section of /etc/fail2ban/jail.local or in /etc/fail2ban/jail.d/jail_name.local 

`backend = systemd`

to

`backend = systemd[journalflags=1]`