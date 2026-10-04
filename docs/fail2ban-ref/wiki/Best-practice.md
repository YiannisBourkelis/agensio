Here are the advises and common smart practices in order to drive Fail2ban operating faster as well as to minimize a load of the system through Fail2Ban:

* If you are familiar with RE-engine, optimize the regex's (by this are meant all regex's Fail2Ban uses - especially `failregex` but also `prefregex`, `ignoreregex` and `datepattern`). This may imply also other precautions you may take by changing of default filters or configuration files, for example:
  - use more precise predefined tags as `<HOST>`, if you don't expect hostname in log-message (e. g. `<ADDR>` for IP-addresses only) or disable `usedns` for such jails
  - use more precise regex parts as predefined in filter or common config-files substitutions, e. g. redefine `__prefix_line` with your own shorter and more efficient RE exactly matching related part of your log-messages, because interpolation of default RE for the `__prefix_line` may be too long (due to all targeting systems or distributions and backwards-compatibility reasons) and therefore not optimal for application on your system
  - potentially remove regex's or its optional parts that are not valid at all for your system (so practically don't occur, related to the application and/or distribution version).
* If log-file or journal show several different types of messages or some pre-filtering may be advantageous, use common `prefregex` (and short and efficient as possible);
* Reorganize the regex-order by occurrence in log (frequently as first). This is valid for all regex too.
* Try to reduce count of log-messages (especially unneeded or unrelated information, which is called "parasitic" further) in observing log-file or journal. See section [Reduce parasitic log-traffic](#reduce-parasitic-log-traffic) below.
* Use incremental bantime (since v.0.11) as well as other Fail2Ban new features might help you to minimize intrusions attempt count resp. to reduce attacks in the long perspective.
* Under DDOS-attack similar circumstances use other tools and make special arrangements too, may be in combination with Fail2Ban and/or information it could provide you. Please note, Fail2Ban is just a tool and it depends on what you make out of it.

### Reduce parasitic log-traffic
It is always recommended to take diverse precautions in order to minimize the unrelated and therefore uninteresting logging messages in log-files or journals that Fail2Ban is monitoring.

This is application- or system-related and could depend on kind of protection is needed, for example:
- using re-targeting in rsyslog, etc (filtering and forwarding into different log-file)
- decreasing the log-level, priority or facility lists (in order to hide uninteresting "parasitic" messages)
- by means of extracting the failures only by application/service into separate log-file or journal, if it is directly possible in corresponding application (e. g. in nginx via extra location for 40x|50x-error codes with own extra access-log set in location), see an example below.

Several applications as well as web-servers write the failures in access or error logs together with other messages, which may be unrelated for some jails of Fail2Ban (one can have more as one jail for some application) or even totally don't interest Fail2Ban at all.

It is important to keep in mind that if multiple `failregex` are configured and there is no `prefregex` (pre-filtering messages or it matches too) each parasitic message would cause a check for possible match across all specified regex's for the jail.

Especially an observing of the access-log directly may be too heavy for your system (well visited web-server generating too many entries in access-log may produce high load by Fail2Ban).
Therefore it is recommended to restrict it in web-server.

Here are examples how it might be implemented in **nginx** using conditional `access_log` or by supplying the failed requests to extra location via postaction resp. via error_page to extra internal location (with extra access-log) which would then get all the requests with 404/403/401/500 etc.:

1. Via conditional [access_log](http://nginx.org/en/docs/http/ngx_http_log_module.html#access_log):
```nginx
map $status $loggable {
    ~^[23]  0;
    default 1;
}

# to log the requests excepting response codes 2xx and 3xx: 
access_log /var/log/nginx/access_for_fail2ban.log combined if=$loggable;
# all requests will not be logged:
access_log /var/log/nginx/access.log combined;
```

2. E. g. in error location, for example:
```nginx
...
fastcgi_intercept_errors on;
proxy_intercept_errors on;
error_page 404 = @fallback;
...
location @fallback {
    access_log /var/log/nginx/access_for_fail2ban.log;
    return $status;
}
```