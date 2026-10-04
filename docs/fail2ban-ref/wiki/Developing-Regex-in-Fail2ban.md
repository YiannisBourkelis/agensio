So, you’re eager to write a new fail2ban filter and it failed … miserably or you have a new case but unsure how to get the best regex ... fastest.

If the `fail2ban` couldn’t match anything … regardless of whether it is standard fail2ban config or your highly, purportedly, hapzardly-concoted filter config file but you're a Regex expert: this page is for you.

That is what this page offers, specifically developing as well as troubleshooting Regex used by `fail2ban`.

TL;DR
=====
Basic Test Iteration
--------------------
Basically, you will be armed on going back-and-forth with the following commands in "seemingly-never-ending" cycles.

It's only "seemingly-never-ending" if you're not a Regex expert.
```bash
fail2ban-regex \
    -l HEAVYDEBUG \
    --print-no-missed \
    /tmp/query-errors.log named-refused.conf
```
then execute
```bash
$EDITOR /etc/fail2ban/filter.d/named-refused.local
```
Add more pattern in between those two commands toward:
* `datepattern` as needed until it pass
* `prefregex` as needed until it pass
* `failregex` until it pass

Rinse, lather, repeat often as needed.

Date Pattern
------------
You first tests for a working `datepattern`:
```
...
Date template hits:
|- [# of hits] date format
|  [6] {^LN-BEG}Day(?P<_sep>[-/])MON(?P=_sep)ExYear[ :]?24hour:Minute:Second(?:\.Microseconds)?(?: Zone offset)?
...
```
Note the '`[6]`' output which matches my examples given in the next top-level section below.

Important note: if your date pattern use %b or %B beware of checking you are in the right locale ! (your terminal might set a different locale than the server default). (use `locale -a` and `export LANG=xxx` to fix this).

Pre-Filtering
-------------
After clearing/setting the `prefregex`, test it again and watch for `Pre-filter matched` in your output:
```console
H:   Looking for prefregex '^(?P<content>.+)$'
T:   Pre-filter matched {'content': ' query-errors: info: client @0x7f01e00004e0 123.123.123.123#80 (sl): view red: query failed (REFUSED) for sl/IN/ANY at query.c:5445'}
```
Ensure that the {'content': '<your-target-pattern'} is viewable and it's all there.

Fail Pattern
------------
After ensuring a success `datepattern` (and optionally the `prefregex`) match, set your `failregex` to a generic pattern of `.+ <HOST>`.

Watch for two things:  `Matched FailRegex:` and parts of `Results:` table.
```console
T:   Matched FailRegex('query.+(?:(?:::f{4,6}:)?(?P<ip4>(?:\\d{1,3}\\.){3}\\d{1,3})|\\[?(?P<ip6>(?:[0-9a-fA-F]{1,4}::?|::){1,7}(?:[0-9a-fA-F]{1,4}|(?<=:):))\\]?|(?P<dns>[\\w\\-.^_]*\\w))')

...

Results
=======

Failregex: 6 total
|-  #) [# of hits] regular expression
|   1) [6] ^<your-target-pattern>
`-
```
During your many iterative test cycle, pay attention to the following output for the match count (of our example '`[6]`' lines):

At any time during your edit cycle of expanding pattern, that you get '`[0]`' match, 
```console
Failregex: 0 total tabulation. 
```
that is A screw-up, go back and revert the `failregex` back to last-known working pattern then resume test cycle.

When no more patterns can be added to `failregex`, end it with a '`$`' pattern.

Restart `fail2ban`.
```bash
fail2ban-client reload
```
For the hoary and gory details, read on...

WHAT ARE THE STAGES OF REGEX?
=============================

Fail2ban has several components of regex in which to apply toward the log text, these components/subcomponents are:

* datepattern
* prefregex
    * failregex
    * ignoreregex

Usually, the date starts at the beginning of each log line that `fail2ban` searches against. For this article, we shall assume that date comes firstly before anything.

ACTUAL EXAMPLES!
================
The actual examples were obtained during a DDOS against my Bind9 master nameserver. And a regex is needed ... fast.

Actual log (`/tmp/captured.log`) file is (after privacy redactions) shown below:
```log
19-Sep-2020 11:47:00.116 query-errors: info: client @0x7f0410000e40 123.123.123.123#80 (sl): view red: query failed (REFUSED) for sl/IN/ANY at query.c:5445
19-Sep-2020 11:47:01.120 query-errors: info: client @0x7f0410000e40 123.123.123.123#80 (sl): view red: query failed (REFUSED) for sl/IN/ANY at query.c:5445
19-Sep-2020 11:47:02.020 query-errors: info: client @0x7f0410000e40 123.123.123.123#80 (sl): view red: query failed (REFUSED) for sl/IN/ANY at query.c:5445
19-Sep-2020 11:47:03.356 query-errors: info: client @0x7f0410000e40 123.123.123.123#80 (sl): view red: query failed (REFUSED) for sl/IN/ANY at query.c:5445
19-Sep-2020 11:47:04.988 query-errors: info: client @0x7f0410000e40 123.123.123.123#80 (sl): view red: query failed (REFUSED) for sl/IN/ANY at query.c:5445
19-Sep-2020 11:47:05.576 query-errors: info: client @0x7f0410000e40 123.123.123.123#80 (sl): view red: query failed (REFUSED) for sl/IN/ANY at query.c:5445
```
Note: A little history, the sl TLD went off-line and IoTs were spraying invalid DNS-QUERY records with falsified source IP address toward selected DNS servers, resulting in a mild DNS amplification attack via DNS-QUERY-REFUSED error message all being sent to the target victim.

Sadly, latest Bind9 daemon has no configurable field to suppress these false DNS-QUERY-REFUSED acknowledgement messages (ISC Bind team claim it is not kosher to do this, but I still have this problem and have intend `fail2ban` to deal with this).

FIRST PATTERN, FIRST
====================
Hopefully you got that ‘date’ hit. `fail2ban` already provided for MANY `datepattern` found in many log files.  

Execute something like `fail2ban-regex -v` (please note the important '`-v`' command line option):
```bash
fail2ban-regex -v /tmp/captured.log /etc/fail2ban/filter.d/named-refused.conf
```
which outputted the following:
```console
...
Date template hits:
|- [# of hits] date format
|  [6] {^LN-BEG}Day(?P<_sep>[-/])MON(?P=_sep)ExYear[ :]?24hour:Minute:Second(?:\.Microseconds)?(?: Zone offset)?
...
```
whose output shows '`[6]`' lines that have matched the date timestamp at the beginning of each line. That’s an excellent good start for troubleshooting.  `fail2ban` tries to get all known `datepattern`s.

NOTE: Common `rsyslog` syslog daemon may output regular `datepattern` or high-precision `datepattern` (via `$ActionFileDefaultTemplate RSYSLOG_TraditionalFileFormat` setting in `/etc/rsyslog.conf`) and fail2ban `datepattern` gets both of these date format right.

In the rare event (and sad case) of '`[0]`' match for a date pattern hit, you can develop a new `datepattern` by usng the '`--VD`' option along with '`-l HEAVYDEBUG`' option in your `fail2ban-regex`. Having a [0] means you are dealing with a log text whose `datepattern` that fail2ban has never dealt with before; you’ll need to craft your own `datepattern`.

Such unknown `datepattern` shall be a subject for another blog, not here.

PRE-FILTER MATCHED
==================
If you have a single-line pattern, skip this section and leave `prefregex` empty or undefined.

`prefregex` is ideally for a pattern that is found (after the `datepattern` portion) in each and every line of the entire log file.  Such common pattern found after `datepattern` MAY contain any 1 or more of the following:
* daemon name (optional)
* subroutine name and/or line number (optional)
* process ID (optional)
* severity level (optional)
* many more...

So, an ideal `prefregex` would be highly dependent on a regex that properly supports a combinatorial of the above list of patterns (some always there, and others mostly optional) in order to make it work for everyone that uses the application (often `rsyslogd` but its `named` here) which generates the logs.  

Secondary benefit of `prefregex` is to ensure that `failregex` is left with the most dynamic (and interesting) part of the regex line.  `prefregex` takes that most common parts (see above list) of the line.

```console
           <-- prefregex ->|<--   failregex  ->
3-Jan-2020 myscript[12512]: Dynamic error message part
```

There's more: the really good reason to support `prefregex` is this: your end-user may tweak that daemon/script configuration file that results in a different line output.  Your finished filter will surely break. So track those configuration settings related to log output.

That said, log line having different but additional info(s) after such `datepattern`.  `prefregex` can be made flexible, for different end-users' daemon configuration settings.

No log settings? Then `prefregex` may not be for you to use.

To Pre-Filter  or Not To Pre-Filter
-----------------------------------
This section only applies if you have (or will have) multiple patterns. This section also applies if log line becomes different with its daemon's configuration settings  related to log output.

If a pre-defined `prefregex` already existed and you know it works, then you can move on to the next section.  If you are creating one, read on.

You can tell that the (default or customized) `prefregex` actually works if you added '`-l HEAVYDEBUG`' to your `fail2ban-regex` command line:
```bash
fail2ban-regex \
    -v \
    -l HEAVYDEBUG \
    /tmp/captured.log \
    /etc/fail2ban/filter.d/named-refused.conf
```
and its output shows a line starting with '`T: Pre-filter matched`':
```console
H:   Looking for prefregex '^(?P<content>.+)$'
T:   Pre-filter matched {'content': ' query-errors: info: client @0x7f01e00004e0 123.123.123.123#80 (sl): view red: query failed (REFUSED) for sl/IN/ANY at query.c:5445'}
```
and note the value of `'content:'`. This content comes after the `datepattern`; we have successfully parse the date timestamp.  Next, remaining content is then fed into the `failregex` patterns.

Note: Please note in 'content': value that there is an extra space at the beginning of that value so be careful with the ‘`^`‘ and make sure it starts with ‘`^ `‘ (note a space after caret symbol.)

In this example, I've opted to use the optional `prefregex` because I know that there is going to be more than one fail-matched pattern.  And don't want future contributors to deal with it again later on.

NEW CONFIG FILE
===============
From there on, we will be creating a local-variant of `named-refused.conf` file; all new and modified
settings are in the new `named-refused.local` file.

With regard to that extra space char, do what I do; incorporate that space into your `prefregex`. Your customized `prefregex` will take away that beginning but lone space character from all your future (and current) `failregex` filter patterns. This makes for an easier-to-read `failpregex` pattern(s).

The new `named-refused.local` file now contains:
```ini
[Definition]

prefregex = ^ <F-CONTENT>.+</F-CONTENT>$
```
The above custom `prefregex` will ensure that that beginning space character is removed before sending the remaining content to the `failregex`.  This new `prefregex` returns just the interesting '`<F-CONTENT>.+</F-CONTENT>$`' which is basically everything after that lone (but unwanted) space char.

WARNING: This is a greedy Regex algorithm.  Many regex are unsafe, having neither contain start- (`^`) nor end-anchor (`$`), as well as contain catch-all like `.+`, especially which is immediately followed by unprecise `<HOST>` tag which is accepting every word as hostname.

Back on track, running that fail2ban-regex with the '`-l HEAVYDEBUG`', the new output shows:
```console
T:   Pre-filter matched {'content': 'query-errors: info: client @0x7f0410000e40 123.123.123.123#80 (sl): view red: query failed (REFUSED) for sl/IN/ANY at query.c:5445'}
```
Notice that a space no longer exist before '`query-errors`'.

Everything from the beginning of the first non-space to the end of the line can then be dealt with by our yet-to-be-defined `failregex`.

Test with the new config file, The `named-refused.conf` will automatically include the new `named-refused.local` (if it exist, which it shall exist in this blog) so there is still no change in command line, from previous step:
```bash
fail2ban-regex \
    -v \
    -l HEAVYDEBUG \
    /tmp/captured.log \
    /etc/fail2ban/filter.d/named-refused.conf
```
Remember the above command; we are going to use it each time we modified the filter configuration file: and quite very often. Use your bash history buffer and recall that command, over and over again. Remember.


FAILREGEX MATCHED
==================
Focus on the `failregex` portion of the filter config file.  New regex patterns for `failregex` go under `[Definition]` section. 

Using `failregex` means that there MUST be at least one regex group match such as:
* '`<HOST>`' - hostname
* '`<ADDR>`' - IPv4 or IPv6 address

There are other macros whose value which can then be captured and later used by `action.conf`.  All captured value are then used to customize for a more detailed message that can:
* send a detailed email, 
* execute a Unix `wall` message, 
* send a tweet
* send SMS/text message.

These macros are listed here for your leisure reading but not used in this example:
* '`<F-ID>`' - Regex group ID
* '`<F-PORT>`' - Port number of UDP/TCP/SCTP/DDCP and other transport layers.
* '`<F-ERRCODE>`' - Error codes, like HTTP status, or shell exit status
* '`<F-MLFGAINED>`' - Access to service was gained.
* '`<F-NOFAIL>`' - Used as a mark for no-failure condition for a helper to accumulate
* '`<F-MLFID>`'
* '`<F-MLFFORGET`' - Forget the multi-line set by `<F-MLFID>`.
* '`<F-USER>`' - Unix-like username (login, ssh)
* '`<F-ALT_USER>`' - Indicates non-Unix username (Dovecot's SMTP account name).

So, do what I do… Make a generic `failregex` in your new local filter config file, like this:
```ini
failregex = query.+<HOST>
```
WARNING: Don't make my example into your permanent change because `.+` is evil.  Do no evil ... but not during this troubleshooting and development of regex.  Just don't forget to have finally replaced all `.+`, `.*` with something staticly-pattern as well as adding range-constraint (ie., `{,2}`, `{0,2}`) instead of a plus or an asterisk symbol.  

WARNING: And  also don't forget to ensure that `^` is at the beginning; also to add that `$` at the end.  But not now for `$`, as we're developing toward a working matching pattern here.

Notice that there is no '`$`' to catch end-of-line match condition? We’ll do those `$` lastly as we are trying to match … just about ANYTHING that we want!

Now, re-run the `fail2ban-regex` with '`-l HEAVYDEBUG`' and look for the '`T: Matched FailRegex part`':
```console
T:   Matched FailRegex('query.+(?:(?:::f{4,6}:)?(?P<ip4>(?:\\d{1,3}\\.){3}\\d{1,3})|\\[?(?P<ip6>(?:[0-9a-fA-F]{1,4}::?|::){1,7}(?:[0-9a-fA-F]{1,4}|(?<=:):))\\]?|(?P<dns>[\\w\\-.^_]*\\w))')
```
Now I am matching SOMETHING! 

Notice the convoluted patterns after '`query.+`'? These new, long patterns represent the expanded part of '`<HOST>`' macro. We can safely ignore that for now.

Most importantly, I am MATCHING something that starts with '`^query.+`'! Yippee!

That evil `.+` is only temporary; we'll get rid of that at the end.

GYRATING TOWARD FULL MATCH
==========================
With a working matching pattern (albeit a failed but overly-broad pattern), we can then work toward a the finished `failregex`; a full-blown but concise (yet flexible) pattern.

Let’s start by adding more static pattern. 

I am pretty sure from my intensive examination of that line 5445 in Bind9 `query.c` source file that '`query-error: info:`' is something that will not change for my target condition. This log output may have other variance like '`query-error: warn`' or '`query-error: debug`' but I am ignoring those.

First iteration of `failregex` expansion:
```ini
failregex = ^query-errors: info: .+<HOST>
```
Execute the command:
```bash
fail2ban-regex \
    -l HEAVYDEBUG \
    --print-no-missed \
    /tmp/query-errors.log named-refused.conf
```
and notice the output:
```console
Results
=======

Failregex: 6 total
|-  #) [# of hits] regular expression
|   1) [6] ^query-errors: info: .+<HOST>
`-
```
See the '`[6]`'? I have six matches out of 6 lines give in log text file. I am getting close to a full-blown pattern! Don’t forget, we have to close that pattern out with a $ but not yet, save that for the end of this tutorial.

CAUTION: Every time you make a change to your filter file, PAY VERY CLOSE ATTENTION to this part of the output:
```console
Failregex: X total tabulation. 
```
Once you get that '`Failregex: 0 total`', you know you have done something HORRIBLE, busted and broke your pattern, so roll that pattern back to its simpler pattern and start again.

INCREMENTS, INCREMENTS, INCREMENTS
==================================
As we add more and more increments of pattern and ensuring that '`Failregex: 6 matches`' still appears:
```console
    failregex: query-errors: info: client.+<HOST>
    failregex: query-errors: info: client @0x[0-9a-fA-F]{8,12}.+<HOST>
```
Whoa, my pattern is getting too long… so I made a variable to contain this entire pattern and called it '`_client`'.
```ini
_client = query-error: info: client @0x[0-9a-f]{8,12}
```
Now I can shorten the '`failregex`' a bit:
```ini
failregex = ^%(_client)s <HOST>
```
It’s the same thing, but oh it so readable, onward to matching the rest of the line.

NOTE: You are running `fail2ban-regex` between each modification, aren’t you?

NOW FOR THE ENDING PART
=======================
We have FINALLY reached the '`<HOST>`' part of the failregex/log text.

Now it is closing time! Let’s race to the '`$`' (end).

Add that port number after the host:
```ini
failregex = ^%(_client)s <HOST>#\d{1,5}
```
NOTE: You are still re-running fail2ban-regex between each modification, aren’t you?

REPETITION
==========
Notice that the domain name '`sl`' got used twice in each of the same log line?

Let us make a pattern called '`_domain`' to reduce our typing errors a bit.
```ini
_domain = [0-9a-zA-Z\._\-]{2,256}
```
Our new `failregex` becomes:
```ini
failregex = ^%(_client)s <HOST>#\d{1,5} \(%(_domain)s\):
```
NOTE: You are running `fail2ban-regex` between each modification, still getting that exact same match '`[6]`' (or whatever count you’re aiming for.)

SIMPLIFICATION
==============
Now for the view part of nameserver error output where `ISC Bind9` handles the view name.
This view name is an optional but common configuration: We may not get a view name on some type of Bind9 nameserver installation.
```ini
_view_name = [0-9a-zA-Z\._\-]{1,64}
_view = ( \%(_domain)s\))?: view %(_view_name)s
```
Our latest `failregex` becomes:
```ini
failregex = ^%(_client)s <HOST>#\d{1,5}%(_view)s
```
Still have a long way to go before we add that '`$`' ending pattern.

NOTE: `fail2ban-regex` between each modification still?

FINAL STRETCH
=============
We have the remaining (after that '`<HOST>`') part of log text left to go:
```console
query failed (REFUSED) for sl/IN/ANY at query.c:5445
```
We’re impatient lot, aren’t we? Rush it up with:
```ini
_query_refused = query failed \(REFUSED\) for %(_dns_tuple)s at %(_codeloc)s$
```
and supply missing defines:
```ini
_domain = [0-9a-zA-Z\._\-]{1,254}
_dns_tuple = %(_domain)s\/IN\/ANY

_filespec = [0-9a-zA-Z\._\-]{1,254}
_codeloc = %(_filespec)s:\d{1,6}
```

NOTE: You are running `fail2ban-regex` between each modification? You still getting that non-zero '`Failregex: 6 total match`' under '`Results`'?
```console
Failregex: 6 total
|-  #) [# of hits] regular expression
|   1) [6] ^query-errors: info: client @0x[0-9a-f]{8,12} <HOST>#\d{1,5}( \([0-9a-zA-Z\._\-]{1,254}\))?: view [0-9a-zA-Z\._\-]{1,64}: query failed \(REFUSED\) for [0-9a-zA-Z\._\-]{1,254}\/IN\/ANY at [0-9a-zA-Z\._\-]{1,254}:\d{1,6}$
`-
```
Ok, you could have paid attention to the last line of the output:
```console
Lines: 6 lines, 0 ignored, 6 matched, 0 missed
```
But I find the '`Results`' to be more informative.

CONCLUSION
==========
Now we can add the `'$'` to the end of `failregex`.

Execute `fail2ban-client reload` and watch the blocking begin.

APPENDIX
========

`named-refused.local` content:
```ini
#
# File: /etc/fail2ban/filter.d/named-refused.local
# Title: Filter for Bind9 DNS-QUERY-REFUSED messages
# Program: ISC Bind9 named
# Version: v9.17.1
# Description:
#     Often times the malicious DDoS bots would send an invalid query
#     with source IP matching its target resulting in a query error (REFUSED).
#     While this DNS-ACK packet is not a major impediment due to its small
#     size, we still want to block the offending DDoS participant.
#
# Requires the following named.conf settings:
#     severity dynamic; // or severity info
#     print-time yes;
#     print-severity true;
#     print-category true;
# in the "<your-custom-channel-name>" channel that references 
# the "query-errors" category in "category" statement 
# inside "logging" clause.
# 
# The required logging clause portion, of the named.conf, is sematically:
#
#     logging {
#         category query-errors { query-errors_file; };
#         channel query-errors_file {
#             file "/var/log/named/query-errors.log" versions 3 size 5m;
#             severity dynamic;
#             print-time yes;
#             print-severity true;
#             print-category true;
#         };
#     };

[Definition]

_client = query-errors: info: client @0x[0-9a-f]{8,12}

_domain = [0-9a-zA-Z\._\-]{1,254}
_view_name = [0-9a-zA-Z\._\-]{1,64}
_view = ( \(%(_domain)s\))?: view %(_view_name)s
_dns_tuple = %(_domain)s\/IN\/ANY

_filespec = [0-9a-zA-Z\._\-]{1,254}
_codeloc = %(_filespec)s:\d{1,6}

_query_refused = query failed \(REFUSED\) for %(_dns_tuple)s at %(_codeloc)s$

prefregex = ^ <F-CONTENT>.+</F-CONTENT>$

# Actual template
# 19-Sep-2020 11:47:05.576 query-errors: info: client @0x7f06f0000c90 123.123.123.123#80 (example.tld): view red: query failed (REFUSED) for example.tld/IN/ANY at query.c:5445

failregex = ^%(_client)s <HOST>#\d{1,5}%(_view)s: %(_query_refused)s

# Author: Steve Egbert
```