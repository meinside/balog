# balog = Ban Action Logger

## What is it?

A logger for [fail2ban](https://www.fail2ban.org/wiki/index.php/Main_Page)'s ban actions.

## What does it do?

Logs ban actions with ip addresses, and if possible, fetch their geolocations from [ipapi.co](https://ipapi.co/).

Also generates reports in various formats, including: plain text, json, and [telegra.ph](https://telegra.ph/).

## Installation and configuration

```bash
$ go install github.com/meinside/balog@latest

```

On the first run, it will create a default configuration file `~/.config/balog.json`:

```json
{
  "db_filepath": "/your/home/.config/balog.db"
}
```

## Usage

Run with `-h` to see the usage:

```bash
$ balog -h
```

### Logging

It can be run from the shell directly:

```bash
$ balog -action log -ip 8.8.8.8 -protocol ssh
```

or it can be called from fail2ban's ban action:

```
# Fail2Ban configuration file
#
# /etc/fail2ban/action.d/log-ban-action.conf
#
# Modified from /etc/fail2ban/action.d/iptables-multiport.conf
#

[Definition]

# Option:  actionstart
# Notes.:  command executed on demand at the first ban (or at the start of Fail2Ban if actionstart_on_demand is set to false).
# Values:  CMD
#
actionstart =

# Option:  actionstop
# Notes.:  command executed at the stop of jail (or at the end of Fail2Ban)
# Values:  CMD
#
actionstop =

# Option:  actioncheck
# Notes.:  command executed once before each actionban command
# Values:  CMD
#
actioncheck =

# Option:  actionban
# Notes.:  command executed when banning an IP. Take care that the
#          command is executed with Fail2Ban user rights.
# Tags:    See jail.conf(5) man page
# Values:  CMD
#
actionban = /path/to/my/balog -action log -ip <ip> -protocol <protocol>

# Option:  actionunban
# Notes.:  command executed when unbanning an IP. Take care that the
#          command is executed with Fail2Ban user rights.
# Tags:    See jail.conf(5) man page
# Values:  CMD
#
actionunban =

[Init]

```

Change `/path/to/my/balog` to the installed path, eg. `$GOPATH/bin/balog`,

and `sudo systemctl restart fail2ban.service`.


### Reporting

```bash
# print report to stdout
$ balog -action report -format plain

# print report to stdout in json format
$ balog -action report -format json

# post report to telegra.ph and print the url to stdout
$ balog -action report -format telegraph
```

You can put the above commands in your crontab:

```crontab
0 0 * * 1 balog -action report -format plain > /tmp/report_weekly.txt
0 0 1 * * balog -action report -format plain > /tmp/report_monthly.txt
```

## License

MIT

