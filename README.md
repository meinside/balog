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
$ balog -action save -ip 8.8.8.8 -protocol ssh
```

or it can be called from fail2ban's ban action.

#### Fail2ban Configuration

Copy `/etc/fail2ban/action.d/iptables-multiport.conf` to `/etc/fail2ban/action.d/iptables-multiport-balog.conf`:

```bash
$ sudo cp /etc/fail2ban/action.d/iptables-multiport.conf /etc/fail2ban/action.d/iptables-multiport-balog.conf
```

then append one line below the `actionban`:

```
# from original
#actionban = <iptables> -I f2b-<name> 1 -s <ip> -j <blocktype>

# to this one
actionban = <iptables> -I f2b-<name> 1 -s <ip> -j <blocktype>
            /path/to/balog -config /path/to/balog.json -action save -ip <ip> -protocol <name>

```

Change `/path/to/balog` and `/path/to/balog.json` to yours,

(NOTE: fail2ban-generated config and database files will be owned by `root`)

and add a custom ban action in your `/etc/fail2ban/jail.local` file:

```
# ...

[DEFAULT]

# ...

# custom ban action
banaction = iptables-multiport-balog

```

Finally, `sudo systemctl restart fail2ban.service` to apply changes.


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

### Maintenance

```bash
# list unknown ips
$ balog -action maintenance -job list_unknown_ips

# resolve unknown ips through ipapi.co
$ balog -action maintenance -job resolve_unknown_ips

# purge logs
$ balog -action maintenance -job purge_logs
```

## License

MIT

