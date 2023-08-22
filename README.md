# balog = Ban Action Logger

## What is it?

A logger for [fail2ban](https://www.fail2ban.org/wiki/index.php/Main_Page)'s ban actions.

## What does it do?

Logs ban actions with ip addresses, and if possible, fetch their geolocations from [ipgeolocation.io](https://ipgeolocation.io/).

Also generates reports in various formats, including: plain text, json, and [telegra.ph](https://telegra.ph/).

## Installation and configuration

```bash
$ go install github.com/meinside/balog@latest

```

On the first run, it will create a default configuration file `~/.config/balog/config.json`:

```json
{
  "db_filepath": "/your/home/.config/balog/database.db"
}
```

### Telegraph Access Token

For posting reports to telegra.ph, set your telegraph access token like this:

```json
{
  "db_filepath": "/path/to/database.db",
  "telegraph_access_token": "1234567890abcdefghijklmnopqrstuvwxyz"
}
```

### ipgeolocaiton.io API Key

For fetching geolocations of banned IP addresses, set your [ipgeolocation.io](https://ipgeolocation.io/) API key like this:

```json
{
  "db_filepath": "/path/to/database.db",

  "telegraph_access_token": "1234567890abcdefghijklmnopqrstuvwxyz",
  "ipgeolocation_api_key": "abcdefghijk1234567890"
}
```

If `ipgeolocation_api_key` is not set, locations will be saved as `Unknown`.

### Using Infisical

You can also use [Infisical](https://infisical.com/) for retrieving your access token and api key:

```json
{
  "db_filepath": "/path/to/database.db",

  "infisical": {
    "workspace_id": "012345abcdefg",
    "token": "st.xyzwabcd.0987654321.abcdefghijklmnop",
    "environment": "dev",
    "secret_type": "shared",

    "telegraph_access_token_key_path": "/path/to/your/KEY_TO_TELEGRAPH_ACCESS_TOKEN",
    "ipgeolocation_api_key_key_path": "/path/to/your/KEY_TO_IPGEOLOCATION_API_KEY"
  }
}
```

If your Infisical workspace's E2EE setting is enabled, you also need to provide your API key:

```json
{
  "db_filepath": "/path/to/database.db",

  "infisical": {
    "e2ee": true,
    "api_key": "ak.1234567890.abcdefghijk",

    "workspace_id": "012345abcdefg",
    "token": "st.xyzwabcd.0987654321.abcdefghijklmnop",
    "environment": "dev",
    "secret_type": "shared",

    "telegraph_access_token_key_path": "/path/to/your/KEY_TO_TELEGRAPH_ACCESS_TOKEN",
    "ipgeolocation_api_key_key_path": "/path/to/your/KEY_TO_IPGEOLOCATION_API_KEY"
  }
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

Duplicate `iptables-multiport.conf` to `iptables-multiport-balog.conf`:

```bash
$ sudo cp /etc/fail2ban/action.d/iptables-multiport.conf /etc/fail2ban/action.d/iptables-multiport-balog.conf
```

then append 3 lines below the `actionban` in that file:

```
# /etc/fail2ban/action.d/iptables-multiport-balog.conf

# from original
#actionban = <iptables> -I f2b-<name> 1 -s <ip> -j <blocktype>

# to this one
# ('<restored>' is checked for not saving duplicated ban actions on restarts of fail2ban)
actionban = <iptables> -I f2b-<name> 1 -s <ip> -j <blocktype>
            if [ '<restored>' = '0' ]; then
              /path/to/balog -config /path/to/balog.json -action save -ip <ip> -protocol <name>
            fi

```

Change `/path/to/balog` and `/path/to/balog.json` to yours,

(NOTE: fail2ban-generated config and database files will be owned by `root`)

and add custom ban actions in your `/etc/fail2ban/jail.local` file:

```
# ...

[DEFAULT]

# ...

# custom ban actions
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
0 0 * * 0 balog -action report -format plain > /tmp/report_weekly.txt
0 0 1 * * balog -action report -format plain > /tmp/report_monthly.txt
```

### Maintenance

```bash
# list unknown ips
$ balog -action maintenance -job list_unknown_ips

# resolve unknown ips through ipgeolocation.io
$ balog -action maintenance -job resolve_unknown_ips

# purge logs
$ balog -action maintenance -job purge_logs
```

## License

MIT

