# Mullvad socks proxy list
[![Publish mullvad-socks-list.txt](https://github.com/maximko/mullvad-socks-list/actions/workflows/mullvad-socks.yml/badge.svg)](https://github.com/maximko/mullvad-socks-list/actions/workflows/mullvad-socks.yml)

[ALL ACTIVE SOCKS DETAILED LIST](https://raw.githubusercontent.com/maximko/mullvad-socks-list/list/mullvad-socks-list.txt)

[Socks and ipv4_in list](https://raw.githubusercontent.com/maximko/mullvad-socks-list/list/socks-ipv4_in-list.txt)

[Socks and timezone list](https://raw.githubusercontent.com/maximko/mullvad-socks-list/list/socks-timezone-list.txt)

These are lists of socks5 proxy servers usable in mullvad vpn network, as well as the script that generates these lists. The script runs every day by github actions and pushes result to [list branch](https://github.com/maximko/mullvad-socks-list/tree/list).

Please note that all socks dns names are resolved and this is a purpose of this project.

## FoxyProxy

Every list also has a `foxyproxy_` version (e.g. `foxyproxy_country_se.txt`) in FoxyProxy's extended proxy list format. Each proxy gets a title, country flag and city:

```
socks5://10.124.1.240:1080?title=al-tia-wg-socks5-001&cc=AL&city=Tirana&active=true&proxyDNS=true
```

Copy the file's contents into FoxyProxy's **Import → Import Proxy List** box, click **Import**, then **Save**. This adds the proxies to your existing ones.

Don't use **Import from URL** for these lists: it expects a full settings file and replaces your entire proxy list (despite what FoxyProxy's help page says). As with the plain lists, these proxies only work while you're connected to Mullvad.
