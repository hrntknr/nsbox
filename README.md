# nsbox
> DNS server implementation using netbox as a source.

## configration
### example
```yml
server:
  listen:
  - 127.0.0.1:53
webhook:
  listen: :8080
  timeout: 30s
  allowFrom:
  - 127.0.0.1/8
  - ::1/128
dataStore:
  mode: yaml
  path: ./store.yml
tsigSecrets:
- name: example.com.
  secret: so6ZGir4GPAqINNh9U5c3A==
zoneDefault:
  ttl: 3600
  ns:
  - ns1.example.com.
  - ns2.example.com.
  soa:
    ns: ns1.example.com.
    mBox: root.example.com.
    refresh: 3600
    retry: 900
    expire: 604800
    minTTL: 3600
zones:
- suffix: example.com.
  # override zoneDefault
  ttl: 3600
  ns:
  - ns1.example.com.
  - ns2.example.com.
  soa:
    ns: ns1.example.com.
    mBox: root.example.com.
    refresh: 3600
    retry: 900
    expire: 604800
    minTTL: 3600
  records:
  - name: info
    cname: service.example.com
  - name: shop
    cname: service.example.com
  - txt: v=spf1 include:info.example.com
  - name: info
    txt: v=spf1 ip4:192.0.2.200 ~all
netbox:
  host: '192.0.2.0'
  serverName: netbox.example.com
  useTLS: true
  verifyTLS: true
  token: abcdefghijklmnopqrstuvwxyabcdefghijklmno
  mode: description
  interval: 60m
slack:
  webhookURL: https://hooks.slack.com/services/XXXXXXXXX/XXXXXXXXX/XXXXXXXXXXXXXXXXXXXXXXXX
  channel: general
  name: nsbox
  iconEmoji: thinking_face
```

## Implementation status
### support
- A
- AAAA
- TSIG
- CNAME
- Serial update
- TXT
- webhook
- slack integration
### wip
- MX
- AXFR
- dnssec

## Copyright and License
Copyright (c) 2019 Takanori Hirano. Code released under the MIT license.
