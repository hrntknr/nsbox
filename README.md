# nsbox
> DNS server implementation using netbox as a source.

## configration
### example
```yml
server:
  listen:
  - 127.0.0.1:53
tsigSecrets:
- name: example.com.
  secret: LSbfNkN9niiVrTl4AiVvm/sCcoh4m+jFB99qR2XYaFk5j7goL4Xiy1cfezpsT+3KUAMGq9OJcKRYq5yYzq8nZA==
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
netbox:
  host: '192.0.2.0'
  serverName: netbox.example.com
  useTLS: true
  verifyTLS: true
  token: abcdefghijklmnopqrstuvwxyabcdefghijklmno
  mode: description
  interval: 1m
```

## Implementation status
### support
- A
- AAAA
- TSIG
- CNAME
- Serial update
- TXT
### wip
- MX
- AXFR
- dnssec

## Copyright and License
Copyright (c) 2019 Takanori Hirano. Code released under the MIT license.
