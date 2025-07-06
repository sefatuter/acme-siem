# Wazuh Rules

```xml
<!-- Local rules -->
<!-- Modify it at your will. -->
<!-- Copyright (C) 2015, Wazuh Inc. -->

<!-- Example -->
<group name="local,syslog,sshd,">
  <!--
  Dec 10 01:02:02 host sshd[1234]: Failed none for root from 1.1.1.1 port 1066 ssh2
  -->
  <rule id="100001" level="5">
    <if_sid>5716</if_sid>
    <srcip>1.1.1.1</srcip>
    <description>sshd: authentication failed from IP 1.1.1.1.</description>
    <group>authentication_failed,pci_dss_10.2.4,pci_dss_10.2.5,</group>
  </rule>
</group>

<group name="web,rce,attack">
  <rule id="100100" level="12">
    <if_sid>31101</if_sid>
    <regex>/bin/sh|cmd\.exe|powershell</regex>
    <description>Possible remote-code-execution attempt in HTTP request</description>
    <group>attack,rce,critical</group>
  </rule>
</group>
```
```log
192.168.1.100 - - [27/Jun/2025:10:30:45 +0000] "GET /test.php?cmd=/bin/sh HTTP/1.1" 200 1234
10.0.0.1 - - [27/Jun/2025:10:31:00 +0000] "POST /upload.php HTTP/1.1" 200 567 "Mozilla/5.0" "exec=powershell"
172.16.1.50 - - [27/Jun/2025:10:31:15 +0000] "GET /shell.php?c=cmd.exe HTTP/1.1" 404 0
```

```
**Messages:
	WARNING: (7003): '5d684359' token expires
	INFO: (7202): Session initialized with token '24e5da0c'

**Phase 1: Completed pre-decoding.
	full event: '192.168.1.100 - - [27/Jun/2025:10:30:45 +0000] "GET /test.php?cmd=/bin/sh HTTP/1.1" 200 1234'

**Phase 2: Completed decoding.
	name: 'web-accesslog'
	id: '200'
	protocol: 'GET'
	srcip: '192.168.1.100'
	url: '/test.php?cmd=/bin/sh'

**Phase 3: Completed filtering (rules).
	id: '100100'
	level: '12'
	description: 'Possible remote-code-execution attempt in HTTP request'
	groups: '["web","rce","attackattack","rce","critical"]'
	firedtimes: '1'
	mail: 'true'
**Alert to be generated.

**Phase 1: Completed pre-decoding.
	full event: '10.0.0.1 - - [27/Jun/2025:10:31:00 +0000] "POST /upload.php HTTP/1.1" 200 567 "Mozilla/5.0" "exec=powershell"'

**Phase 2: Completed decoding.
	name: 'web-accesslog'
	id: '200'
	protocol: 'POST'
	srcip: '10.0.0.1'
	url: '/upload.php'

**Phase 3: Completed filtering (rules).
	id: '100100'
	level: '12'
	description: 'Possible remote-code-execution attempt in HTTP request'
	groups: '["web","rce","attackattack","rce","critical"]'
	firedtimes: '2'
	mail: 'true'
**Alert to be generated.

**Phase 1: Completed pre-decoding.
	full event: '172.16.1.50 - - [27/Jun/2025:10:31:15 +0000] "GET /shell.php?c=cmd.exe HTTP/1.1" 404 0'

**Phase 2: Completed decoding.
	name: 'web-accesslog'
	id: '404'
	protocol: 'GET'
	srcip: '172.16.1.50'
	url: '/shell.php?c=cmd.exe'

**Phase 3: Completed filtering (rules).
	id: '100100'
	level: '12'
	description: 'Possible remote-code-execution attempt in HTTP request'
	groups: '["web","rce","attackattack","rce","critical"]'
	firedtimes: '3'
	mail: 'true'
**Alert to be generated.
```
