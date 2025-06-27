# Wazuh Rules

```xml
<group name="web,rce,attack,">
  <rule id="100100" level="12">

    <if_sid>31101</if_sid>
    <regex>(/bin/sh|cmd\.exe|powershell|;[[:space:]]*\w|\|[[:space:]]*\w|\$\{IFS\})</regex>

    <description>Possible Remote Code Execution attempt in HTTP request</description>
    <mitre_id>T1190</mitre_id>   <!-- Initial access: Exploit public-facing app -->
    <group>attack,rce,</group>
  </rule>
</group>
```
