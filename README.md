# acme-siem
Security information & event management node – receives logs, stores them, runs correlation rules, raises alerts, sends Slack webhooks, shows dashboards.

## Create GCP VM Instance

- VM instance name: acme-siem
- Machine type: e2-standard-4 (4 vCPU, 2 core, 16 GB memory)
- OS and Storage 
Operating system: Ubuntu
Version: Ubuntu 22.04 LTS Minimal x86/64, amd64 jammy minimal image built on 2025-06-26
Boot disk type: Balanced persistent disk
Size (GB): 50

Edit VM Instance:

- Go to the VPC networks -> Select default -> Firewalls -> Add Firewall Rule
Name: allow-wazuh-dashboard
Network: default
Priority: 1000
Direction of traffic: Ingress
Action on match: Allow

Targets: Specified target tags -> Target tags: wazuh-lab 
Source filter: IPv4 ranges -> 0.0.0.0/0

Protocols and ports: Specified protocols and ports -> TCP 443,1514,1515,5601,9200,5000

- After saving Firewall Rule Go to the acme-siem instance and edit
Select -> Network interface: Primary internal IPv4 address -> Ephemeral, External IPv4 address -> Ephemeral
Add -> Network tags: wazuh-lab

## Update linux ubuntu 22.04
```bash
sudo apt update
sudo apt upgrade
```

## Wazuh Installation
```bash
curl -sO https://packages.wazuh.com/4.12/wazuh-install.sh && sudo bash ./wazuh-install.sh -a

# https://<VM_EXTERNAL_IP>:443
    User: admin
    Password: gz6QU1f2+4Yy4.IQkppMQk04lnYV9L6F


#Recommended Action: Disable Wazuh Updates.
#We recommend disabling the Wazuh package repositories after installation to prevent accidental upgrades that could break the environment.

sudo sed -i "s/^deb /#deb /" /etc/apt/sources.list.d/wazuh.list
sudo apt update
```

## Create Agent
- Wazuh Dashboard -> Agent Management -> Summary -> Deploy New Agent
Package: Linux DEB amd64
Server Address: <VM_EXTERNAL_IP>
Agent Name: ubuntu-s1
Select Group: default

- Run the given commands on acme-server, then start the agent
```
wget https://packages.wazuh.com/....
```
```
sudo systemctl daemon-reload
sudo systemctl enable wazuh-agent
sudo systemctl start wazuh-agent
```

# acme-server

Monitored workload – the machine we care about and want to protect. Runs the application that might be attacked. A lightweight Wazuh agent ships its local logs up to the manager.

## Create GCP VM Instance

- VM instance name: acme-server
- Machine type: e2-standard-2 (2 vCPUs, 8 GB Memory)
- OS and Storage 
Operating system: Ubuntu
Version: Ubuntu 22.04 LTS Minimal x86/64, amd64 jammy minimal image built on 2025-06-26
Boot disk type: Balanced persistent disk
Size (GB): 50

Edit VM Instance:

Firewalls
- Allow HTTP traffic
- Allow HTTPS traffic

---

# acme-siem continued

## Some Detection rules
```xml
<!-- remote_detection_rules.xml -->
<group name="custom_high_priority">
  <!-- RCE via command-injection -->
  <rule id="120001" level="12">
    <if_sid>31100</if_sid>
    <regex type="pcre2">(?i)(cmd=|command=|exec=|system=|shell=|bash=|sh=|powershell=|cmd\.exe)</regex>
    <description>Potential RCE via command parameter</description>
    <group>rce,web_attack</group>
  </rule>

  <!-- Back-tick / eval / $() payloads -->
  <rule id="120002" level="12">
    <if_sid>31100</if_sid>
    <regex type="pcre2">(?i)(%60|`|\$\(|\${|eval\(|base64_decode|shell_exec\()</regex>
    <description>Suspicious code-execution payload in URL</description>
    <group>rce,web_attack</group>
  </rule>

  <!-- SQLi + xp_cmdshell -->
  <rule id="120005" level="12">
    <if_sid>31100</if_sid>
    <regex type="pcre2">(?i)(xp_cmdshell|sp_execute_external_script|OPENROWSET|INTO\s+OUTFILE|LOAD_FILE)</regex>
    <description>SQL injection with possible command execution</description>
    <group>rce,sqli</group>
  </rule>
</group>
```

## Create Alert + Slack
```sudo nano /var/ossec/etc/ossec.conf```
```xml
<integration>
  <name>slack</name>
  <hook_url>https://hooks.slack.com/services/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</hook_url>
  <alert_format>json</alert_format>
  <level>12</level>
</integration>


<localfile>
  <log_format>apache</log_format>
  <location>/tmp/wazuh-test.log</location>
</localfile>
```
```bash
sudo systemctl restart wazuh-manager
sudo systemctl status wazuh-manager
```

## Test Logs in Terminal or Wazuh Dashboard
```https://<VM_EXTERNAL_IP>/app/rules#/manager/?tab=ruleset``` -> Ruleset Test
```bash
/var/ossec/bin/wazuh-logtest -V
/var/ossec/bin/wazuh-logtest
```

## Run alerts via log file
```bash
mkdir -p /tmp/wazuh-test.log
echo '192.168.1.100 - - [28/Jun/2025:10:00:00 +0000] "GET /vulnerable.php?cmd=whoami HTTP/1.1" 200 1234 "-" "Mozilla/5.0"' >> /tmp/wazuh-test.log
```

