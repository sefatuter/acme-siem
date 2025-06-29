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
sudo apt install nano
```

## Wazuh Installation
```bash
curl -sO https://packages.wazuh.com/4.12/wazuh-install.sh && sudo bash ./wazuh-install.sh -a

# Access the web interface https://<wazuh-dashboard-ip>:443
    User: admin
    Password: tUyPp6W1na+VH7tUHsJkRCce.iobjVrH


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
```bash
sudo apt update
sudo apt upgrade
wget https://packages.wazuh.com/....
```
```bash
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
<!-- ------------------------------------------------- -->
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

  <rule id="120010" level="13">
    <if_sid>31100</if_sid>
    <regex type="pcre2">(?i)(wget|curl|nc|netcat)</regex>
    <description>Level 13: Possible download tool in request</description>
    <group>web_attack,tools</group>
  </rule>
<!-- Failed Login Detection Rules -->
  <!-- SSH specific failed login (uses existing SSH rule as parent) -->
  <rule id="120020" level="10">
    <if_sid>5760</if_sid>
    <description>SSH failed login attempt detected</description>
    <group>failed_login,ssh,authentication_failed</group>
  </rule>
<!-- ------------------------------------------------- -->
  <!-- Multiple SSH failed login attempts from same IP -->
  <rule id="120021" level="10" frequency="2" timeframe="300">
    <if_matched_sid>120020</if_matched_sid>
    <same_source_ip />
    <description>Multiple SSH failed login attempts from same IP: $(srcip)</description>
    <group>failed_login,ssh,brute_force</group>
  </rule>

  <!-- High number of SSH failed login attempts - trigger ban -->
  <rule id="120022" level="12" frequency="3" timeframe="300">
    <if_matched_sid>120020</if_matched_sid>
    <same_source_ip />
    <description>SSH IP $(srcip) blocked due to multiple failed login attempts</description>
    <group>failed_login,ssh,brute_force,ip_ban</group>
  </rule>

  <!-- General system login failures -->
  <rule id="120023" level="10">
    <if_sid>5503,5504,5551,5552</if_sid>
    <description>System login failure detected</description>
    <group>failed_login,authentication_failed</group>
  </rule>

  <!-- Multiple system login failures -->
  <rule id="120024" level="12" frequency="3" timeframe="300">
    <if_matched_sid>120023</if_matched_sid>
    <same_source_ip />
    <description>System login IP $(srcip) blocked due to brute force attack</description>
    <group>failed_login,brute_force,ip_ban</group>
  </rule>
</group>
```

Rule Structure:



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
echo '192.168.1.100 - - [28/Jun/2025:10:00:00 +0000] "GET /vulnerable.php?cmd=whoami HTTP/1.1" 200 1234 "-" "Mozilla/5.0"' >> /tmp/wazuh-test.log
echo '192.0.2.88 - - [28/Jun/2025:14:00:00 +0000] "GET /exploit.php?tool=curl HTTP/1.1" 200 1337 "-" "curl/7.68.0"' >> /tmp/wazuh-test.log
```
Now slack is showing alerts correctly, add buttons to slack message: True Positive, False Positive

```bash
sudo cp /var/ossec/integrations/slack.py /var/ossec/integrations/custom-slack.py
sudo cp /var/ossec/integrations/slack /var/ossec/integrations/custom-slack
chmod 755 /var/ossec/integrations/custom-slack
chmod 755 /var/ossec/integrations/custom-slack.py
```
```bash
sudo nano /var/ossec/integrations/custom-slack.py
```
custom-slack.py -> add code block to generate_message():
```py
    msg['fields'].append({'title': 'Location', 'value': alert['location']})
    msg['fields'].append(
        {
            'title': 'Rule ID',
            'value': f"{alert['rule']['id']} _(Level {level})_",
        }
    )

    msg['ts'] = alert['id']
    msg['callback_id'] = f"wazuh_{alert['id']}"

    msg['actions'] = [
        {
            "name": "tp",
            "text": "TP",
            "type": "button",
            "style": "primary",
            "value": f"TP|{alert['id']}"
        },
        {
            "name": "fp",
            "text": "FP",
            "type": "button",
            "style": "danger",
            "value": f"FP|{alert['id']}"
        }
    ]
```
check if there is errors: ```tail -f /var/ossec/logs/ossec.log | grep -i custom-slack```


Create Flask File
```
sudo apt update
sudo apt install -y python3-venv
mkdir -p /opt/wazuh-slack-handler
cd /opt/wazuh-slack-handler
```
Create Environment:
```
python3 -m venv venv
source venv/bin/activate
pip install flask slack_sdk requests
```
Create action file:
```sudo nano /opt/wazuh-slack-handler/slack_demo.py```
```py
from flask import Flask, request, abort
import json, os, datetime as dt

app  = Flask(__name__)
PORT = 5000                     # change if 5000 is taken

# ── utilities ────────────────────────────────────────────────────────────
def log(msg):
    ts = dt.datetime.now().isoformat(timespec="seconds")
    print(f"[{ts}] {msg}", flush=True)

# ── main endpoint ────────────────────────────────────────────────────────
@app.route("/slack/actions", methods=["POST"])
def slack_actions():
    try:
        payload = json.loads(request.form["payload"])
    except (KeyError, json.JSONDecodeError):
        return abort(400, "Bad payload")

    button_value = payload["actions"][0]["value"]   # "TP|1751052544.2016042"
    label, alert_id = button_value.split("|", 1)

    if label == "TP":
        handle_true_positive(alert_id, payload)
    elif label == "FP":
        handle_false_positive(alert_id, payload)
    else:
        abort(400, "Unknown button")

    return "", 200          # Slack only needs a 200 OK

# ── placeholder logic ────────────────────────────────────────────────────
def handle_true_positive(alert_id, payload):
    """
    Pretend to invoke Wazuh active-response here.
    For now we just print a line; replace with real API call later.
    """
    src_ip = payload["original_message"]["attachments"][0]["fields"][0]["value"]
    log(f"TP  -> would call active-response to block {src_ip} (alert {alert_id})")

def handle_false_positive(alert_id, payload):
    """
    Pretend to mark the rule as ignored.
    """
    rule_id_field = payload["original_message"]["attachments"][0]["fields"][-1]["value"]
    rule_id = rule_id_field.split()[0]
    log(f"FP  -> would tune out rule {rule_id} (alert {alert_id})")

# ── main ────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    log("Starting Slack action demo …")
    app.run(host="0.0.0.0", port=PORT)
```

- Running as a service

creating a systemd service unit:
```sudo nano /etc/systemd/system/slack-flask.service```

```service
[Unit]
Description=Flask Webhook Handler for Slack Buttons
After=network.target

[Service]
User=root
WorkingDirectory=/opt/wazuh-slack-handler
Environment="PATH=/opt/wazuh-slack-handler/venv/bin"
ExecStart=/opt/wazuh-slack-handler/venv/bin/python slack_actions.py
Restart=always

[Install]
WantedBy=multi-user.target
```
```bash
sudo systemctl daemon-reload
sudo systemctl enable --now slack-flask
sudo systemctl status slack-flask
```

---
## Webhook + Interactive Components Integration:

With ngrok:
```bash
ngrok config add-authtoken 2z8pSLOYdLbT4lv7aOu1uSdd9FJ_27PZ5uoUJgxTWgcYgJFwB
ngrok http 5000
```
and run the python on another terminal
```bash
cd /opt/wazuh-slack-handler
source venv/bin/activate
python slack_actions.py
```
and don't forget to change (https://api.slack.com/apps) -> Interactivity & Shortcuts -> Request URL to https://......ngrok-free.app/slack/actions

![image](https://github.com/user-attachments/assets/196867bc-6cda-4042-8ca3-b8dcb5f51c40)



With CloudFlare:
```bash
sudo apt update
curl -L https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64.deb -o cloudflared.deb
sudo dpkg -i cloudflared.deb
cloudflared tunnel login
cloudflared tunnel --url http://localhost:5000
```
and don't forget to change (https://api.slack.com/apps) -> Interactivity & Shortcuts -> Request URL to https://.....trycloudflare.com/slack/actions

![image](https://github.com/user-attachments/assets/7c83e545-a1fb-4193-afed-2c564d11aea7)

- Running as a service

creating a systemd service unit:
```sudo nano /etc/systemd/system/cloudflared-tunnel.service```

```service
# /etc/systemd/system/cloudflared-tunnel.service
[Unit]
Description=Cloudflare Tunnel for Slack Integration
After=network.target

[Service]
ExecStart=/usr/bin/cloudflared tunnel --url http://localhost:5000 --no-autoupdate
Restart=always
User=root

[Install]
WantedBy=multi-user.target
```
```bash
sudo systemctl daemon-reload
sudo systemctl restart cloudflared-tunnel
sudo systemctl status cloudflared-tunnel
```

See the Tunnel URL -> ```journalctl -u cloudflared-tunnel -n 20 --no-pager | grep -Eo 'https://[a-z0-9-]+\.trycloudflare\.com'```

and don't forget to change (https://api.slack.com/apps) -> Interactivity & Shortcuts -> Request URL to https://.....trycloudflare.com/slack/actions

---

## Wazuh Active Response

**Active response structure:**

- The ```<command>``` block contains information about the action to be executed on the Wazuh agent
- ```<name>``` Sets a name for the command. In our case -> firewall-drop
- ```<executable>``` file in /var/ossec/active-response/bin/, Specifies the active response script or executable that must run upon a trigger. In this case, it’s the firewall-drop executable.
- ```<timeout_allowed>``` – if yes, Wazuh may send the script a delete request when the ```<timeout>``` expires.
- In this case ```<timeout>180</timeout>``` → “After 180 seconds, please un-do the block.” ```<timeout_allowed>yes</timeout_allowed>``` → “I allow you to call the script again with ```ACTION=delete```.”


- ```<active-response>``` Tells Wazuh when and where to run that tool.
- ```<command>``` Specifies the command to configure. This is the command name firewall-drop defined in the previous step.
- ```<location>``` Specifies where the command executes. Using the ```<location>local</location>``` value means that the command executes on the monitored endpoint where the trigger event occurs. The script runs only on the single node that generated the alert. If Agent A sees the alert → Agent A runs the script. If the Manager sees the alert (agent ID 000) → the Manager runs the script. ```<location>all</location>``` Every node (all agents and the Manager) will run the script whenever any of them gets that alert. Agent A sees an alert → Agent A, Agent B, … Manager all run the script. Manager sees an alert → again, every node runs it.
- ```<rules_id>``` The Active Response module executes the command if rule ID 5710,5712,5763 - SSHD brute force trying to get access to the system fires.
- ```<timeout>``` Specifies how long the active response action must last. In this use case, the module blocks for 180 seconds the IP address of the endpoint carrying out the brute-force attack.


Test default active response:

```conf
<!-- Default -->
  <command>
    <name>firewall-drop</name>
    <executable>firewall-drop</executable>
    <timeout_allowed>yes</timeout_allowed>
  </command>

<active-response>
  <disabled>no</disabled>
  <command>firewall-drop</command>
  <location>local</location>
  <!-- you can list several IDs, comma-separated -->
  <rules_id>5710,5712,5763</rules_id>
  <timeout>180</timeout>
</active-response>
```
```sudo systemctl restart wazuh-manager```

**Testing the configuration**

![image](https://github.com/user-attachments/assets/eb195481-28ac-4e79-b3c6-c612d05416cd)


Test from another VM instead of Agent vm, because firewall-drop only blocks real remote addresses
(it skips 127., 10., 172.16/12, 192.168/16 unless you edit the script) 
```bash
for i in {1..10}; do
    ssh -o ConnectTimeout=2 wronguser@<AGENT_IP> 2>/dev/null
done
```


![image](https://github.com/user-attachments/assets/8dc53bf9-3fad-4262-99c9-80a945e749bd)


```bash
sudo watch iptables -L -n
sudo tail -f /var/ossec/logs/active-responses.log
```

![image](https://github.com/user-attachments/assets/ff25fdf8-9082-43d8-8e4d-e76ff02f0055)


![image](https://github.com/user-attachments/assets/ad89ccd3-75a5-496d-9998-d3d120af0411)

Testing host blocked unblocked ```ssh -o ConnectTimeout=2 nosuchuser@<AGENT_IP> 2>/dev/null || true```

![image](https://github.com/user-attachments/assets/f0f2fc28-25b3-480d-b06c-f3f5a6168a37)

![image](https://github.com/user-attachments/assets/ebc17b84-da59-4227-86e6-88e48f3d4228)


**Writing my own Active Response Script**

Wherever we expect the script to run, it needs to live under that node’s Wazuh installation in: ```sudo nano /var/ossec/active-response/bin/....``` Agent or Manager VM.

Where to put scripts?

Put your active-response scripts under the same directory on every node that might execute them:
- Path: ```/var/ossec/active-response/bin/<my-script>```
- If configure ```<location>local</location>``` and only the manager/agent runs it, install it just on manager.
- If configure ```<location>001,005,012</location>``` for an agent, install it on that agent (acme-server/ubuntu-s1).
- If configure ```<location>all</location>``` (or list multiple IDs), install the script on both the manager and every agent.

That way, whichever node Wazuh tells “run this,” it finds the script in ```/var/ossec/active-response/bin/```.
* Put the script where it might work or where we want it to work.
* Declare the ```<active-response>``` block in Manager only.
* Manager (acme-siem): hosts the ```<command>``` and ```<active-response>``` stanzas.

Negate = "Don't include this situation, focus on the opposite."

- Ban Host Script:

```sudo nano /var/ossec/active-response/bin/ban-host.sh```
Make it executable ```chmod +x /var/ossec/active-response/bin/ban-host.sh```

```sh
#!/bin/bash

# Wazuh provides:
#   ACTION = add | delete
#   SRCIP  = the IP address from the alert
IP="$SRCIP"

if [[ "$ACTION" == "add" ]]; then
  iptables -I INPUT -s "$IP" -j DROP
elif [[ "$ACTION" == "delete" ]]; then
  iptables -D INPUT -s "$IP" -j DROP
else
  exit 1
fi

exit 0
```

**Simulate the script**

```bash
# Simulate a block
sudo ACTION=add SRCIP=203.0.113.55 /var/ossec/active-response/bin/ban-host.sh
iptables -L -n | grep 203.0.113.55   # you should see the DROP rule

# Simulate an unblock
sudo ACTION=delete SRCIP=203.0.113.55 /var/ossec/active-response/bin/ban-host.sh
iptables -L -n | grep 203.0.113.55   # the rule should be gone
```

![image](https://github.com/user-attachments/assets/0500ecba-78c1-4172-8880-5ab1aec6a3d6)


**Custom Script**

![image](https://github.com/user-attachments/assets/6b13ec70-bd0f-4147-8c04-3a40170db196)


```sudo cat /var/ossec/ar-test-result.txt```

```sudo tail -f /var/ossec/logs/active-responses.log```
