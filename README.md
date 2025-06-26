# acme-siem

```bash
sudo apt update
sudo apt upgrade
```

## Wazuh Installation
```bash
curl -sO https://packages.wazuh.com/4.12/wazuh-install.sh && sudo bash ./wazuh-install.sh -a

26/06/2025 18:13:08 INFO: You can access the web interface https://<wazuh-dashboard-ip>:443
    User: admin
    Password: IpAbDNVzpqcxwB8X2N+4BXYUTNZA8y2G

#Recommended Action: Disable Wazuh Updates.
#We recommend disabling the Wazuh package repositories after installation to prevent accidental upgrades that could break the environment.

sudo sed -i "s/^deb /#deb /" /etc/apt/sources.list.d/wazuh.list
sudo apt update

```
