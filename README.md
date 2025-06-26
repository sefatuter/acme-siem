# acme-siem

```bash
sudo apt update
sudo apt upgrade
```

## Wazuh Installation
```bash
curl -sO https://packages.wazuh.com/4.12/wazuh-install.sh && sudo bash ./wazuh-install.sh -a

# https://<wazuh-dashboard-ip>:443
    User: admin
    Password: 2bQ6Pu.Hj7BbdhwnTDWAXj4vo*Ih7uzI

#Recommended Action: Disable Wazuh Updates.
#We recommend disabling the Wazuh package repositories after installation to prevent accidental upgrades that could break the environment.

sudo sed -i "s/^deb /#deb /" /etc/apt/sources.list.d/wazuh.list
sudo apt update

```
