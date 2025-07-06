# Kali Linux Setup On GCP VM

## Operating system and storage
- name: attacker-kali
- e2-standard-2 (2 vCPU, 1 core, 8 GB memory)
- Image: Debian GNU/Linux 12 (bookworm)
- Disk size: 50 GB

## Install Kali
```bash
sudo -i
cd /etc/apt
ls
nano sources.list
```

Add current Repo (https://www.kali.org/docs/general-use/kali-linux-sources-list-repositories/)
```bash
deb http://http.kali.org/kali kali-rolling main contrib non-free non-free-firmware
```

Then update ```apt update``` We will see GPG error, use this commands:
```bash
gpg --keyserver pgpkeys.mit.edu --recv-key  ED444FF07D8D0BF6
gpg -a --export ED444FF07D8D0BF6 | sudo apt-key add -
```

If last command fails use:
```bash
wget https://kali.download/kali/pool/main/k/kali-archive-keyring/kali-archive-keyring_2025.1_all.deb
dpkg -i kali-archive-keyring_2025.1_all.deb
```

If fails, get the latest link from: https://kali.download/kali/pool/main/k/kali-archive-keyring/

Then,
```bash
apt update
apt upgrade
```

```bash
apt install -y kali-linux-default
reboot
```
(Installation will takes time)


Go to the google cloud platform VM Instances and connect attacker-kali instance via "View gcloud command"
A command similar to this will be filled in automatically: ```gcloud compute ssh --zone "us-central1-c" "attacker-kali" --project "ecstatic-bounty-464116-d2"```
Generate public/private rsa key pair enter some password you will remember.

Use this command to make the SSH button on the Google cloud platform work.
```bash
sudo tee -a /etc/ssh/sshd_config << 'EOF'
KexAlgorithms +diffie-hellman-group14-sha1,diffie-hellman-group-exchange-sha256
EOF
```
```bash
sudo systemctl restart sshd
```

Then connect via SSH button, ```sudo -i``` We have Kali on Gcp VM.


