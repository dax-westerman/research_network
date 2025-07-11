# research_network

## Description

1. Accessible on the public internet, but does not broadcast the endpoint
Use a peer-to-peer overlay network like WireGuard or ZeroTier, but configure it to:
Not expose public IPs.
Use NAT traversal and encrypted tunnels.
Avoid broadcasting presence (e.g., no mDNS or public discovery).
2. FIPS 140-2 compliant encryption
WireGuard uses ChaCha20-Poly1305, which is not FIPS 140-2 certified.
For FIPS compliance, consider:
StrongSwan with IPsec, which supports FIPS 140-2 certified cryptographic modules.
Or use OpenVPN compiled with a FIPS-validated OpenSSL module.
3. Only registered devices can join
Use certificate-based authentication or pre-shared keys.
Maintain a device registry on the master controller.
Use mutual TLS (mTLS) or X.509 certificates for authentication.
4. Master controller for device lookup (no peer IP knowledge)
Implement a centralized directory service (like a custom DNS or API-based lookup).
Devices query the master for a session token or encrypted routing info.
Use ephemeral session keys and on-demand routing.
5. Data passed between devices does not go through the master
Use peer-to-peer encrypted tunnels (e.g., via WireGuard or IPsec).
The master only facilitates initial handshake or lookup, not data routing.
🧠 Suggested Architecture

```
+------------------+       +------------------+       +------------------+
|  Raspberry Pi A  |<----->|  Raspberry Pi B  |<----->|  Raspberry Pi C  |
+------------------+       +------------------+       +------------------+
        |                          |                          |
        |                          |                          |
        +--------------------------+--------------------------+
                                   |
                          +-------------------+
                          |  Master Controller|
                          | (Directory + Auth)|
                          +-------------------+

```

- Master Controller:
  - Authenticates devices.
  - Provides encrypted peer info (e.g., public keys, virtual IPs).
  - Does not relay traffic.
- Devices:
  - Use secure tunnels (e.g., WireGuard/IPsec).
  - Only connect to peers after authenticated lookup.


Tools & Technologies
Component	        Recommended Tool/Tech
VPN / Tunnel	    WireGuard (easy) or IPsec (FIPS-compliant)
Auth & Directory	Custom API with mTLS or JWT
Device Registry	  PostgreSQL or lightweight SQLite
Key Management	  HashiCorp Vault or custom PKI
NAT Traversal	    STUN/TURN or built-in VPN features

## Decisions

Great! Here's a **step-by-step guide** to set up a secure, FIPS 140-2 compliant virtual network for your Raspberry Pi devices, using a **central master controller** for device lookup and **peer-to-peer encrypted communication**.

---

## 🛠️ Step-by-Step Guide

### 🔹 **Step 1: Choose the Right VPN Technology**
To meet FIPS 140-2 compliance, use **StrongSwan (IPsec)** instead of WireGuard.

- **Why StrongSwan?**
  - Supports FIPS 140-2 certified cryptographic modules.
  - Works well on Raspberry Pi.
  - Supports certificate-based authentication.

---

### 🔹 **Step 2: Set Up the Master Controller**
This will act as:
- A **certificate authority (CA)**.
- A **device registry and lookup service** (via a secure API).

#### ✅ Tasks:
1. **Install StrongSwan** and enable FIPS mode (e.g., using a FIPS-compliant OpenSSL).
2. **Set up a CA** to issue certificates to each Pi.
3. **Create a secure API** (e.g., Flask + HTTPS) that:
   - Authenticates devices.
   - Returns encrypted peer info (e.g., virtual IP, public key).
   - Logs access and device metadata.

---

### 🔹 **Step 3: Configure Each Raspberry Pi**
Each Pi will:
- Use StrongSwan to connect to peers.
- Query the master controller for peer info.
- Only connect to authorized devices.

#### ✅ Tasks:
1. **Install StrongSwan**:
   ```bash
   sudo apt update
   sudo apt install strongswan
   ```
2. **Install the certificate** issued by the master controller.
3. **Configure IPsec** to:
   - Use FIPS-compliant ciphers (e.g., AES-GCM, SHA-256).
   - Use certificate-based authentication.
4. **Query the master controller** for peer info using HTTPS and a device token.

---

### 🔹 **Step 4: Secure Communication**
- Devices use **IPsec tunnels** to communicate directly.
- The **master controller is not in the data path**.
- Devices do **not know each other's IPs** until they query the master.

---

### 🔹 **Step 5: Enforce Access Control**
- Only devices with valid certificates and tokens can:
  - Query the master.
  - Establish IPsec tunnels.
- Revoke access by:
  - Revoking certificates.
  - Disabling tokens in the registry.

---

### 🔹 **Step 6: Monitor and Maintain**
- Use logging on the master controller to track device queries.
- Rotate certificates and tokens periodically.
- Monitor IPsec tunnel health and logs on each Pi.

---

## 🔐 FIPS 140-2 Compliance Tips
- Use a Linux distro with **FIPS mode enabled** (e.g., RHEL or Ubuntu with FIPS kernel).
- Use **OpenSSL FIPS module** for all cryptographic operations.
- Configure StrongSwan with:
  ```bash
  ike=aes256gcm16-prfsha256-ecp256
  esp=aes256gcm16-ecp256
  ```
---

## Network Architecture Diagram

<img width="1024" height="1024" alt="image" src="https://github.com/user-attachments/assets/5d51b144-6cd5-4efe-96b9-39b40ed9edbc" />


## Example Scripts

### API for master controller

```python
from flask import Flask, request, jsonify
from functools import wraps

app = Flask(__name__)

# Dummy token store (in production, use a secure DB)
AUTHORIZED_TOKENS = {
    "device1-token": "raspberry-pi-1",
    "device2-token": "raspberry-pi-2"
}

# Dummy peer data
PEER_INFO = {
    "raspberry-pi-1": {"ip": "10.0.0.2", "pubkey": "pubkey1"},
    "raspberry-pi-2": {"ip": "10.0.0.3", "pubkey": "pubkey2"}
}

# Token-based authentication decorator
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token or token not in AUTHORIZED_TOKENS:
            return jsonify({"message": "Unauthorized"}), 401
        request.device_id = AUTHORIZED_TOKENS[token]
        return f(*args, **kwargs)
    return decorated

@app.route('/lookup', methods=['GET'])
@token_required
def lookup():
    device_id = request.device_id
    # Return all peers except the requesting device
    peers = {k: v for k, v in PEER_INFO.items() if k != device_id}
    return jsonify(peers)

if __name__ == '__main__':
    # For production, use a proper certificate and reverse proxy
    app.run(host='0.0.0.0', port=443, ssl_context=('cert.pem', 'key.pem'))
```

Enable HTTPS

```python
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes
```
Place cert.pem and key.pem in the same directory as your script.

### ipsec config

Here’s a Python automation script that runs on each Raspberry Pi to:

Query the master controller for peer information.
Update the StrongSwan ipsec.conf file with the new peer IP.
Restart the IPsec service to apply the changes.

```python
import requests
import subprocess
import json

# Configuration
MASTER_CONTROLLER_URL = "https://your-master-controller/lookup"
AUTH_TOKEN = "device1-token"
LOCAL_ID = "peer1.example.com"
CERT_FILE = "peer1Cert.pem"
KEY_FILE = "peer1Key.pem"
IPSEC_CONF_PATH = "/etc/ipsec.conf"
IPSEC_SECRETS_PATH = "/etc/ipsec.secrets"

def fetch_peer_info():
    headers = {"Authorization": AUTH_TOKEN}
    response = requests.get(MASTER_CONTROLLER_URL, headers=headers, verify=False)
    response.raise_for_status()
    return response.json()

def generate_ipsec_conf(peers):
    conf = [
        "config setup",
        "    charondebug=\"ike 2, knl 2, cfg 2, net 2, esp 2, dmn 2,  mgr 2\"",
        "",
        "conn %default",
        "    keyexchange=ikev2",
        "    ike=aes256gcm16-prfsha256-ecp256",
        "    esp=aes256gcm16-ecp256",
        "    dpdaction=restart",
        "    dpddelay=30s",
        "    dpdtimeout=120s",
        "    rekey=no",
        f"    leftcert={CERT_FILE}",
        f"    leftid=@{LOCAL_ID}",
        "    left=%any",
        "    leftfirewall=yes",
        ""
    ]

    for peer_id, info in peers.items():
        conf += [
            f"conn to-{peer_id}",
            f"    rightid=@{peer_id}",
            f"    right={info['ip']}",
            "    auto=start",
            ""
        ]

    return "\n".join(conf)

def write_files(conf_text):
    with open(IPSEC_CONF_PATH, "w") as f:
        f.write(conf_text)
    with open(IPSEC_SECRETS_PATH, "w") as f:
        f.write(f": RSA {KEY_FILE}\n")

def restart_ipsec():
    subprocess.run(["sudo", "ipsec", "restart"], check=True)

def main():
    peers = fetch_peer_info()
    conf_text = generate_ipsec_conf(peers)
    write_files(conf_text)
    restart_ipsec()
    print("IPsec configuration updated and service restarted.")

if __name__ == "__main__":
    main()

```

Setup Notes:
Run this script at boot or on a schedule using cron or systemd.
Replace your-master-controller with your actual controller's domain or IP.
Ensure the device has the correct certificate and key files in place.

## Config (StrongSwan)

### Master Controller

Here’s a sample configuration for the **master controller** in your secure Raspberry Pi network. This setup assumes the master controller is responsible for:

- Acting as a **Certificate Authority (CA)**.
- Hosting a **Flask-based API** for device authentication and peer lookup.
- Optionally serving as a **VPN gateway** or **directory service**, but **not** routing traffic.

---

#### 🔐 1. StrongSwan Configuration (if acting as CA or VPN endpoint)

##### `/etc/ipsec.conf`

```conf
config setup
    charondebug="ike 2, knl 2, cfg 2, net 2, esp 2, dmn 2,  mgr 2"

conn %default
    keyexchange=ikev2
    ike=aes256gcm16-prfsha256-ecp256
    esp=aes256gcm16-ecp256
    dpdaction=clear
    dpddelay=30s
    dpdtimeout=120s
    rekey=no
    left=%any
    leftcert=masterCert.pem
    leftid=@master.example.com
    leftfirewall=yes
    auto=add
```

> This config allows the master to accept connections from peers if needed (e.g., for certificate enrollment or diagnostics).

---

##### 🔑 2. `/etc/ipsec.secrets`

```conf
: RSA masterKey.pem
```

---

##### 🌐 3. Flask API Configuration

The Flask API (as shown earlier) should:
- Use HTTPS with a valid certificate.
- Authenticate devices using tokens or mTLS.
- Return peer info without exposing full network topology.

---

##### 🧾 4. Device Registry (Example JSON or DB)

```json
{
  "raspberry-pi-1": {
    "ip": "10.0.0.2",
    "pubkey": "pubkey1",
    "token": "device1-token"
  },
  "raspberry-pi-2": {
    "ip": "10.0.0.3",
    "pubkey": "pubkey2",
    "token": "device2-token"
  }
}
```

This can be stored in a secure database or encrypted file and queried by the Flask API.

---

### Master as CA

The automation script failed to run in this environment because the `ipsec` command-line tool (used by StrongSwan) isn't available here. However, I can still provide you with a **ready-to-use script** that you can run directly on your master controller.

---

## 🐍 Python Script: `generate_device_cert.py`

This script automates:
- Generating a private key
- Creating a certificate signing request (CSR)
- Signing the certificate with your CA
- Copying the CA certificate for deployment

```python
import subprocess
from pathlib import Path

# Configuration
device_id = "pi1"
device_cn = "peer1.example.com"
base_dir = Path("pki")
ca_cert = "/etc/ipsec.d/cacerts/ca-cert.pem"
ca_key = "/etc/ipsec.d/private/ca-key.pem"

# Paths
private_dir = base_dir / "private"
certs_dir = base_dir / "certs"
reqs_dir = base_dir / "reqs"
cacerts_dir = base_dir / "cacerts"

private_dir.mkdir(parents=True, exist_ok=True)
certs_dir.mkdir(exist_ok=True)
reqs_dir.mkdir(exist_ok=True)
cacerts_dir.mkdir(exist_ok=True)

key_path = private_dir / f"{device_id}-key.pem"
req_path = reqs_dir / f"{device_id}-req.pem"
cert_path = certs_dir / f"{device_id}-cert.pem"
ca_cert_dest = cacerts_dir / "ca-cert.pem"

# Generate private key
subprocess.run([
    "ipsec", "pki", "--gen", "--type", "rsa", "--size", "2048",
    "--outform", "pem"
], stdout=open(key_path, "w"), check=True)

# Generate CSR
subprocess.run([
    "ipsec", "pki", "--req", "--in", str(key_path), "--type", "rsa",
    "--dn", f"CN={device_cn}", "--outform", "pem"
], stdout=open(req_path, "w"), check=True)

# Sign certificate
subprocess.run([
    "ipsec", "pki", "--issue", "--lifetime", "1825",
    "--cacert", ca_cert,
    "--cakey", ca_key,
    "--in", str(req_path), "--type", "rsa",
    "--dn", f"CN={device_cn}", "--outform", "pem"
], stdout=open(cert_path, "w"), check=True)

# Copy CA cert
subprocess.run(["cp", ca_cert, str(ca_cert_dest)], check=True)

print(f"Certificate and key for {device_id} generated in {base_dir.resolve()}")
```

---

### 📦 Output Directory Structure:
```
pki/
├── cacerts/
│   └── ca-cert.pem
├── certs/
│   └── pi1-cert.pem
├── private/
│   └── pi1-key.pem
└── reqs/
    └── pi1-req.pem
```

---

## 📘 What is a Certificate Revocation List (CRL)?

A **CRL** is a list of certificates that have been **revoked** by the CA before their expiration date. Reasons for revocation include:
- Device compromise
- Certificate misuse
- Decommissioning

### How it works:
- The CA maintains and signs the CRL.
- Devices check the CRL to ensure a peer’s certificate is still valid.
- StrongSwan can be configured to **download and verify** CRLs automatically.

TODO - how to generate CRL with Swansong IPSec

### Peer Device

/etc/ipsec.conf
```python
config setup
    charondebug="ike 2, knl 2, cfg 2, net 2, esp 2, dmn 2,  mgr 2"

conn %default
    keyexchange=ikev2
    ike=aes256gcm16-prfsha256-ecp256
    esp=aes256gcm16-ecp256
    dpdaction=restart
    dpddelay=30s
    dpdtimeout=120s
    rekey=no
    leftcert=peer1Cert.pem
    leftid=@peer1.example.com
    left=%any
    leftfirewall=yes
    rightid=@peer2.example.com
    right=10.0.0.3  # This IP should be dynamically retrieved from the master controller
    auto=start

```

/etc/ipsec.secrets

```python
: RSA peer1Key.pem

```

### Notes on FIPS Compliance

The ike and esp lines specify FIPS 140-2 compliant algorithms:
- AES-256-GCM for encryption
- SHA-256 for integrity
- ECP256 for key exchange (Elliptic Curve)


Since your devices don’t know each other’s IPs:

Replace the right= IP with a script or service that queries the master controller’s API before starting the tunnel.
You can use a systemd service or cron job to:
Query the master controller.
Update ipsec.conf dynamically.
Restart the IPsec service.
