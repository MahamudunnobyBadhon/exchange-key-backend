# Secure Peer-to-Peer Chat System (React & Node.js)

This repository contains the source code for a secure, two-party chat application developed for the CSE722 course project. The system uses a modern, decoupled architecture with a ReactJS front-end and a Node.js back-end engine to provide end-to-end encrypted communication.

---

## Features

* **Decoupled Architecture:** A robust design featuring a ReactJS front-end for the UI and a Node.js back-end for all cryptographic and networking operations.
* **Secure Key Exchange:** Implements an authenticated **Elliptic Curve Diffie-Hellman (ECDH)** key exchange to securely agree upon a shared secret.
* **Authentication:** The authenticity of the key exchange is guaranteed by signing the ECDH public keys with **RSA-2048** digital signatures, preventing Man-in-the-Middle (MitM) attacks.
* **End-to-End Encryption:** All messages sent after the secure handshake are encrypted using **AES-256-GCM**, which provides confidentiality, integrity, and authenticity.

---

## Prerequisites

Before running the application, ensure you have the following installed on **both** computers:

* **Node.js** (LTS version recommended, e.g., v20.x)

---

## How to Run

To deploy and test the application, you will need two computers connected to the same local network.

1.  **Installation:**
    * Copy the `exchange-key-backend` and `key-exchange-frontend` folders to both computers.
    * On both machines, open a terminal and run `npm install` inside both the `backend` and `frontend` directories to download the necessary dependencies.

2.  **Execution (Computer A - The "Listener"):**
    * Find its local IP address (e.g., using `ipconfig` on Windows or `ip addr` on macOS/Linux).
    * In one terminal, start the back-end server:
        ```bash
        cd exchange-key-backend
        npm start
        ```
    * In a second terminal, start the front-end UI:
        ```bash
        cd key-exchange-frontend
        npm start
        ```

3.  **Execution (Computer B - The "Connector"):**
    * Start its back-end and front-end servers using the same commands as above.
    * In the browser window that opens, click the **"Connect to Peer"** button and enter the IP address of **Computer A**.

The two clients will now be connected and able to chat.

---

## Cryptographic Protocol Overview

The application follows a three-phase protocol:

1.  **Unencrypted Connection:** A standard TCP socket is established for initial communication, allowing for a baseline packet capture.
2.  **Secure Handshake:** When a user clicks "Go Secure," the clients perform an authenticated ECDH exchange. RSA signatures are used to verify the authenticity of the ECDH public keys. The clients agree on a shared secret without ever transmitting it over the network.
3.  **Encrypted Communication:** The derived shared secret is used as a key for AES-256-GCM, which encrypts all subsequent messages, ensuring confidentiality and integrity.
