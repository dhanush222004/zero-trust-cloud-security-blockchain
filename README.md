# 🔐 Zero-Trust Cloud Security System using Blockchain

This project implements a **Zero-Trust Cloud Security Architecture** using **Blockchain** and **Python**, ensuring that no user or request is trusted by default.

## 🚀 Features
- Zero-Trust access verification
- Blockchain-based authorization
- SHA-256 hashed identity storage
- Role-Based Access Control (Admin/User)
- Unauthorized attack simulation
- Immutable audit logs with timestamps
- Flask-based REST API (Cloud simulation)

## 📌 API Usage Examples
  Example
    ### Register a User (Admin)
    
```bash
curl -X POST http://127.0.0.1:5000/register \
-H "Content-Type: application/json" \
-d '{"identity":"user@example.com","role":"USER"}'
   
   Request Access (Authorized User)

curl -X POST http://127.0.0.1:5000/access \
-H "Content-Type: application/json" \
-d '{"identity":"user@example.com"}'

   Simulate Unauthorized Attack
curl -X POST http://127.0.0.1:5000/attack \
-H "Content-Type: application/json" \
-d '{"identity":"attacker@evil.com"}'

   View Audit Logs
curl http://127.0.0.1:5000/logs

## 🏗 Architecture Overview

Client → Flask API → Blockchain Smart Contract → Audit Logs

## 📂 Project Structure

app.py | Flask API implementing Zero-Trust logic 
ZeroTrust.sol | Smart contract for access control & audit logs 
requirements.txt | Python dependencies 
start_windows.bat | Windows startup script
start_linux.sh | Linux startup script 
start_mac.sh | macOS startup script 

## 🧠 Technologies Used
- Python (Flask)
- Solidity (Smart Contracts)
- Ethereum Tester (Python-only blockchain)
- Web3.py
- SHA-256 Cryptographic Hashing

## 🔐 Zero-Trust Flow
1. User submits identity
2. Identity is hashed using SHA-256
3. Smart contract verifies role and identity
4. Access decision is made
5. All attempts are logged immutably on blockchain

## ⚔ Unauthorized Attack Simulation
Attackers with invalid identities are denied access, and their attempts are permanently logged on the blockchain.


## ▶ Quick Start (All Platforms)

### Windows
```bash
```bash
python app.py
start_windows.bat

### Linux

chmod +x start_linux.sh
./start_linux.sh

### Mac
chmod +x start_mac.sh
./start_mac.sh


## 📄 License

This project is licensed under the MIT License.

© 2026 Dhanu  
If you use this project for academic or commercial purposes, please provide appropriate credit to the original author.



