# EmotiBitSec

This repository contains the implementation of a cryptographic security layer for the EmotiBit system, enabling secure communication between biometric sensors and a central receiver (Oscilloscope) over Wi-Fi.

## 🧩 Project Overview

This security protocol ensures:

- 🔐 **Confidentiality** using symmetric encryption (AES-128 in ECB mode)
- 🧾 **Integrity** and 🆔 **Authentication** using HMAC-SHA256
- 🔄 **Replay protection** through packet sequence numbering

It has been designed for **resource-constrained IoT devices**, maintaining compatibility with the original EmotiBit architecture and ensuring low computational overhead.

---

## 📁 Repository Structure
```
EmotiBitSecureProtocol/
├── EmotiBitHost/
│   ├── EmotiBitSecurityHost.h       # Security logic for the Oscilloscope
│   ├── EmotiBitSecurityHost.cpp
│   ├── EmotiBitWiFiHost.h           # Adapted Wi-Fi layer (host)
│   └── EmotiBitWiFiHost.cpp
│
├── EmotiBit/
│   ├── EmotiBitSecurity.h           # Security logic for EmotiBit (ESP32)
│   ├── EmotiBitSecurity.cpp
│   ├── EmotiBitWiFi.h               # Adapted Wi-Fi layer (firmware)
│   └── EmotiBitWiFi.cpp
│
├── EmotiBitOscilloscope_Security.app.zip   # Precompiled Oscilloscope 
└── README.md
```

---

## ⚙️ Features

- 📦 Packet encryption & signing using PSK (Pre-Shared Keys)
- ✅ Secure bootstrapping of new devices via `HelloHost` messages
- 📡 UDP-based communication with duplicate and order control
- 🔄 Compatible with EmotiBit firmware (ESP32-based) and OpenFrameworks-based Oscilloscope
- 🔐 Keys loaded from SD (EmotiBit) and centralized MySQL database (Oscilloscope)

---

## 🔧 Getting Started

### 🧠 1. Security Layer in Oscilloscope (Host)
1. Clone [`ofxEmotiBit`](https://github.com/EmotiBit/ofxEmotiBit)
2. Use OpenFrameworks v0.11.2
3. Add `mbedtls` cryptographic library to `addons/`
4. Replace the following files in the `ofxEmotiBit` project:
   - `EmotiBitWiFiHost.h/.cpp` → use the ones in this repo
   - Add `EmotiBitSecurityHost.h/.cpp`
5. Add header search paths in Xcode for `mbedtls/include` and `mbedtls/library`

💡 See Annex in the documentation for step-by-step instructions.

---

### 📲 2. Security Layer in EmotiBit Firmware (ESP32)
1. Use Arduino IDE with ESP32 board support (Adafruit Feather ESP32)
2. Install EmotiBit libraries and dependencies
3. Replace:
   - `EmotiBitWiFi.h/.cpp` → use the ones in this repo
   - Add `EmotiBitSecurity.h/.cpp` to the `EmotiBit_FeatherWing` library
4. Upload firmware using `EmotiBit_stock_firmware.ino`

💡 Keys must be stored in the SD card using the format:
```
t1=<PSK_EMOTIBIT>
t2=<PSK_OSCILLOSCOPE>
```

---

## 🔐 Key Management

The Oscilloscope loads PSKs dynamically via HTTP from a **MySQL backend** using a PHP API. Device IDs and keys are stored in a central database with fields:

- `id` (VARCHAR)
- `secretkey` (CHAR(32))
- `lastmodified` (DATETIME)

Example output (JSON):

```json
{
  "status": "success",
  "data": [
    { "id": "MD-V5-0000001", "secretkey": "00000000000000000000000000000000", "lastmodified": "2025-04-25 06:01:00" }
  ]
}
