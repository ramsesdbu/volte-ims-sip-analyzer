# 📞 VoLTE / IMS SIP Analyzer

> **From SIP PCAP to NOC Decision**

> ⚠️ **Source-Available / Proprietary Software**
>
> The source code is publicly available for viewing, learning, research, and non-commercial evaluation. Commercial use, redistribution, enterprise deployment, or derivative commercial products require prior written permission from the copyright owner.

A Python-based SIP/PCAP analyzer designed for **VoLTE, IMS, VoIP and Core Network NOC/L1 troubleshooting**.

The application analyzes SIP signaling from PCAP/PCAPNG files and converts packet-level information into a simple operational dashboard to help engineers quickly identify network health, call failures, SIP errors, affected Call-IDs, and the next troubleshooting action.

---

## 🎯 Project Objective

SIP troubleshooting can require an engineer to inspect hundreds or thousands of packets before answering a simple operational question:

- Is the network healthy?
- Are calls succeeding?
- Which SIP errors are occurring?
- Which calls are affected?
- Which SIP node or endpoint is involved?
- What should an L1/NOC engineer check first?

This project is designed to reduce that investigation effort by transforming raw SIP packet information into a **NOC-oriented decision dashboard**.

```text
SIP PCAP
   ↓
SIP Parsing
   ↓
Call-ID Correlation
   ↓
Call / SIP Error Analysis
   ↓
Network Health
   ↓
NOC / L1 Decision
   ↓
SIP Ladder / Deep Troubleshooting
```

---

# 🚀 Key Features

## 🟢 NOC / L1 Dashboard

The dashboard provides a simplified operational view for first-level engineers.

- 🟢 HEALTHY
- 🟠 WARNING / INVESTIGATE
- 🔴 ACTION REQUIRED
- ⚪ NO DATA / INCOMPLETE CAPTURE
- Call success and failure KPIs
- SIP 4xx / 5xx / 6xx statistics
- L1 troubleshooting recommendations

> **Important:** Health status is calculated from the uploaded PCAP/PCAPNG only. It is not a live network-wide assurance status.

---

## 📊 Call KPI

The dashboard provides:

- Total Calls
- Call OK
- Rejected Calls
- Dropped Calls
- Call Errors
- Success Rate
- SIP 4xx
- SIP 5xx
- SIP 6xx
- Total SIP Errors

Example:

```text
┌──────────────────────────────────────────────────────────┐
│                    KEY KPI                               │
├──────────┬──────────┬──────────┬──────────┬─────────────┤
│ Total    │ Call OK  │ Reject   │ Dropped  │ Call Error  │
│ Calls    │          │          │          │             │
├──────────┼──────────┼──────────┼──────────┼─────────────┤
│  1,250   │  1,205   │    30    │     5    │     10      │
└──────────┴──────────┴──────────┴──────────┴─────────────┘
```

---

# 🚨 SIP Error Analysis

The analyzer detects SIP response classes:

| Class | Description |
|---|---|
| 4xx | Client / request related errors |
| 5xx | Server / service related errors |
| 6xx | Global rejection |

Common SIP responses supported by the analyzer include:

| SIP Code | Meaning |
|---|---|
| 400 | Bad Request |
| 401 | Unauthorized |
| 403 | Forbidden |
| 404 | Not Found |
| 408 | Request Timeout |
| 480 | Temporarily Unavailable |
| 486 | Busy Here |
| 500 | Server Internal Error |
| 503 | Service Unavailable |
| 504 | Server Time-out |
| 603 | Decline |

The dashboard highlights frequent SIP errors so L1 engineers can identify the dominant problem quickly.

---

# 📞 SIP Call Analysis

The application correlates SIP messages using **Call-ID**.

Example successful call:

```text
INVITE
   ↓
100 Trying
   ↓
180 Ringing
   ↓
200 OK
   ↓
ACK
   ↓
RTP
   ↓
BYE
   ↓
200 OK
```

The analyzer can classify calls into:

- `OK`
- `REJECTED`
- `ERROR`
- `DROPPED`
- `INCOMPLETE`

### INCOMPLETE

`INCOMPLETE` means a Call-ID was found but the final SIP response was not visible in the capture.

This should **not automatically be treated as a network failure**.

Possible reasons include:

- Capture ended before the call completed
- Missing packets
- One-way capture
- Packet loss
- Capture filter limitations
- Incomplete signaling visibility

---

# 🔬 SIP Ladder / Sequence Diagram

The application provides a SIP ladder view for troubleshooting individual calls.

Example:

```text
UE / SBC              IMS / SIP Node
   │                        │
   │──── INVITE ───────────>│
   │<─── 100 Trying ────────│
   │<─── 180 Ringing ───────│
   │<─── 200 OK ────────────│
   │──── ACK ──────────────>│
   │                        │
   │<════ RTP MEDIA ═══════>│
   │                        │
   │──── BYE ──────────────>│
   │<─── 200 OK ────────────│
```

The ladder can be used to identify:

- Missing SIP responses
- SIP transaction failures
- Unexpected response codes
- Call setup problems
- Call release problems
- Signaling direction
- Timing between SIP messages

---

# 🔎 SIP Message Explorer

Individual SIP frames can be inspected in detail.

Example:

```text
Frame       : 304
Timestamp   : 2014-12-16 21:37:06.178
Source      : 10.2.10.18
Destination : 10.2.17.60
Method      : INVITE
Call-ID     : example-call-id
CSeq        : 1 INVITE
```

The analyzer can expose SIP information such as:

- Frame
- Timestamp
- Source
- Destination
- Method
- Call-ID
- CSeq
- From
- To
- Via
- User-Agent

---

# 🛠️ NOC / L1 Decision Support

The main objective is to move beyond simply displaying packet data.

The dashboard attempts to answer:

> **"What should the L1 engineer do next?"**

Example:

```text
🔴 ACTION REQUIRED

SIP 500 Server Internal Error detected.

Recommended L1 checks:

1. Identify the affected SIP node
2. Check node/service alarms
3. Check transport connectivity
4. Check CPU / memory / service status
5. Check recent configuration changes
6. Inspect the affected Call-ID
7. Review the SIP ladder
8. Escalate to IMS/Core team when required
```

Another example:

```text
🟠 INVESTIGATE

SIP rejection rate is increasing.

Recommended checks:

1. Identify the dominant SIP response code
2. Check affected Source / Destination
3. Inspect affected Call-IDs
4. Check timestamps against alarms
5. Determine whether the issue is isolated or widespread
```

---

# 🧭 Typical L1 Troubleshooting Workflow

```text
                 PCAP
                   │
                   ▼
          ┌─────────────────┐
          │ NETWORK STATUS  │
          └────────┬────────┘
                   │
          ┌────────▼────────┐
          │    CALL KPI     │
          └────────┬────────┘
                   │
          ┌────────▼────────┐
          │   SIP ERRORS    │
          └────────┬────────┘
                   │
          ┌────────▼────────┐
          │  AFFECTED CALL  │
          │     / NODE      │
          └────────┬────────┘
                   │
          ┌────────▼────────┐
          │   SIP LADDER    │
          └────────┬────────┘
                   │
          ┌────────▼────────┐
          │    L1 ACTION    │
          └─────────────────┘
```

---

# 📡 RTP Analysis

The analyzer can detect RTP traffic in the capture and provide an indication of media traffic.

It can help identify:

- RTP present
- RTP absent
- Possible one-way RTP
- Bidirectional RTP indication

> **Important:** Absence of RTP in a PCAP does not automatically mean that the network has a media failure. The capture may contain SIP signaling only.

---

# 📈 Timeline Analysis

Timestamp-based analysis helps correlate:

```text
SIP Error
    ↓
Timestamp
    ↓
Network Alarm
    ↓
Configuration Change
    ↓
Node Event
```

This can be useful for troubleshooting intermittent VoLTE/IMS problems.

---

# 🧪 Sample PCAP

A synthetic test PCAP can be included for demonstration and application testing.

Suggested directory:

```text
sample/
└── volte_ims_noc_test.pcap
```

Suggested scenarios:

| Scenario | SIP Result |
|---|---|
| Successful Call | 200 OK |
| User Busy | 486 Busy Here |
| Server Internal Problem | 500 Server Internal Error |
| Service Unavailable | 503 Service Unavailable |
| Request Timeout | 408 Request Timeout |
| User Decline | 603 Decline |

The sample PCAP should contain synthetic or anonymized data only.

---

# 🏗️ Application Architecture

```text
                  PCAP / PCAPNG
                       │
                       ▼
                    Scapy
                       │
                       ▼
                  SIP Parser
                       │
                       ▼
               Call-ID Correlation
                       │
              ┌────────┴────────┐
              │                 │
              ▼                 ▼
        SIP Analysis       RTP Analysis
              │                 │
              └────────┬────────┘
                       ▼
                 Health Engine
                       │
                       ▼
               NOC/L1 Dashboard
                       │
       ┌───────────────┼────────────────┐
       │               │                │
       ▼               ▼                ▼
   Call KPI       SIP Errors       SIP Ladder
       │               │                │
       └───────────────┼────────────────┘
                       ▼
                  L1 Decision
```

---

# 🛠️ Technology Stack

- Python 3.13
- Streamlit
- Scapy
- Pandas
- Plotly

---

# 📁 Project Structure

```text
volte-ims-sip-analyzer/
│
├── app.py
├── README.md
├── LICENSE
├── requirements.txt
│
├── sample/
│   └── volte_ims_noc_test.pcap
│
└── screenshots/
    ├── dashboard.png
    ├── sip-error.png
    └── sip-ladder.png
```

---

# ⚙️ Installation

## 1. Clone Repository

```bash
git clone https://github.com/ramsesdbu/volte-ims-sip-analyzer.git
```

## 2. Enter Project Directory

```bash
cd volte-ims-sip-analyzer
```

## 3. Install Dependencies

```bash
pip install -r requirements.txt
```

## 4. Run Application

```bash
streamlit run app.py
```

The application will open in your web browser.

---

# 🪟 Windows Installation

```powershell
cd "D:\volte-ims-sip-analyzer"
pip install -r requirements.txt
streamlit run app.py
```

---

# 📦 Requirements

Example `requirements.txt`:

```text
streamlit
pandas
scapy
plotly
```

---

# 🔐 Security & Privacy

PCAP files can contain sensitive telecommunications information, including:

- Subscriber identifiers
- Phone numbers
- IMSI
- IP addresses
- Call-ID
- SIP headers
- Network topology
- User-Agent information
- Other operational information

**Do not upload production PCAP files to a public GitHub repository.**

Use synthetic or anonymized PCAP files for public demonstrations.

---

# 🔮 Roadmap

## v0.1

- PCAP upload
- Packet parsing
- SIP analysis
- Call correlation
- NOC dashboard
- SIP error detection
- SIP ladder
- RTP indication

## v0.2

- Advanced SIP error correlation
- Improved Call-ID analysis
- Enhanced SIP ladder
- Better capture completeness detection

## v0.3

- Node-level failure analysis
- SIP error trending
- KPI trending
- Multiple PCAP comparison

## v0.4

- Automated RCA
- NOC alarm correlation
- Historical analysis
- Failure pattern detection

## v1.0

- Production-oriented VoLTE/IMS troubleshooting platform
- Automated RCA
- Historical KPI analysis
- Report generation
- Advanced NOC decision support

---

# 💡 Future Development

Possible future capabilities include:

### Automated RCA

```text
SIP 503
   ↓
Affected Node
   ↓
Repeated Failures
   ↓
Timestamp Correlation
   ↓
Possible Node/Service Issue
```

### Node-Level Health

```text
P-CSCF       🟢
I-CSCF       🟢
S-CSCF       🟠
TAS          🟢
SBC          🔴
MGCF         🟢
```

### Historical KPI

```text
Success Rate
100% ┤
 98% ┤───────╮
 96% ┤       ╰────╮
 94% ┤            ╰──
 92% ┤
     └────────────────
       Time
```

---

# 👨‍💻 Author

**Romulus Ramses**

Telecommunications Engineer

Areas of interest:

- Telecom Core Network
- IMS / VoLTE
- SIP
- Diameter
- SMS over IP / SMPP
- RTP
- Network Performance
- NOC / Service Assurance
- Network Automation
- Python
- Data Analysis

GitHub:

https://github.com/ramsesdbu

---

# ⭐ Project Philosophy

> **A good network analyzer should not only show data.  
> It should help engineers make decisions.**

**From SIP PCAP to NOC Decision.**

---

# 📄 License

This project is distributed under the **Ramses Telecom Software License v1.0**.

The software is **source-available and proprietary**.

The source code may be viewed and used for personal, educational, research, and non-commercial evaluation purposes, subject to the terms in the `LICENSE` file.

Commercial use, redistribution, enterprise deployment, OEM use, sublicensing, or creation of derivative commercial products requires prior written permission from the copyright owner.

See [LICENSE](LICENSE) for the complete terms.
