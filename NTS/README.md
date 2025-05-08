White Paper

# Network Time Security (NTS) for OCPP


## Abstract
This white paper provides a detailed guide for configuring Open Charge Point Protocol (OCPP) v1.6 and v2.x compliant electric vehicle (EV) charging stations to
implement Network Time Security (NTS), ensuring secure and precise time synchronization critical for compliance with emerging time-based and dynamic tariff regulations.
It outlines the setup of NTS Key Establishment (NTS-KE) and NTS-protected Network Time Protocol (NTS), supporting multiple prioritized servers with parallel querying
for optimal performance and reliability. The operational guide presents two implementation strategies: direct access to legal NTS servers (e.g., Germany’s PTB servers)
including network, firewall, and Network Address Translation (NAT) configurations for private IP networks within the Charge Point Operator’s backend, and integration
with a local Smart Meter Gateway (SMGW) using NTP-over-TLS, a solution primarily relevant in Germany. The paper concludes with recommended testing parameters to
validate configurations.


## Introduction

Accurate and secure time synchronization is critical for EV charging stations to ensure reliable transaction logging, billing accuracy, and compliance with regulatory
requirements. Both OCPP heartbeats and the Network Time Protocol (NTP) have traditionally been used for time synchronization, but both lack either accurancy especially
over high latency mobile networks or inherent security, making NTP vulnerable to attacks such as man-in-the-middle (MITM). Securing NTP via (D)TLS introduces additional
delay and jitter. Network Time Security (NTS), as defined in RFC 8915, addresses these drawbacks and vulnerabilities by providing authenticated and encrypted time
synchronization while introducing low additional delays. This white paper outlines how to configure OCPP v1.6 and v2.x charging stations to leverage NTS, including NTS
Key Establishment (NTS-KE) and NTS-protected NTP, with support for multiple servers and prioritized selection. It also provides operational guidance for Charge Point
Operators (CPOs) to configure network and firewall settings for accessing legal NTS servers or integrating with a local SMGW and how to test those use cases.
