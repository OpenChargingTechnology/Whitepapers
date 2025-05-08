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

Accurate and secure time synchronization is essential for electric vehicle (EV) charging stations to ensure reliable transaction logging, trustworthy billing, and
compliance with regulatory standards. Traditionally, Open Charge Point Protocol (OCPP) heartbeats and the Network Time Protocol (NTP) have been used for time
synchronization in the EV charging infrastructure. However, OCPP heartbeats lack precision, particularly over high-latency mobile networks, and NTP is inherently
insecure, leaving it vulnerable to attacks such as man-in-the-middle (MITM). Securing NTP with (D)TLS adds latency and jitter, compromising performance. Network Time
Security (NTS), as defined in RFC 8915, overcomes these limitations by delivering authenticated and encrypted time synchronization with minimal additional delay. This
white paper details the configuration of OCPP v1.6 and v2.x charging stations to implement NTS, including NTS Key Establishment (NTS-KE) and NTS-protected NTP, with
support for multiple prioritized servers and an optional extension for signed NTS responses. It also provides operational guidance for Charge Point Operators (CPOs)
to configure network and firewall settings for accessing legal NTS servers or integrating with a local Smart Meter Gateway (SMGW), alongside recommended testing
procedures for these implementations.
