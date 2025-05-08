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

