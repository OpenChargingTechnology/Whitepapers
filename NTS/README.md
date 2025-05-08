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

Precise and secure time synchronization is vital for electric vehicle (EV) charging stations to ensure accurate transaction logging, reliable billing, and adherence
to regulatory mandates, particularly with the rise of time-based and dynamic tariff structures. The Open Charge Point Protocol (OCPP) v1.6 and v2.x facilitate
communication between charging stations and Charging Station Management Systems (CSMS), relying on consistent timekeeping for secure operations, such as validating
TLS certificates and scheduling smart charging profiles. Traditionally, OCPP heartbeats and the Network Time Protocol (NTP) have been employed for time synchronization.
However, OCPP heartbeats lack the precision required for high-latency mobile networks, and NTP’s inherent lack of security exposes it to vulnerabilities like
man-in-the-middle (MITM) attacks. Securing NTP with (D)TLS introduces additional latency and jitter, which can degrade performance in time-sensitive applications.

Network Time Security (NTS), as defined in RFC 8915, addresses these shortcomings by providing authenticated and encrypted time synchronization with minimal delay,
making it an ideal solution for modern EV charging infrastructure. NTS combines NTS Key Establishment (NTS-KE) for secure key exchange with NTS-protected NTP for robust
time queries, ensuring both security and accuracy. This white paper provides a comprehensive guide for configuring OCPP v1.6 and v2.x compliant charging stations to
implement NTS, enabling Charge Point Operators (CPOs) to meet emerging regulatory requirements, such as those for time-based and dynamic tariffs in markets. It details
the setup of NTS-KE and NTS-protected NTP, including support for multiple prioritized servers with parallel querying to optimize performance and reliability.

Additionally, the paper offers an operational guide outlining two implementation strategies tailored to CPO needs. The first strategy involves direct access to legal
NTS servers, such as Germany’s Physikalisch-Technische Bundesanstalt (PTB) servers, requiring specific network, firewall, and Network Address Translation (NAT)
configurations to accommodate private IP networks within the CPO’s backend. The second strategy focuses on integration with a local Smart Meter Gateway (SMGW) using NTS
or NTP-over-TLS, a solution primarily applicable in Germany to comply with the Mess- und Eichrecht (calibration law). The paper concludes with recommended testing
parameters to validate these configurations, ensuring robust and compliant time synchronization. By adopting NTS, CPOs can enhance the security, scalability, and
regulatory compliance of their EV charging networks, paving the way for advanced tariff models and operational efficiency.
