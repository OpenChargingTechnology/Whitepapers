# Safe & Secure OCPP v2.x Device Model Updates

...

### SetVariables *(extended)*

This request extends the existing *SetVariables* request functionality by adding support for structured, **recursive transactions**. It allows multiple individual SetVariable operations to be grouped into a single atomic unit, with clearly defined semantics for **concurrent execution**, **dependency ordering**, and **error handling**.

In addition, the extension addresses a critical limitation of the current SetVariable operation: In standard OCPP, **variables are unconditionally overwritten**, regardless of their previous state. While this is acceptable in centralized or single-writer environments, it poses risks in modern distributed or concurrent control architectures, where multiple systems (e.g., CSMS, local controllers, or operator tools) may attempt to update the same variable concurrently.

To improve safety in such contexts, this extension introduces **conditional update semantics**. A SetVariable entry may optionally specify the expected current value, and the update is only applied if the value on the target system matches this expectation at the time of execution. This mechanism is conceptually equivalent to *HTTP constraint-based updates* using *If-Match* headers or *Compare-and-Swap (CAS)* operations in distributed systems.

Such conditional updates reduce the risk of unintended overwrites, support optimistic concurrency control, and enable reliable configuration workflows in asynchronous and multi-actor environments.

