# Open Source Strategy

QWED operates on an "Open Core" philosophy, similar to Android or Linux.

## The Split

| Component | Visibility | Description |
|-----------|------------|-------------|
| **QWED Kernel** | **Private** | The proprietary 8-engine consensus logic. This is our IP. |
| **Client SDKs** | **Public** | Python and JS libraries to access the kernel. |
| **Benchmarks** | **Public** | Tools to verify our accuracy claims. |
| **Protocol** | **Public** | The API specification for verification. |

## Why Open Source the SDKs?
1.  **Adoption**: Developers need easy tools. `pip install qwed` reduces friction.
2.  **Trust**: By open-sourcing the benchmarks, we allow anyone to audit us.
3.  **Ecosystem**: We want others to build apps (browser extensions, slack bots) on top of QWED.

## Repository Structure
-   `qwed-open`: The public GitHub repo containing SDKs and Benchmarks.
-   `qwed-core`: The internal repo containing the Engines and API.
