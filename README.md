# DNS Proxy Server

## Overview
This project implements a DNS Proxy Server in C that supports a blacklist for domain names. The server uses a configuration file for parameters including the upstream DNS server and the blacklist. The proxy listens on the standard DNS port (53), checks incoming DNS queries against the blacklist, and forwards other queries to the upstream server.

## Features

- Blacklist Support: The server blocks domain names listed in a configurable blacklist JSON file.
- Configuration File: All settings including the DNS upstream server address and the blacklist are loaded from a JSON configuration file.
- DNS Query Handling: The server handles DNS queries, blocking or redirecting them based on the blacklist.
- Upstream Query Forwarding: Queries not blocked by the blacklist are forwarded to an upstream DNS server.

## Getting Started

### Prerequisites
To run this DNS Proxy Server, you will need:
- Linux based operating system
- GCC
- sudo rights for binding to port 53
- DaveGamble/cJSON library installed: https://github.com/DaveGamble/cJSON
- Stop default DNS system service before running dns_proxy executable: systemctl stop systemd-resolved

## Installation and usage

1. Clone the repository:
    ``` git clone https://github.com/JustDeny/DNS-proxy.git ```

2. Clone, build and install DaveGamble/cJSON library

3. Build project with Makefile:
    ```
    cd DNS-proxy
    make
    ```
    Executable file ```dns-proxy``` will be in ```build``` directory 

4. Create configuration JSON file with following fields e.g:
    ```
    touch dns_config.json
    ```

    dns_config.json: 
    ```
    {
        "upstream_server": "8.8.8.8",
        "blacklist": ["mail.google.com", "habr.com"],
        "response": "not resolved"
    }
    ```

5. Stop default DNS system service for 53 port to be free for our use (Don't forget to start back this service after termination of dns-proxy):
    ```systemctl stop systemd-resolved```

6. Run dns-proxy:
    ```
    cd build
    sudo ./dns-proxy
    ```