---
title: "SSRF via Unrestricted Internal URL Fetching"
date: 2026-07-06T00:00:00Z
tags: ["SSRF","LLM", "agent", "CTF"]
categories: ["security", "AI"]
draft: false
---

## Level 6: Server-Side Request Forgery (SSRF)

Server side request forgery is a type of attack that leads the server to make connections to internal facing services and applications and in other cases connect to arbitrary attcker controlled sites with the aim of leaking sensitive data.
In an SSRF attack against the server, the attacker causes the application to make an HTTP request back to the server that is hosting the application, via its loopback network interface. This typically involves supplying a URL with a hostname like `127.0.0.1` or `localhost` which is what we will exploit via the model.

### The exploit and Result : SSRF via Unrestricted URL Fetching

**Step 1: Reconnaisance**

On level 6, I started by probing the model to discover what tools were exposed and how they handle URL destinations. The model confirmed this level had `fetch_url` and `multi_tool_use.parallel` tools as shown in the following screenshot.

![Tool explanation](explain_tools.png)

A key clue from the tool explanation was that local resources might be accessible from the model, which strongly suggested that an **SSRF attack** was possible.

I first tested localhost with port 8080 and got the following error:

![Localhost port error](fetch_localhost_port_error.png)

I then tried `fetch_url localhost`  with no port and I got the response: **WELCOME TO THE INTERNAL WEBSITE**:

![Localhost fetch](call_localhost.png)

The response above confirmed an **SSRF attack** was possible using this model because the agent could fetch internal facing content from localhost (an internal URL), despite the tool description mentioning that it only fetches data from external URLs.

From there, I requested the likely internal flag path using `fetch_url localhost/flag.txt` and recovered the flag `flag-9a14c2` as shown below:

![Level 7 flag](flag_7.png)


### Root Cause of the Vulnerability

The `fetch_url` tool did not enforce destination restrictions for loopback or internal addresses. This turned the agent into a server-side proxy that could be abused by attackers to to access internal services.

### Impact and Severity

1. **Internal service exposure** since localhost-only resources become accessible through the agent.
2. **Sensitive data risk** because metadata services, admin endpoints, or internal APIs may be reachable via the model.
3. **Lateral reconnaissance** where attackers can map internal network behavior through SSRF probes like we did with the `http_get localhost` request.

### Prevention:

- Strictly validate and normalize all URL inputs before request execution.
- Enforce allowlists for domains, schemes, and destination ports.
- Block loopback, link-local, metadata, and private address ranges.
- Route outbound requests through an egress-controlled proxy and firewall policy.
- Monitor URL-fetch tool usage for internal target and SSRF-like patterns.

### Standard LLM OWASP Top 10 Mapping

**Sensitive Information Disclosure (LLM02):**
Internal-only resources became accessible through a model-facing fetch pathway, exposing data outside the intended trust boundaries.

**Excessive Agency (LLM06):**
The agent had unrestricted outbound retrieval capability, including internal targets it should never be able to reach.

**Tool Misuse & Exploitation (ASI02):**
A normal content retrieval tool was repurposed into an internal network exploitation primitive.
