# Introduction to Reverse Engineering

Can you take apart the systems in your home and reverse engineer the inner workings e.g intercom at appartments

Devices:
https://www.saleae.com/
Measure the signal
CAPs






# MCP and Control Planes

Streamable HTTP - leads to confused deputy attacks. Has access to token, filesys, tool schedule / perform automated tasks.(legacy but still in use)

MCP Server auth is optional
Often bound to 0.0.0.0 by default making them accessible to the public - (21k servers end of April)
OWASP MCP top 10
Shadow MCP servers


ISSUES
1. 0.0.0.0 binding and DNS rebinding
2. Fail-open auth defaults
3. SSRF
4. Path traversal - file tools
5. Command Injection
6. Over-broad Access control
7. 
8. 

https://nvd.nist.gov/vuln/detail/CVE-2025-49596

https://nvd.nist.gov/vuln/detail/CVE-2025-6514

**Other vulns/attacks**
Tool poisoning / prompt injection - tricking models
Line jumping
Github MCP description

https://www.bleepingcomputer.com/news/security/asana-warns-mcp-ai-feature-exposed-customer-data-to-other-orgs/

Classic bug - agent automation - careless deployment could lead to infra compromise


CVE-2026-27826: MCP Atlassian SSRF Vulnerability: https://www.sentinelone.com/vulnerability-database/cve-2026-27826/
1. Exfiltration
multi tenancy , control plane 

how is the http header attacker controlled? - attcker can change the header to whaever host

Server becomes the SSRF proxy using the token of the victim to access internal files and services. **confluence_upload_attachment()** for exfil for e.g

2. Arbitarary file write

os.path.abspath() to .bashrc for example so everytime shell is opened it could run as root for e.g


**header injection -> ssrf -> exfil -> file injection -> RCE**

CVE-2026-33032: Nginx UI Missing MCP Authentication: https://www.rapid7.com/blog/post/etr-cve-2026-33032-nginx-ui-missing-mcp-authentication/

**AGENT THREAT ZONES** - *where in your system to check* for the **OWASP top 10** (*what could go wrong when deploying agents*)
1. **Input surface** - user prompts, RAG metadata and resources, API calls (modift model goal) Trust = none
2. **Planning and reasining** - gaol intepretation, task decomposition, tool selection (select tools)
Trust 
3. **Tool execution** 
Trust = scoped to task and user perms
4. **Memory state**
Trust = iuncertain of what gets persistent in memory
Poison future sessions and users
5. **Interagent communication**
Trust = cascades inherists trust of the weakest model 


***SCENARIO 1: RAG pipeline poisoning***

Agent with select access to vector db

Poisoned response reaches the user

How? the attack tree

- Zone 1:  Plant poison in data being ingested by the RAG e.g internal docs compromised or www docs **ASI06**
- Zone 2: Retriver ranks the poisoned chunk in top k (what is semantic mimicry?) **ASI06**
- Zone 3: LLM treats the retrived poisoned chunk as intrsucts **ASI01**
- Zone 4:Poison persists via embedding cache or conversation memory **ASI09**
- Zone 5:Poisoned response reaches the user **ASI06**

**Multi Agent **

E.g instagram agent asked to change emails a few weeks leading to account modif

Scenario 3 - 
MCP toopl descvription is treated as input to the model

So input is user input + MCP tool description
Agent select tools
Multiple MCP servers 


*Rug pull variant attacks therefore need to pin descriptions*

CAn happen if a dev installs a maliciopus MCP server thru e.g typosquatted mcps (supply chain vuln)

What is attacker .tld file?


Goal lock giuardrails, input classifier filters

## Amazon Bedrock Attacks

- Agent *action groups* (what are they?)
- Guardrails attached to model invocations or model call ops (iunput / response)
- 

1. Insecure guardrail policies
 

 ## SECURING GITHUB ACTIONS PIPELINE

 Software supply chain security using [SLSA](https://slsa.dev/)
Artifacts pushed to npm/pypi

Pwn request - using tools but configuring the config to allow them to have RCE
Template injection - interpolate cmds in templates (comand injection)
Bot mediated confused deputy
Self hosted runners that are not ephemeral

## Threat Model

**Smoked meat** - like metasploit for CI/CD

How is the exploitation payload generated?

Commands cheatsheet?
Custom behaviour? E.g some bu
