---
title: "Abusing eval() in Agent Calculators"
date: 2026-07-06T00:00:00Z
tags: ["LLM", "agent", "CTF", "command injection"]
categories: ["security", "AI"]
draft: false
---

## Level 5:  Bad Robot  

### The exploit and Result : Command Injection via eval()

**Step 1: Reconnaisance**

On level 5, I knew from the description that the application featured a calculator functionality. I started by probing the system to see if I could force it to leak its system prompt. This attempt was unsuccessful, as the application simply echoed my input back to the output.

Next, I wanted to see what acceptable values the system could process and determine how it handled mathematical evaluations. I tried inputs like **4 * 4** and **4 / 0** to see if it would return results. It did, which indicates that the application passes my input directly unsanitized to the underlying calculation function.

Furthermore, when I tested 4 / 0, the system returned an error message stating, `The expression could not be evaluated.` This specific error message strongly suggests that the application is built using Python, as the error message closely mirrors Python's native language errors when processing invalid mathematical expressions.

![Python evaluator rejecting the invalid expression](invalid_expr.png)

Next, I then tried *a direct file read* instead of math to confirm if my suspicion of the function executing unsanitized user input might be right using the prompt below `open ('/etc/passwd).read()`:

![Attempt to read /etc/passwd through the calculator tool](open_read_file.png)

The error message `Output format not supported` led me to believe that the expression was executed successfully, but the result (a long string) couldn't be displayed possibly because of the tool's output formatter that only expects numeric results. This confirms we have a command injection vulnerability. 

The next challenge was to try and bypass the output obstacle by getting the flag output in a format the tool allowed.

From the expected format of the flag stated on the flag window, I know that the flag is 11 characters long. So I probed a few common `.env` locations (`.env`, `/.env`, `./.env`, `/app/.env`) to try and locate the correct location of the flag file. But they mostly returned `FileNotFoundError` messages, confirming the file simply wasn't located in either of these locations.

I swapped tactics by checking the length of the files e.g `ord(open('/etc/passwd).read())` and based of the output, I knew this was not the flag's location:

![Length probe used to test whether a system file could be read](read_env_vars.png)

I confirmed the extraction technique worked by getting the length of the `/etc/passwd` file using `ord()` and `len()` python functions:

![First character code extracted from /etc/passwd](read_etc_file_char.png)


![File length check confirming the file is readable](length_file.png)

Next, I checked if there exists a file named **flag.txt** in the curent dir using the file length check again `len(open('flag.txt').read())`:

![Length check confirming flag.txt exists in the working directory](confirm_flag_txt.png)

The length of the file showed that it contained 11 characters matching the expected string value length of our flag. so I extracted it one character at a time via the same `ord()` **side-channel technique** as shown below:

```yml
> ord(open('flag.txt').read()[0])
 
Result: 102
 
> ord(open('flag.txt').read()[1])
Result: 108
 
> ord(open('flag.txt').read()[2])
Result: 97
 
> ord(open('flag.txt').read()[3])
Result: 103
 
> ord(open('flag.txt').read()[4])
Result: 45
 
> ord(open('flag.txt').read()[5]) 
Result: 101
 
> ord(open('flag.txt').read()[6])
Result: 98
 
> ord(open('flag.txt').read()[7])
Result: 50
 
> ord(open('flag.txt').read()[8])
Result: 99
 
> ord(open('flag.txt').read()[9])
Result: 97
 
> ord(open('flag.txt').read()[10])
Result: 51
```

After this I reconstructed the characters extracted to flag using Cyberchef:

![Recovered Level 5 flag reconstructed from character codes](flag_5.png)

### Root Cause of the Vulnerability

The calculator tool used Python's `eval()` to execute user input as Python code, allowing arbitrary code execution including file system access. `Eval()` is vulnerable by design and allowed me to do reconnaisance on files available in the system, check if they contained any information in them using length check and finally I was able to extract data from internal system files that the model has access to.

### Impact and Severity

1. **Data Breach** where sensitive company data can get exfiltrated by attackers leading to compliance lawsuits like GDPR penalty of 20 million in Europe.
2. **Remote Code Execution** - since attackers can run their code on your your internal system by passing some malicious piece of code as input to teh model, this can lead to implanted backdoors and even persistent acess in the companies internal networks indefinitely.
3. **Loss of integrity** since the clients will no longer trust you with their data whjich will eventually result in losses

### Prevention:

- Never use `eval()`, `exec()`, or similar vulnerable functions that execute unsanitized user input
- Use safe expression evaluators or mathematical parsers instead
- Validate and sanitize all inputs according to strict schemas
- Run code in sandboxed environments with restricted permissions
- Use allowlists of permitted operations rather than trying to block dangerous ones

### Standard LLM OWASP Top 10 Mapping

**Sensitive Information Disclosure (LLM02):**
The calculator's `eval()` function processes unsanitized user input and can execute arbitrary Python code, allowing attackers to gain knowledge about the existence and contents of sensitive system files such as `/etc/passwd`, `.env` and `flag files`, application configs. The vulnerability would exposes confidential data that should never be accessible through a mathematical expression interface.

**Improper Output Handling (LLM05):**
The calculator tool passes unsanitized user input straight into `eval()` and executes it as code which could result in remote code execution.

**Excessive Agency (LLM06):**
The calculator tool is capable of executing arbitrary Python code with full root access since it can read the contents of `/etc/passwd`. This excessive permission set enables attackers to break containment and access privileged operations.


