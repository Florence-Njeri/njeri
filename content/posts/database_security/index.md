---
title: "3 Critical Database Security Threats You Need to Know"
date: 2026-02-03T00:00:00Z
tags: ["database", "security", "database security"]
categories: ["security"]
draft: false
---

# 3 Critical Database Command Injection Security Threats

For software engineers, it may be easy to assume that no hacker would target our app since it isn’t big or well known. This attitude can lead to recklessness and lower measures for securing data on an app. However, it’s important to remember that security begins at the design phase. Database security is about protecting the "CIA Triad": Confidentiality, Integrity, and Availability.

In this blog post, you’ll learn about the core database threats that jeopardize the CIA triad principles. By the end of the post, you’ll have learned about the following topics:

- SQL Injection (SQLi)
- Cross-Site Scripting (XSS)
- Cross-Site Request Forgery (CSRF)

## 1. SQL Injection (SQLi)

Happens when the SQL database executes user data as code. This exploit happens when untrusted user input is used in an SQL query without sanitization. This alters database queries, leading to consequences such as data loss and data exfiltration by malicious attackers.

![](sqli.png)

**Types of SQL Injection**

1. **Basic Boolean Logic**: Using conditions that are always true, like `' OR '1'='1`, or commenting parts of the SQL query (like the password check) using comments `--` to bypass authentication.


2. **Union-based**: Combines results from different tables using the `UNION` operator to steal data from another table.


3. **Blind SQL**: Used when the application doesn't return direct error messages; attackers instead rely on server response patterns or timing.

- Boolean attacks which rely on binary answers from the database by observing the response body or headers.
- Time-based attacks that rely on time delays i.e. how long the database took to respond, e.g. if user = "Admin" WAIT 5 seconds. 


4. **Error-based**: Causing the database to produce error messages that reveal the database type or table names.

### Countermeasures

1. Prepared Statements  
The most effective way to prevent SQL injection is the use of prepared statements, also known as parameterized queries.  
**Why it is secure**: The database treats the bind variables strictly as data, not code. Even if an attacker inputs SQL commands like `' OR '1'='1`, the database reads it merely as a literal string searching for a user named `' OR '1'='1`.

2. Input Sanitization  
Validating input ensures the data meets expected formats before it is processed and can be done using:
- Allow listing – only accepting a well-defined set of safe values.
- Block listing – filtering out specific characters known to be dangerous, such as apostrophes `'`, semicolons `;`, or hyphens `--`.

## 2. Cross-Site Scripting (XSS)

XSS targets the user's browser. It happens when an application takes untrusted input and sends it back to the browser without proper encoding, so that the input is treated as HTML/JavaScript and executed in the context of the victim’s session.

**How the compromise happens**

An attacker injects a malicious script (the XSS payload) into a page the victim will load. When the victim’s browser renders that page, the script runs with the victim’s cookies, tokens and permissions.

**XSS Types**

1. **Reflected XSS**: The attacker tricks a user into clicking a malicious link that contains the script payload in a query parameter or form field. The server takes that value and “reflects” it back in the response without sanitizing it, so the script executes as soon as the victim loads the response.

2. **Stored / Persistent XSS**: The malicious script is saved on the server side (for example, as a blog comment, profile field or chat message). Every user who later views that page automatically runs the script in their browser—no special link is required for those subsequent victims.

## 3. Cross-Site Request Forgery (CSRF)

CSRF happens when an attacker forces an authenticated user to send unwanted requests to a web application where they are currently logged in. This is dangerous because browsers automatically attach your cookies and session IDs to every request, so the app thinks the forged request is coming from you.

A CSRF attack happens this way:

- **The Session**: You are logged into a site (like your bank portal) in Tab A. The website has stored a cookie and session ID in your browser so you can perform multiple actions—like checking a balance and then downloading a statement—without re‑authenticating for every click.
- **The Trap**: In Tab B, you visit a malicious site or click a maliciously crafted link. This page contains a hidden request such as a form that submits automatically or a link to `https://bank.com/transfer?amount=10000&to=attacker`.
- **The Hijack**: Because your browser sees a request going to your bank, it automatically sends your valid session cookie. The bank's server sees your valid cookie, assumes the request originated from you, and processes the transfer.

![](csrf.png)

### Countermeasures

Protecting against CSRF requires more than just relying on the browser's default behavior:

- **Anti-CSRF Tokens**: The server generates a unique, unpredictable nonce (a random string) that must be included in every state‑changing request, like a POST request to initiate a transfer of funds. Because of the Same‑Origin Policy (SOP), an attacker on a different website cannot read this token, making it very hard to forge a valid request.

![](sop.png)

- **HTTP Referer / Origin Validation**: The server checks the `Referer` or `Origin` header to ensure the request really started from your app (e.g. `https://bank.com`) and not from a third‑party malicious site.
- **Double Submit Cookies**: The server sends both a session cookie and a separate anti‑CSRF cookie. The client must submit the anti‑CSRF value (e.g. in a hidden form field) along with the request. The server verifies that the submitted value matches the cookie value before processing the action.

### Key Terms (for beginners)

- **CIA Triad** – Security model that focuses on protecting data Confidentiality (no unauthorized reading), Integrity (no unauthorized changes), and Availability (systems stay up and usable).
- **Database** – A structured place where your application stores data (for example, users, orders, or transactions).
- **SQL (Structured Query Language)** – The language used to talk to relational databases (e.g. `SELECT`, `INSERT`, `UPDATE`).
- **Query** – A request you send to the database, such as “give me all users with this email”.
- **SQL Injection** – A vulnerability where untrusted user input is treated as part of the SQL query, letting an attacker change what the query does.
- **Prepared / Parameterized Statement** – A safe way to build SQL queries where placeholders (like `?` or `:id`) are used and user input is bound as data instead of being concatenated into the query string.
- **Input Sanitization / Validation** – Checking and cleaning user input to make sure it matches an expected pattern (for example, an email, an integer, or a limited set of values).
- **Cookie** – A small piece of data stored in the browser and sent automatically with requests to a website, often used to keep you logged in.
- **Session ID** – A unique identifier stored in a cookie that tells the server which logged‑in user you are.
- **XSS (Cross‑Site Scripting)** – A vulnerability where untrusted input is rendered as HTML/JavaScript and executed in the victim’s browser.
- **CSRF (Cross‑Site Request Forgery)** – An attack where a malicious site tricks your browser into sending a request to a site where you are already logged in.
- **Same‑Origin Policy (SOP)** – Browser rule that only allows scripts to read responses from the same origin (same scheme, host, and port). This helps prevent one site from reading another site’s data.
- **Nonce** – A random value that is used once (number‑used‑once) to make requests unique and harder to forge.