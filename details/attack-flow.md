# Technical Details – Stored XSS in MyBeeHome

This document provides a detailed technical explanation of the stored cross-site
scripting (XSS) vulnerability identified in the MyBeeHome web application. The issue
affects multiple authenticated input vectors and results in automatic execution of
malicious JavaScript code in the context of other authenticated users.

---

## Vulnerability Overview
- Vulnerability Type: Stored Cross-Site Scripting (XSS)
- CWE: CWE-79
- Authentication Required: Yes
- User Interaction Required: No (after payload storage)
- Application Type: Cloud / SaaS (Web Application)

---

## Attack Vector 1 – User Profile Fields

### Description
The MyBeeHome application allows authenticated users to update profile information
such as professional certifications. During testing, it was identified that the
**"Certifications"** field does not properly sanitize or encode user-supplied input.

As a result, an attacker can inject a malicious JavaScript payload into this field.
Once the profile is saved, the payload is persistently stored by the application and
executed whenever the affected profile is viewed by another authenticated user.

The same behavior was observed in the **"Social Name"** field available on the
profile editing page (`/directory/editProfile`), which also allows stored JavaScript
execution.

### Proof of Concept (High-Level)
1. Authenticate to the MyBeeHome platform.
2. Navigate to the profile editing page.
3. Insert a JavaScript payload into the **"Certifications"** or **"Social Name"** field.
4. Save the profile.
5. When another authenticated user views the profile, the injected code is executed.

> The exact payload is intentionally omitted to prevent misuse.

### Evidence
- Profile field injection: `images/profile-certifications-xss.png`
- Payload execution: `images/profile-certifications-xss-execution.png`
- Social name field injection: `images/profile-socialname-xss.png`

---

## Attack Vector 2 – Chat Messaging Feature

### Description
The stored XSS vulnerability is also present in the MyBeeHome chat functionality.
Authenticated users can send messages to other users without proper sanitization of
message content.

An attacker can send a malicious JavaScript payload via chat message. When the
message is received, the application automatically opens the chat window to display
the new message. This behavior causes the injected JavaScript code to be executed
immediately, without any interaction from the recipient.

### Proof of Concept (High-Level)
1. Authenticate to the MyBeeHome platform.
2. Open a chat conversation with another user.
3. Send a message containing a JavaScript payload.
4. When the recipient receives the message, the chat window opens automatically.
5. The injected JavaScript code is executed in the victim's browser context.

> No user interaction is required for payload execution once the message is received.

### Evidence
- Chat payload injection: `images/chat-xss-injection.png`
- Automatic execution upon message reception: `images/chat-xss-execution.png`

---

## Security Impact
The identified vulnerabilities allow authenticated attackers to execute arbitrary
JavaScript code in the browsers of other authenticated users. This could enable
attacks such as:
- Session hijacking
- Account takeover
- Unauthorized actions on behalf of victims
- Exposure of sensitive user data

---

## Root Cause Analysis
The root cause of the vulnerability is the lack of proper input validation and output
encoding of user-controlled data across multiple application components, including
profile fields and chat messages.

---

## Mitigation and Fix
The issue was resolved by implementing proper server-side input validation and
context-aware output encoding for all user-supplied data rendered in HTML contexts.

---

## Disclosure Notes
This vulnerability was reported responsibly to the MyBeeHome security team. Public
disclosure was performed only after confirmation that the issue had been fixed.

---

## Credits
Discovered by: Jhonnyffer Hannyel Ferro da Silva
