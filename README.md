# Stored Cross-Site Scripting (XSS) in MyBeeHome

## Summary
A stored cross-site scripting (XSS) vulnerability was identified in the MyBeeHome
web application, a corporate social networking platform similar to Workplace.
Authenticated attackers could inject malicious JavaScript code through multiple
user-controlled input vectors. The injected payloads were persistently stored by
the application and automatically executed in the browsers of other authenticated
users.

## Affected Product
- Product: MyBeeHome Web Application
- Domain: mybeehome.com
- Environment: Cloud / SaaS
- Affected versions: All versions prior to the security fix deployed in 2025

## Vulnerability Type
Stored Cross-Site Scripting (XSS)  
CWE-79

## Attack Vectors
The vulnerability could be exploited through multiple authenticated input vectors
due to insufficient input sanitization and output encoding of user-supplied data.

### 1. User Profile Fields
Users are allowed to update several profile information fields. It was possible to
inject malicious JavaScript code into the **"Certifications"** field. After saving
the profile, the payload was persistently stored and executed whenever the affected
profile was rendered by other users.

In addition, the **"Social Name"** field available in the profile editing page
(`/directory/editProfile`) was also vulnerable, allowing stored XSS execution in
the context of other authenticated users.

### 2. Chat Messaging Feature
The stored XSS vulnerability was also present in the user chat functionality.
An attacker could send a malicious JavaScript payload via chat message to another
user. When a new message was received, the application automatically opened the
chat window, causing the injected code to be executed without any user interaction
from the victim.

## Impact
An authenticated attacker could execute arbitrary JavaScript code in the browsers
of other authenticated users. This could lead to session hijacking, account
takeover, unauthorized actions performed on behalf of the victim, or exposure of
sensitive user information.

## Authentication
Authentication is required to exploit this vulnerability. However, once the
malicious payload is stored, no additional user interaction is required for
execution, particularly in the chat messaging attack vector.

## Resolution
The vulnerability was fixed by the MyBeeHome security team through proper input
validation and output encoding across the affected components.

## Timeline
- Discovery: 2025-02-14
- Reported to vendor: 2025-04-11
- Fixed: 2025-11-01
- Public disclosure: 2025-12-26

## References
- Additional technical details and screenshots are available in the `details/`
  or `images/` directory of this repository.

## Credits
Discovered by: Jhonnyffer Hannyel Ferro da Silva

> CVE ID: TBD
