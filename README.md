# -LDAP-injection
LDAP injection (Lightweight Directory Access Protocol injection) is a security vulnerability that occurs when an application allows untrusted user input to be included in an LDAP query without proper validation or sanitization. This can enable attackers to manipulate or alter the structure of the LDAP query, leading to unauthorized access to or manipulation of the application's directory services.

LDAP is often used for accessing and managing directory information such as user credentials, permissions, and resources. When an application constructs LDAP queries dynamically based on user input, the query can be exploited if the input is not properly handled.

### Example of LDAP Injection

Consider a login form that takes a username and password and constructs an LDAP query to authenticate users:

```plaintext
(&(uid={username})(userPassword={password}))
```

If the application directly includes user input without sanitization, an attacker could inject malicious input like:

* Username: `*)(|(uid=*))`
* Password: `anything`

The resulting query becomes:

```plaintext
(&(uid=*)(|(uid=*))(userPassword=anything))
```

This query effectively bypasses authentication checks, allowing the attacker to log in without valid credentials because it returns all users.

### Potential Risks

* **Unauthorized Access**: Attackers may gain access to sensitive information.
* **Privilege Escalation**: Exploiting injection vulnerabilities might allow attackers to escalate privileges.
* **Data Manipulation**: Attackers could modify directory data, impacting the system's functionality.

### Mitigation Strategies

1. **Input Validation**: Validate and sanitize all user inputs to ensure only expected characters are allowed.
2. **Parameterized Queries**: Use parameterized LDAP queries or prepared statements to prevent direct manipulation of the query structure.
3. **Escape Special Characters**: Properly escape special characters in user input, such as `*`, `(`, `)`, `|`, etc.
4. **Use Least Privilege**: Restrict the privileges of the LDAP account used by the application to limit potential damage.
5. **Testing and Monitoring**: Regularly test applications for injection vulnerabilities and monitor for suspicious activity.

By following these best practices, organizations can significantly reduce the risk of LDAP injection vulnerabilities.
