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

Sure! Let's explore **practical examples of LDAP injection** and discuss implementation details with mitigation techniques.

---

### **Practical Example 1: User Authentication**

#### Scenario:

A web application authenticates users using an LDAP server. A query is constructed based on the username and password provided by the user.

**Code Example (Vulnerable):**

```python
import ldap

def authenticate(username, password):
    ldap_server = "ldap://localhost:389"
    conn = ldap.initialize(ldap_server)
    
    # Constructing LDAP query dynamically (VULNERABLE!)
    search_filter = f"(&(uid={username})(userPassword={password}))"
    try:
        conn.simple_bind_s()  # Anonymous bind
        results = conn.search_s("ou=users,dc=example,dc=com", ldap.SCOPE_SUBTREE, search_filter)
        if results:
            print("Authentication successful!")
        else:
            print("Invalid credentials.")
    except Exception as e:
        print(f"Error: {e}")
```

---

#### Attack:

If an attacker provides:

* `username = *)(uid=*))(|(uid=*`
* `password = irrelevant`

The resulting query becomes:

```plaintext
(&(uid=*)(uid=*))(|(uid=*))(userPassword=irrelevant)
```

This query returns **all users** because of the `(|(uid=*))` part, bypassing authentication.

---

#### Mitigation:

1. Use **parameterized queries** or libraries that escape special characters.
2. Validate inputs strictly to prevent injection.

**Fixed Code Example:**

```python
import ldap
from ldap.filter import escape_filter_chars  # Escapes input safely

def authenticate(username, password):
    ldap_server = "ldap://localhost:389"
    conn = ldap.initialize(ldap_server)
    
    # Escape special characters in user input
    username = escape_filter_chars(username)
    password = escape_filter_chars(password)
    
    # Safely construct the LDAP query
    search_filter = f"(&(uid={username})(userPassword={password}))"
    try:
        conn.simple_bind_s()
        results = conn.search_s("ou=users,dc=example,dc=com", ldap.SCOPE_SUBTREE, search_filter)
        if results:
            print("Authentication successful!")
        else:
            print("Invalid credentials.")
    except Exception as e:
        print(f"Error: {e}")
```

---

### **Practical Example 2: Directory Search**

#### Scenario:

A web application has a search feature to look up user profiles. The user provides a search term, and the application queries the LDAP server.

**Code Example (Vulnerable):**

```python
def search_users(search_term):
    ldap_server = "ldap://localhost:389"
    conn = ldap.initialize(ldap_server)
    
    # Dynamic search query (VULNERABLE!)
    search_filter = f"(cn=*{search_term}*)"
    try:
        conn.simple_bind_s()
        results = conn.search_s("ou=users,dc=example,dc=com", ldap.SCOPE_SUBTREE, search_filter)
        for dn, entry in results:
            print(f"Found: {dn}")
    except Exception as e:
        print(f"Error: {e}")
```

---

#### Attack:

If an attacker provides:

* `search_term = *)(objectClass=*))(|(cn=*`

The query becomes:

```plaintext
(cn=*)(objectClass=*))(|(cn=*)
```

This matches every user or directory object, leaking sensitive data.

---

#### Mitigation:

1. Escape all user inputs.
2. Implement input validation (e.g., allow only alphanumeric characters).

**Fixed Code Example:**

```python
from ldap.filter import escape_filter_chars

def search_users(search_term):
    ldap_server = "ldap://localhost:389"
    conn = ldap.initialize(ldap_server)
    
    # Escape special characters
    search_term = escape_filter_chars(search_term)
    
    # Safely construct the query
    search_filter = f"(cn=*{search_term}*)"
    try:
        conn.simple_bind_s()
        results = conn.search_s("ou=users,dc=example,dc=com", ldap.SCOPE_SUBTREE, search_filter)
        for dn, entry in results:
            print(f"Found: {dn}")
    except Exception as e:
        print(f"Error: {e}")
```

---

### **Mitigation Checklist**

1. **Input Validation**: Reject any unexpected or suspicious inputs.

   * Example: Use regex to allow only alphanumeric characters.

     ```python
     import re
     def validate_input(input_value):
         if not re.match(r'^[a-zA-Z0-9]*$', input_value):
             raise ValueError("Invalid input")
         return input_value
     ```

2. **Escape Special Characters**: Use libraries or built-in functions to escape LDAP special characters, such as `*`, `(`, `)`, `|`, `&`, `=`, `!`, etc.

3. **Parameterized Queries**: If your LDAP library supports parameterized queries, use them to avoid dynamically constructing query strings.

4. **Minimize Privileges**: The LDAP account used by the application should have the least privileges necessary for its operations. This limits the impact of an injection attack.

5. **Monitor and Log**: Track abnormal activity in logs for early detection of attacks.

---

### **Tools for Testing LDAP Injection**

1. **OWASP ZAP** and **Burp Suite**: Tools for finding vulnerabilities, including LDAP injection.
2. **Custom Scripts**: Write scripts to simulate injection payloads for testing purposes.

---

### Example Injection Payloads:

Here are some common LDAP injection payloads for testing:

1. `*)(|(uid=*))` - Exploits wildcards to bypass authentication.
2. `admin*)(objectClass=*))(|(uid=*` - Bypasses authentication by manipulating filters.
3. `*` - Attempts to match all records.

By implementing the above mitigation strategies, you can safeguard your applications against LDAP injection attacks.

