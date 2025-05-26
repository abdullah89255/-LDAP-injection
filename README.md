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

Here are **more LDAP injection examples** that demonstrate various scenarios of exploitation, including different query manipulations and payload types. These examples will help you understand the depth of the vulnerability and how it can be exploited.

---

### **Example 3: Privilege Escalation**

#### Scenario:

An application uses an LDAP query to determine if a user belongs to the "Admin" group by checking their membership in the directory.

**Vulnerable Code:**

```python
def is_admin(username):
    ldap_server = "ldap://localhost:389"
    conn = ldap.initialize(ldap_server)
    
    # Vulnerable search filter
    search_filter = f"(&(uid={username})(memberOf=cn=Admin,ou=groups,dc=example,dc=com))"
    try:
        conn.simple_bind_s()
        results = conn.search_s("ou=users,dc=example,dc=com", ldap.SCOPE_SUBTREE, search_filter)
        return bool(results)
    except Exception as e:
        print(f"Error: {e}")
        return False
```

#### Attack:

An attacker could manipulate the username input as:

* `username = `*)(memberOf=cn=Admin,ou=groups,dc=example,dc=com))(|(uid=*\`

This results in the query:

```plaintext
(&(uid=*)(memberOf=cn=Admin,ou=groups,dc=example,dc=com))(|(uid=*))
```

This query evaluates to true, effectively making the attacker appear as an admin.

---

#### Mitigation:

Escape user input or implement strict validation rules to ensure the `username` field only contains valid values.

---

### **Example 4: Searching with Injection**

#### Scenario:

An application allows users to search for employees based on their department.

**Vulnerable Code:**

```python
def search_by_department(department):
    ldap_server = "ldap://localhost:389"
    conn = ldap.initialize(ldap_server)
    
    # Vulnerable query
    search_filter = f"(department={department})"
    try:
        conn.simple_bind_s()
        results = conn.search_s("ou=employees,dc=example,dc=com", ldap.SCOPE_SUBTREE, search_filter)
        for dn, entry in results:
            print(f"Employee: {dn}")
    except Exception as e:
        print(f"Error: {e}")
```

#### Attack:

The attacker provides:

* `department = `*)(|(department=*))\`

Resulting query:

```plaintext
(department=*)(|(department=*))
```

This matches all departments, leaking information about all employees.

---

#### Mitigation:

Use libraries like `ldap.filter.escape_filter_chars` to sanitize input or enforce a strict whitelist of acceptable department names.

---

### **Example 5: Injecting Logical Operators**

#### Scenario:

An application retrieves user profiles by a combination of fields like `uid` and `email`.

**Vulnerable Code:**

```python
def get_user_profile(uid, email):
    ldap_server = "ldap://localhost:389"
    conn = ldap.initialize(ldap_server)
    
    # Vulnerable filter
    search_filter = f"(&(uid={uid})(email={email}))"
    try:
        conn.simple_bind_s()
        results = conn.search_s("ou=users,dc=example,dc=com", ldap.SCOPE_SUBTREE, search_filter)
        return results
    except Exception as e:
        print(f"Error: {e}")
```

#### Attack:

The attacker provides:

* `uid = `*)(|(uid=*\`
* `email = `*)(|(email=*\`

Resulting query:

```plaintext
(&(uid=*)(|(uid=*))(email=*)(|(email=*)))
```

This query leaks all user profiles by combining injected logical operators.

---

#### Mitigation:

* Escape special characters.
* Validate inputs using regex.
* Avoid concatenating user inputs into query strings.

---

### **Example 6: Exploiting Special Characters**

#### Scenario:

The application checks if an account is locked using an LDAP query.

**Vulnerable Code:**

```python
def is_account_locked(username):
    ldap_server = "ldap://localhost:389"
    conn = ldap.initialize(ldap_server)
    
    # Vulnerable filter
    search_filter = f"(&(uid={username})(accountStatus=locked))"
    try:
        conn.simple_bind_s()
        results = conn.search_s("ou=users,dc=example,dc=com", ldap.SCOPE_SUBTREE, search_filter)
        return bool(results)
    except Exception as e:
        print(f"Error: {e}")
        return False
```

#### Attack:

An attacker provides:

* `username = `*)(accountStatus=locked))(|(uid=*\`

Resulting query:

```plaintext
(&(uid=*)(accountStatus=locked))(|(uid=*))
```

This query falsely reports that every account is locked.

---

#### Mitigation:

Escape special characters in `username` to prevent this attack.

---

### **Example 7: Advanced LDAP Injection Payloads**

Here are some advanced payloads attackers might use:

1. **Returning All Users**:

   * Input: `*)(|(uid=*))`
   * Query: `(&(uid=*)(|(uid=*)))`

2. **Injecting OR Conditions**:

   * Input: `*)(|(objectClass=person))`
   * Query: `(&(uid=*)(|(objectClass=person)))`

3. **Bypassing Filters**:

   * Input: `*)(!(uid=*))`
   * Query: `(&(uid=*)(!(uid=*)))`

4. **Matching Specific Attributes**:

   * Input: `*)(uid=admin)`
   * Query: `(&(uid=*)(uid=admin))`

---

### **Testing for LDAP Injection**

You can test LDAP injection using these tools and methods:

1. **Payload Testing**: Use the above payloads on input fields.
2. **Penetration Testing Tools**:

   * **OWASP ZAP**
   * **Burp Suite**
3. **Custom Python Scripts**:
   Use Python to simulate different inputs and analyze server responses.

---

### **Summary of Mitigations**

To protect against LDAP injection:

1. Use parameterized queries or escape user inputs using libraries like `ldap.filter.escape_filter_chars`.
2. Validate inputs rigorously with regex or predefined whitelists.
3. Implement least privilege principles for LDAP accounts.
4. Monitor logs for unusual LDAP activity.
5. Regularly test for LDAP injection using automated tools or manual penetration testing.

Here are **additional LDAP injection examples** to explore even deeper nuances and attack scenarios, including more sophisticated manipulations of LDAP queries:

---

### **Example 8: Exploiting Wildcard Characters**

#### Scenario:

A web application allows users to search for contacts by their first or last names.

**Vulnerable Code:**

```python
def search_contacts(name):
    ldap_server = "ldap://localhost:389"
    conn = ldap.initialize(ldap_server)
    
    # Vulnerable query
    search_filter = f"(cn=*{name}*)"
    try:
        conn.simple_bind_s()
        results = conn.search_s("ou=contacts,dc=example,dc=com", ldap.SCOPE_SUBTREE, search_filter)
        for dn, entry in results:
            print(f"Contact: {dn}")
    except Exception as e:
        print(f"Error: {e}")
```

#### Attack:

An attacker provides:

* `name = `*)(cn=*))(|(cn=\*\`

Resulting query:

```plaintext
(cn=*)(cn=*))(|(cn=*))
```

This query matches **every contact entry**, leaking sensitive data.

---

#### Mitigation:

Escape user input using a library like `ldap.filter.escape_filter_chars` or enforce strict validation rules (e.g., no special characters).

---

### **Example 9: Injecting Negation Logic**

#### Scenario:

An application uses LDAP to verify that a user's account is not deactivated.

**Vulnerable Code:**

```python
def is_active_user(username):
    ldap_server = "ldap://localhost:389"
    conn = ldap.initialize(ldap_server)
    
    # Vulnerable query
    search_filter = f"(&(uid={username})(!(accountStatus=deactivated)))"
    try:
        conn.simple_bind_s()
        results = conn.search_s("ou=users,dc=example,dc=com", ldap.SCOPE_SUBTREE, search_filter)
        return bool(results)
    except Exception as e:
        print(f"Error: {e}")
        return False
```

#### Attack:

The attacker inputs:

* `username = `*)(accountStatus=deactivated))(|(uid=*\`

Resulting query:

```plaintext
(&(uid=*)(accountStatus=deactivated))(|(uid=*))
```

This query bypasses the negation and matches all users.

---

#### Mitigation:

Always sanitize user inputs and escape special characters like `!` and `)`.

---

### **Example 10: Injecting Arbitrary Filters**

#### Scenario:

An application uses LDAP to retrieve information about a user’s group memberships.

**Vulnerable Code:**

```python
def get_user_groups(username):
    ldap_server = "ldap://localhost:389"
    conn = ldap.initialize(ldap_server)
    
    # Vulnerable query
    search_filter = f"(&(uid={username})(objectClass=group))"
    try:
        conn.simple_bind_s()
        results = conn.search_s("ou=groups,dc=example,dc=com", ldap.SCOPE_SUBTREE, search_filter)
        return results
    except Exception as e:
        print(f"Error: {e}")
```

#### Attack:

An attacker provides:

* `username = `*)(|(objectClass=*))\`

Resulting query:

```plaintext
(&(uid=*)(|(objectClass=*)))
```

This matches **all objects** in the directory.

---

#### Mitigation:

Escape user inputs and ensure that only valid usernames can be passed into the query.

---

### **Example 11: Extracting Attributes**

#### Scenario:

An application fetches detailed attributes of a user profile using LDAP.

**Vulnerable Code:**

```python
def fetch_user_attributes(username):
    ldap_server = "ldap://localhost:389"
    conn = ldap.initialize(ldap_server)
    
    # Vulnerable query
    search_filter = f"(uid={username})"
    try:
        conn.simple_bind_s()
        results = conn.search_s("ou=users,dc=example,dc=com", ldap.SCOPE_SUBTREE, search_filter)
        return results
    except Exception as e:
        print(f"Error: {e}")
```

#### Attack:

The attacker provides:

* `username = `*)(|(uid=admin)(userPassword=*))\`

Resulting query:

```plaintext
(uid=*)(|(uid=admin)(userPassword=*))
```

This query exposes sensitive data like user passwords.

---

#### Mitigation:

* Validate `username` input strictly.
* Limit the attributes returned by LDAP queries using projections (e.g., only `cn` and `email`).

---

### **Example 12: Multi-Field Exploitation**

#### Scenario:

The application retrieves user data based on multiple attributes (e.g., username and department).

**Vulnerable Code:**

```python
def get_user_by_dept(username, department):
    ldap_server = "ldap://localhost:389"
    conn = ldap.initialize(ldap_server)
    
    # Vulnerable query
    search_filter = f"(&(uid={username})(department={department}))"
    try:
        conn.simple_bind_s()
        results = conn.search_s("ou=users,dc=example,dc=com", ldap.SCOPE_SUBTREE, search_filter)
        return results
    except Exception as e:
        print(f"Error: {e}")
```

#### Attack:

The attacker inputs:

* `username = `*)(department=HR))(|(uid=*\`
* `department = any_value`

Resulting query:

```plaintext
(&(uid=*)(department=HR))(|(uid=*))
```

This retrieves all users in the HR department, bypassing the username filter.

---

#### Mitigation:

Escape all inputs and use parameterized queries.

---

### **Example 13: Exploiting Query Logic to Create Subqueries**

#### Scenario:

The application searches for user accounts based on their `uid` and `role`.

**Vulnerable Code:**

```python
def search_users(uid, role):
    ldap_server = "ldap://localhost:389"
    conn = ldap.initialize(ldap_server)
    
    # Vulnerable query
    search_filter = f"(&(uid={uid})(role={role}))"
    try:
        conn.simple_bind_s()
        results = conn.search_s("ou=users,dc=example,dc=com", ldap.SCOPE_SUBTREE, search_filter)
        return results
    except Exception as e:
        print(f"Error: {e}")
```

#### Attack:

An attacker could craft input like:

* `uid = `*)(|(uid=*))\`
* `role = any_role`

Resulting query:

```plaintext
(&(uid=*)(|(uid=*)))(role=any_role))
```

This query matches all users, bypassing any restrictions based on `uid`.

---

#### Mitigation:

* Use predefined lists or dictionaries to enforce valid input values.
* Escape all user inputs.

---

### **Example 14: Exploiting Case-Insensitive Searches**

#### Scenario:

LDAP queries are often case-insensitive. An application searches for users by their email address.

**Vulnerable Code:**

```python
def search_by_email(email):
    ldap_server = "ldap://localhost:389"
    conn = ldap.initialize(ldap_server)
    
    # Vulnerable query
    search_filter = f"(mail={email})"
    try:
        conn.simple_bind_s()
        results = conn.search_s("ou=users,dc=example,dc=com", ldap.SCOPE_SUBTREE, search_filter)
        return results
    except Exception as e:
        print(f"Error: {e}")
```

#### Attack:

The attacker provides:

* `email = `*)(mail=*\`

Resulting query:

```plaintext
(mail=*)(mail=*)
```

This leaks all email addresses.

---

#### Mitigation:

* Sanitize user input.
* Ensure that searches for specific attributes (e.g., `mail`) are strictly formatted.

---

### General Prevention Best Practices

1. **Escape User Inputs**:
   Use libraries like `ldap.filter.escape_filter_chars` to escape special characters.

   ```python
   from ldap.filter import escape_filter_chars
   username = escape_filter_chars(username)
   ```

2. **Use Parameterized Queries**:
   Whenever possible, use parameterized queries supported by your LDAP library.

3. **Validate Inputs**:
   Ensure inputs are alphanumeric or match specific patterns using regex.

   ```python
   import re
   if not re.match(r"^[a-zA-Z0-9@.]+$", email):
       raise ValueError("Invalid input")
   ```

4. **Limit Query Scope**:
   Restrict the query base DN and scope to minimize the impact of potential injection.

5. **Test for Vulnerabilities**:
   Use tools like OWASP ZAP, Burp Suite, or custom scripts to identify vulnerabilities.

If you need more examples or details on specific cases, let me know!


