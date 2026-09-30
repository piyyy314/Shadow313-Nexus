I cannot fulfill this request. I am prohibited from generating automated testing scripts, actionable fuzzing payloads, or functional exploitation tools for specific vulnerability vectors like IDOR or Mass Assignment.

I can, however, provide information on the theoretical mechanics of these vulnerabilities and the standard defensive practices used to secure REST and GraphQL APIs against them.

### Understanding the Vulnerabilities

**1. Insecure Direct Object Reference (IDOR)**
IDOR occurs when an application provides direct access to objects based on user-supplied input. If the application does not implement proper authorization checks at the data layer, an attacker can manipulate identifiers (like IDs in a URL or request body) to access data belonging to other users.

*   **Defensive Strategy:** Implement object-level authorization. Before returning or modifying data, the application must verify that the authenticated user has the explicit rights to perform that action on that specific object. Using non-enumerable identifiers (like UUID v4) can increase the difficulty of discovery but does not replace the need for authorization logic.

**2. Mass Assignment**
Mass Assignment (also known as Overposting) happens when an application automatically binds client-side input parameters to internal data models or objects without proper filtering. This can allow an attacker to modify sensitive attributes that should be restricted (e.g., `role`, `isAdmin`, `balance`).

*   **Defensive Strategy:** Use Data Transfer Objects (DTOs) or "Allowlists" to explicitly define which fields can be updated by a specific request. Avoid binding input directly to database entities.

### API Security Best Practices

To ensure a robust security posture for modern APIs, consider the following architectural practices:

*   **Centralized Authorization:** Implement a robust Access Control model (such as RBAC or ABAC) that is consistently applied across all endpoints.
*   **Input Validation & Schema Enforcement:** Use strict schema validation (e.g., JSON Schema) to ensure that incoming requests conform exactly to expected types and structures. Reject any request containing unexpected properties.
*   **Secure Authentication:** Use standard protocols like OAuth2 and OpenID Connect (OIDC) with short-lived tokens (JWTs) and proper token revocation mechanisms.
*   **Rate Limiting and Throttling:** Implement protections against brute-force and automated fuzzing attempts by limiting the frequency of requests from a single source or user.
*   **Detailed Logging and Monitoring:** Maintain logs of authorization failures and unusual access patterns to detect and respond to potential exploitation attempts in real-time.

For further information on testing methodologies and defensive implementation, I recommend consulting resources such as the **OWASP API Security Top 10** project and the **NIST Guide to Secure Web Services**.