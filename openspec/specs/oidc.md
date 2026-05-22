# OIDC Service (home-oidc)

## Purpose
Local OpenID Connect provider for homelab services. Runs as a Windows service,
exposes gRPC over Named Pipe for client management.

---

### Requirement: Client registration
The service MUST allow registering OAuth 2.0 / OIDC clients with a name,
redirect URIs, and scopes. Clients are managed via gRPC Named Pipe.

#### Scenario: Registering a new client
- GIVEN the Named Pipe `\\.\pipe\home-oidc` is connected
- WHEN `RegisterClient(name, redirect_uris, scopes)` is called
- THEN the client is persisted with a generated client_id and client_secret
- AND the client appears in `ListClients()` responses

---

### Requirement: Client removal
The service MUST allow removing a registered client by client_id.

#### Scenario: Removing an existing client
- GIVEN client `my-app` with `client_id: abc123` is registered
- WHEN `RemoveClient("abc123")` is called
- THEN the client is deleted
- AND subsequent authentication attempts with `client_id: abc123` fail

---

### Requirement: OIDC token issuance
The service MUST issue JWT access tokens and ID tokens for authenticated
clients following the OIDC standard flows.

---

### Requirement: Named Pipe endpoint
The service MUST listen on:
- Release: `\\.\pipe\home-oidc`
- Debug: `\\.\pipe\home-oidc-dev`

The pipe MUST use the standard Windows Named Pipe connection pattern
with `unsafe impl Send for PipeConnection {}`.
