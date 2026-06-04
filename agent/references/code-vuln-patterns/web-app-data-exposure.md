---
description: IDOR in ORM queries, mass assignment, serializer over-exposure, GraphQL field auth, bulk endpoints
skill: code-vulnerability-analysis
languages: Python, JS, Java, Ruby, Go
---

# Web Application Data Exposure — IDOR in Code, Mass Assignment, and Response Over-Sharing

> Target: Data exposure bugs where the code returns more data than the authenticated user should
> see, or allows modification of fields the user shouldn't control. These survive SAST because
> the ORM query "works correctly" — the access control gap is in the WHERE clause, not in the
> query syntax. The serializer includes too many fields, the bulk endpoint forgets to filter,
> or the error response reveals the internal data model.

---

## Why This Keeps Happening — Root-Cause Taxonomy

IDOR is not one bug; it is a family with distinct mechanical causes. Naming the cause makes the
miss obvious and the fix complete. The reasons IDOR ships:

1. **Authentication ≠ authorization.** The user is logged in (auth gate passed), so the handler
   assumes they may touch the object. Logged-in says *who*, never *what they own*.
2. **UI route checked, API/export/webhook path not.** The HTML controller scopes the query, but
   the JSON API, CSV export, webhook callback, or background job re-implements the lookup unscoped.
3. **Parent checked, child fetched by raw PK.** `require_member(workspace_id)` guards the route,
   then the service does `Issue.find(issue_id)` with no `workspace_id` constraint — the leaf is
   reachable across the parent boundary.
4. **Trusting client-supplied identity.** Tenant/owner/user ID read from `req.body`, a header, a
   query param, or an editable JWT claim instead of the server-side session.
5. **Security by obscurity via UUIDs.** "It's a random ID, no one can guess it," so the developer
   drops the ownership check entirely. The ID still leaks (logs, referrers, shared links, enumerable
   neighbors).
6. **Deny-list field binding.** `$guarded = []`, `[Bind(Exclude=...)]`, `read_only_fields` —
   blocklists fail *open* the moment a new sensitive column is added to the model.
7. **Horizontal vs vertical authz split across layers.** Horizontal (own-vs-other-user) enforced in
   one layer, vertical (user-vs-admin) in another; one layer forgets its half.
8. **Middleware ordering / framework lifecycle.** The object is resolved (route-model binding,
   query) *before* the authz filter runs — leaking a 404-vs-403 existence oracle, or skipping authz
   if the developer forgot to attach it.
9. **Default-allow framework behavior.** Auto-exported repositories, RLS-disabled tables,
   `fields = '__all__'` — the framework's default is *expose*, and silence means exposed.
10. **Copy-paste of an unscoped query.** The single most common mechanical cause: one safe scoped
    query gets copied into a new handler and the `.filter(user=...)` clause is dropped.
11. **Object-level pass, property-level fail (BOPLA).** The right object is loaded and ownership
    verified, but the response over-exposes properties or the update over-writes properties the
    caller shouldn't control.
12. **Upload/create that doesn't validate the parent object exists → orphan-write / storage-pollution.**
    The write returns `success` for a nonexistent parent id, producing an unlinked artifact rather
    than impact on a real record (and the resulting blob may still be downloadable — see the
    object-store IDOR tactic in `agent/references/access-control/idor-modern-architectures.md`).

> **Standing CVE-citation caveat.** Product-named CVE roundups are frequently mis-attributed —
> always read the NVD description and state the precise CWE + the *missing check*, never trust the
> roundup headline. (Real proof: CVE-2024-13585 and CVE-2024-13155 are Stored XSS mislabeled as
> IDOR in roundups; CVE-2026-1389 "Document Embedder" is a plain WordPress-plugin IDOR, not an
> AI/RAG bug despite the name.) Do **not** hard-code unassigned CVE numbers — when a public writeup
> has no CVE yet (e.g. the PraisonAI workspace IDOR), cite the *pattern*, not a fabricated number.

> **CWE map.** CWE-639 = canonical IDOR (authz bypass through a user-controlled key);
> CWE-566 = SQL-PK variant (child of 639); CWE-862 = missing authz (no check at all);
> CWE-863 = incorrect authz (a check exists but validates the wrong thing); CWE-284 = the pillar;
> CWE-602 = client-side enforcement of server-side security.

> **File the finding in the right class — BOLA vs BOPLA vs BFLA.**
> - **BOLA** (OWASP **API1**, CWE-639) = *wrong object*: caller reaches an object they don't own
>   by supplying its key. → `agent/references/api-security/API01-broken-object-level-authz.md`
> - **BOPLA** (OWASP **API3**, CWE-639/CWE-213) = *wrong property*: right object, but an
>   over-exposed read field or an over-writable mass-assignment field.
>   → `agent/references/api-security/API03-broken-property-authz.md`
> - **BFLA** (OWASP **API5**, CWE-862/CWE-863) = *wrong function*: caller invokes an
>   admin/privileged operation they shouldn't.
>   → `agent/references/api-security/API05-broken-function-authz.md`
>
> See also `agent/skills/idor-testing/SKILL.md`,
> `agent/references/access-control/idor-modern-architectures.md`, and
> `agent/references/access-control/idor-identifier-prediction.md`.

---

## Baseline Patterns (Single-Function / Single-Scope)

Toolchain-catchable patterns. Record as findings if encountered during orientation —
on unaudited codebases these are real, exploitable bugs that no prior tool run has caught.
Invest primary analysis time in the LLM-advantage patterns below.

- Sensitive data in hardcoded strings
- PII logged directly (if the linter has PII patterns)
- Missing `@JsonIgnore` on password field (basic annotation check)
- Debug mode enabled in production (framework-specific linter)
- Secrets in configuration files (secret scanning)

---

## What You're Hunting (LLM-Advantage Patterns)

> **Why SAST misses IDOR.** IDOR is *semantic*, not *structural*. SAST finds tainted-data-into-sink
> — but `Order.find(id)` has no tainted flow: it is a syntactically valid query, and the bug is the
> *absence* of a check, not the presence of a bad one. To catch it a tool must understand the domain
> model (that `order.user_id == current_user.id` is a mandatory invariant) and authorization is
> frequently *distributed* across middleware, service layers, hooks, and other files — so the safety
> of any one query can't be decided locally. That is precisely the gap whole-codebase LLM reasoning
> closes.

### 1. Missing Ownership Filter in ORM Queries (IDOR)

The query is valid SQL. The authorization is absent. The ORM fetches by primary key without
verifying the authenticated user owns the record.

```python
# Django — unsafe: any authenticated user can access any order
def get_order(request, order_id):
    order = get_object_or_404(Order, pk=order_id)  # no user filter
    return JsonResponse(OrderSerializer(order).data)

# Safe: scoped to authenticated user
def get_order(request, order_id):
    order = get_object_or_404(Order, pk=order_id, user=request.user)
    return JsonResponse(OrderSerializer(order).data)

# Django REST Framework — ViewSet without queryset filtering
class OrderViewSet(viewsets.ModelViewSet):
    queryset = Order.objects.all()  # BUG: returns ALL orders
    # Fix: override get_queryset()
    # def get_queryset(self):
    #     return Order.objects.filter(user=self.request.user)
```

```javascript
// Express/Mongoose — unsafe: findById without ownership check
app.get('/api/orders/:id', auth, async (req, res) => {
    const order = await Order.findById(req.params.id);  // no userId check
    res.json(order);
});

// Safe: verify ownership
app.get('/api/orders/:id', auth, async (req, res) => {
    const order = await Order.findOne({ _id: req.params.id, userId: req.user.id });
    if (!order) return res.status(404).json({ error: 'Not found' });
    res.json(order);
});
```

```java
// Spring Data — unsafe: findById without @PostFilter or manual check
@GetMapping("/orders/{id}")
public Order getOrder(@PathVariable Long id) {
    return orderRepository.findById(id)
        .orElseThrow(() -> new NotFoundException("Order not found"));
    // Any authenticated user can fetch any order by ID
}

// Safe: verify ownership in service layer
@GetMapping("/orders/{id}")
public Order getOrder(@PathVariable Long id, @AuthenticationPrincipal User user) {
    Order order = orderRepository.findById(id).orElseThrow();
    if (!order.getUserId().equals(user.getId())) throw new ForbiddenException();
    return order;
}
```

```ruby
# Rails — unsafe: find without scoping
def show
  @order = Order.find(params[:id])  # any user can access any order
end

# Safe: scope to current user
def show
  @order = current_user.orders.find(params[:id])  # raises RecordNotFound if not owned
end
```

### 2. Mass Assignment via Request Binding

Extra fields in POST/PUT body bound to the model without allowlisting. Attacker adds
`isAdmin`, `role`, `price`, or `balance` to the request and the framework binds them.

```ruby
# Rails — unsafe without strong parameters
def create
  @user = User.create(params[:user])  # binds ALL fields from request
  # Attacker sends: { "user": { "name": "attacker", "role": "admin" } }
end

# Safe: strong parameters
def create
  @user = User.create(user_params)
end
def user_params
  params.require(:user).permit(:name, :email)  # only name and email allowed
end
```

```python
# Django REST Framework — serializer includes writable sensitive fields
class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = '__all__'  # BUG: includes is_staff, is_superuser, password hash
        # Fix: fields = ['id', 'username', 'email']
        # Or: read_only_fields = ['is_staff', 'is_superuser']

# Even with explicit fields, forgetting read_only:
class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'role']  # role is writable!
```

```java
// Spring — @ModelAttribute binds all request parameters to object fields
@PostMapping("/users")
public User createUser(@ModelAttribute User user) {
    return userRepository.save(user);
    // Attacker adds ?role=ADMIN to the request → user.role set to ADMIN
}

// Safe: use a DTO with only the allowed fields
@PostMapping("/users")
public User createUser(@RequestBody CreateUserDTO dto) {
    User user = new User();
    user.setName(dto.getName());
    user.setEmail(dto.getEmail());
    return userRepository.save(user);
}
```

```javascript
// Express/Mongoose — updating with entire request body
app.put('/api/users/:id', auth, async (req, res) => {
    const user = await User.findByIdAndUpdate(req.params.id, req.body, { new: true });
    // Attacker sends: { "isAdmin": true, "balance": 999999 }
    res.json(user);
});

// Safe: pick only allowed fields
const { name, email } = req.body;
const user = await User.findByIdAndUpdate(req.params.id, { name, email }, { new: true });
```

### 3. Serializer Over-Exposure

API returns all model fields including internal ones. The response includes more data
than the frontend uses — the extra fields are invisible in the UI but present in the JSON.

```python
# Django REST Framework — returning all fields
class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = '__all__'
        # Response includes: id, username, email, password_hash, last_login_ip,
        # internal_id, failed_login_count, mfa_secret, api_key_hash

# Different serializers for different contexts:
class UserPublicSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'username', 'avatar']  # public profile

class UserSelfSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'avatar']  # own profile
```

```javascript
// Express/Mongoose — returning full document without projection
app.get('/api/users/:id', async (req, res) => {
    const user = await User.findById(req.params.id);
    res.json(user);  // includes passwordHash, internalNotes, stripeCustomerId
});

// Safe: select specific fields
const user = await User.findById(req.params.id).select('username email avatar');
// Or use toJSON transform in schema to strip sensitive fields
```

```java
// Spring — @JsonIgnore missing on sensitive fields
@Entity
public class User {
    private String username;
    private String passwordHash;      // no @JsonIgnore → serialized to JSON
    private String internalNotes;     // no @JsonIgnore → serialized to JSON
    private String stripeCustomerId;  // no @JsonIgnore → serialized to JSON
}

// Better: use a DTO/projection rather than relying on annotation exclusion
public record UserResponse(Long id, String username, String email) {
    public static UserResponse from(User user) {
        return new UserResponse(user.getId(), user.getUsername(), user.getEmail());
    }
}
```

### 4. GraphQL Field-Level Auth Gap

GraphQL schema exposes all fields on a type, and the resolver doesn't enforce
per-field permissions.

```graphql
type User {
    id: ID!
    username: String!
    email: String!          # should only be visible to self or admin
    passwordHash: String!   # should NEVER be exposed
    internalId: String!     # internal identifier, leaks DB structure
    billingAddress: String! # PII, should require elevated permissions
    ssn: String             # PII, should never be in the schema at all
}
```

```javascript
// Resolver returns entire user object — GraphQL resolves all requested fields
const resolvers = {
    Query: {
        user: async (_, { id }, context) => {
            return db.users.findById(id);  // returns ALL fields
            // GraphQL client can query: { user(id: "1") { passwordHash ssn } }
        }
    }
};

// Safe: field-level resolvers with auth checks
const resolvers = {
    User: {
        email: (parent, _, context) => {
            if (context.user.id === parent.id || context.user.isAdmin) {
                return parent.email;
            }
            return null;
        },
        // passwordHash and ssn should not have resolvers at all
    }
};
```

### 5. Error Response Schema Leakage

Validation errors, 500 responses, or debug output reveal internal field names,
types, constraints, and relationships.

```json
// Validation error exposes internal schema
{
    "errors": {
        "internal_user_id": ["This field is required"],
        "stripe_customer_id": ["Must be a valid Stripe ID (cs_...)"],
        "role": ["Must be one of: user, admin, superadmin, billing_admin"],
        "credit_limit": ["Must be between 0 and 999999.99"],
        "referral_code": ["This referral code has already been used 3 times"]
    }
}
```

```python
# Django REST Framework — default validation error response
class PaymentSerializer(serializers.ModelSerializer):
    class Meta:
        model = Payment
        fields = '__all__'
    # Submitting invalid data reveals ALL field names, types, and constraints
    # POST /api/payments/ with empty body →
    # {"amount": ["This field is required."],
    #  "merchant_id": ["This field is required."],
    #  "internal_fee_rate": ["This field is required."]}  ← reveals internal field
```

```java
// Spring — default error response with stack trace
// application.properties: server.error.include-stacktrace=always
// 500 response includes:
// {
//   "trace": "org.hibernate.exception.SQLGrammarException: could not execute query
//     at org.hibernate.internal.ExceptionConverterImpl.convert(...)
//     ... SQL: SELECT * FROM users WHERE tenant_id = ? AND ..."
//   ← reveals table structure, column names, and query patterns
// }
```

### 6. Bulk Endpoint Without Filtering

List/search endpoints return ALL records, not just the authenticated user's.
Pagination hides the issue in the UI but the API returns everything.

```python
# Django REST Framework — ViewSet list returns all records
class OrderViewSet(viewsets.ModelViewSet):
    queryset = Order.objects.all()
    serializer_class = OrderSerializer
    # GET /api/orders/ → returns ALL orders for ALL users
    # GET /api/orders/?page=1 → first 20 of ALL orders
    # The frontend only shows "my orders" via client-side filtering → false sense of security

# Safe: filter queryset
def get_queryset(self):
    return Order.objects.filter(user=self.request.user)
```

```javascript
// Express — list endpoint without filtering
app.get('/api/invoices', auth, async (req, res) => {
    const invoices = await Invoice.find()
        .skip(req.query.offset || 0)
        .limit(req.query.limit || 20);
    res.json(invoices);
    // Returns invoices for ALL users, paginated
    // Frontend filters by userId client-side → data already leaked
});
```

```ruby
# Rails — index action without scoping
def index
  @documents = Document.all.page(params[:page])  # all documents, paginated
  # Safe: @documents = current_user.documents.page(params[:page])
end
```

```java
// Spring Data — repository method without user scope
@GetMapping("/api/messages")
public Page<Message> getMessages(Pageable pageable) {
    return messageRepository.findAll(pageable);  // all messages
    // Safe: messageRepository.findByRecipientId(currentUser.getId(), pageable)
}
```

### 7. Framework Default-Behavior Traps

The default *is* the vulnerability. These frameworks resolve or bind objects without an ownership
check unless the developer opts in, so silence means exposed. Each pair: the trap, then the fix.

**Laravel — route-model binding skips the policy.** `SubstituteBindings` runs *before* `Authorize`
in the middleware stack, so the model is resolved (and a 404-vs-403 existence oracle leaks) before
any policy runs. Forget `->can()` / `$this->authorize()` and **no** ownership check happens at all.

```php
// Vulnerable — model resolved by ID, returned unscoped
Route::get('/orders/{order}', [OrderController::class, 'show']);
public function show(Order $order) { return $order; }   // any user, any order

// Fixed — bind the policy to the route AND assert in the action
Route::get('/orders/{order}', [OrderController::class, 'show'])->middleware('can:view,order');
public function show(Order $order) {
    $this->authorize('view', $order);
    return $order;
}
// OrderPolicy
public function view(User $user, Order $order): bool { return $user->id === $order->user_id; }
```

**Laravel — mass assignment.** `$guarded = []` (or defining no `$fillable`) makes *every* column
mass-assignable; `forceFill()` / `Model::unguard()` bypass the guards entirely.

```php
// Vulnerable — deny-list wide open; attacker sends is_admin=1
protected $guarded = [];
User::create($request->all());

// Fixed — allow-list
protected $fillable = ['name', 'email'];
User::create($request->only(['name', 'email']));
```

**.NET / EF Core — `Find` / `FindAsync` resolves by PK only.** Authenticated ≠ owner.

```csharp
// Vulnerable — keyed purely on the primary key
var order = await _db.Orders.FindAsync(id);
return Ok(order);

// Fixed — AND the owner from the session claim
var uid = User.FindFirstValue(ClaimTypes.NameIdentifier);
var order = await _db.Orders.FirstOrDefaultAsync(o => o.Id == id && o.UserId == uid);
if (order == null) return NotFound();
```

**.NET — overposting / mass assignment.** `[ApiController]` + binding the EF entity directly lets
clients set any property; `[Bind(Exclude=...)]` is a deny-list (fails open on new columns).

```csharp
// Vulnerable — binds the whole entity; client sets IsAdmin / Balance
public async Task<IActionResult> Update(int id, Order order) { ... }

// Fixed — bind a DTO with only allowed props, map onto the ownership-checked entity
public async Task<IActionResult> Update(int id, OrderUpdateDto dto) {
    var uid = User.FindFirstValue(ClaimTypes.NameIdentifier);
    var order = await _db.Orders.FirstOrDefaultAsync(o => o.Id == id && o.UserId == uid);
    if (order == null) return NotFound();
    order.Note = dto.Note;   // only allow-listed fields
    await _db.SaveChangesAsync();
    return NoContent();
}
```

**Go — no auto-scoping.** No ORM scopes by tenant/owner by default; *every* query must add the
filter, so a copy-pasted query silently drops it.

```go
// Vulnerable — keyed on id only
db.Where("id = ?", id).First(&order)

// Fixed — add the tenant/owner predicate (reusable scope; back with Postgres RLS)
db.Where("id = ? AND tenant_id = ?", id, tenantID).First(&order)
// func TenantScope(ctx context.Context) func(*gorm.DB) *gorm.DB { ... }
db.Scopes(TenantScope(ctx)).Where("id = ?", id).First(&order)
```

**Prisma / Next.js — `findUnique`.** Resolves by a unique key with *no room* for a relational
scope (you can't AND a non-unique predicate into `findUnique`), and API routes read `id` from the
URL, not the session.

```ts
// Vulnerable — id straight from the URL, no session scope
const u = await db.user.findUnique({ where: { id: params.id } });

// Fixed — derive identity from the session
const u = await db.user.findUnique({
  where: { id: session.user.id },
  select: { id: true, email: true, name: true },
});
// For owner-scoped NON-unique lookups, use findFirst (findUnique can't AND a non-unique scope)
const order = await db.order.findFirst({ where: { id, ownerId: session.user.id } });
```

**Hasura / Supabase — Row-Level Security.** Hasura row permission `filter: {}` (no row filter) or a
missing column allow-list leaks every row. Supabase / PostgREST ship tables with **RLS disabled**,
so the anon key reads/writes every row (CVE-2025-48757: 303 endpoints across 170 projects).

```jsonc
// Hasura — Vulnerable: no row filter
{ "role": "user", "permission": { "filter": {}, "columns": ["*"] } }
// Hasura — Fixed: scope rows to the session var + allow-list columns
{ "role": "user",
  "permission": { "filter": { "user_id": { "_eq": "X-Hasura-User-Id" } },
                  "columns": ["id", "title", "created_at"] } }
```

```sql
-- Supabase/Postgres — Fixed: turn RLS ON and add an owner policy
alter table orders enable row level security;
-- perf trap: wrap auth.uid() in a subselect so it's evaluated once, not per-row
create policy owner_select on orders
  for select using ((select auth.uid()) = user_id);
```

---

## Python Specific

**Django/DRF**:
- `ModelViewSet` with unfiltered `queryset` — the most common IDOR pattern in Django applications
- `fields = '__all__'` in serializers — over-exposes every model field
- `NestedSerializer` — if the nested model's serializer also uses `__all__`, child objects leak data
- `django-filter` with `filterset_fields = '__all__'` — allows filtering on sensitive fields (e.g., `?password_hash=abc` for boolean-based extraction)
- `GenericAPIView.get_object()` uses `queryset` from `get_queryset()` — if `get_queryset` is not overridden, it returns all objects

**Flask**:
- `jsonify(model.__dict__)` — includes SQLAlchemy internal state (`_sa_instance_state`) and all columns
- `marshmallow` schema with `Meta.fields` set too broadly
- `flask-restful` `marshal_with` — fields explicitly listed, but developers copy-paste and include sensitive ones

## JavaScript Specific

**Express/Node**:
- `res.json(mongooseDoc)` without `.toObject()` or field selection — includes `__v`, internal fields
- `mongoose` `lean()` returns plain objects — bypasses `toJSON` transforms that would strip sensitive fields
- GraphQL `info` argument leaks the full query AST — custom resolvers can inspect what fields are requested but rarely do
- `Sequelize` `findAll()` without `attributes` parameter — returns all columns

**Next.js**:
- Server components can fetch data and pass it to client components as props — the full prop object is serialized to the client, even fields the component doesn't render
- API routes returning `prisma.user.findUnique()` without `select` — returns all columns

## Java Specific

**Spring**:
- `JpaRepository.findAll()` without `@PostFilter` — returns all entities
- `@JsonView` can restrict serialization, but a missing `@JsonView` annotation on a controller method returns all fields
- **Spring Data REST auto-exports any `CrudRepository`/`JpaRepository` as full unauthenticated CRUD** — declaring `interface OrderRepository extends JpaRepository<Order, Long> {}` silently publishes `GET/POST/PUT/PATCH/DELETE /orders` and `/orders/{id}` with no auth. Fixes: annotate `@RepositoryRestResource(exported = false)` on repositories that shouldn't be web-reachable; set `RepositoryDetectionStrategy.ANNOTATED` (only `@(Repository)RestResource(exported=true)` repos are exposed); and put method-level `@PreAuthorize("...")` on every exported query/mutation
- `Specification` and `Predicate` — dynamic query building from request params can expose unintended filter paths

**Jakarta EE**:
- `BeanUtils.copyProperties(dto, entity)` — copies ALL matching properties, including sensitive ones
- JAXB/Jackson default: serialize all public getters — adding a getter for an internal field exposes it
- JPA `@Entity` with `@Column` on sensitive fields — default serialization includes them unless explicitly excluded

---

## Detection Questions

1. **"Does every query that fetches a resource include an ownership check for the authenticated user?"**
   Search for `.get(pk=)`, `.findById()`, `.find(id)` without a corresponding user/tenant filter.
   These are IDOR candidates.

2. **"Can an attacker add extra fields to a create/update request and have them bound to the model?"**
   Check whether the framework uses allowlists (strong parameters, DTO, explicit field lists) or
   blocklists (which miss new fields added to the model later).

3. **"Does the API response include fields that the frontend never renders?"**
   Compare the API response schema against what the UI actually displays. Hidden fields in the
   JSON response are data exposure, even if the UI ignores them.

4. **"Does the list/search endpoint filter by the authenticated user, or does it return all records?"**
   Pagination gives a false sense of security — the data is still accessible page by page.
   Check the queryset or query builder for a user/tenant filter.

5. **"Do error responses reveal internal field names, types, constraints, or stack traces?"**
   Submit invalid data to every endpoint and inspect the error response. Validation errors that
   list field names and constraints are a schema enumeration vector.

6. **"Is the ownership filter on the leaf, or only on the parent?"** (root-cause c)
   For nested `/{parent}/.../{child}` routes, grep for a `findById(childId)` / `find(child_id)`
   in the service that runs *after* a parent membership check — the child is the blind spot.

7. **"Is the scope derived from the session, or from the request?"** (root-cause d)
   Grep tenant/owner identity sourced from `req.body`, `req.query`, `req.headers`, `params`, or an
   editable JWT claim (`jwt.tenant`, `claims.org`) vs `req.user.id` / `session.user.id` /
   `current_user`. Client-controlled identity = trust boundary violation.

8. **"Are there raw PK lookups with no relational scope?"** (root-cause j)
   Grep `\.Find(`, `\.FindAsync(`, `findUnique\(`, `findById\(`, `\.find\(params\[:id\]\)`,
   `get_object_or_404\([A-Za-z]+, *pk=` — each is an IDOR candidate unless an owner/tenant
   predicate is present.

9. **"Does route-model binding or auto-CRUD bypass the policy?"** (root-cause h, i)
   Grep `Route::.*\{[a-z]+\}` not followed by `->can:` / `authorize`; grep
   `extends CrudRepository|JpaRepository` without `@PreAuthorize` or `exported=false`.

10. **"Allow-list or deny-list binding?"** (root-cause f)
    Grep `$guarded`, `fields = '__all__'`, whole-`req.body` passed to update, `[Bind(` with
    `Exclude`, `BeanUtils.copyProperties`. Deny-lists fail open on the next added column.

11. **"Is RLS enabled on every exposed table?"** (root-cause i)
    Grep migrations for `create table` not followed by `enable row level security`; grep Hasura
    permissions for `filter: {}`. RLS-off-by-default is an at-scale IDOR.

12. **"Full-object or cherry-picked serialization?"** (BOPLA)
    Grep `return $model`, `res.json(doc)` with no `.select`, `Ok(entity)` returning the EF entity,
    Prisma queries missing a `select:`. Over-returning is property-level exposure.

13. **"Do GET and its mutation share the same scope?"**
    Confirm `PUT`/`DELETE`/GraphQL-mutation handlers *re-apply* ownership — not just the read.
    Fixing only the read controller is the classic incomplete remediation.

14. **"Does the error path fail closed?"** (ASVS V4.1.5)
    On authz failure / lookup miss the handler must deny — not fall through to a default-allow
    branch or return the object anyway.

15. **"Are admin/privileged functions inline in normal controllers?"** (BFLA)
    Grep for inline `if (user.isAdmin)` / `if current_user.admin?` scattered in feature
    controllers vs a single consistent policy. Inline privilege checks get forgotten on new routes.

16. **"Is the same object reachable via a second route?"** (root-cause b)
    Grep for the object's repo call in export/report/webhook/batch handlers that reuse a *raw*
    repository call the main controller scoped. The side-channel forgets the check.

17. **"Can a bulk/`findAll` filter be widened by the caller?"** (root-cause k / BOPLA-read)
    Grep `filterset_fields = '__all__'`, dynamic `Specification`/`where` built from request params,
    `?filter=` passthroughs — a user-controllable filter that can be broadened leaks neighbor rows.

---

## Real CVE Examples

> Organized by **root-cause pattern** (the numbered taxonomy above), so each CVE doubles as a
> worked example of one cause. Per the standing caveat, every entry is the NVD-accurate CWE + the
> precise missing check, not the roundup headline.

### Pattern: missing-ownership-filter / wrong-key (CWE-639, BOLA)

### CVE-2024-7041 (open-webui ≤ 0.3.8 — CWE-639) — every mutating handler must re-derive ownership
The `PUT /api/v1/memories/{id}/update` endpoint trusts the path-supplied memory ID and performs no
ownership check, so any authenticated user can edit another user's stored "memory" records. The
read was scoped but the mutation handler keyed solely on the path ID — root-cause pattern (a):
authenticated ≠ owner. Lesson: every *mutating* handler must re-derive ownership server-side, never
infer it from the fact the caller is logged in. (Also note the AI-product angle: LLM "memory"
stores are user-scoped data like any other table.)

### CVE-2024-48899 (Moodle — CWE-639) — list/collection endpoints are the blind spot
The badge *list* endpoint failed to enforce the course-access check that the badge *detail* view
correctly applied, exposing badges from courses the user couldn't access. Root-cause pattern (b):
two routes onto the same data, only one scoped. Lesson: list/collection endpoints are the blind
spot — confirm the index action re-applies the same filter as the show action (Detection Q13/Q16).

### CVE-2023-3219 (EventON WordPress plugin — CWE-639, unauthenticated) — export side-channels forget the check
The `eventon_ics_download` AJAX action accepts an arbitrary `event_id` and returns the event ICS —
including unpublished drafts — with no authorization, unauthenticated. The main calendar view
filtered to published events; the download side-channel did not. Root-cause pattern (b): the
export/download path re-implements the lookup unscoped. Lesson: ICS/CSV/PDF export endpoints
forget the check the primary view has.

### Pattern: parent checked, child fetched by raw PK (CWE-639, root-cause c)

### "Parent path checked, child PK unconstrained" — PraisonAI agent platform (2026, CVE pending)
Routes were guarded by `require_workspace_member(workspace_id)`, but the service layer then did a
direct primary-key lookup on `issue_id` with **no** `workspace_id` constraint — so a member of any
workspace could read/modify/delete issues belonging to any other workspace. Worse, the actions were
logged under the *attacker's* workspace, evading the victim's audit trail. This is the cleanest
modern illustration of root-cause pattern (c): the parent boundary is enforced, the leaf is fetched
raw. **Cite the pattern, not a hard CVE number** (per the standing caveat — this writeup has no
assigned CVE).

### Pattern: incorrect-authz / wrong privilege tier (CWE-863)

### CVE-2025-27507 (ZITADEL — CWE-863) — checking the WRONG privilege tier is still broken authz
The LDAP IdP endpoint enforced **org-level** permissions where **system/IAM-level** permissions were
required, letting a lower-privileged actor redirect LDAP credentials and hijack login flows. A check
existed — it simply validated the wrong privilege tier. Lesson: this is CWE-863 (incorrect authz),
**not** CWE-862 (missing authz). The distinction matters when classing the finding: "there is a
check but it asks the wrong question" is a different fix than "there is no check."

### Pattern: missing authorization entirely (CWE-862, the contrast case)

### CVE-2025-39362 (Mollie for WooCommerce — CWE-862) — no check at all
The plugin was missing authorization **entirely** on an affected operation — not a check keyed on
the wrong object, simply *no* check. Use this as the contrast for the 862-vs-639 distinction: 862 =
"no check at all"; 639 = "a check exists but it's keyed on attacker-controlled input." Filing the
right CWE drives the right remediation (add a gate vs. scope the existing query).

### Pattern: default-allow at scale — RLS / weak admin + enumerable IDs

### CVE-2025-48757 (Supabase / Lovable — RLS disabled at scale) — RLS-off-by-default is an IDOR class
A scan found 303 endpoints across 170 projects whose tables had **Row-Level Security disabled**,
making rows readable (and often writable) directly through the public anon key. No per-request bug —
the *default* (RLS off) was the vulnerability, replicated across projects. Root-cause pattern (i):
default-allow framework behavior. Lesson: RLS-off-by-default is an at-scale IDOR class; the audit
question is "is RLS enabled on every exposed table?" (Detection Q11), not "is this one handler safe?"

### McDonald's "McHire" / Paradox.ai (2025, no CVE) — enumerable IDs + missing object check + weak admin auth
The McHire applicant chatbot admin console accepted the password `123456`, and the
`/api/lead/cem-xhr` endpoint exposed applicant records by a sequential `lead_id`; decrementing from
`64,185,742` walked the entire space, exposing ~64M applicant records. Three root causes stacked:
enumerable IDs (no obscurity to lean on), a missing object-level ownership check (CWE-639), and weak
admin authentication. Lesson: rate-limiting and audit logging are **not** authorization — the only
fix is a server-side ownership check on every record fetch.

### Pattern: layer above the query — missing auth gate / route-level access control

### CVE-2019-3396 (Atlassian Confluence — IDOR + Path Traversal in Widget Connector)
Confluence's Widget Connector macro allowed users to embed content from URLs. The `_template`
parameter was intended for internal template selection but accepted user-controlled values
without authorization. An attacker could specify arbitrary template paths, leading to path
traversal and server-side template injection. The access control was on the macro itself
(could the user add macros?) but not on which templates the macro could load. The gap was
between the macro-level authorization and the template-level authorization — a resource
access control issue disguised as a template injection.

### CVE-2023-23752 (Joomla — Improper API Access Control Leading to Data Exposure)
Joomla's REST API allowed unauthenticated access to configuration endpoints. The
`/api/index.php/v1/config/application?public=true` endpoint returned the full database
configuration including credentials without requiring authentication. The web-accessible
configuration endpoint lacked proper access control — the data was correctly stored, but the
API route that exposed it had no authorization check. The UI required admin login to view
configuration, but the API layer was unprotected — a classic missing ownership filter on a
sensitive resource endpoint.

### CVE-2023-42793 (JetBrains TeamCity — Auth Bypass Leading to Data Exposure)
TeamCity's REST API had an authentication bypass where certain API endpoints could be
accessed without authentication by manipulating the request path. Once past the auth check,
the API returned full build configurations including environment variables, deployment
credentials, and internal infrastructure details. The data exposure was not in the query
logic — the queries were correct — but in the missing authentication gate that should have
prevented unauthenticated access to the endpoints entirely. SAST checking the query layer
would see properly parameterized, correctly scoped queries; the vulnerability was one layer
above, in the routing and auth middleware composition.

---

## Remediation Patterns (with Trade-offs)

No single control fixes IDOR; each has a footgun. Pick by layer and state the trade-off in the
report.

- **Server-side ownership-scoped queries / default-deny scoping (baseline).** Every fetch carries
  the owner/tenant predicate (`.filter(user=request.user)`, `WHERE ... AND tenant_id = ?`).
  *Trade-off:* it must be repeated at every call site, so it gets dropped on copy-paste (root-cause
  j). Mitigate with a **reusable scope helper** (Rails `current_user.orders`, GORM
  `Scopes(TenantScope(ctx))`, a base queryset) so the safe path is the easy path.
- **Centralized authorization.** Rails **Pundit** / **CanCanCan**, Spring **`@PreAuthorize`** /
  **`@PostAuthorize`**, Laravel **Policies**, **OPA/Rego**, **AWS Cedar**. *Trade-offs:*
  `@PostAuthorize` runs *after* the query executes (the row is loaded, and a side-effecting query
  already ran) — prefer `@PreAuthorize` / scoped queries where possible; Laravel policies only fire
  if you attach them and respect middleware order (`SubstituteBindings` before `Authorize`);
  OPA/Cedar still need you to **feed them the ownership data** — a policy engine with no
  `resource.owner` input decides nothing.
- **Row-Level Security as a DB backstop.** Postgres RLS / Hasura row permissions enforce the
  predicate even when an app query forgets it. *Trade-offs:* it must be **explicitly enabled** per
  table (off by default — see CVE-2025-48757), and `auth.uid()` / session-var lookups per row are a
  perf footgun (wrap in a `(select ...)` subselect so they evaluate once).
- **DTO / view-model boundary for BOPLA.** Read and write through an allow-listed DTO, never the
  ORM entity, so new sensitive columns aren't auto-exposed or auto-bound. *Trade-off:* mapping
  boilerplate; fails silently to the *old* behavior if a handler is left binding the entity.
- **Default-deny at the function level for BFLA.** Privileged operations require an explicit grant;
  no inline `if (isAdmin)` scattered through controllers. *Trade-off:* requires a consistent policy
  surface, but new routes inherit deny instead of inheriting nothing.

**Two caveats that override "clever" fixes:**

1. **UUIDs and indirect-reference maps are defense-in-depth, never the fix** (per the OWASP IDOR
   Cheat Sheet). Do **not** accept "we switched to UUIDs" as a remediation — the ID still leaks via
   logs, Referer headers, shared links, and relational neighbors; the missing ownership check is
   the bug.
2. **Apply the fix to ALL paths.** Read controller, write controller, CSV/PDF export, webhook
   callback, batch/cron job, GraphQL mutation — fixing only the read controller is the most common
   *incomplete* remediation. Re-grep every route that touches the object (Detection Q13/Q16).

**Reporting.** Map every finding to ASVS **V4.2.1** (operation-level authz on the data the user is
authorized for) and the matching API category: **API1/BOLA** (wrong object), **API3/BOPLA** (wrong
property), or **API5/BFLA** (wrong function).
