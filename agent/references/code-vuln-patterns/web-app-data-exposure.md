# Web Application Data Exposure — IDOR in Code, Mass Assignment, and Response Over-Sharing

> Target: Data exposure bugs where the code returns more data than the authenticated user should
> see, or allows modification of fields the user shouldn't control. These survive SAST because
> the ORM query "works correctly" — the access control gap is in the WHERE clause, not in the
> query syntax. The serializer includes too many fields, the bulk endpoint forgets to filter,
> or the error response reveals the internal data model.

---

## What SAST Already Catches (Skip These)

- Sensitive data in hardcoded strings
- PII logged directly (if the linter has PII patterns)
- Missing `@JsonIgnore` on password field (basic annotation check)
- Debug mode enabled in production (framework-specific linter)
- Secrets in configuration files (secret scanning)

---

## What You're Hunting (LLM-Advantage Patterns)

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
- Spring Data REST auto-exposes repository methods as REST endpoints — `findAll`, `findById` without auth by default
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

---

## Real CVE Examples

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
