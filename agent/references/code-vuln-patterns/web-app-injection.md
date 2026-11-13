---
description: ORM bypass, second-order injection, template injection, deserialization in web contexts, NoSQL injection
skill: code-vulnerability-analysis, code-variant-analysis
languages: Python, JS, Java, Ruby, PHP
---

# Web Application Injection — ORM Bypass, Template Escape, and Deserialization in Frameworks

The framework's default API is safe; the bug is in the escape hatch, the template path, or the
deserialization layer it exposes for advanced use. Second-order injection, shell construction, and
protocol injection are in `injection.md`.

## What You're Hunting (LLM-Advantage Patterns)

### 1. ORM escape hatches

- **Django:** `.extra(where=[f"..."])`, `.raw(f"...")`, `RawSQL(f"...")`,
  `Func(function=user_input, ...)`, and `annotate()`/`aggregate()`/`values()` fed a user-controlled
  `**kwargs` dict, whose keys become SQL (CVE-2022-28346). On a model with a `JSONField`, a crafted
  JSON key passed positionally (`*args`) to `values()`/`values_list()` became a column alias
  (CVE-2024-42005). `order_by(user_input)` lets the user sort by any column, a blind oracle on
  `password` or token fields; raw SQL inside `order_by` was CVE-2021-35042 (3.1/3.2) and is rejected
  since Django 4.0.
- **SQLAlchemy:** `text(f"...")`, `filter(text(user_input))`, `column(user_input)`, `func` with a
  user-chosen function name, and `literal_column`.
- **Sequelize / knex:** `sequelize.literal()` and `sequelize.fn()` with interpolation (including inside
  `order`), `knex.raw()` with template strings, and Sequelize before v5 accepting `$`-prefixed
  operator aliases from object input.
- **Hibernate/JPA:** HQL or native query concatenation, and Criteria `root.get(userInput)` choosing the
  column.
- **ActiveRecord:** `where("name = '#{...}'")`, `order(params[:sort])`, `pluck(params[:field])`,
  `calculate(:sum, params[:column])`.

### 2. Template injection (SSTI)

- Jinja2/Flask `render_template_string(user_input)` or an f-string template (`{{config}}` leaks the
  app config). `Markup()` around user input disables autoescaping, and custom filters that call
  `eval` are sinks.
- Pug `pug.render()`/`pug.compile()` of user text; EJS `<%- include(userInput) %>`.
- Ruby `ERB.new(user_input).result`.
- Thymeleaf: a controller returning `"page :: " + section` makes `section` a fragment expression, and
  `__${...}__` preprocessing evaluates before resolution, so SpEL such as
  `T(java.lang.Runtime).getRuntime().exec(...)` runs. `th:utext` is unescaped output (XSS, not SSTI).
- Spring SpEL: `parser.parseExpression(userInput).getValue()`, and custom SpEL in `@Query`.

### 3. Argument injection through argv-safe calls

An argv array stops shell injection, not option injection: input that becomes its own argument and
starts with `-` is parsed as an option. `execFile('git', ['ls-remote', userUrl])` with
`--upload-pack=<cmd>` runs a command; `git log <input>` accepts `--output=<path>`. A `--` separator
before user arguments, or a leading-dash check, is the fix. Input embedded as an option's value
(`--author=${x}`) stays a value.

### 4. Deserialization hidden behind framework abstractions

This file owns the concrete web sinks:
- Django cache backends pickle values, so `cache.get()` deserializes; cache key injection or a shared
  cache with a less-trusted writer is RCE.
- Celery with `task_serializer`/`accept_content` set to `pickle` (JSON has been the default since
  Celery 4) executes whatever a queue writer submits.
- PyYAML: `yaml.load` with `Loader=yaml.Loader`/`UnsafeLoader` builds arbitrary objects; `FullLoader`
  allowed code execution before 5.3.1 (CVE-2020-1747) and again before 5.4 through an incomplete fix
  (CVE-2020-14343, `python/object/new`); `SafeLoader`/`safe_load` is the fix.
- `pickle.loads(cache.get(key))` with Redis as the cache: SAST sees the cache, not the poisoner.
- Java `ObjectInputStream.readObject()` on request bodies, and Spring Session's Redis store, which
  defaults to JDK serialization.
- PHP `unserialize()` of cookies or hidden fields; `allowed_classes` limits instantiation, but an
  allowed class's `__destruct()`/`__wakeup()` still runs and can be a file-write primitive.

### 5. NoSQL operator injection

A JSON body — or `qs`-parsed query and urlencoded parameters (`user[$ne]=`) — turns a scalar field
into an operator object: `{"password": {"$ne": ""}}` authenticates as anyone, `{"$regex": "^a"}`
extracts data character by character, and `$where` runs JavaScript in MongoDB (Mongoose, PyMongo
alike). Validate that each field is a string before it reaches the query.

### 6. GraphQL resolvers

Resolver arguments interpolated into SQL (`ORDER BY ${sortBy}`), and nested resolvers that
interpolate `parent.id` on the assumption that database-sourced values are clean. Custom scalars
that do no validation pass payloads through.

### 7. Log injection

CR/LF in logged fields forges entries, and ANSI escapes in a User-Agent act on whoever tails the
log. Log4j: message lookups (`${jndi:...}`) were disabled by default in 2.15.0 and removed in
2.16.0. A Context Lookup in a `PatternLayout` (`${ctx:loginId}`) fed attacker-controlled Thread
Context (MDC) data into lookup evaluation: a JNDI payload there bypassed the 2.15.0 fix
(CVE-2021-45046, fixed in 2.16.0), and a self-referential one overflowed the stack (CVE-2021-45105,
fixed in 2.17.0). From 2.17.0 (2.12.3 on Java 7, 2.3.1 on Java 6) lookups are never recursively
evaluated while log events are processed, so on those versions attacker data in a lookup result is
inert text; the Context Lookup finding is a version below them combined with a `${ctx:...}` layout
reading request-derived MDC values.

## Detection Questions

- Can a request value be an object or array instead of a scalar (JSON bodies, `qs` brackets)?
- Is user input ever the template itself rather than a template variable (`render_template_string`,
  `pug.compile`, `ERB.new`, `Template(input)`, a returned Thymeleaf view name)?
- Where does deserialization happen — cache backends, session stores, queue consumers, upload
  handlers — and who can write to that store?

## Real CVE Examples

- **CVE-2019-14234 (Django JSONField/HStoreField).** The lookup value was parameterized but the key
  path was interpolated into SQL, so a user-controlled key in `data__<key>` injected; "every ORM call
  is parameterized" missed it because the injection was in how the ORM built the path.
