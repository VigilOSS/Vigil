---
description: Standard paths checklist (framework debug and admin endpoints, /.env and config files, manifests, VCS, backups)
skill: info-disclosure-testing
source: Custom — compiled from security research and common patterns
---

# Information Disclosure Probes — Checklist

> Source: Custom — compiled from security research and common patterns

## Framework Debug / Admin Endpoints

### Java / Spring Boot

```
/actuator
/actuator/env
/actuator/health
/actuator/info
/actuator/metrics
/actuator/mappings
/actuator/configprops
/actuator/beans
/actuator/heapdump
/actuator/threaddump
/actuator/loggers
/trace
/env
/dump
/jolokia
/jolokia/list
```

### .NET / ASP.NET

```
/elmah.axd
/trace.axd
/glimpse.axd
/_debug
/swagger
/swagger/v1/swagger.json
```

### PHP

```
/phpinfo.php
/info.php
/php_info.php
/test.php
/i.php
/pi.php
```

### Python (Django / Flask)

```
/_debug
/__debug__/
/debug/default/view
/admin/
/api/debug
/flask/debug
```

### Node.js

```
/status
/debug
/health
/healthcheck
/api/docs
/swagger.json
/api-docs
```

### Ruby on Rails

```
/rails/info
/rails/info/properties
/rails/info/routes
/rails/mailers
```

## Common Sensitive Files

### Configuration / Secrets

```
/.env
/.env.bak
/.env.local
/.env.production
/.env.development
/config.yml
/config.yaml
/config.json
/config.php
/config.inc.php
/configuration.php
/settings.py
/settings.json
/wp-config.php
/wp-config.php.bak
/wp-config.php.old
/wp-config.php.save
/web.config
/appsettings.json
/appsettings.Development.json
/application.yml
/application.properties
/database.yml
/credentials.json
/.npmrc
/.dockerenv
/docker-compose.yml
/Dockerfile
```

Exposed key material: `/keys/`, `/certs/`, `/.ssh/` (`id_rsa`, `authorized_keys`), and `*.pem` /
`*.key` beside the config files above.

### Package Manifests (Dependency Enumeration)

```
/package.json
/package-lock.json
/composer.json
/composer.lock
/Gemfile
/Gemfile.lock
/requirements.txt
/Pipfile
/Pipfile.lock
/pom.xml
/build.gradle
/go.mod
/go.sum
```

### Version Control

```
/.git/config
/.git/HEAD
/.git/index
/.gitignore
/.svn/entries
/.svn/wc.db
/.hg/
/.bzr/
```

### Backup Files

```
/backup.sql
/backup.zip
/dump.sql
/database.sql
/db.sql
/site.tar.gz
/www.zip
/backup/
/*.bak
/*.old
/*.save
/*.swp
/*~
```

Cloud metadata endpoints (reached through SSRF or a proxy) are in `agent/references/payloads/ssrf-payloads.md`
"Cloud Metadata Endpoints"; robots, sitemap and the other well-known files are in `agent/skills/web-recon/SKILL.md` "Step 9".
