# A03:2025 — Software Supply Chain Failures

## Fingerprinting & Version Detection
- [ ] Fingerprint frameworks and libraries: `whatweb target`
- [ ] Check server/framework versions in response headers: `Server`, `X-Powered-By`, `X-AspNet-Version`
- [ ] Scan for known CVEs: `nuclei -u https://target -t cves/`
- [ ] Detect JavaScript library versions from source comments, global variables, or known file hashes
- [ ] Check for outdated jQuery, Angular, React, Lodash, Bootstrap versions in page source

## Exposed Package Manifests
- [ ] `curl https://target/package.json` — Node.js dependency tree
- [ ] `curl https://target/package-lock.json` — pinned versions with vulnerability audit
- [ ] `curl https://target/composer.json` — PHP dependencies
- [ ] `curl https://target/composer.lock` — PHP locked versions
- [ ] `curl https://target/requirements.txt` — Python dependencies
- [ ] `curl https://target/Pipfile.lock` — Python locked versions
- [ ] `curl https://target/Gemfile` / `curl https://target/Gemfile.lock` — Ruby dependencies
- [ ] `curl https://target/pom.xml` — Java Maven dependencies
- [ ] `curl https://target/build.gradle` — Java Gradle dependencies
- [ ] `curl https://target/go.sum` — Go module checksums

## Source Control & Build Artifact Exposure
- [ ] Check for exposed `.git` directory: `curl https://target/.git/HEAD`
- [ ] Dump git objects if accessible: `git-dumper https://target/.git/ ./output`
- [ ] Check for `.svn/entries`: `curl https://target/.svn/entries`
- [ ] Check `.hg/`: `curl https://target/.hg/store/00manifest.i`
- [ ] Check for exposed CI/CD configs: `.github/workflows/`, `.gitlab-ci.yml`, `Jenkinsfile`, `.circleci/config.yml`
- [ ] Check for Docker configs: `Dockerfile`, `docker-compose.yml`
- [ ] Check for `.env.example` or `.env.sample` revealing expected environment variables

## Dependency Confusion & Typosquatting
- [ ] Identify internal/private package names from exposed manifests or JS source maps
- [ ] Check if private package names exist on public registries (npm, PyPI, RubyGems)
- [ ] Look for typosquatting candidates: common misspellings of popular packages in dependency lists
- [ ] Check for scoped vs unscoped npm packages — `@company/pkg` vs `company-pkg`

## Subresource Integrity (SRI)
- [ ] Check if externally loaded scripts have `integrity` attributes
- [ ] Verify CDN-hosted CSS/JS files use SRI hashes
- [ ] Test if missing SRI on CDN resources allows content injection via CDN compromise

## Lockfile Integrity
- [ ] Check for lockfile manipulation: does the app use lockfiles for reproducible builds?
- [ ] Verify that `package-lock.json` registry URLs point to expected registries (not attacker-controlled)
- [ ] Check for mixed registries in lockfiles (public + private pointing to wrong source)

## CI/CD Pipeline Exposure
- [ ] Check for exposed build logs: `/build/`, `/jenkins/`, `/ci/`
- [ ] Test for GitHub Actions workflow artifacts accessible via public URLs
- [ ] Look for hardcoded secrets in exposed CI configs (API keys, tokens, passwords)
- [ ] Check for exposed `.npmrc` or `.pypirc` with registry auth tokens

## Framework-Specific Checks
- [ ] **Node.js**: `npm audit` output if accessible, check for prototype pollution-vulnerable packages
- [ ] **Python**: Check for known Django/Flask/FastAPI CVEs matching detected versions
- [ ] **Ruby/Rails**: Check for CVEs in detected Rails version, especially Action Pack and Active Record
- [ ] **Java/Spring**: Check for Spring4Shell, Log4Shell indicators, Jackson deserialization CVEs
- [ ] **PHP/Laravel**: Check for exposed debug pages revealing exact package versions

---
> Cross-reference skills: `osint-recon`, `source-analysis`
