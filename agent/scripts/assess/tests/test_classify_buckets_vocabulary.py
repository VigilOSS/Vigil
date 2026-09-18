"""Vocabulary-recall sweep for the gf-style bucket classifier.

`assess.lib.classify_buckets` is a hand-curated table of 41 buckets holding
451 parameter-key entries, 272 path-fragment entries, and 11 regex entries
(734 curated vocabulary entries total; all four counts verified by importing
`_BUCKETS`/`_REGEX_BUCKET_RULES` directly and summing -- see
`test_classifier_vocabulary_totals_match_the_measured_baseline` below).

Those totals are the POST-audit shape. The sweep below was measured against
the pre-audit table (40 buckets / 432 keys / 269 fragments / 11 regexes = 712
entries); the 22-entry delta is the `llm_api` bucket (19 keys + 3 fragments)
that the audit added, every one of whose entries carries its own sweep row
here. The bucket shipped with three MORE entries than it now carries -- the
bare `prompt` key and the `/v1/messages` / `/v1/responses` fragments were
withdrawn once each was shown to name a non-LLM surface (see "Withdrawn
`llm_api` vocabulary" below). A 2026-09 empirical sweep instrumented
`bucket_matches`/`fragment_in_path`/
`regex_fragment_in_path` and ran the full existing test corpus that touches
this module (386 backend-suite tests + 2,527 assess-suite tests, all green)
to record which of those 712 entries ever actually fire. The result: 180/712
(25.3%) -- 69/432 keys (16.0%), 101/269 fragments (37.5%), 10/11 regexes
(90.9%). That is meaningfully better than the tree-sitter sink catalogue's
11/249 (4.4%) -- this module is NOT silently at zero recall -- but 532
curated entries (74.7%) had never fired in any existing test, and 6 of the 40
buckets (`xxe`, `img_traversal`, `prototype-pollution`, `mass-assignment`,
`ssi`, `cors` -- 15% of all buckets) had ZERO exercised vocabulary: any of
those six bucket definitions could be deleted or silently broken today and no
test would notice.

This file closes that measured gap. `_KEY_CASES` / `_FRAGMENT_CASES` /
`_REGEX_CASES` below are a byte-for-byte materialization of every entry the
above sweep found never fired (minus a small, explicitly documented
exclusion list -- see "Entries deliberately NOT swept" below) -- 363 keys +
153 fragments + 1 regex = 517 rows, each independently verified by execution
(`assess.lib.classify_buckets.classify_from_fields`) before being written
here. Every row will FAIL if its entry is deleted from `_BUCKETS` /
`_REGEX_BUCKET_RULES`, because each fixture's only classification signal is
the literal entry under test.

Entries deliberately NOT swept (with reasons -- this is the taxonomy
allow-list the meta-test at the bottom of this file checks against):

  * REDUNDANT path fragments (15): a shorter sibling fragment in the SAME
    bucket already matches every path the excluded fragment would, because
    `fragment_in_path`'s boundary set `(?=[/?#=&.]|$)` (classify_buckets.py:1820)
    treats `/`, `?`, `#`, `=`, `&`, `.`, and end-of-string as equivalent
    "the fragment just ended here" boundaries -- so e.g. `/actuator` already
    matches `/actuator/env` (boundary `/`), `/adminer` already matches
    `/adminer.php` (boundary `.`), and `/graphql` already matches
    `/graphql/v1` (boundary `/`). No fixture can distinguish "the shorter
    fragment fired" from "the longer one did" because every path the longer
    one matches, the shorter one matches too -- asserting the longer one
    would not "FAIL if the pattern is removed" (its own bucket membership is
    unfalsifiable given its sibling), so per the brief's rule it is excluded
    rather than given a decorative always-green test. Full list:
#   api                  '/rest/v'
#   cms_db_admin         '/adminer.php'
#   debug_logic          '/actuator/beans'
#   debug_logic          '/actuator/env'
#   debug_logic          '/actuator/health'
#   debug_logic          '/actuator/mappings'
#   debug_logic          '/actuator/metrics'
#   debug_logic          '/build.gradle.kts'
#   debug_logic          '/gemfile.lock'
#   debug_logic          '/pipfile.lock'
#   debug_logic          '/settings.gradle.kts'
#   graphql              '/graphql/v1'
#   graphql              '/graphql/v2'
#   sso                  '/sso'
#   wordpress            '/wp-json/wp/v2/users'

  * `_TYPE_FLOOR["privileged_write"]` (classify_buckets.py:1083) -- DEAD, not
    swept: `privileged_write` is a `surface_type` value (see
    `agent/scripts/assess/lib/surfaces.py`, `vuln_taxonomy.py`'s
    `SURFACE_TYPE_TO_CLASSES`), never a `type`/`case_type` value. Verified by
    reading every `return "..."` in `classify_type()`
    (`agent/scripts/assess/lib/classify.py`) and `candidate_type()`
    (`agent/scripts/assess/lib/candidate_records.py`) -- the two functions
    that produce `row["type"]` -- neither ever returns `"privileged_write"`,
    and a repo-wide grep for the literal string assigned as a `type` (not
    `surface_type`) found none. `classify_row()`'s `case_type` lookup
    (classify_buckets.py:1477) can therefore never reach this floor entry.
    Not swept here because asserting its output would cement a floor lookup
    that production code never exercises.

  * `cloud_metadata` (regex bucket) and `api-versioning` (regex bucket) have
    ZERO dead entries -- both were already 100% exercised by the existing
    suite (`cloud_metadata`: 7/7 regexes fired; `api-versioning`: 1/1 regex
    fired) -- so neither contributes rows to `_KEY_CASES`/`_FRAGMENT_CASES`/
    `_REGEX_CASES` below. They are exactly the two buckets excused in the
    meta-test's allow-list.

Two MISROUTED findings surfaced while building this sweep. Both are now
FIXED, and both fixes are pinned -- here and, behaviourally, in
`test_classify_precision_and_context_threading.py`:

  1. `_UPLOAD_GENERIC_SHADOWS` omitted `"img_traversal"`, so an `upload`-typed
     row whose only field name was `image`/`photo` (an extremely common
     avatar/profile-picture upload shape) clustered `gf:img_traversal` at
     score 35, while the byte-identical `file`/`document` shape clustered
     `gf:upload_fields` at 40 via `select_cluster_bucket()`'s shadow override.
     `img_traversal` joined the shadow set; it is still RECORDED in the reason
     chain, the override moves the cluster pick only.
  2. A bare `?query=` on an ordinary, non-GraphQL REST search endpoint (e.g.
     `/api/v1/products/search?query=widget`) clustered `gf:graphql` (weight
     45, the second-highest bucket in the whole table) purely because `query`
     is graphql's canonical request key -- with zero other GraphQL signal.
     `_suppress_graphql_on_bare_query` now requires corroboration (a graphql
     path fragment, a second unambiguous graphql key, a braced `query` VALUE,
     or a `graphql` producer type); the row keeps its real `sqli`/`xss`
     matches, so it is re-ranked (`45 gf:graphql` -> `40 gf:sqli`), never
     dropped. Pinned by
     `test_bare_query_key_is_multi_bucket_and_no_longer_misroutes_to_graphql`
     below.

     The braced-VALUE corroborator is a follow-up: the first version of the
     predicate could only see a POST, because `classify_type()` derives the
     `graphql` producer type from the path, the content-type, or a braced
     `query` value in the BODY and never reads the query string. That
     regressed GraphQL-over-GET -- including `graphql.md`'s own documented
     example, `/api/data?query={users{id,email}}`.

Withdrawn `llm_api` vocabulary. Three of the bucket's shipped entries named a
NON-LLM surface and were removed; each now carries a negative pin in
`test_classify_llm_api.py` instead of a sweep row here:

  * the bare `prompt` KEY. OIDC Core S3.1.2.1 defines `prompt`
    (`none`/`login`/`consent`/`select_account`) and every major IdP emits it,
    so at weight 40 it re-clustered SSO entry points as LLM endpoints
    (`/oauth2/authorize?...&prompt=login` -> `gf:llm_api`).
    `/login?prompt=select_account` escaped only on the declaration-order
    tie-break with `auth`. This is the same analysis that already excluded
    `model`, `system`, `temperature` and bare `tools`/`functions` from the
    bucket -- `prompt` was simply missed by it. The unambiguous compounds
    (`user_prompt`, `system_prompt`, `prompt_template`) are kept and still
    swept below.
  * the `/v1/messages` and `/v1/responses` FRAGMENTS. REST APIs are
    conventionally versioned, so `/api/v1/messages` IS the inbox route and
    `/api/v1/responses` IS the survey-response route: version-qualifying a
    generic collection noun buys no discrimination over the bare `/messages`
    the bucket already (correctly) refuses. `/completions` is boundary-
    anchored and still covers `/v1/chat/completions` on its own.

Every fix and the `llm_api` addition are recorded in
`agent/references/gf-patterns/DRIFT.md` ("Accepted decisions (2026-09
vocabulary audit)").
"""
from __future__ import annotations

import json

import pytest

from assess.lib import classify_buckets as cb


def _classify(case_type: str = "unknown", url_path: str = "", **params: str) -> dict:
    """Classify a synthetic row. `params` becomes a single-key JSON query dict."""
    query_params = json.dumps(params) if params else "{}"
    return cb.classify_from_fields(
        case_type=case_type, url_path=url_path, query_params=query_params
    )


def _matched(case_type: str = "unknown", url_path: str = "", **params: str) -> list[str]:
    return _classify(case_type=case_type, url_path=url_path, **params)["matched_buckets"]


# ---------------------------------------------------------------------------
# Baseline sanity: the measured facts this file is built from must still hold.
# ---------------------------------------------------------------------------

def test_classifier_vocabulary_totals_match_the_measured_baseline() -> None:
    """Pins the 2026-09 empirical baseline this file's docstring quotes.

    If this test ever fails, `_BUCKETS`/`_REGEX_BUCKET_RULES` changed shape
    and the recall sweep below (and its numbers) need re-deriving.
    """
    assert len(cb._BUCKETS) == 41
    assert sum(len(key_set) for _, _, key_set, _ in cb._BUCKETS) == 451
    assert sum(len(frags) for _, _, _, frags in cb._BUCKETS) == 272
    assert sum(len(rules) for rules in cb._REGEX_BUCKET_RULES.values()) == 11
    assert set(cb._REGEX_BUCKET_RULES) == {"api-versioning", "cloud_metadata", "object-storage"}


def test_no_bucket_key_contains_uppercase() -> None:
    """`collect_keys` always lowercases incoming keys (classify_buckets.py:1721);
    a key literal containing an uppercase char could therefore never match and
    would be silently DEAD. Structural guard across every bucket at once."""
    for name, _weight, key_set, _frags in cb._BUCKETS:
        for key in key_set:
            assert key == key.lower(), f"bucket {name!r} key {key!r} can never match"


# ---------------------------------------------------------------------------
# Vocabulary sweep -- parameter keys.
#
# One row per curated key that never fired in the existing 17-file / 2,913-
# test corpus (verified: 386 backend-suite + 2,527 assess-suite tests, all
# passing, instrumented). "/generic-endpoint" is a neutral url_path that
# matches no bucket's path fragments, so the key is each row's ONLY
# classification signal -- removing the key from its bucket's frozenset makes
# the row fail.
# ---------------------------------------------------------------------------

_KEY_CASES: tuple[tuple[str, int, str], ...] = (
    ('auth', 40, 'mfa_code'),
    ('auth', 40, 'otp'),
    ('auth', 40, 'totp'),
    ('cors', 25, 'access_control'),
    ('cors', 25, 'allow_origin'),
    ('cors', 25, 'origin'),
    ('debug_logic', 30, 'dbg'),
    ('deserialization', 40, 'blob'),
    ('deserialization', 40, 'data'),
    ('deserialization', 40, 'object'),
    ('deserialization', 40, 'serialized'),
    ('graphql', 45, 'mutation'),
    ('graphql', 45, 'operationname'),
    ('graphql', 45, 'subscription'),
    ('idor', 35, 'account'),
    ('idor', 35, 'account_id'),
    ('idor', 35, 'accountid'),
    ('idor', 35, 'case_id'),
    ('idor', 35, 'conversation'),
    ('idor', 35, 'conversation_id'),
    ('idor', 35, 'customer'),
    ('idor', 35, 'customer_id'),
    ('idor', 35, 'doc'),
    ('idor', 35, 'doc_id'),
    ('idor', 35, 'document_id'),
    ('idor', 35, 'file_id'),
    ('idor', 35, 'fileid'),
    ('idor', 35, 'gid'),
    ('idor', 35, 'group'),
    ('idor', 35, 'guid'),
    ('idor', 35, 'invoice'),
    ('idor', 35, 'invoice_id'),
    ('idor', 35, 'member'),
    ('idor', 35, 'member_id'),
    ('idor', 35, 'message_id'),
    ('idor', 35, 'msg_id'),
    ('idor', 35, 'node'),
    ('idor', 35, 'number'),
    ('idor', 35, 'object'),
    ('idor', 35, 'object_id'),
    ('idor', 35, 'objectid'),
    ('idor', 35, 'oid'),
    ('idor', 35, 'order'),
    ('idor', 35, 'order_id'),
    ('idor', 35, 'orderid'),
    ('idor', 35, 'org'),
    ('idor', 35, 'org_id'),
    ('idor', 35, 'organization'),
    ('idor', 35, 'organization_id'),
    ('idor', 35, 'owner'),
    ('idor', 35, 'owner_id'),
    ('idor', 35, 'payment'),
    ('idor', 35, 'payment_id'),
    ('idor', 35, 'pid'),
    ('idor', 35, 'profile'),
    ('idor', 35, 'record'),
    ('idor', 35, 'record_id'),
    ('idor', 35, 'ref'),
    ('idor', 35, 'reference'),
    ('idor', 35, 'report'),
    ('idor', 35, 'tenant'),
    ('idor', 35, 'tenant_id'),
    ('idor', 35, 'thread'),
    ('idor', 35, 'thread_id'),
    ('idor', 35, 'ticket'),
    ('idor', 35, 'ticket_id'),
    ('idor', 35, 'transaction'),
    ('idor', 35, 'transaction_id'),
    ('idor', 35, 'uid'),
    ('idor', 35, 'user_id'),
    ('idor', 35, 'userid'),
    ('idor', 35, 'uuid'),
    ('idor', 35, 'workspace'),
    ('img_traversal', 35, 'image'),
    ('img_traversal', 35, 'img'),
    ('img_traversal', 35, 'photo'),
    ('img_traversal', 35, 'thumb'),
    ('img_traversal', 35, 'thumbnail'),
    ('interestingparams', 15, 'api_key'),
    ('interestingparams', 15, 'apikey'),
    ('interestingparams', 15, 'auth'),
    ('interestingparams', 15, 'passwd'),
    ('interestingparams', 15, 'pwd'),
    ('interestingparams', 15, 'secret'),
    ('interestingparams', 15, 'session'),
    ('jwt', 30, 'bearer'),
    ('jwt', 30, 'id_token'),
    ('jwt', 30, 'jwt'),
    ('jwt', 30, 'refresh_token'),
    ('lfi', 40, 'base_path'),
    ('lfi', 40, 'basepath'),
    ('lfi', 40, 'conf'),
    ('lfi', 40, 'config_path'),
    ('lfi', 40, 'configfile'),
    ('lfi', 40, 'configpath'),
    ('lfi', 40, 'dir'),
    ('lfi', 40, 'doc'),
    ('lfi', 40, 'doc_path'),
    ('lfi', 40, 'docpath'),
    ('lfi', 40, 'document'),
    ('lfi', 40, 'downloadpath'),
    ('lfi', 40, 'filepath'),
    ('lfi', 40, 'include'),
    ('lfi', 40, 'include_file'),
    ('lfi', 40, 'include_path'),
    ('lfi', 40, 'includefile'),
    ('lfi', 40, 'load'),
    ('lfi', 40, 'load_file'),
    ('lfi', 40, 'loadfile'),
    ('lfi', 40, 'local_path'),
    ('lfi', 40, 'localpath'),
    ('lfi', 40, 'log_file'),
    ('lfi', 40, 'log_path'),
    ('lfi', 40, 'logfile'),
    ('lfi', 40, 'logpath'),
    ('lfi', 40, 'page'),
    ('lfi', 40, 'path'),
    ('lfi', 40, 'pg'),
    ('lfi', 40, 'read'),
    ('lfi', 40, 'read_file'),
    ('lfi', 40, 'readfile'),
    ('lfi', 40, 'root'),
    ('lfi', 40, 'root_path'),
    ('lfi', 40, 'rootpath'),
    ('lfi', 40, 'template'),
    ('lfi', 40, 'template_path'),
    ('lfi', 40, 'templatepath'),
    ('llm_api', 40, 'embedding'),
    ('llm_api', 40, 'embeddings'),
    ('llm_api', 40, 'function_call'),
    ('llm_api', 40, 'functioncall'),
    ('llm_api', 40, 'max_tokens'),
    ('llm_api', 40, 'maxtokens'),
    ('llm_api', 40, 'messages'),
    ('llm_api', 40, 'prompt_template'),
    ('llm_api', 40, 'prompttemplate'),
    ('llm_api', 40, 'system_message'),
    ('llm_api', 40, 'system_prompt'),
    ('llm_api', 40, 'systemmessage'),
    ('llm_api', 40, 'systemprompt'),
    ('llm_api', 40, 'tool_choice'),
    ('llm_api', 40, 'toolchoice'),
    ('llm_api', 40, 'top_p'),
    ('llm_api', 40, 'topp'),
    ('llm_api', 40, 'user_prompt'),
    ('llm_api', 40, 'userprompt'),
    ('mass-assignment', 30, 'access_level'),
    ('mass-assignment', 30, 'accesslevel'),
    ('mass-assignment', 30, 'account_type'),
    ('mass-assignment', 30, 'accounttype'),
    ('mass-assignment', 30, 'admin'),
    ('mass-assignment', 30, 'approved'),
    ('mass-assignment', 30, 'is_active'),
    ('mass-assignment', 30, 'is_admin'),
    ('mass-assignment', 30, 'is_approved'),
    ('mass-assignment', 30, 'is_verified'),
    ('mass-assignment', 30, 'isactive'),
    ('mass-assignment', 30, 'isadmin'),
    ('mass-assignment', 30, 'isapproved'),
    ('mass-assignment', 30, 'isverified'),
    ('mass-assignment', 30, 'permission'),
    ('mass-assignment', 30, 'permissions'),
    ('mass-assignment', 30, 'privilege'),
    ('mass-assignment', 30, 'privileges'),
    ('mass-assignment', 30, 'role'),
    ('mass-assignment', 30, 'roles'),
    ('mass-assignment', 30, 'user_role'),
    ('mass-assignment', 30, 'user_type'),
    ('mass-assignment', 30, 'userrole'),
    ('mass-assignment', 30, 'usertype'),
    ('mass-assignment', 30, 'verified'),
    ('nosqli', 35, '$exists'),
    ('nosqli', 35, '$gt'),
    ('nosqli', 35, '$gte'),
    ('nosqli', 35, '$in'),
    ('nosqli', 35, '$lt'),
    ('nosqli', 35, '$or'),
    ('nosqli', 35, '$regex'),
    ('nosqli', 35, '$where'),
    ('oauth-oidc', 35, 'code_challenge'),
    ('oauth-oidc', 35, 'grant_type'),
    ('oauth-oidc', 35, 'nonce'),
    ('oauth-oidc', 35, 'response_type'),
    ('oauth-oidc', 35, 'scope'),
    ('oauth-oidc', 35, 'state'),
    ('object-storage', 25, 'blob'),
    ('object-storage', 25, 'bucket'),
    ('object-storage', 25, 'continuation-token'),
    ('object-storage', 25, 'delimiter'),
    ('object-storage', 25, 'prefix'),
    ('privileged_action', 30, 'alter'),
    ('privileged_action', 30, 'clone'),
    ('privileged_action', 30, 'create'),
    ('privileged_action', 30, 'disable'),
    ('privileged_action', 30, 'enable'),
    ('privileged_action', 30, 'modify'),
    ('privileged_action', 30, 'rename'),
    ('privileged_action', 30, 'reset'),
    ('privileged_action', 30, 'toggle'),
    ('prototype-pollution', 35, '__proto__'),
    ('prototype-pollution', 35, 'constructor'),
    ('prototype-pollution', 35, 'prototype'),
    ('rce', 50, 'cli'),
    ('rce', 50, 'cmd_line'),
    ('rce', 50, 'cmdexec'),
    ('rce', 50, 'cmdline'),
    ('rce', 50, 'command'),
    ('rce', 50, 'command_line'),
    ('rce', 50, 'commandline'),
    ('rce', 50, 'exe'),
    ('rce', 50, 'exec'),
    ('rce', 50, 'exec_cmd'),
    ('rce', 50, 'exec_command'),
    ('rce', 50, 'execcmd'),
    ('rce', 50, 'execcommand'),
    ('rce', 50, 'execute'),
    ('rce', 50, 'func'),
    ('rce', 50, 'function'),
    ('rce', 50, 'run'),
    ('rce', 50, 'run_cmd'),
    ('rce', 50, 'run_command'),
    ('rce', 50, 'runcmd'),
    ('rce', 50, 'shell'),
    ('rce', 50, 'shell_cmd'),
    ('rce', 50, 'shell_exec'),
    ('rce', 50, 'shellcmd'),
    ('rce', 50, 'shellexec'),
    ('rce', 50, 'system_cmd'),
    ('rce', 50, 'system_command'),
    ('rce', 50, 'systemcmd'),
    ('rce', 50, 'systemcommand'),
    ('redirect', 25, 'back_url'),
    ('redirect', 25, 'backurl'),
    ('redirect', 25, 'callback_uri'),
    ('redirect', 25, 'callbackuri'),
    ('redirect', 25, 'callbackurl'),
    ('redirect', 25, 'continue'),
    ('redirect', 25, 'continue_url'),
    ('redirect', 25, 'continueurl'),
    ('redirect', 25, 'dest'),
    ('redirect', 25, 'dest_url'),
    ('redirect', 25, 'destination'),
    ('redirect', 25, 'desturl'),
    ('redirect', 25, 'domain'),
    ('redirect', 25, 'failure_url'),
    ('redirect', 25, 'failureurl'),
    ('redirect', 25, 'forward'),
    ('redirect', 25, 'forward_url'),
    ('redirect', 25, 'forwardurl'),
    ('redirect', 25, 'go'),
    ('redirect', 25, 'goto_url'),
    ('redirect', 25, 'gotourl'),
    ('redirect', 25, 'nexturl'),
    ('redirect', 25, 'origin_url'),
    ('redirect', 25, 'originurl'),
    ('redirect', 25, 'redir'),
    ('redirect', 25, 'redirect'),
    ('redirect', 25, 'redirect_to'),
    ('redirect', 25, 'redirectto'),
    ('redirect', 25, 'redirecturl'),
    ('redirect', 25, 'return'),
    ('redirect', 25, 'return_path'),
    ('redirect', 25, 'return_to'),
    ('redirect', 25, 'return_uri'),
    ('redirect', 25, 'returnpath'),
    ('redirect', 25, 'returnto'),
    ('redirect', 25, 'returnuri'),
    ('redirect', 25, 'rt'),
    ('redirect', 25, 'rurl'),
    ('redirect', 25, 'success_url'),
    ('redirect', 25, 'successurl'),
    ('redirect', 25, 'target'),
    ('redirect', 25, 'to'),
    ('redirect', 25, 'u'),
    ('servicenow', 30, 'sysparm_query'),
    ('servicenow', 30, 'sysparm_table'),
    ('sqli', 40, 'category'),
    ('sqli', 40, 'column'),
    ('sqli', 40, 'fetch'),
    ('sqli', 40, 'field'),
    ('sqli', 40, 'filter'),
    ('sqli', 40, 'from'),
    ('sqli', 40, 'group_by'),
    ('sqli', 40, 'groupby'),
    ('sqli', 40, 'having'),
    ('sqli', 40, 'order'),
    ('sqli', 40, 'order_by'),
    ('sqli', 40, 'orderby'),
    ('sqli', 40, 'pid'),
    ('sqli', 40, 'q'),
    ('sqli', 40, 'row'),
    ('sqli', 40, 'search'),
    ('sqli', 40, 'select'),
    ('sqli', 40, 'sid'),
    ('sqli', 40, 'sort'),
    ('sqli', 40, 'sort_by'),
    ('sqli', 40, 'sortby'),
    ('sqli', 40, 'table'),
    ('sqli', 40, 'tid'),
    ('sqli', 40, 'uid'),
    ('sso', 35, 'samlrequest'),
    ('sso', 35, 'wctx'),
    ('sso', 35, 'wresult'),
    ('ssrf', 40, 'avatar_url'),
    ('ssrf', 40, 'avatarurl'),
    ('ssrf', 40, 'dest_uri'),
    ('ssrf', 40, 'desturi'),
    ('ssrf', 40, 'feed'),
    ('ssrf', 40, 'feed_url'),
    ('ssrf', 40, 'feedurl'),
    ('ssrf', 40, 'fetchurl'),
    ('ssrf', 40, 'host'),
    ('ssrf', 40, 'icon_url'),
    ('ssrf', 40, 'iconurl'),
    ('ssrf', 40, 'image_url'),
    ('ssrf', 40, 'imageurl'),
    ('ssrf', 40, 'logo_url'),
    ('ssrf', 40, 'logourl'),
    ('ssrf', 40, 'photo_url'),
    ('ssrf', 40, 'photourl'),
    ('ssrf', 40, 'picture_url'),
    ('ssrf', 40, 'pictureurl'),
    ('ssrf', 40, 'port'),
    ('ssrf', 40, 'proxyurl'),
    ('ssrf', 40, 'remote_url'),
    ('ssrf', 40, 'remoteurl'),
    ('ssrf', 40, 'request_uri'),
    ('ssrf', 40, 'requesturi'),
    ('ssrf', 40, 'target_uri'),
    ('ssrf', 40, 'targeturi'),
    ('ssrf', 40, 'thumbnail_url'),
    ('ssrf', 40, 'thumbnailurl'),
    ('ssrf', 40, 'uri'),
    ('ssrf', 40, 'webhookurl'),
    ('ssrf', 40, 'window'),
    ('ssti', 25, 'custom_template'),
    ('ssti', 25, 'customtemplate'),
    ('ssti', 25, 'email_template'),
    ('ssti', 25, 'emailtemplate'),
    ('ssti', 25, 'layout'),
    ('ssti', 25, 'page_template'),
    ('ssti', 25, 'pagetemplate'),
    ('ssti', 25, 'render_template'),
    ('ssti', 25, 'template'),
    ('ssti', 25, 'template_code'),
    ('ssti', 25, 'template_content'),
    ('ssti', 25, 'template_engine'),
    ('ssti', 25, 'template_name'),
    ('ssti', 25, 'templatecode'),
    ('ssti', 25, 'templatecontent'),
    ('ssti', 25, 'templateengine'),
    ('ssti', 25, 'templatename'),
    ('ssti', 25, 'templatestring'),
    ('ssti', 25, 'theme'),
    ('ssti', 25, 'tpl'),
    ('ssti', 25, 'view'),
    ('upload_fields', 30, 'attachment'),
    ('upload_fields', 30, 'avatar'),
    ('upload_fields', 30, 'content_type'),
    ('upload_fields', 30, 'document'),
    ('upload_fields', 30, 'filename'),
    ('upload_fields', 30, 'image'),
    ('upload_fields', 30, 'media'),
    ('upload_fields', 30, 'photo'),
    ('upload_fields', 30, 'upload'),
    ('webhook', 30, 'target'),
    ('websocket', 30, 'room'),
    ('websocket', 30, 'topic'),
    ('wordpress', 35, 'rest_route'),
    ('xss', 20, 'comment'),
    ('xss', 20, 'content'),
    ('xss', 20, 'data'),
    ('xss', 20, 'input'),
    ('xss', 20, 'keyword'),
    ('xss', 20, 'message'),
    ('xss', 20, 'q'),
    ('xss', 20, 'search'),
    ('xss', 20, 'text'),
    ('xxe', 40, 'rss'),
    ('xxe', 40, 'soap'),
    ('xxe', 40, 'wsdl'),
    ('xxe', 40, 'xml'),
)


@pytest.mark.parametrize(
    "bucket_name,weight,key",
    _KEY_CASES,
    ids=[f"{b}:{k}" for b, _w, k in _KEY_CASES],
)
def test_curated_param_key_reaches_its_bucket(bucket_name: str, weight: int, key: str) -> None:
    result = _classify(url_path="/generic-endpoint", **{key: "x"})
    assert bucket_name in result["matched_buckets"], (
        f"key {key!r} no longer reaches bucket {bucket_name!r} "
        f"(matched={result['matched_buckets']})"
    )
    assert weight == next(w for n, w, _k, _p in cb._BUCKETS if n == bucket_name)


# ---------------------------------------------------------------------------
# Vocabulary sweep -- path fragments.
#
# One row per curated path fragment that never fired in the existing corpus,
# EXCLUDING the 15 within-bucket REDUNDANT fragments (see the module
# docstring). Each fixture's url_path is the fragment itself, verbatim:
# `_fragment_pattern` (classify_buckets.py:1824) strips a trailing "/" before
# anchoring, so a fragment used verbatim as the entire url_path always
# satisfies its own boundary lookahead (either the next char after the
# stripped core is the trailing "/" itself, or the core reaches end-of-string
# -- both are members of the boundary set `(?=[/?#=&.]|$)`).
# ---------------------------------------------------------------------------

_FRAGMENT_CASES: tuple[tuple[str, int, str], ...] = (
    ('api', 20, '/apexrest/'),
    ('auth', 40, '/2fa'),
    ('auth', 40, '/auth/login'),
    ('auth', 40, '/auth/signin'),
    ('auth', 40, '/authenticate'),
    ('auth', 40, '/logout'),
    ('auth', 40, '/otp'),
    ('auth', 40, '/saml/sso'),
    ('auth', 40, '/sign-in'),
    ('auth', 40, '/sign-on'),
    ('auth', 40, '/sign-out'),
    ('auth', 40, '/signon'),
    ('auth', 40, '/totp'),
    ('cms_db_admin', 35, '/adminer'),
    ('cms_db_admin', 35, '/dbadmin'),
    ('cms_db_admin', 35, '/ghost'),
    ('cms_db_admin', 35, '/manager/html'),
    ('cms_db_admin', 35, '/pma'),
    ('cms_db_admin', 35, '/sitecore'),
    ('cms_db_admin', 35, '/typo3'),
    ('cms_db_admin', 35, '/umbraco'),
    ('debug_logic', 30, '/.env'),
    ('debug_logic', 30, '/.git'),
    ('debug_logic', 30, '/_profiler'),
    ('debug_logic', 30, '/backup'),
    ('debug_logic', 30, '/cargo.toml'),
    ('debug_logic', 30, '/console'),
    ('debug_logic', 30, '/dbg'),
    ('debug_logic', 30, '/dev'),
    ('debug_logic', 30, '/internal'),
    ('debug_logic', 30, '/libs.versions.toml'),
    ('debug_logic', 30, '/manage'),
    ('debug_logic', 30, '/mgmt'),
    ('debug_logic', 30, '/npm-shrinkwrap.json'),
    ('debug_logic', 30, '/phpinfo'),
    ('debug_logic', 30, '/pipfile'),
    ('debug_logic', 30, '/readyz'),
    ('debug_logic', 30, '/server-info'),
    ('debug_logic', 30, '/settings.gradle'),
    ('debug_logic', 30, '/stage'),
    ('debug_logic', 30, '/staging'),
    ('debug_logic', 30, '/test'),
    ('deserialization', 40, '/deserialize'),
    ('deserialization', 40, '/java-serial'),
    ('deserialization', 40, '/marshal'),
    ('deserialization', 40, '/pickle'),
    ('deserialization', 40, '/unmarshal'),
    ('devops_console', 30, '/_cat/'),
    ('devops_console', 30, '/api/v4/projects'),
    ('devops_console', 30, '/druid'),
    ('devops_console', 30, '/hystrix'),
    ('devops_console', 30, '/jenkins'),
    ('devops_console', 30, '/jolokia'),
    ('devops_console', 30, '/kibana'),
    ('devops_console', 30, '/solr/'),
    ('dotnet_handler', 40, '/elmah.axd'),
    ('dotnet_handler', 40, '/trace.axd'),
    ('graphql', 45, '/api/graphql'),
    ('idp_admin', 35, '/admin/master/console'),
    ('idp_admin', 35, '/as/authorization.oauth2'),
    ('idp_admin', 35, '/as/clients.oauth2'),
    ('idp_admin', 35, '/auth/admin'),
    ('idp_admin', 35, '/idp/'),
    ('idp_admin', 35, '/nidp/'),
    ('img_traversal', 35, '/image/'),
    ('img_traversal', 35, '/images/'),
    ('img_traversal', 35, '/img/'),
    ('img_traversal', 35, '/photo/'),
    ('img_traversal', 35, '/thumb/'),
    ('img_traversal', 35, '/thumbnail/'),
    ('interestingext', 10, '.bak'),
    ('interestingext', 10, '.bkp'),
    ('interestingext', 10, '.cnf'),
    ('interestingext', 10, '.conf'),
    ('interestingext', 10, '.config'),
    ('interestingext', 10, '.crt'),
    ('interestingext', 10, '.csr'),
    ('interestingext', 10, '.dat'),
    ('interestingext', 10, '.ds_store'),
    ('interestingext', 10, '.gitlab-ci.yml'),
    ('interestingext', 10, '.hg'),
    ('interestingext', 10, '.ini'),
    ('interestingext', 10, '.key'),
    ('interestingext', 10, '.log'),
    ('interestingext', 10, '.mdb'),
    ('interestingext', 10, '.old'),
    ('interestingext', 10, '.pac'),
    ('interestingext', 10, '.pem'),
    ('interestingext', 10, '.pwd'),
    ('interestingext', 10, '.rdp'),
    ('interestingext', 10, '.sql'),
    ('interestingext', 10, '.swo'),
    ('interestingext', 10, '.swp'),
    ('interestingext', 10, '.terraform'),
    ('jwt', 30, '/bearer'),
    ('jwt', 30, '/refresh-token'),
    ('llm_api', 40, '/completions'),
    ('llm_api', 40, '/embeddings'),
    ('llm_api', 40, '/inference'),
    ('nosqli', 35, '/_msearch'),
    ('oauth-oidc', 35, '/.well-known/jwks.json'),
    ('oauth-oidc', 35, '/.well-known/oauth-authorization-server'),
    ('oauth-oidc', 35, '/connect/authorize'),
    ('oauth-oidc', 35, '/connect/userinfo'),
    ('oauth-oidc', 35, '/jwks.json'),
    ('object-storage', 25, '/blob/'),
    ('object-storage', 25, '/bucket/'),
    ('object-storage', 25, '/gcs/'),
    ('object-storage', 25, 'didc'),
    ('object-storage', 25, 'files.nsf'),
    ('rce', 50, '/cmd/'),
    ('rce', 50, '/shell/'),
    ('secret_vault', 45, '/api/secrets'),
    ('secret_vault', 45, '/credential-stores'),
    ('secret_vault', 45, '/credentials/retrieve'),
    ('secret_vault', 45, '/keyvault'),
    ('secret_vault', 45, '/secretsmanager'),
    ('secret_vault', 45, '/v1/secrets'),
    ('secret_vault', 45, '/values/retrieve'),
    ('servicenow', 30, '/$'),
    ('servicenow', 30, '/sp?'),
    ('servicenow', 30, '/sys_'),
    ('servicenow', 30, '/x_'),
    ('ssi', 30, '.shtm'),
    ('ssi', 30, '.shtml'),
    ('ssi', 30, '.stm'),
    ('sso', 35, '/cas/'),
    ('sso', 35, '/fed/'),
    ('sso', 35, '/sts/'),
    ('trust_surface', 35, '/convert'),
    ('trust_surface', 35, '/download'),
    ('trust_surface', 35, '/export'),
    ('trust_surface', 35, '/import'),
    ('trust_surface', 35, '/invite'),
    ('trust_surface', 35, '/oauth'),
    ('trust_surface', 35, '/preview'),
    ('trust_surface', 35, '/recover'),
    ('trust_surface', 35, '/reset'),
    ('trust_surface', 35, '/share'),
    ('trust_surface', 35, '/webhook'),
    ('upload_fields', 30, '/attach'),
    ('upload_fields', 30, '/media-upload'),
    ('upload_fields', 30, '/upload-file'),
    ('webhook', 30, '/hook'),
    ('webhook', 30, '/hooks'),
    ('webhook', 30, '/webhook'),
    ('websocket', 30, '/mqtt'),
    ('websocket', 30, '/sockjs'),
    ('websocket', 30, '/stomp'),
    ('websocket', 30, '/websocket'),
    ('websocket', 30, '/wss'),
    ('wordpress', 35, '/wp-content/debug.log'),
    ('wordpress', 35, '/wp-cron.php'),
    ('wordpress', 35, '/wp-login.php'),
    ('xxe', 40, '.wsdl'),
    ('xxe', 40, '/soap'),
)


@pytest.mark.parametrize(
    "bucket_name,weight,fragment",
    _FRAGMENT_CASES,
    ids=[f"{b}:{f}" for b, _w, f in _FRAGMENT_CASES],
)
def test_curated_path_fragment_reaches_its_bucket(bucket_name: str, weight: int, fragment: str) -> None:
    result = _classify(url_path=fragment)
    assert bucket_name in result["matched_buckets"], (
        f"fragment {fragment!r} no longer reaches bucket {bucket_name!r} "
        f"(matched={result['matched_buckets']})"
    )


# ---------------------------------------------------------------------------
# Vocabulary sweep -- regexes.
#
# Only one regex in the whole 11-entry `_REGEX_BUCKET_RULES` table never
# fired in the existing corpus: object-storage's Google Cloud Storage host
# marker. `bucket_matches` (classify_buckets.py:1847) tests every regex
# bucket rule against `url_path_lower` regardless of `_FULL_URL_REGEX_BUCKETS`
# membership, so embedding the host string in the url_path (as a real proxy/
# fetch target embedded in a path segment would appear) is a faithful
# fixture.
# ---------------------------------------------------------------------------

_REGEX_CASES: tuple[tuple[str, int, str, str], ...] = (
    ('object-storage', 25, 'storage\\.googleapis\\.com', '/fetch/storage.googleapis.com/mybucket/obj'),
)


@pytest.mark.parametrize(
    "bucket_name,weight,pattern,url_path",
    _REGEX_CASES,
    ids=[f"{b}:{p}" for b, _w, p, _u in _REGEX_CASES],
)
def test_curated_regex_reaches_its_bucket(bucket_name: str, weight: int, pattern: str, url_path: str) -> None:
    result = _classify(url_path=url_path)
    assert bucket_name in result["matched_buckets"], (
        f"regex {pattern!r} no longer reaches bucket {bucket_name!r} "
        f"(matched={result['matched_buckets']})"
    )


# ---------------------------------------------------------------------------
# Boundary precision -- negative cases the mechanical sweep above cannot
# express (it only asserts positive fires). These pin that the fragment/regex
# boundary machinery correctly REJECTS realistic near-miss paths, matching
# the module's own documented intent for each pattern.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "url_path",
    [
        "/version/1.0",   # segment "version", not "v"+digits
        "/v/1",            # segment "v" carries no digits
        "/vue/app",        # segment "vue", not "v"+digits
        "/v1beta/x",       # lookahead rejects a non-boundary char after the digits
    ],
)
def test_api_versioning_regex_rejects_near_miss_paths(url_path: str) -> None:
    result = _classify(url_path=url_path)
    assert "api-versioning" not in result["matched_buckets"]


def test_api_versioning_regex_accepts_a_real_versioned_segment() -> None:
    result = _classify(url_path="/api/v1/users")
    assert "api-versioning" in result["matched_buckets"]


def test_cloud_metadata_regex_rejects_a_plural_instances_collection_path() -> None:
    """`/metadata/instance(?=[/?#]|$)` (classify_buckets.py:992) must not fire on
    `/api/metadata/instances` -- the plural collection route is not the IMDS
    instance-identity endpoint (documented FP guard, classify_buckets.py:980-983)."""
    result = _classify(url_path="/api/metadata/instances")
    assert "cloud_metadata" not in result["matched_buckets"]


def test_cloud_metadata_regex_accepts_the_real_imds_path() -> None:
    result = _classify(url_path="/latest/meta-data/iam/")
    assert "cloud_metadata" in result["matched_buckets"]


def test_admin_fragment_rejects_a_content_slug_with_no_boundary() -> None:
    """`/admin` (debug_logic) must not fire on `/administration-guide` -- the
    next character after the fragment core is `i`, not a boundary char."""
    result = _classify(url_path="/administration-guide")
    assert "debug_logic" not in result["matched_buckets"]


def test_nsf_extension_fragment_rejects_a_similarly_spelled_file() -> None:
    """`.nsf` (object-storage) must not fire on `/notes.nsfx` -- next char `x`
    is not a boundary."""
    result = _classify(url_path="/notes.nsfx")
    assert "object-storage" not in result["matched_buckets"]


def test_login_fragment_rejects_a_login_prefixed_filename() -> None:
    """`/login` (auth) must not fire on `.../loginuserpass.php` -- the next
    char after the fragment core is `u`, not a boundary. This is also why
    SimpleSAMLphp's real default login route
    (`/simplesaml/module.php/core/loginuserpass.php`) gets NO classifier
    signal at all today (see the coverage-gaps section of the audit's final
    report: `/simplesaml`/`/shibboleth.sso` were deliberately left off the
    `sso` bucket's fragment list, per its own comment, to avoid a different
    demotion risk -- leaving this real, common SSO entry point unclassified)."""
    result = _classify(url_path="/simplesaml/module.php/core/loginuserpass.php")
    assert "auth" not in result["matched_buckets"]
    assert result["matched_buckets"] == []


# ---------------------------------------------------------------------------
# Cross-bucket duplicate keys/fragments -- tie-break behaviour.
#
# Documented (not bugs): when two buckets share a literal key/fragment, the
# HIGHER-weight bucket always wins `cluster_key`; the lower-weight bucket is
# still recorded in `matched_buckets`/`priority_reason` (never silently
# dropped). classify_buckets.py's own module docstring (lines 10-15) frames
# this as intentional: "Adding a marginal bucket at low weight is therefore
# strictly better than letting the URL drown in a path:<seg1>/<seg2>
# cluster." These pin that both halves of that contract hold for the exact
# literal duplicates this file's own vocabulary audit found.
# ---------------------------------------------------------------------------

def test_shared_webhook_fragment_trust_surface_outranks_the_dedicated_bucket() -> None:
    """`/webhook` is a literal member of BOTH `trust_surface` (w=35) and
    `webhook` (w=30) (classify_buckets.py:392, 633). trust_surface wins
    cluster_key; webhook is still recorded (not shadowed out of the reason
    chain, just out of the cluster-key pick)."""
    result = _classify(url_path="/webhook")
    assert result["cluster_key"] == "gf:trust_surface"
    assert set(result["matched_buckets"]) >= {"trust_surface", "webhook"}


def test_shared_wp_admin_fragment_wordpress_wins_the_weight_tie() -> None:
    """`/wp-admin` is a literal member of BOTH `wordpress` (w=35) and
    `cms_db_admin` (w=35) (classify_buckets.py:471, 491) -- an exact weight
    TIE. `wordpress` is declared first, so first-at-max-weight tie-break
    picks it for cluster_key; cms_db_admin is still recorded."""
    result = _classify(url_path="/wp-admin")
    assert result["cluster_key"] == "gf:wordpress"
    assert set(result["matched_buckets"]) >= {"wordpress", "cms_db_admin"}


def test_bare_query_key_is_multi_bucket_and_no_longer_misroutes_to_graphql() -> None:
    """`query` is a literal member of `graphql` (w=45), `sqli` (w=40), and
    `xss` (w=20). The `sqli`/`xss` overlap is a real, intentional multi-bucket
    signal and stays; the `graphql` membership needs corroboration, which a
    plain REST search route does not supply, so `sqli` wins the cluster (see
    the module docstring's misroute #2)."""
    result = _classify(url_path="/api/v1/products/search", query="widget")
    assert set(result["matched_buckets"]) >= {"sqli", "xss"}
    assert "graphql" not in result["matched_buckets"], result
    assert result["cluster_key"] == "gf:sqli"


# ---------------------------------------------------------------------------
# Compound open-redirect / SSRF keys -- precision layer (Fix 4) routing.
#
# `expand_compound_key` (classify_buckets.py:1725) splits ONLY on `.`/`[`/`]`
# -- never `_`/`-`/camelCase -- specifically so a bare `?return_url=` cannot
# tokenize down to its `url` suffix and mis-route to `gf:ssrf` (SSRF, weight
# 40) instead of `gf:redirect` (open redirect, weight 25). These pin that the
# compound names the brief singled out land where the curated whole-key
# families (classify_buckets.py:786-802 for redirect, 152-153 for ssrf) say
# they should. The `_url`/`_uri`-suffixed names additionally still reach
# `ssrf` as a SECONDARY (capped weak-token) signal via their inner `url`/`uri`
# token (`weak_tokens_for_key`, classify_buckets.py:1771) -- `next` has no
# such suffix (`weak_tokens_for_key("next") == {"next"}`, nothing to split),
# so it carries no secondary ssrf signal and is checked separately.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "key,expected_cluster",
    [
        ("return_url", "gf:redirect"),
        ("callback_url", "gf:redirect"),
        ("redirect_uri", "gf:oauth-oidc"),  # canonical OAuth key outranks redirect (w=35 > 25)
    ],
)
def test_curated_compound_key_lands_on_redirect_not_ssrf(key: str, expected_cluster: str) -> None:
    result = _classify(url_path="/app/go", **{key: "https://evil.example/"})
    assert result["cluster_key"] == expected_cluster
    assert "ssrf" in result["secondary_buckets"], (
        "the inner 'url'/'uri' token should still reach ssrf as a secondary "
        "(weak-token) signal, just never win cluster_key over the curated "
        f"whole-key match (matched={result['matched_buckets']!r}, "
        f"secondary={result['secondary_buckets']!r})"
    )


def test_bare_next_key_lands_on_redirect_with_no_secondary_ssrf_token() -> None:
    """`next` (classify_buckets.py:786) is a bare curated redirect key, not a
    compound `_url`/`_uri` name -- `weak_tokens_for_key("next")` has nothing
    to split, so (unlike `return_url`/`callback_url`/`redirect_uri` above) it
    carries no secondary ssrf signal at all."""
    result = _classify(url_path="/app/go", next="https://evil.example/")
    assert result["cluster_key"] == "gf:redirect"
    assert result["secondary_buckets"] == []


def test_image_url_compound_key_is_curated_ssrf_not_redirect() -> None:
    """Unlike the *_url family above, `image_url` is DELIBERATELY curated
    into `ssrf` (classify_buckets.py:152), not `redirect` -- the server
    fetches the image URL server-side (avatar/profile-picture SSRF), which is
    the classic bug-bounty pattern the bucket's own comment names
    (classify_buckets.py:134-144)."""
    result = _classify(url_path="/app/avatar", image_url="https://evil.example/")
    assert result["cluster_key"] == "gf:ssrf"


def test_expand_compound_key_never_splits_on_underscore_or_camelcase() -> None:
    """The strong `.`/`[`/`]`-only split (classify_buckets.py:1725), verified
    directly: `return_url` must stay whole (not decompose to {return, url})."""
    assert cb.expand_compound_key("return_url") == {"return_url"}
    assert cb.expand_compound_key("filter[user][id]") == {
        "filter[user][id]", "filter", "user", "id",
    }


# ---------------------------------------------------------------------------
# Meta-test -- the recall floor.
#
# Every one of the 40 real buckets must have at least one exercised key,
# fragment, or regex SOMEWHERE -- either in this file's sweep tables, or (for
# the two buckets that were already 100% covered by the existing suite
# before this file existed) via the explicit, commented allow-list below.
# This is what stops the curated vocabulary drifting back toward the
# 74.7%-untested state this file's docstring measured.
# ---------------------------------------------------------------------------

# Buckets with ZERO rows in this file's sweep tables, and why that is fine:
# both were already 100% exercised by the pre-existing 17-file corpus (see
# the module docstring) -- cloud_metadata: 7/7 regexes fired; api-versioning:
# 1/1 regex fired. Nothing for this file to add.
_PRE_COVERED_ELSEWHERE: frozenset[str] = frozenset({"cloud_metadata", "api-versioning"})


def test_every_bucket_has_at_least_one_exercised_entry_in_this_sweep() -> None:
    covered_in_this_file: set[str] = set()
    covered_in_this_file.update(name for name, _w, _k in _KEY_CASES)
    covered_in_this_file.update(name for name, _w, _f in _FRAGMENT_CASES)
    covered_in_this_file.update(name for name, _w, _p, _u in _REGEX_CASES)

    all_bucket_names = {name for name, _w, _k, _p in cb._BUCKETS}
    uncovered = all_bucket_names - covered_in_this_file - _PRE_COVERED_ELSEWHERE
    assert not uncovered, (
        f"buckets with NO exercised vocabulary anywhere (this file's sweep, "
        f"nor the pre-covered allow-list): {sorted(uncovered)} -- either add "
        f"rows to _KEY_CASES/_FRAGMENT_CASES/_REGEX_CASES above, or add the "
        f"bucket to _PRE_COVERED_ELSEWHERE with a cited reason."
    )
    # And the allow-list itself must not silently grow stale: both entries
    # really do have zero rows in this file's own tables (else they would
    # need their own sweep rows instead of an excuse).
    for name in _PRE_COVERED_ELSEWHERE:
        assert name not in covered_in_this_file, (
            f"{name!r} now has rows in this file's own sweep tables -- drop "
            f"it from _PRE_COVERED_ELSEWHERE, the allow-list reason no "
            f"longer applies"
        )


def test_previously_zero_coverage_buckets_are_now_exercised() -> None:
    """The six buckets the empirical sweep found with ZERO exercised
    vocabulary before this file existed (`xxe`, `img_traversal`,
    `prototype-pollution`, `mass-assignment`, `ssi`, `cors`) must each have
    at least one row in this file's own sweep tables -- not merely be absent
    from `_PRE_COVERED_ELSEWHERE`, which only excuses the two buckets that
    were ALREADY fully covered elsewhere."""
    previously_zero = {
        "xxe", "img_traversal", "prototype-pollution", "mass-assignment",
        "ssi", "cors",
    }
    covered_in_this_file: set[str] = set()
    covered_in_this_file.update(name for name, _w, _k in _KEY_CASES)
    covered_in_this_file.update(name for name, _w, _f in _FRAGMENT_CASES)
    covered_in_this_file.update(name for name, _w, _p, _u in _REGEX_CASES)
    missing = previously_zero - covered_in_this_file
    assert not missing, f"still-zero-coverage buckets: {sorted(missing)}"
