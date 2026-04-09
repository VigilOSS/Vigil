"""URL type classification — replaces lib/classify.sh.

Pure Python regex replaces 30+ grep subprocess pairs per call.
Same classification priority order as the bash version.
"""
from __future__ import annotations

import json
import re

_WRITE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})

# Pre-compiled patterns (one-time cost)
_GRAPHQL_PATH = re.compile(r"/graphql", re.IGNORECASE)
_GRAPHQL_CT = re.compile(r"^application/graphql$", re.IGNORECASE)
_WS_SCHEME = re.compile(r"^wss?://", re.IGNORECASE)
_WS_PATH = re.compile(r"/ws(/|$)|^/socket\.io(/|$)", re.IGNORECASE)
_API_SPEC_PATH = re.compile(
    r"^/(api-docs|openapi(\.json)?|swagger(\.json|-ui(\.html)?)?|v[0-9]+/api-docs)(/|$)",
    re.IGNORECASE,
)
_API_PATH = re.compile(r"^/(api|rest)(/|$)|/v[0-9]+(/|$)", re.IGNORECASE)
_API_CT = re.compile(r"application/json", re.IGNORECASE)
_UPLOAD_CT = re.compile(r"multipart/form-data", re.IGNORECASE)
_FORM_CT = re.compile(r"application/x-www-form-urlencoded", re.IGNORECASE)
_JS_EXT = re.compile(r"\.js$", re.IGNORECASE)
_JS_CT = re.compile(r"text/javascript|application/javascript", re.IGNORECASE)
_CSS_EXT = re.compile(r"\.css$", re.IGNORECASE)
_CSS_CT = re.compile(r"text/css", re.IGNORECASE)
_PAGE_EXT = re.compile(r"\.(html?|xhtml|php|aspx?|jsp)$", re.IGNORECASE)
_PAGE_CT = re.compile(r"text/html|application/xhtml|image/svg\+xml", re.IGNORECASE)
_DATA_EXT = re.compile(r"\.(json|xml|csv|ya?ml|txt)$", re.IGNORECASE)
_DATA_CT = re.compile(
    r"application/json|application/xml|text/csv|text/xml|application/pdf|text/plain|application/ld\+json|text/markdown",
    re.IGNORECASE,
)
_IMAGE_CT = re.compile(r"^image/", re.IGNORECASE)
_SVG_CT = re.compile(r"svg", re.IGNORECASE)
_IMAGE_EXT = re.compile(r"\.(png|jpg|jpeg|gif|webp|ico|bmp|tiff|avif|apng)$", re.IGNORECASE)
_VIDEO_CT = re.compile(r"^(video|audio)/", re.IGNORECASE)
_VIDEO_EXT = re.compile(r"\.(mp4|webm|avi|mp3|wav|ogg)$", re.IGNORECASE)
_FONT_CT = re.compile(r"^font/|application/vnd\.ms-fontobject", re.IGNORECASE)
_FONT_EXT = re.compile(r"\.(woff|woff2|ttf|otf|eot)$", re.IGNORECASE)
_ARCHIVE_CT = re.compile(r"zip|gzip|tar|rar|7z|bzip", re.IGNORECASE)


def classify_type(method: str, url_path: str, content_type: str = "", body_snippet: str = "") -> str:
    """Classify a request into a case type. Same priority order as classify.sh."""
    method_upper = method.upper()
    ct_lower = content_type.lower() if content_type else ""
    path_no_query = url_path.split("?", 1)[0]
    is_write = method_upper in _WRITE_METHODS

    # 1. graphql
    if _GRAPHQL_PATH.search(url_path):
        return "graphql"
    if ct_lower and _GRAPHQL_CT.search(ct_lower):
        return "graphql"
    if body_snippet:
        try:
            obj = json.loads(body_snippet)
            qval = obj.get("query", "")
            if qval and "{" in qval and "}" in qval:
                return "graphql"
        except (json.JSONDecodeError, TypeError, AttributeError):
            pass

    # 2. websocket
    if _WS_SCHEME.search(url_path):
        return "websocket"
    if _WS_PATH.search(url_path):
        return "websocket"

    # 3. api-spec
    if _API_SPEC_PATH.search(url_path):
        return "api-spec"

    # 4. api
    if _API_PATH.search(url_path):
        return "api"
    if is_write and _API_CT.search(ct_lower):
        return "api"

    # 5. upload
    if _UPLOAD_CT.search(ct_lower):
        return "upload"

    # 6. form
    if method_upper in ("POST", "PUT") and _FORM_CT.search(ct_lower):
        return "form"

    # 7. javascript
    if _JS_EXT.search(path_no_query):
        return "javascript"
    if _JS_CT.search(ct_lower):
        return "javascript"

    # 8. stylesheet
    if _CSS_EXT.search(path_no_query):
        return "stylesheet"
    if _CSS_CT.search(ct_lower):
        return "stylesheet"

    # 9. page
    if _PAGE_EXT.search(path_no_query):
        return "page"
    if _PAGE_CT.search(ct_lower):
        return "page"

    # 10. data
    if _DATA_EXT.search(path_no_query):
        return "data"
    if _DATA_CT.search(ct_lower):
        return "data"

    # 11. image (excluding svg, already handled as page)
    if _IMAGE_CT.search(ct_lower) and not _SVG_CT.search(ct_lower):
        return "image"
    if _IMAGE_EXT.search(path_no_query):
        return "image"

    # 12. video/audio
    if _VIDEO_CT.search(ct_lower):
        return "video"
    if _VIDEO_EXT.search(path_no_query):
        return "video"

    # 13. font
    if _FONT_CT.search(ct_lower):
        return "font"
    if _FONT_EXT.search(path_no_query):
        return "font"

    # 14. archive
    if _ARCHIVE_CT.search(ct_lower):
        return "archive"

    # 15. unknown
    return "unknown"
