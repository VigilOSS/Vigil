"""Lossless JSON transport for authored data that includes lone surrogates."""

import json

from fastapi.responses import JSONResponse


class LosslessJSONResponse(JSONResponse):
    def render(self, content: object) -> bytes:
        try:
            return super().render(content)
        except UnicodeEncodeError:
            # Escaping preserves the exact parsed value without invalid UTF-8.
            return json.dumps(
                content,
                ensure_ascii=True,
                allow_nan=False,
                indent=None,
                separators=(",", ":"),
            ).encode("ascii")
