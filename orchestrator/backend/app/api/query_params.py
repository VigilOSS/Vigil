"""Refusal of query keys a route does not declare.

FastAPI drops undeclared query params, so a mistyped filter name returns the
unfiltered listing: a wrong answer that looks like a right one. A route that
depends on ``reject_unknown_query_params`` answers 400 naming the unknown keys
and every key it accepts. The accepted set is read off the route's own
signature (its query params and those of its sub-dependencies, by alias), so it
never drifts from what the endpoint actually reads.
"""
from __future__ import annotations

from collections.abc import Callable, Sequence
from typing import Any

from fastapi import Depends, HTTPException, Request, status
from fastapi.dependencies.models import Dependant
from fastapi.routing import APIRoute
from pydantic import BaseModel

# A refusal names the route the way the CLI does: relative to the assessment
# API, or to the engagement for the engagement-level families.
_ROUTE_LABEL_PREFIXES = (
    "/engagements/{engagement_key}/assessment/",
    "/engagements/{engagement_key}/",
)

# Routes are unhashable, so each route carries its own accepted set once read.
_ACCEPTED_ATTR = "_declared_query_params"


def _declared_query_params(dependant: Dependant) -> frozenset[str]:
    names: set[str] = set()
    pending = [dependant]
    while pending:
        current = pending.pop()
        for field in current.query_params:
            annotation = field.field_info.annotation
            if isinstance(annotation, type) and issubclass(annotation, BaseModel):
                # A query-parameter model is read field by field.
                names.update(
                    model_field.alias or name
                    for name, model_field in annotation.model_fields.items()
                )
            else:
                names.add(field.alias)
        pending.extend(current.dependencies)
    return frozenset(names)


def reject_unknown_query_params(request: Request) -> None:
    """Refuse the request when it carries a query key the route does not read."""
    route: APIRoute = request.scope["route"]
    accepted: frozenset[str] | None = getattr(route, _ACCEPTED_ATTR, None)
    if accepted is None:
        accepted = _declared_query_params(route.dependant)
        setattr(route, _ACCEPTED_ATTR, accepted)
    # A path param is the path's own; sent as a query key it is unknown.
    accepted = accepted - set(request.path_params)
    unknown = sorted(set(request.query_params) - accepted)
    if unknown:
        label = route.path
        for prefix in _ROUTE_LABEL_PREFIXES:
            if label.startswith(prefix):
                label = label.removeprefix(prefix)
                break
        label = label.lstrip("/") or label
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                f"{label} does not accept query params: {', '.join(unknown)}. "
                f"Accepted: {', '.join(sorted(accepted)) or '(none)'}"
            ),
        )


REJECT_UNKNOWN_QUERY_PARAMS = Depends(reject_unknown_query_params)


class DeclaredQueryParamsRoute(APIRoute):
    """An ``APIRoute`` whose GET endpoints depend on ``reject_unknown_query_params``.

    Every API router passes it as ``route_class`` (an included router keeps its
    own route class, so a sub-router declares it too), so every list/fetch route
    refuses undeclared query keys; writes keep their own validation. App-level
    GET routes depend on ``REJECT_UNKNOWN_QUERY_PARAMS`` directly, except the SPA
    fallback, whose query string belongs to the frontend router.
    """

    def __init__(
        self,
        path: str,
        endpoint: Callable[..., Any],
        *,
        methods: set[str] | list[str] | None = None,
        dependencies: Sequence[Any] | None = None,
        **kwargs: Any,
    ) -> None:
        if methods is not None and "GET" in {method.upper() for method in methods}:
            dependencies = [*(dependencies or ()), REJECT_UNKNOWN_QUERY_PARAMS]
        super().__init__(
            path, endpoint, methods=methods, dependencies=dependencies, **kwargs
        )
