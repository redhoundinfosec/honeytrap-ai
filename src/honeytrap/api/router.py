"""Tiny decorator-style HTTP router used by the management API.

Routes are declared against an :class:`Router` instance via the
:meth:`Router.route` decorator. Path templates use ``{name}`` placeholders
which are parsed as handler keyword arguments. The router is designed
for a fixed, small route set known at import time -- there is no trie,
just a linear scan over precompiled regexes, which is ample for the
low-tens of endpoints we expose.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from honeytrap.api.rbac import Role

Handler = Callable[..., Any]
_PLACEHOLDER_RE = re.compile(r"\{([a-zA-Z_][a-zA-Z0-9_]*)\}")


@dataclass
class Route:
    """A single registered route."""

    path: str
    methods: tuple[str, ...]
    handler: Handler
    required_role: Role | None
    summary: str
    tags: tuple[str, ...]
    public: bool = False
    pattern: re.Pattern[str] = field(init=False, repr=False)
    param_names: tuple[str, ...] = field(init=False, repr=False)

    def __post_init__(self) -> None:
        """Compile the path template into a regex and capture param names."""
        names: list[str] = []

        def _sub(match: re.Match[str]) -> str:
            names.append(match.group(1))
            return f"(?P<{match.group(1)}>[^/]+)"

        regex = _PLACEHOLDER_RE.sub(_sub, self.path)
        object.__setattr__(self, "pattern", re.compile(f"^{regex}$"))
        object.__setattr__(self, "param_names", tuple(names))

    def match(self, path: str) -> dict[str, str] | None:
        """Return parsed path params if ``path`` matches, else None."""
        m = self.pattern.match(path)
        if m is None:
            return None
        return m.groupdict()


class Router:
    """Registry of :class:`Route` objects with decorator-style registration."""

    def __init__(self) -> None:
        """Create an empty router."""
        self._routes: list[Route] = []

    def route(
        self,
        path: str,
        *,
        methods: list[str] | tuple[str, ...] | None = None,
        role: Role | str | None = None,
        summary: str = "",
        tags: list[str] | tuple[str, ...] | None = None,
        public: bool = False,
    ) -> Callable[[Handler], Handler]:
        """Decorator: register ``handler`` for ``path`` with the given methods."""
        methods_tuple = tuple(m.upper() for m in (methods or ["GET"]))
        role_obj: Role | None = Role.from_str(role) if isinstance(role, str) else role
        tags_tuple = tuple(tags or [])

        def decorator(handler: Handler) -> Handler:
            self._routes.append(
                Route(
                    path=path,
                    methods=methods_tuple,
                    handler=handler,
                    required_role=role_obj,
                    summary=summary or handler.__doc__ or handler.__name__,
                    tags=tags_tuple,
                    public=public,
                )
            )
            return handler

        return decorator

    def match(self, method: str, path: str) -> tuple[Route, dict[str, str]] | None:
        """Find the route for ``(method, path)``.

        Returns the matched route plus parsed path params, or ``None``
        when no route matches. A path that matches a registered route
        but with the wrong method causes the returned route to have
        method ``"<METHOD_NOT_ALLOWED>"`` so the caller can emit 405.
        """
        method_upper = method.upper()
        method_mismatch: tuple[Route, dict[str, str]] | None = None
        for route in self._routes:
            params = route.match(path)
            if params is None:
                continue
            if method_upper in route.methods:
                return route, params
            method_mismatch = (route, params)
        return method_mismatch

    def iter_routes(self) -> list[Route]:
        """Return a snapshot list of all registered routes."""
        return list(self._routes)


def extract_method_not_allowed(match: tuple[Route, dict[str, str]] | None, method: str) -> bool:
    """Return True when ``match`` exists but its route does not accept ``method``."""
    if match is None:
        return False
    route, _ = match
    return method.upper() not in route.methods
