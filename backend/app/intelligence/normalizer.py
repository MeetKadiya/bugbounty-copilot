"""Normalize discovered endpoint URLs into path templates.

Endpoints that only differ by a variable identifier are collapsed into one
template, e.g.:

    /api/users/1
    /api/users/2
    /api/users/100

    ->  /api/users/{id}

This is purely structural (regex/heuristic) analysis -- it never issues a
network request.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List, Optional
from urllib.parse import parse_qs, urlparse

_NUMERIC_RE = re.compile(r"^\d+$")
_UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
_MONGO_ID_RE = re.compile(r"^[0-9a-fA-F]{24}$")
_HEX_RE = re.compile(r"^[0-9a-fA-F]{16,}$")
# Alphanumeric slug-like identifiers -- must mix letters and digits, no other
# heuristic already claimed it, and be long enough that it's unlikely to be a
# meaningful static path segment (e.g. "v2", "faq").
_ALNUM_ID_RE = re.compile(r"^(?=.*[0-9])(?=.*[a-zA-Z])[a-zA-Z0-9_-]{8,}$")

# Static segments that look identifier-ish but should never be templated.
_SEGMENT_STOPWORDS = {
    "api", "v1", "v2", "v3", "graphql", "rest", "rpc", "static", "assets",
}


@dataclass
class PathParam:
    index: int
    placeholder: str
    example_value: str
    kind: str  # numeric | uuid | mongo_id | hex | alnum_id


@dataclass
class NormalizedEndpoint:
    hostname: str
    normalized_path: str
    path_params: List[PathParam] = field(default_factory=list)
    query_param_names: List[str] = field(default_factory=list)


def _classify_segment(segment: str) -> Optional[str]:
    lowered = segment.lower()
    if lowered in _SEGMENT_STOPWORDS:
        return None
    if _NUMERIC_RE.match(segment):
        return "numeric"
    if _UUID_RE.match(segment):
        return "uuid"
    if _MONGO_ID_RE.match(segment):
        return "mongo_id"
    if _HEX_RE.match(segment):
        return "hex"
    if _ALNUM_ID_RE.match(segment):
        return "alnum_id"
    return None


def normalize_url(url: str) -> NormalizedEndpoint:
    """Parse a URL into (hostname, normalized_path, path_params, query_params)."""
    parsed = urlparse(url)
    hostname = (parsed.netloc or "").lower()
    segments = [s for s in parsed.path.split("/") if s != ""]

    normalized_segments: List[str] = []
    path_params: List[PathParam] = []
    id_counter = 0

    for idx, seg in enumerate(segments):
        kind = _classify_segment(seg)
        if kind:
            id_counter += 1
            placeholder = "{id}" if id_counter == 1 else f"{{id{id_counter}}}"
            path_params.append(
                PathParam(index=idx, placeholder=placeholder, example_value=seg, kind=kind)
            )
            normalized_segments.append(placeholder)
        else:
            normalized_segments.append(seg)

    normalized_path = "/" + "/".join(normalized_segments) if segments else "/"
    query_param_names = list(parse_qs(parsed.query).keys())

    return NormalizedEndpoint(
        hostname=hostname,
        normalized_path=normalized_path,
        path_params=path_params,
        query_param_names=query_param_names,
    )
