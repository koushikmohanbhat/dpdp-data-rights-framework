"""Plug-in registry.

Everything that touches a specific cloud, product or client system is a plug-in in one of these groups.
Built-ins register themselves here; other packages add plug-ins through Python entry points, so partners
can ship connectors, detectors and the rest as separate packages without forking this repository.

    # pyproject.toml of a plug-in package
    [project.entry-points."dpdp_rights.connectors"]
    zendesk = "acme_dpdp.zendesk:ZendeskConnector"

The entry-point name is the type name used in configs (``type: zendesk``). Built-in names cannot be
overridden. What each group's object must be:

=================  ============================================================================
group              entry point loads
=================  ============================================================================
connectors         a ``Connector`` subclass with ``supports`` and ``capabilities`` declared
detectors          a callable ``(**options) -> object with detect(text) -> list[Entity]``
key_wrappers       a callable ``(vault_config, sealed: bool) -> KeyWrapper``
vault_storage      a callable ``(vault_config, lineage_url) -> VaultStorage``
providers          a callable ``(provider_config) -> LLMProvider``
queues             a callable ``(lineage_store, queue_config) -> queue`` (``JobQueue`` interface)
notifiers          a callable ``(**options) -> object with notify(event: str, payload: dict)``
=================  ============================================================================
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from importlib import metadata
from typing import Any, Callable

log = logging.getLogger("dpdp_rights.plugins")

GROUPS = ("connectors", "detectors", "key_wrappers", "vault_storage", "providers", "queues", "notifiers")
ENTRY_POINT_PREFIX = "dpdp_rights."


@dataclass
class PluginInfo:
    group: str
    name: str
    source: str                 # "builtin" or "<distribution> <version>"
    target: str                 # import path
    error: str | None = None


_builtins: dict[str, dict[str, Callable[..., Any]]] = {g: {} for g in GROUPS}
_external: dict[str, dict[str, Any]] | None = None
_external_info: list[PluginInfo] = []


def register_builtin(group: str, name: str, factory: Callable[..., Any]) -> None:
    _builtins[group][name] = factory


def _load_external() -> dict[str, dict[str, Any]]:
    global _external
    if _external is not None:
        return _external
    _external = {g: {} for g in GROUPS}
    for group in GROUPS:
        try:
            eps = metadata.entry_points(group=ENTRY_POINT_PREFIX + group)
        except Exception as exc:  # noqa: BLE001 - a broken environment must not stop the framework
            log.warning("could not read entry points for %s: %s", group, exc)
            continue
        for ep in eps:
            dist = getattr(ep, "dist", None)
            source = f"{dist.name} {dist.version}" if dist else "unknown package"
            info = PluginInfo(group, ep.name, source, ep.value)
            if ep.name in _builtins[group]:
                info.error = "name clashes with a built-in; ignored"
            else:
                _external[group][ep.name] = ep           # loaded lazily on first use
            _external_info.append(info)
    return _external


def reset() -> None:
    """Forget discovered entry points (tests, or after installing a package at runtime)."""
    global _external
    _external = None
    _external_info.clear()


def get(group: str, name: str) -> Any:
    """The factory registered as ``name`` in ``group``; built-ins first, then installed plug-ins."""
    if group not in GROUPS:
        raise ValueError(f"unknown plug-in group {group}")
    if name in _builtins[group]:
        return _builtins[group][name]
    ext = _load_external()[group]
    if name not in ext:
        raise ValueError(f"Unknown {group[:-1].replace('_', ' ')} '{name}'. Available: {available(group)}. "
                         f"To add one, install a package that declares the entry point "
                         f"'{ENTRY_POINT_PREFIX}{group}'.")
    obj = ext[name]
    if isinstance(obj, metadata.EntryPoint):
        try:
            obj = ext[name] = obj.load()
        except Exception as exc:
            for i in _external_info:
                if i.group == group and i.name == name:
                    i.error = f"failed to load: {exc}"
            raise ValueError(f"plug-in '{name}' ({group}) failed to load: {exc}") from exc
    return obj


def available(group: str) -> list[str]:
    return sorted(set(_builtins[group]) | set(_load_external()[group]))


def listing() -> list[PluginInfo]:
    """Every plug-in, built-in and installed, for ``dpdp-rights plugins``."""
    _ensure_builtins()
    _load_external()
    out = [PluginInfo(g, n, "builtin", f"{getattr(f, '__module__', '?')}.{getattr(f, '__qualname__', '?')}")
           for g in GROUPS for n, f in sorted(_builtins[g].items())]
    return out + list(_external_info)


def _ensure_builtins() -> None:
    """Import the modules whose import registers the built-ins."""
    from .connectors import base as _cb

    _cb.load_builtin_connectors()
    from . import notify as _n  # noqa: F401
    from .jobs import queue as _q  # noqa: F401
    from .pii import detectors as _d  # noqa: F401
    from .providers import base as _p  # noqa: F401
    from .vault import keys as _k  # noqa: F401
