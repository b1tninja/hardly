"""hardly — HAR analysis for agents (MCP + library).

Public Python API: exactly the names in ``__all__`` (``open_session``, ``Session`` and the error
classes). Everything else, in particular ``hardly.core.*``, ``hardly.index.*``, ``hardly.capture*``
and any name starting with an underscore, is internal and may change in any release. The compatibility
policy is docs/api-stability.md.
"""

__version__ = "0.2.30"

# Public Python API (lazy, so `import hardly` stays cheap for the CLI).
_API = (
    "open_session",
    "Session",
    "SessionError",
    "UnknownSession",
    "OutputExists",
    "OutputError",
    "IndexOutdated",
    "HarNotFound",
    "session_id_for",
)
__all__ = ["__version__", *_API]


def __getattr__(name: str):
    if name in _API:
        from hardly import session

        return getattr(session, name)
    raise AttributeError(f"module 'hardly' has no attribute {name!r}")
