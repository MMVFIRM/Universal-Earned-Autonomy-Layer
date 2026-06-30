"""HTTP API (optional). Requires the [api] extra: pip install -e '.[api]'."""

def create_app(*args, **kwargs):
    from .server import create_app as _create_app
    return _create_app(*args, **kwargs)

__all__ = ["create_app"]
