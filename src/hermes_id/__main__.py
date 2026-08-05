"""Allow ``python -m hermes_id`` to invoke the CLI."""
from hermes_id.cli import main

if __name__ == "__main__":  # pragma: no cover — only run via `python -m`
    import sys
    sys.exit(main())
