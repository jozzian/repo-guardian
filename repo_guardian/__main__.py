"""Package entry point so `python3 -m repo_guardian` runs the CLI."""

import sys

from .cli import main

if __name__ == "__main__":
    sys.exit(main())
