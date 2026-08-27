"""Load the hyphenated scripts as importable modules."""

import importlib.util
import pathlib
import sys

SCRIPTS = pathlib.Path(__file__).resolve().parent.parent


def load(stem: str):
    """Import `scripts/<stem>.py` under a module name pytest can hold."""
    name = stem.replace("-", "_")
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / f"{stem}.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod
