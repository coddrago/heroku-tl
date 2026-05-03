"""Custom Hatch build hook to generate Python from .tl definitions."""

import itertools
import os
import sys
from pathlib import Path
from typing import Any

try:
    from hatchling.builders.hooks.plugin.interface import BuildHookInterface
except ImportError:
    class BuildHookInterface:
        pass

# Needed since we're importing local files
GENERATOR_DIR = Path('telethon_generator')
LIBRARY_DIR = Path('telethon')

ERRORS_IN = GENERATOR_DIR / 'data/errors.csv'
ERRORS_OUT = LIBRARY_DIR / 'errors/rpcerrorlist.py'

METHODS_IN = GENERATOR_DIR / 'data/methods.csv'

# Which raw API methods are covered by *friendly* methods in the client?
FRIENDLY_IN = GENERATOR_DIR / 'data/friendly.csv'

TLOBJECT_IN_TLS = [Path(x) for x in GENERATOR_DIR.glob('data/*.tl')]
TLOBJECT_OUT = LIBRARY_DIR / 'tl'
IMPORT_DEPTH = 2

class CustomBuildHook(BuildHookInterface):
    def clean(self, versions: list[str]) -> None:
        if self.root not in sys.path:
            sys.path.insert(0, self.root)

        from telethon_generator.generators import clean_tlobjects
        clean_tlobjects(self.directory / TLOBJECT_OUT)
        if (self.directory / ERRORS_OUT).is_file():
            (self.directory / ERRORS_OUT).unlink()

    def initialize(self, version: str, build_data: dict[str, Any]) -> None:
        if self.root not in sys.path:
            sys.path.insert(0, self.root)

        from telethon_generator.parsers import\
            parse_errors, parse_methods, parse_tl, find_layer

        from telethon_generator.generators import\
            generate_errors, generate_tlobjects

        layer = next(filter(None, map(lambda p: find_layer(self.root / p), TLOBJECT_IN_TLS)))
        errors = list(parse_errors(self.root / ERRORS_IN))
        methods = list(parse_methods(self.root / METHODS_IN, self.root / FRIENDLY_IN, {e.str_code: e for e in errors}))

        tlobjects = list(itertools.chain(*(
            parse_tl(self.root / file, layer, methods) for file in TLOBJECT_IN_TLS)))

        self.clean([])
        generate_tlobjects(tlobjects, layer, IMPORT_DEPTH, self.directory / TLOBJECT_OUT)
        (self.directory / ERRORS_OUT).parent.mkdir(parents=True, exist_ok=True)
        with (self.directory / ERRORS_OUT).open('w') as file:
            generate_errors(errors, file)

        build_data['force_include'][str(self.directory / LIBRARY_DIR)] = str(LIBRARY_DIR)

    def finalize(self, version: str, build_data: dict[str, Any], artifact_path: str) -> None:
        self.clean([])
