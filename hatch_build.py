"""Custom Hatch build hook to generate Python from .tl definitions."""

import itertools
import shutil
import sys
from pathlib import Path
from typing import Any

_BuildHookInterface: Any
try:
    from hatchling.builders.hooks.plugin.interface import (
        BuildHookInterface as _BuildHookInterface,
    )
except ImportError:

    class _FallbackBuildHookInterface:
        pass

    _BuildHookInterface = _FallbackBuildHookInterface


BuildHookInterface: Any = _BuildHookInterface


# Needed since we're importing local files
GENERATOR_DIR = Path("telethon_generator")
LIBRARY_DIR = Path("herokutl")

ERRORS_IN = GENERATOR_DIR / "data/errors.csv"
ERRORS_OUT = LIBRARY_DIR / "errors/rpcerrorlist.py"

METHODS_IN = GENERATOR_DIR / "data/methods.csv"

# Which raw API methods are covered by *friendly* methods in the client?
FRIENDLY_IN = GENERATOR_DIR / "data/friendly.csv"

TLOBJECT_IN_TLS = [Path(x) for x in GENERATOR_DIR.glob("data/*.tl")]
TLOBJECT_OUT = LIBRARY_DIR / "tl"
IMPORT_DEPTH = 2


class CustomBuildHook(BuildHookInterface):
    def _root(self) -> Path:
        return Path(self.root)

    def _build_dir(self) -> Path:
        return Path(self.directory)

    def _clean_generated_artifacts(self) -> None:
        build_dir = self._build_dir().resolve()
        root = self._root().resolve()
        generated_package = build_dir / LIBRARY_DIR

        if build_dir == root:
            clean_tl_dir = root / TLOBJECT_OUT
            clean_errors_file = root / ERRORS_OUT
        else:
            clean_tl_dir = generated_package / "tl"
            clean_errors_file = generated_package / "errors/rpcerrorlist.py"

        from telethon_generator.generators import clean_tlobjects

        clean_tlobjects(clean_tl_dir)
        if clean_errors_file.is_file():
            clean_errors_file.unlink()

        if build_dir != root and generated_package.is_dir():
            shutil.rmtree(generated_package)

    def clean(self, versions: list[str]) -> None:
        if self.root not in sys.path:
            sys.path.insert(0, self.root)

        self._clean_generated_artifacts()

    def initialize(self, version: str, build_data: dict[str, Any]) -> None:
        if self.root not in sys.path:
            sys.path.insert(0, self.root)

        self.clean([])
        if self.target_name == "sdist":
            return

        from telethon_generator.parsers import (
            parse_errors,
            parse_methods,
            parse_tl,
            find_layer,
        )

        from telethon_generator.generators import generate_errors, generate_tlobjects

        root = self._root()
        build_dir = self._build_dir()
        generated_tl_dir = build_dir / TLOBJECT_OUT
        generated_errors = build_dir / ERRORS_OUT

        layer = next(filter(None, map(lambda p: find_layer(root / p), TLOBJECT_IN_TLS)))
        errors = list(parse_errors(root / ERRORS_IN))
        methods = list(
            parse_methods(
                root / METHODS_IN,
                root / FRIENDLY_IN,
                {e.str_code: e for e in errors},
            )
        )

        tlobjects = list(
            itertools.chain(
                *(parse_tl(root / file, layer, methods) for file in TLOBJECT_IN_TLS)
            )
        )

        generate_tlobjects(tlobjects, layer, IMPORT_DEPTH, generated_tl_dir)
        generated_errors.parent.mkdir(parents=True, exist_ok=True)
        with generated_errors.open("w") as file:
            generate_errors(errors, file)

        build_data["force_include"][str(generated_tl_dir / "functions")] = str(
            TLOBJECT_OUT / "functions"
        )
        build_data["force_include"][str(generated_tl_dir / "types")] = str(
            TLOBJECT_OUT / "types"
        )
        build_data["force_include"][str(generated_tl_dir / "alltlobjects.py")] = str(
            TLOBJECT_OUT / "alltlobjects.py"
        )
        build_data["force_include"][str(generated_errors)] = str(ERRORS_OUT)

    def finalize(
        self, version: str, build_data: dict[str, Any], artifact_path: str
    ) -> None:
        self.clean([])
