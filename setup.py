#!/usr/bin/env python3

import subprocess
import sys
import os
import glob
from pathlib import Path

from setuptools import Extension, setup
from Cython.Build import cythonize

REQUIRED_C_LIBS: tuple[str, ...] = ("libsepol", "libselinux")


def pkg_config(lib: str, flag: str) -> list[str]:
    """Query pkg-config for a library's compiler/linker flags."""
    try:
        return subprocess.check_output(
            ["pkg-config", flag, lib], text=True,
            stderr=subprocess.PIPE).split()
    except FileNotFoundError:
        sys.exit("Error: pkg-config not found. Install pkg-config.")
    except subprocess.CalledProcessError as e:
        print(e.stderr)
        sys.exit(f"Error: {lib} development files not found. "
                 f"Install {lib}-devel (RPM) or {lib}-dev (deb).")


# Library linkage
lib_dirs: list[str] = ['.']
include_dirs: list[str] = []

userspace_src = os.getenv("USERSPACE_SRC", "")
if userspace_src:
    userspace_path = Path(userspace_src)
    include_dirs.insert(0, str(userspace_path / "libsepol/include"))
    include_dirs.insert(1, str(userspace_path / "libselinux/include"))
    lib_dirs.insert(0, str(userspace_path / "libsepol/src"))
    lib_dirs.insert(1, str(userspace_path / "libselinux/src"))
elif not os.getenv("CFLAGS") or not os.getenv("LDFLAGS"):
    for lib in REQUIRED_C_LIBS:
        include_dirs.extend(f[2:] for f in pkg_config(lib, "--cflags") if f.startswith("-I"))
        lib_dirs.extend(f[2:] for f in pkg_config(lib, "--libs") if f.startswith("-L"))

macros: list[tuple[str, str | int]] = [('DARWIN',1)] if sys.platform.startswith('darwin') else []

# Code coverage.  Enable this to get coverage in the cython code.
enable_coverage = bool(os.getenv("SETOOLS_COVERAGE", ""))
if enable_coverage:
    macros.append(("CYTHON_TRACE", 1))

cython_annotate = bool(os.getenv("SETOOLS_ANNOTATE", ""))

ext_py_mods = [Extension('setools.policyrep', ['setools/policyrep.pyx'],
                         include_dirs=include_dirs,
                         libraries=['selinux', 'sepol'],
                         library_dirs=lib_dirs,
                         define_macros=macros,
                         extra_compile_args=['-Wextra',
                                             '-Waggregate-return',
                                             '-Wfloat-equal',
                                             '-Wformat', '-Wformat=2',
                                             '-Winit-self',
                                             '-Wmissing-format-attribute',
                                             '-Wmissing-include-dirs',
                                             '-Wnested-externs',
                                             '-Wold-style-definition',
                                             '-Wpointer-arith',
                                             '-Wstrict-prototypes',
                                             '-Wunknown-pragmas',
                                             '-Wwrite-strings',
                                             '-fno-exceptions'])]

linguas: set[Path] = set(Path(p) for p in os.getenv("LINGUAS", "").split(" ") if p)
if not linguas:
    linguas.add(Path("ru"))
linguas.add(Path("."))

base_source_path = Path("man")  # below source root
base_target_path = Path("share/man")  # below prefixdir, usually /usr or /usr/local
installed_data = list[tuple]()
for lang in linguas:
    source_path = base_source_path / lang
    if source_path.exists():
        for i in range(1, 9):
            installed_data.append((base_target_path / lang / f"man{i}",
                                   glob.glob(str(source_path / f"*.{i}"))))

# see pyproject.toml for most package options.
setup(data_files=installed_data,
      ext_modules=cythonize(ext_py_mods, include_path=['setools/policyrep'],
                            annotate=cython_annotate,
                            compiler_directives={"language_level": 3,
                                                 "c_string_type": "str",
                                                 "c_string_encoding": "ascii",
                                                 "linetrace": enable_coverage}))
