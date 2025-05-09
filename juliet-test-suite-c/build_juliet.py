#!/usr/bin/env python3

import re
import sys
import shutil
import argparse
import subprocess
from pathlib import Path

root_dir = Path(__file__).parent

def juliet_print(string: str) -> None:
    print(f'========== {string} ==========')

def get_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description='build Juliet test cases for CWE416')
    parser.add_argument('-c', '--clean', action='store_true', help='clean all CMake and Makefiles')
    parser.add_argument('-o', '--output-dir', action='store', default='bin', help='specify the output directory relative to the directory containing this script (default: bin)')
    args = parser.parse_args()
    return args

def clean(path: Path) -> None:
    """
    Clean all CMake and Makefiles.
    """
    try:
        (path / 'Makefile').unlink()
        (path / 'CMakeLists.txt').unlink()
        (path / 'CMakeCache.txt').unlink()
        (path / 'cmake_install.cmake').unlink()
        shutil.rmtree(path / 'CMakeFiles')
    except FileNotFoundError:
        pass

def generate(path: Path, output_dir: str) -> None:
    """
    Use CMake and make files.
    """
    shutil.copy(root_dir / 'CMakeLists.txt', path)
    retcode = subprocess.Popen(['cmake', f'-DOUTPUT_DIR:STRING={output_dir}', '.'], cwd=path).wait()
    if retcode != 0:
        juliet_print(f'error generating {path} - stopping')
        sys.exit(1)

def make(path: Path) -> None:
    """
    Use make to build test cases.
    """
    retcode = subprocess.Popen(['make', '-j16'], cwd=path).wait()
    if retcode != 0:
        juliet_print(f'error generating {path} - stopping')
        sys.exit(1)

def main() -> int:
    """
    Run cmake followed by make to build CWE416 test cases into individual executables.
    """
    args = get_args()
    testcases = root_dir / 'testcases'
    if not testcases.exists():
        juliet_print('no testcases directory')
        return 1
    if not (root_dir / 'CMakeLists.txt').exists():
        juliet_print('no CMakeLists.txt')
        return 1
    for subdir in testcases.iterdir():
        match = re.search('^CWE(\d+)', subdir.name)
        if match is not None:
            parsed_CWE = int(match.group(1))
            if parsed_CWE == 416:
                if args.clean:
                    juliet_print(f'cleaning {subdir}')
                    clean(subdir)
                else:
                    juliet_print(f'generating {subdir}')
                    generate(subdir, args.output_dir)
                    juliet_print(f'making {subdir}')
                    make(subdir)
    return 0

if __name__ == '__main__':
    sys.exit(main())
