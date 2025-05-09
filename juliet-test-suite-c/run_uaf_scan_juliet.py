#!/usr/bin/env python3

import os
import re
import sys
import time
import argparse
import subprocess
import importlib.util
from pathlib import Path
from typing import Callable

def TPR(tp: int, fn: int) -> float:
    """
    Calculate the True Positive Rate.
    """
    return tp / (tp + fn) * 100

def TNR(tn: int, fp: int) -> float:
    """
    Calculate the True Negative Rate.
    """
    return tn / (tn + fp) * 100

def ACC(tp: int, tn: int, fp: int, fn: int) -> float:
    """
    Calculate the Accuracy.
    """
    return (tp + tn) / (tp + tn + fp + fn) * 100

def print_with_timestamp(contents: str) -> None:
    """
    Print a string with the timestamp at the beginning of the line.
    """
    print(f'[{time.ctime(None)}] {contents}')

def print_results(pos: int, neg: int, res: dict) -> None:
    """
    Print overall TPR, TNR and ACC.
    """
    name = 'CWE-416: Use-After-Free'
    tpr_w = TPR(res['TP'], res['FN'])
    acc_w = ACC(res['TP'], res['TN'], res['FP'], res['FN'])
    tnr = TNR(res['TN'], res['FP'])

    print()
    print('=' * (len(name) + 6))
    print(f'| {name}{" " * 4}|')
    print("=" * (len(name) + 6))
    print()
    print("Positive cases: {:>12}".format(pos))
    print("Negative cases: {:>12}".format(neg))
    print()
    print("True Positive:  {:>12}".format(res['TP']))
    print("False Positive: {:>12}".format(res['FP']))
    print("True Negative:  {:>12}".format(res['TN']))
    print("False Negative: {:>12}".format(res['FN']))
    print()
    print("TPR:            {:>12}".format(str(f"{tpr_w:.{2}f}%")))
    print("TNR:            {:>12}".format(str(f"{tnr:.{2}f}%")))
    print("ACC:            {:>12}".format(str(f"{acc_w:.{2}f}%")))
    print()

def convert_seconds_to_dhms(seconds: int) -> str:
    """
    Converts seconds into days, hours, minutes, seconds
    """
    if seconds >= 0 and seconds < 1:
        seconds = round(seconds, 2)
        return f'{seconds} seconds'
    seconds = int(round(seconds))
    minutes, seconds = divmod(seconds, 60)
    hours, minutes = divmod(minutes, 60)
    days, hours = divmod(hours, 24)
    formatStr = "{0} day{1}, {2} hour{3}, {4} minute{5}, {6} second{7}"
    output = formatStr.format( \
        days,    "" if days==1 else "s", \
        hours,   "" if hours==1 else "s", \
        minutes, "" if minutes==1 else "s", \
        seconds, "" if seconds==1 else "s")
    return output

def find_files_in_dir(directory: str, regex: str) -> list[str]:
    """
    Find files (non-directory) that match a regex in a certain directory. (recursively, case-insensitive)
    """
    matching_files = []
    for root, dirs, files in os.walk(directory):
        files.sort()
        files = [Path(root) / file_name for file_name in files if re.search(regex, file_name, re.IGNORECASE)]
        matching_files.extend(files)
    return matching_files

def get_cpp_name(file_name: str) -> str:
    """
    Turn <file_name>_bad into <file_name>3bad.
    C++ functions end with 3bad or 3good instead of _bad or _good.
    """
    return '3'.join(file_name.rsplit('_', 1))

def check_occurrence(file_name: str, output: bytes) -> None:
    """
    Check the occurences of correctly identified CWEs.
    """
    occurrence = 0
    output = output.decode('utf-8')
    for line in output.splitlines():
        if 'Call stack' in line and (file_name in line or get_cpp_name(file_name) in line):
            occurrence += 1
    return occurrence

def get_results(results: dict, file_name: str, detected: int) -> None:
    """
    Check if the correct amount of CWEs was detected and
    save if the test case is a true/false positve/negative.
    """
    # ANSI escape sequences for colored text
    RED = '\033[1;31m'
    GREEN = '\033[32m'
    RESET = '\033[0;0m'

    positive = True if file_name.endswith('bad') else False
    has_struct = True if 'struct' in file_name else False
    passed = f'{GREEN}PASSED: {file_name}\n{RESET}'
    failed = f'{RED}FAILED: {file_name}\n{RESET}' 
    if positive:
        if (not has_struct and detected == 1) or (has_struct and detected == 2):
            results['TP'] += 1
            print_with_timestamp(passed)
        else:
            results['FN'] += 1
            print_with_timestamp(failed)
    else:
        if detected == 0:
            results['TN'] += 1
            print_with_timestamp(passed)
        else:
            results['FP'] += 1
            print_with_timestamp(failed)

def run_analysis(test_case_path: Path, file_regex: str, run_analysis_fx: Callable) -> None:
    """
    Helper method to run an analysis using a tool.
    Takes a test case path and a function pointer.
    """
    positive = 0
    negative = 0
    results = {
        'TP' : 0,
        'FP' : 0,
        'TN' : 0,
        'FN' : 0
    }
    time_started = time.time()
    # find all the files
    files = find_files_in_dir(test_case_path, file_regex)
    # run all the files using the function pointer
    for test_file in files:
        output = run_analysis_fx(test_file)
        occurrence = check_occurrence(test_file.name, output)
        get_results(results, test_file.name, occurrence)
        if test_file.name.endswith('bad'):
            positive += 1
        else:
            negative += 1
    time_ended = time.time()
    print_with_timestamp(f'Started: {time.ctime(time_started)}')
    print_with_timestamp(f'Ended: {time.ctime(time_ended)}')
    elapsed_seconds = time_ended - time_started
    print_with_timestamp(f'Elapsed time: {convert_seconds_to_dhms(elapsed_seconds)}')
    print_results(positive, negative, results)

def run_uaf_scan(test_file: Path) -> bytes:
    """
    This method is called from the run_analysis method. It is called for
    each matching file. Files are matched against the regex specifed in main.
    """
    command = [f'../uaf_analysis/uaf_scan.py', test_file]
    print_with_timestamp(f'Running Use After Free analysis on {test_file.name}')
    output = subprocess.check_output(command, stderr=subprocess.PIPE)
    print(output.decode('utf-8'), end='')
    return output

def main() -> int:
    """
    Run the Use After Analysis on all Juliet test cases.
    """
    spec = importlib.util.find_spec('angr')
    if spec is not None:
        run_analysis('bin', 'CWE416', run_uaf_scan)
    else:
        print('ERROR: angr is not installed. Please install it with:')
        print('virtualenv --python=$(which python3) angr && source angr/bin/activate && pip install angr')
    return 0

if __name__ == '__main__':
    sys.exit(main())
