# Juliet Test Suite for CWE416 Use After Free
This folder contains the CWE416 testcases of the Juliet Test Suite for C/C++ version 1.3 from https://samate.nist.gov/SARD/testsuite.php augmented with a build script for Unix-like OSes and a script to measure True Positive and True Negative rates for the Use-After-Free analysis.

## Dependencies
```shell
sudo apt install cmake
```

## Build Executables
The build script supports automatically building test cases into individual executables. To build executables, `build_juliet.py` uses [CMakeLists.txt](https://github.com/arichardson/juliet-test-suite-c/blob/master/CMakeLists.txt) and runs cmake followed by make. Output appears by default in a `bin` subdirectory. The `bin/CWE416` directory is further divided into `bin/CWE416/good` and `bin/CWE416/bad` subdirectories. For each test case, a "good" binary that does not contain a Use After Free (UAF) is built and placed into the good subdirectory and a "bad" binary that contains a UAF is built and placed into the bad subdirectory.
```shell
unzip juliet-test-suite-for-CWE416.zip
./build_juliet.py -c && ./build_juliet.py
```

## Run Tests
The script runs the Use-After-Free analysis on all Juliet test cases and determines True Positives, False Positives, True Negatives and False Negatives for each test case.
```shell
./run_uaf_scan_juliet.py
```
