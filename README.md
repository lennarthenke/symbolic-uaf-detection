# Finding Use-After-Free vulnerabilities using Symbolic Execution with angr
This folder contains the code for finding Use-After-Free (UAF) vulnerabilities in binary executables using [angr](https://angr.io/) and the data for the evaluation.

## Organization
* [uaf_analysis](./uaf_analysis/): Contains the code for the UAF analysis.
* [juliet-test-suite-c](./juliet-test-suite-c/): Contains the CWE416 test cases from the Juliet Test Suite, augmented with a build script and a script to measure the accuracy of the UAF analysis.
* [cves](./cves/): Contains real-world binaries with CVEs and results of the real-world analysis runs.
* [docs](./docs/) Contains thesis and slides:
  * [Bachelor Thesis (PDF)](docs/thesis.pdf)
  * [Presentation Slides (PDF)](docs/talk.pdf)


## Setup
To set up the environment, run the following command:
```shell
python3 -m venv angr --clear --upgrade-deps && source angr/bin/activate && pip install angr==9.2.48
```

## Usage 
To use the `uaf_scan` script provide the binary path as a positional argument:
```shell
usage: uaf_scan [-h] [-v] [-d] [-l] [-t] [-u [func_addrs ...]]
                [-g goal_addrs [goal_addrs ...]] [-e]
                binary_path

Script for finding Use-After-Free vulnerabilities using Symbolic Execution with
angr.

positional arguments:
  binary_path           path to the binary executable

options:
  -h, --help            show this help message and exit
  -v, --verbose         increase verbosity
  -d, --dfs             use depth first search (DFS) instead of breadth first
                        search (BFS)
  -l, --loopSeer        bound symbolic loops
  -t, --veritesting     use veritesting
  -u [func_addrs ...], --ucse [func_addrs ...]
                        use under-constrained symbolic execution (UCSE). Optionally
                        define function addresses to run (Default run all
                        functions)
  -g goal_addrs [goal_addrs ...], --goals goal_addrs [goal_addrs ...]
                        specify UAF goal addresses to use directed symbolic
                        execution
  -e, --export          export all vulnerability paths as a json file
```

### Exmamples
Normal run:
```shell
$ ./uaf_analysis/uaf_scan.py uaf_analysis/tests/data/simple_malloc_uaf
[+] Running CFGFast analysis...
100% ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ Elapsed Time: 0:00:00 Time: 0:00:00  
[+] CFGFast analysis ended. Created a DiGraph with 46 nodes and 50 edges
[+] Running Use-After-Free analysis...
[+] Use-After-Free analysis ended. Paths dropped: {}
[+] Max number of paths: 1
[+] Use-After-Free: <SimState @ 0x401189> in main may access a dangling pointer
    Call stack: __libc_start_main -> main
```

Verbose output:
```shell
$ ./uaf_analysis/uaf_scan.py uaf_analysis/tests/data/simple_malloc_uaf -v
100% ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ Elapsed Time: 0:00:00 Time: 0:00:00  
[+] CFGFast analysis ended. Created a DiGraph with 46 nodes and 50 edges
[+] Running Use-After-Free analysis..
[+] Use-After-Free analysis ended. Paths dropped: {}
[+] Max number of paths: 1
[+] Use-After-Free: <SimState @ 0x401189> in main may access a dangling pointer
    Call stack: __libc_start_main -> main
    Allocation-site: @ 0x401159
    Free-site:       @ 0x40116b
    Use-site:        @ 0x401189
    Free-ptr:        @ <BV64 0xc0000f40>
    Use-ptr:         @ <BV64 0xc0000f40>
    Size:              <BV64 0x4>
    Registers:
	rax: <BV64 0xc0000f40>
	rcx: <BV64 0x0>
	rdx: <BV64 0x7ffffffffff0010 + 0x8 * mem_7ffffffffff000...
	rbx: <BV64 reg_28_8_64{UNINITIALIZED}>
	rsp: <BV64 0x7fffffffffeffc0>
	rbp: <BV64 0x7fffffffffeffd0>
	rsi: <BV64 0x7ffffffffff0008>
	rdi: <BV64 0xc0000f40>
	r8 : <BV64 0x0>
	r9 : <BV64 reg_20_4_64{UNINITIALIZED}>
	r10: <BV64 reg_60_9_64{UNINITIALIZED}>
	r11: <BV64 reg_68_10_64{UNINITIALIZED}>
	r12: <BV64 reg_70_11_64{UNINITIALIZED}>
	r13: <BV64 reg_78_12_64{UNINITIALIZED}>
	r14: <BV64 reg_80_13_64{UNINITIALIZED}>
	r15: <BV64 reg_88_14_64{UNINITIALIZED}>
	rip: <BV64 0x401189>
    Path:
	  1: 0x401060 - _start
	  2: 0x500000 - __libc_start_main
	  3: 0x401159 - main
	  4: 0x401050 - malloc
	  5: 0x500018 - malloc
	  6: 0x40116b - main
	  7: 0x401030 - free
	  8: 0x500008 - free
	  9: 0x401185 - main
	 10: 0x401189 - main
```