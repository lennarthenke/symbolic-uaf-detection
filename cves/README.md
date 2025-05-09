# CVEs in Real-World Binaries
This repository contains real-world binaries with known CVEs (Common Vulnerabilities and Exposures) and the results of analysis runs on these binaries. The structure of the repository is organized by CVE-ID, with each folder containing the following files:
```
- [CVE-ID]
    ├── README.md
    ├── [compiled-version].zip
    ├── cwe_checker_output.txt
    ├── addrs.txt
    ├── directed.txt
    ├── ucse.txt
    └── veritesting.txt

```

## File Descriptions
- `README.md`: Provides an overview of the CVE.
- `[compiled-version].zip`: Contains the compiled binary with the CVE.
- `cwe_checker_output.txt`: Output from the `cwe_checker` tool for CWE-416.
- `addrs.txt`: Contains the dangling pointer addresses and addresses after the calls with dangling pointer arguments extracted from the `cwe_checker` output. These addresses serve as input for the Directed Symbolic Execution. 
- `directed.txt`: Results from the Directed Symbolic Execution run.
- `ucse.txt`: Results from the Under-Constrained Symbolic Execution (UCSE) run.
- `veritesting.txt`: Results from the veritesting run.
