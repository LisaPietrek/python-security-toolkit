#8 Python Security Toolkit

A small cybersecurity-focused toolkit written in Python.

## Features

- TCP port scanner
- Banner grabbing

**planned features*

- Log file parser
- Suspicious login detection

## Prerequisites

- **Python 3.11+**
- **Conda**  or **Miniconda**

## Installation

Setup conda environment and activate

```bash
conda env create -f environment.yml
conda activate security-toolkit
```
## Usage

*scanner*
```bash
python scanner/scanner.py
```

The scanner will prompt the user to input
1. a target hostname
2. a port range (e.g., 11 100)
