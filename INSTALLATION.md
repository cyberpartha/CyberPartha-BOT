# CyberPartha BOT v3 — Installation Guide

## Requirements

- Kali Linux WSL2 or a compatible Debian-based Linux system
- Python 3.11 or newer
- Python venv and pip support
- Internet access may be required to install dependencies

## Installation

Extract the release archive into a dedicated project directory.

Open a terminal in that directory and run:

    bash install.sh

The installer:

1. Checks that Python 3 is available.
2. Creates a timestamped backup of existing programs, state, reports and logs from the current project directory.
3. Creates `.venv` if it does not already exist.
4. Upgrades pip and installs dependencies from requirements.txt.
5. Runs the packaged unittest suite.

## Important Installer Limitations

- The current installer does not enforce Python 3.11 as a minimum.
- Dependencies may be downloaded from the internet.
- The backup location uses the current Linux users HOME directory.
- The installer does not create a complete source-code backup.
- Run the installer only after reviewing its contents.
- Do not run it as root unless specifically required.

## Manual Verification

Run:

    python3 bot.py --help

Run the regression suite:

    python3 -m unittest discover -s tests -q

For an existing authorized local-lab profile, generate an offline summary:

    python3 bot.py phase5-report --program YourProgram

## Safety

Installation does not grant permission to test external targets.

Review the applicable research policy before enabling any research capabilities.

See SECURITY-LIMITATIONS.md for additional restrictions.
