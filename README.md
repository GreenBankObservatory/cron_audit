# Cron Audit

Creates a report of all cron jobs for a specific user, across all hosts.

NOTE: This is a Green Bank specific tool, in that it depends on http://leo.gb.nrao.edu/php/inventory/text.php in order to function.

## Usage

```bash
# Find all cron jobs for monctrl, across all hosts
cron_audit.py monctrl
# Read the generated report
less ./report.md
```

## Test

Simply use `pytest` to run the tests:

```bash
pytest
```
