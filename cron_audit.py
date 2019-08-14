#! /usr/bin/env python3

"""Audit cron jobs"""


import argparse
import csv
from pprint import pprint
from subprocess import check_output, CalledProcessError, PIPE

import requests
from tqdm import tqdm

DEFAULT_HOST_SPECS_PATH = "http://leo.gb.nrao.edu/php/inventory/text.php"
# Update these to narrow down the hosts that are selected for auditing. Currently,
# this selects hosts running Linux, located at the GB site
DEFAULT_HOST_FILTERS = {"os": "Linux", "site": "GB"}
# Quite a high, safe default value given here
DEFAULT_SSH_TIMEOUT = 30
DEFAULT_SSH_OPTIONS = [
    # This avoids _most_ of the welcome message
    "-T",
    "-o",
    # This suppresses extraneous stderr output, but leaves in messages about
    # connection timeouts (which -q strips out)
    "LogLevel=ERROR",
    "-o",
    # This avoids hanging on a password prompt on hosts that don't allow key auth
    "PasswordAuthentication=no",
]
DEFAULT_OUTPUT_PATH = "./report.md"


def parse_host_specs(host_specs_path, host_blacklist_path):
    host_blacklist = []
    if host_blacklist_path:
        with open(host_blacklist_path) as file:
            host_blacklist = file.read().splitlines()
        print(f"Excluding hosts from audit: {host_blacklist}")

    response = requests.get(host_specs_path)
    content = response.content.decode("UTF-8")
    host_specs = csv.DictReader(content.splitlines(), delimiter=",")
    return (
        [
            host_spec
            for host_spec in host_specs
            if host_spec["hostname"] not in host_blacklist
        ],
        host_blacklist,
    )


def expand_ssh_options(ssh_options=None, timeout=None):
    """Adds user-specified values to SSH options

    These can't be defined prior to runtime, so we need to add them dynamically here"""

    if ssh_options is None:
        ssh_options = DEFAULT_SSH_OPTIONS

    if timeout is None:
        timeout = DEFAULT_SSH_TIMEOUT
    return [
        *ssh_options,
        "-o",
        # This avoids hanging for waaaay too long on hosts that are reachable but
        # don't respond for whatever reason
        f"ConnectTimeout={timeout}",
    ]


def check_crontab(username, hostname, ssh_options):
    print(username, hostname, ssh_options)
    return check_output(
        ["ssh", *ssh_options, f"{username}@{hostname}", "crontab", "-l"], stderr=PIPE
    )


def filter_hosts(host_specs, host_filters):
    """Filter out host_specs that don't match all filters in host_filters"""

    return sorted(
        (
            host_spec
            for host_spec in host_specs
            if all(
                # Get the value for the given key, or just use filter_value
                # if it doesn't exist (so that the comparison will pass -- this
                # allows us to easily handle keys that exist in the filter but not
                # the host_spec)
                host_spec.get(filter_key, filter_value) == filter_value
                for filter_key, filter_value in host_filters.items()
            )
        ),
        key=lambda host_spec: host_spec["hostname"],
    )


def called_process_error_to_string(error):
    error_message = error.stderr.decode("UTF-8").strip()
    return f"{error} Error message: {error_message}", error_message


def cron_audit(
    username,
    host_specs,
    allow_invalid_hosts=True,
    allow_missing_crontab=True,
    allow_unknown_errors=True,
    dry_run=False,
    ssh_options=None,
    ssh_timeout=DEFAULT_SSH_TIMEOUT,
    host_filters=DEFAULT_HOST_FILTERS,
):
    ssh_options = expand_ssh_options(ssh_options, ssh_timeout)
    print(host_filters)
    print("host_specs", host_specs)
    if host_filters:
        host_specs = filter_hosts(host_specs, host_filters)

    print("host_specs", [hs["hostname"] for hs in host_specs])
    crontabs_by_host = {
        "valid": {},
        "error_no_crontab": {},
        "error_invalid_host": {},
        "error_unknown": {},
    }
    for host_spec in tqdm(host_specs):
        hostname = host_spec["hostname"]
        tqdm.write(f"Fetching crontab for {username}@{hostname}...")
        if not dry_run:
            try:
                crontab = check_crontab(username, hostname, ssh_options=ssh_options)
            except CalledProcessError as error:
                full_error_str, error_message = called_process_error_to_string(error)
                tqdm.write(f"  ERROR: {full_error_str}")
                if error.returncode == 255 and (
                    "Could not resolve hostname" in error_message
                    or "Connection timed out" in error_message
                ):
                    if allow_invalid_hosts:
                        crontabs_by_host["error_invalid_host"][hostname] = error_message
                    else:
                        raise ValueError("Invalid host!") from error
                elif error.returncode == 1 and "no crontab" in error_message:
                    if allow_missing_crontab:
                        crontabs_by_host["error_no_crontab"][hostname] = error_message
                    else:
                        raise ValueError("Missing crontab!") from error
                else:
                    if allow_unknown_errors:
                        crontabs_by_host["error_unknown"][hostname] = error_message
                    else:
                        raise ValueError("Unknown error!") from error
            else:
                crontabs_by_host["valid"][hostname] = crontab.decode("UTF-8")
                tqdm.write("  SUCCESS: Found crontab!")
        else:
            tqdm.write(f"DRY RUN: ssh {username}@{hostname}")
    return crontabs_by_host


def report(crontabs_by_host, host_blacklist, output):
    with open(output, "w") as file:
        for subsection_type, subsection in crontabs_by_host.items():
            file.write(f"## {subsection_type}\n")
            if subsection:
                print(subsection_type)
                for host, response in subsection.items():
                    file.write(f"### {host}\n```\n{response}\n```\n")
                    print(host)
                print("-" * len(subsection_type) + "\n")
            else:
                file.write("No hosts\n")

        blacklist_str = "\n" + "\n* ".join(host_blacklist)
        file.write(
            "## Blacklisted\nThe following files were ignored during the audit "
            f"due to their presence in the blacklist file:\n{blacklist_str}"
        )


def main():
    args = parse_args()
    host_specs, host_blacklist = parse_host_specs(
        args.host_specs_path, args.host_blacklist_path
    )
    crontabs_by_host = cron_audit(
        args.user, host_specs, dry_run=args.dry_run, ssh_timeout=args.ssh_timeout
    )
    pprint(crontabs_by_host)
    report(crontabs_by_host, host_blacklist, args.output_path)


def parse_args():
    parser = argparse.ArgumentParser(
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument("user")
    parser.add_argument(
        "-d",
        "--dry-run",
        action="store_true",
        help="Don't actually check any crontabs; "
        "just print out what _would be_ checked",
    )
    parser.add_argument(
        "-P",
        "--host-specs-path",
        default=DEFAULT_HOST_SPECS_PATH,
        help="Path to the URL that specifies the host specifications "
        "(via CSV file). This should only need to change if the URL changes.",
    )
    parser.add_argument(
        "-B",
        "--host-blacklist-path",
        help="Path to a file that contains hosts that should be ignored "
        "during the audit, regardless of the host filters. This should be used to ignore known-bad hosts.",
    )
    parser.add_argument(
        "-t",
        "--ssh-timeout",
        type=int,
        default=DEFAULT_SSH_TIMEOUT,
        help="The timeout, in seconds, of the SSH command that checks the crontab",
    )
    parser.add_argument(
        "-o",
        "--output-path",
        default=DEFAULT_OUTPUT_PATH,
        help="The path that the report will be written to",
    )

    return parser.parse_args()


if __name__ == "__main__":
    main()
