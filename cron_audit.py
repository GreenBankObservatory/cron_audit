#! /usr/bin/env python3

"""Audit cron jobs"""


import argparse
import csv
import json
import requests
import shutil
from getpass import getuser
from pathlib import Path
from pprint import pprint
from subprocess import check_output, CalledProcessError, PIPE
from tqdm import tqdm

CRON_AUDIT_CACHE_PATH = Path(Path.home(), ".cache/cron_audit")
DEFAULT_NO_CACHE = False
DEFAULT_HOST_SPECS_URL = "http://leo.gb.nrao.edu/php/inventory/text.php"
# Update these to narrow down the hosts that are selected for auditing. Currently,
# this selects hosts running Linux, located at the GB site
DEFAULT_HOST_FILTERS = {"os": "Linux", "site": "GB"}
DEFAULT_SSH_TIMEOUT = 3
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
TERMINAL_WIDTH, __ = shutil.get_terminal_size()


def get_host_specs_from_url(host_specs_url=None):
    if host_specs_url is None:
        host_specs_url = DEFAULT_HOST_SPECS_URL
    response = requests.get(host_specs_url)
    content = response.content.decode("UTF-8")
    host_specs = csv.DictReader(content.splitlines(), delimiter=",")
    return host_specs


def get_host_specs_from_file(host_specs_path):
    with open(host_specs_path) as file:
        host_specs = file.read().splitlines()
    host_specs = csv.DictReader(host_specs, delimiter=",")
    return host_specs


def parse_host_specs(host_specs, host_blacklist_path):
    host_blacklist = []
    if host_blacklist_path:
        with open(host_blacklist_path) as file:
            host_blacklist = file.read().splitlines()
        print(f"Excluding hosts from audit: {host_blacklist}")

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
    hostnames,
    allow_invalid_hosts=True,
    allow_missing_crontab=True,
    allow_unknown_errors=True,
    dry_run=False,
    ssh_options=None,
    ssh_timeout=DEFAULT_SSH_TIMEOUT,
):
    ssh_options = expand_ssh_options(ssh_options, ssh_timeout)

    crontabs_by_host = {
        "valid": {},
        "error_no_crontab": {},
        "error_invalid_host": {},
        "error_unknown": {},
    }
    for hostname in tqdm(hostnames):
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


def report(user, crontabs_by_host, host_blacklist, output):
    with open(output, "w") as file:
        for subsection_type, subsection in crontabs_by_host.items():
            file.write(f"## {subsection_type}\n")
            if subsection:
                print(subsection_type.upper())
                print("=" * TERMINAL_WIDTH)
                for host, crontab in subsection.items():
                    file.write(f"### {host}\n```\n{crontab}\n```\n")
                    print(f"{user}@{host}:")
                    print("-" * TERMINAL_WIDTH)
                    print(crontab)
                    print("-" * TERMINAL_WIDTH)
                print("=" * TERMINAL_WIDTH + "\n")
            else:
                file.write("No hosts\n")

        blacklist_str = "\n" + "\n* ".join(host_blacklist)
        file.write(
            "## Blacklisted\nThe following files were ignored during the audit "
            f"due to their presence in the blacklist file:\n{blacklist_str}"
        )


def do_full(host_specs_path, host_specs_url, host_blacklist_path):
    if host_specs_path:
        host_specs = get_host_specs_from_file(host_specs_path)
    else:
        host_specs = get_host_specs_from_url(host_specs_url)

    host_specs, host_blacklist = parse_host_specs(host_specs, host_blacklist_path)
    # Filter out the non-relevant ones
    # TODO: GBO-agnostic? Could maybe fix/remove DEFAULT_HOST_FILTERS
    host_specs = filter_hosts(host_specs, DEFAULT_HOST_FILTERS)
    hostnames = [host_spec["hostname"] for host_spec in host_specs]
    return hostnames, host_blacklist


def do_partial(last_run_output_path):
    try:
        with open(last_run_output_path) as file:
            last_run_json = json.load(file)
    except FileNotFoundError:
        last_run_json = None

    if last_run_json:
        hostnames = last_run_json["valid"]
        host_blacklist = [
            hostname
            for key, hostnames in last_run_json.items()
            if key != "valid"
            for hostname in hostnames
        ]
        return hostnames, host_blacklist
    return None, None


def main():
    args = parse_args()
    user = args.user if args.user else getuser()
    last_run_output_path = Path(CRON_AUDIT_CACHE_PATH, f"last_run.{user}.json")
    if args.full:
        hostnames, host_blacklist = do_full(
            args.host_specs_path, args.host_specs_url, args.host_blacklist_path
        )
    else:
        hostnames, host_blacklist = do_partial(last_run_output_path)
        if not hostnames:
            hostnames, host_blacklist = do_full(
                args.host_specs_path, args.host_specs_url, args.host_blacklist_path
            )
    crontabs_by_host = cron_audit(
        user, hostnames, dry_run=args.dry_run, ssh_timeout=args.ssh_timeout
    )
    _report = {result: list(hosts.keys()) for result, hosts in crontabs_by_host.items()}
    if not args.no_cache and not args.dry_run:
        CRON_AUDIT_CACHE_PATH.mkdir(parents=True, exist_ok=True)
        with open(last_run_output_path, "w") as file:
            json.dump({**_report, "blacklist": host_blacklist}, file)
    # pprint(crontabs_by_host)
    report(user, crontabs_by_host, host_blacklist, args.output_path)


def parse_args():
    parser = argparse.ArgumentParser(
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument(
        "user",
        nargs="?",
        help="Username to audit crontabs for. If not given, "
        "defaults to the current user.",
    )
    parser.add_argument(
        "-D",
        "--dry-run",
        action="store_true",
        help="Don't actually check any crontabs; "
        "just print out what _would be_ checked",
    )
    parser.add_argument(
        "-p",
        "--host-specs-url",
        help="Path to the URL that specifies the host specifications "
        "(via CSV file). This should only need to change if the URL changes.",
    )
    parser.add_argument(
        "-P",
        "--host-specs-path",
        help="Path to the CSV file that specifies the host specifications. "
        "Useful for testing",
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
    parser.add_argument(
        "--no-cache",
        action="store_true",
        default=DEFAULT_NO_CACHE,
        help=f"If given, don't read from or write to {CRON_AUDIT_CACHE_PATH}",
    )
    parser.add_argument(
        "--full",
        action="store_true",
        help=f"If given, force a full audit of all hosts. This will re-populate the "
        "cache of valid hosts (unless --no-cache or --dry-run are given).",
    )

    return parser.parse_args()


if __name__ == "__main__":
    main()
