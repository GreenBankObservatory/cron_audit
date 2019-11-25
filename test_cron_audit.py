import pytest

from cron_audit import cron_audit, filter_hosts


def test_cron_audit_allow_invalid_hosts_true():
    hostnames = ["foo"]
    actual = cron_audit("foo_user", hostnames)
    expected = {
        "valid": {},
        "error_no_crontab": {},
        "error_invalid_host": {
            "foo": "ssh: Could not resolve hostname foo: No address associated with hostname"
        },
        "error_unknown": {},
    }
    assert actual == expected


# TODO: This is not a real unit test; depends on external behavior! Needs mock
def test_cron_audit_allow_invalid_hosts_false():
    hostnames = ["foo"]
    with pytest.raises(ValueError) as excinfo:
        cron_audit("foo_user", hostnames, allow_invalid_hosts=False)

    assert "Invalid host!" in str(excinfo.value)


# TODO: This is not a real unit test; depends on external behavior! Needs mock
def test_cron_audit_allow_missing_crontab_false():
    hostnames = ["trent2"]
    with pytest.raises(ValueError) as excinfo:
        cron_audit("monctrl", hostnames, allow_missing_crontab=False)

    assert "Missing crontab!" in str(excinfo.value)


def test_filter_hosts():
    host_specs = [{"hostname": "foo", "site": "GB"}, {"hostname": "bar", "site": "CV"}]
    host_filters = {"site": "GB"}
    actual = filter_hosts(host_specs, host_filters)
    expected = [{"hostname": "foo", "site": "GB"}]
    assert actual == expected
