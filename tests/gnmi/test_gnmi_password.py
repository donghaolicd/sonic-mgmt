"""Password Get/Set tests with fixed accounts in a dedicated, serial test environment.

The legacy setup helper replaces a same-named host user. Password initialization
uses task-level no_log and stdin; real SSH/become pipelining must be qualified
before device execution to avoid remote temporary plaintext files.
"""

import json
import os
import re
import secrets
import subprocess
from contextlib import ExitStack
from functools import partial

import grpc
import pytest
from pygnmi.spec.v080 import gnmi_pb2

from tests.common.fixtures.duthost_utils import (  # noqa: F401
    backup_and_restore_config_db,
)
from tests.common.fixtures.grpc_fixtures import (  # noqa: F401
    _restart_gnoi_server,
    gnmi_tls,
)
from tests.common.helpers.gnmi_connection import (
    build_native_set_request,
    gnmi_connection,
)
from tests.common.helpers.sonic_db import CONFIG_DB, redis_hdel, redis_hset
from tests.common.helpers.tacacs.tacacs_helper import setup_local_user
from tests.common.utilities import get_inventory_files

pytestmark = [pytest.mark.topology("any")]
DB_KEY = "DEVICE_METADATA|localhost"
PARTS = ("CONFIG_DB", "localhost", "DEVICE_METADATA", "localhost", "cloudtype")


@pytest.fixture(autouse=True)
def restore_startup_config(backup_and_restore_config_db):  # noqa: F811
    """Back up before TLS setup and restore after TLS teardown, including failures."""
    yield


def _set_password(request, duthost, username, password):
    """Use a no_log task; adhoc module kwargs cannot set task-level no_log."""
    __tracebackhide__ = True
    inventories = get_inventory_files(request)
    assert inventories and all(os.path.isfile(path) for path in inventories), "Require actual inventory files"
    assert re.fullmatch(r"[A-Za-z0-9_.-]+", duthost.hostname), "Require one literal DUT hostname"
    assert not request.config.getoption("ansible_extra_inventory", default=None), "Extra inventory not supported"
    cmd = ["ansible-playbook"]
    for path in inventories:
        cmd.extend(["-i", os.path.abspath(path)])
    cmd.extend(["--limit", duthost.hostname, "/dev/stdin"])
    play = [
        {
            "hosts": duthost.hostname,
            "gather_facts": False,
            "become": True,
            "vars": {"ansible_ssh_pipelining": True, "ansible_pipelining": True},
            "tasks": [
                {
                    "name": "Set test password",
                    "no_log": True,
                    "ansible.builtin.command": {"argv": ["chpasswd"], "stdin": username + ":" + password},
                }
            ],
        }
    ]
    env = dict(os.environ, ANSIBLE_PIPELINING="True", ANSIBLE_KEEP_REMOTE_FILES="False", ANSIBLE_DEBUG="False")
    try:
        result = subprocess.run(cmd, input=json.dumps(play), text=True, capture_output=True, timeout=60, env=env)
    except subprocess.TimeoutExpired:
        raise pytest.fail.Exception(
            "Password initialization timed out; remote process/cleanup state unknown", pytrace=False
        ) from None
    except OSError:
        raise pytest.fail.Exception("Password initialization could not start", pytrace=False) from None
    if result.returncode:
        pytest.fail("Password initialization failed, rc={}".format(result.returncode), pytrace=False)


def _delete_user(duthost, prefix, username):
    result = duthost.command(argv=prefix + ["userdel", username], module_ignore_errors=True)
    assert result["rc"] in (0, 6), "Test user cleanup failed"  # 6: absent after failed setup


def _cloudtype(duthost):
    # HEXISTS distinguishes an absent field from an existing empty string.
    exists = duthost.command(argv=["sonic-db-cli", CONFIG_DB, "HEXISTS", DB_KEY, "cloudtype"])
    assert exists["stdout"].strip() in ("0", "1"), "Invalid sentinel existence result"
    value = duthost.command(argv=["sonic-db-cli", CONFIG_DB, "HGET", DB_KEY, "cloudtype"])
    return exists["stdout"].strip() == "1", value["stdout"].rstrip("\n")


def _restore_cloudtype(duthost, original):
    exists, value = original
    result = (
        redis_hset(duthost, CONFIG_DB, DB_KEY, cloudtype=value)
        if exists
        else redis_hdel(duthost, CONFIG_DB, DB_KEY, "cloudtype")
    )
    assert result["rc"] == 0 and _cloudtype(duthost) == original, "Sentinel restoration failed"


@pytest.fixture
def password_identity(request, gnmi_tls, role):  # noqa: F811
    """Reuse a fixed test name sequentially; clean up before TLS rollback."""
    __tracebackhide__ = True
    duthost = gnmi_tls.duthost
    container = ["docker", "exec", "gnmi"]
    info = json.loads(duthost.command(argv=["docker", "inspect", "gnmi"])["stdout"])[0]
    assert info["HostConfig"]["NetworkMode"] == "host", "Password authentication requires host sshd"
    files = ("/etc/passwd", "/etc/group", "/etc/shadow", "/etc/gshadow")
    for mount in info["Mounts"]:
        destination = mount["Destination"].rstrip("/")
        assert not any(
            path == destination or path.startswith(destination + "/") for path in files
        ), "Container account files must not be shared mounts"
    for prefix in ([], container):
        for path in files:
            actual = duthost.command(argv=prefix + ["readlink", "-f", path])["stdout"].strip()
            assert actual == path, "Account file symlinks are unsupported"
    username = "gnmi_test_" + role.rsplit("_", 1)[1]
    original = _cloudtype(duthost)
    with ExitStack() as cleanup:
        cleanup.callback(_restore_cloudtype, duthost, original)
        group = duthost.command(argv=container + ["getent", "group", role], module_ignore_errors=True)
        assert group["rc"] in (0, 2), "Role group lookup failed"
        if group["rc"] == 2:
            duthost.command(argv=container + ["groupadd", role])
            cleanup.callback(duthost.command, argv=container + ["groupdel", role])
        cleanup.callback(_delete_user, duthost, [], username)
        cleanup.callback(_delete_user, duthost, container, username)
        password = "Gnmi!9_" + secrets.token_hex(20)
        useradd_args = [
            "--no-create-home",
            "--no-user-group",
            "--gid",
            "nogroup",
            "--no-log-init",
            "-K",
            "CREATE_MAIL_SPOOL=no",
            "--shell",
            "/bin/bash",
        ]
        setup_local_user(
            duthost,
            {"local_user": username, "local_user_passwd": password},
            useradd_args=useradd_args,
            password_setter=partial(_set_password, request),
        )
        duthost.command(argv=container + ["useradd"] + useradd_args + ["--groups", role, username])
        result = redis_hset(duthost, CONFIG_DB, "GNMI|gnmi", user_auth="password")
        assert result["rc"] == 0, "Could not select password-only authentication"
        _restart_gnoi_server(duthost)
        cmdline = duthost.command(argv=container + ["sh", "-c", "ps -eo args | grep '^/usr/sbin/telemetry '"])["stdout"]
        assert re.search(r"--?client_auth(?:=|\s+)password(?:\s|$)", cmdline), "Password-only mode not active"
        assert "config_table_name" not in cmdline, "Unexpected certificate role mapping"
        # Keep the test password out of pytest fixture-value reprs and --showlocals.
        yield gnmi_tls, username, lambda: password


@pytest.mark.parametrize("role", ["gnmi_config_db_readonly", "gnmi_config_db_readwrite"], ids=["readonly", "readwrite"])
def test_password_access(password_identity, role):
    __tracebackhide__ = True
    fixture, username, get_password = password_identity
    duthost = fixture.duthost
    assert redis_hset(duthost, CONFIG_DB, DB_KEY, cloudtype="Private")["rc"] == 0
    assert _cloudtype(duthost) == (True, "Private"), "Sentinel setup failed"
    metadata = (("username", username), ("password", get_password()))
    write = build_native_set_request(PARTS, "Public")
    with gnmi_connection(fixture) as (_, stub):
        if role.endswith("readonly"):
            read = gnmi_pb2.GetRequest(encoding=gnmi_pb2.JSON_IETF)
            path = read.path.add(origin="sonic-db")
            for part in PARTS:
                path.elem.add(name=part)
            try:
                response = stub.Get(read, metadata=metadata, timeout=30)
            except grpc.RpcError:
                raise pytest.fail.Exception("Password Get failed", pytrace=False) from None
            values = [
                json.loads(update.val.json_ietf_val)
                for notification in response.notification
                for update in notification.update
            ]
            assert values == ["Private"], "Password Get did not return the sentinel"
            try:
                stub.Set(write, metadata=metadata, timeout=30)
            except grpc.RpcError as error:
                if error.code() != grpc.StatusCode.PERMISSION_DENIED or role not in error.details():
                    raise pytest.fail.Exception(
                        "Password Set did not return the target readonly denial", pytrace=False
                    ) from None
            else:
                pytest.fail("Password readonly Set unexpectedly succeeded", pytrace=False)
            assert _cloudtype(duthost) == (True, "Private"), "Denied Set changed Redis"
        else:
            try:
                stub.Set(write, metadata=metadata, timeout=30)
            except grpc.RpcError:
                raise pytest.fail.Exception("Password readwrite Set failed", pytrace=False) from None
            assert _cloudtype(duthost) == (True, "Public"), "Authorized Set did not change Redis"


@pytest.fixture
def ssh_public_keys(gnmi_tls):  # noqa: F811
    """Check deployed public-key pairs, not rejection of a mismatched SSH server."""
    duthost = gnmi_tls.duthost
    pairs = 0
    for algorithm in ("ed25519", "ecdsa", "rsa"):
        path = "/etc/ssh/ssh_host_{}_key.pub".format(algorithm)
        fingerprints = []
        for prefix, filename in (([], path), (["docker", "exec", "gnmi"], "/mnt/host" + path)):
            exists = duthost.command(argv=prefix + ["test", "-e", filename], module_ignore_errors=True)
            assert exists["rc"] in (0, 1), "SSH public-key existence check failed"
            if exists["rc"] == 1:
                # A dangling symlink is a broken deployment, not an absent algorithm.
                link = duthost.command(argv=prefix + ["test", "-L", filename], module_ignore_errors=True)
                assert link["rc"] == 1, "SSH public-key path is a broken symlink"
                fingerprints.append(None)
                continue
            public_key = duthost.command(argv=prefix + ["cat", filename])["stdout"]
            parsed = duthost.command(argv=["ssh-keygen", "-l", "-E", "sha256", "-f", "/dev/stdin"], stdin=public_key)[
                "stdout"
            ].splitlines()
            assert len(parsed) == 1, "Expected one valid SSH public key per file"
            fields = parsed[0].split()
            assert len(fields) >= 3 and fields[1].startswith("SHA256:"), "Invalid SSH public-key fingerprint"
            fingerprints.append((fields[1], fields[-1]))
        assert fingerprints[0] == fingerprints[1], "Host and mounted SSH public keys differ"
        pairs += fingerprints[0] is not None
    assert pairs, "No matching host and mounted SSH public-key pair"


@pytest.mark.parametrize("role", ["gnmi_config_db_readonly"])
@pytest.mark.parametrize("credentials", ["wrong-password", "missing-password"])
def test_password_authentication_rejection(password_identity, ssh_public_keys, credentials, role):
    """#850 deployment smoke: valid Get then wrong/missing password rejection.

    This does not prove host-key pinning: the upstream pamAuth_test.go covers
    missing/mismatched keys and handshake timeout in isolation.
    """
    __tracebackhide__ = True
    fixture, username, get_password = password_identity
    duthost = fixture.duthost
    assert redis_hset(duthost, CONFIG_DB, DB_KEY, cloudtype="Private")["rc"] == 0
    request = gnmi_pb2.GetRequest(encoding=gnmi_pb2.JSON_IETF)
    path = request.path.add(origin="sonic-db")
    for part in PARTS:
        path.elem.add(name=part)
    password = get_password()
    with gnmi_connection(fixture) as (_, stub):
        try:
            response = stub.Get(request, metadata=(("username", username), ("password", password)), timeout=30)
        except grpc.RpcError:
            raise pytest.fail.Exception("Valid password Get baseline failed", pytrace=False) from None
        values = [
            json.loads(update.val.json_ietf_val)
            for notification in response.notification
            for update in notification.update
        ]
        assert values == ["Private"], "Valid password Get did not return the sentinel"
        metadata = (("username", username),)
        if credentials == "wrong-password":
            metadata += (("password", password + "-wrong"),)
        try:
            stub.Get(request, metadata=metadata, timeout=30)
        except grpc.RpcError as error:
            if error.code() != grpc.StatusCode.UNAUTHENTICATED:
                raise pytest.fail.Exception(
                    "Invalid credentials returned an unexpected status", pytrace=False
                ) from None
        else:
            pytest.fail("Invalid credentials unexpectedly succeeded", pytrace=False)
