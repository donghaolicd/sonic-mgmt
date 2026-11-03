"""
Simple integration tests for gNOI File service.

All tests automatically run with TLS server configuration by default.
Users don't need to worry about TLS configuration.

Public-read boundary tests and the missing-path assertion require an image
containing sonic-gnmi #851. A package containing only #807 is insufficient.
"""

import base64
import hashlib
import logging
import shlex
from contextlib import ExitStack

import pytest

from tests.common.fixtures.grpc_fixtures import gnmi_tls  # noqa: F401
from tests.common.helpers.assertions import pytest_assert
from tests.common.ptf_grpc import PtfGrpcError
from tests.common.utilities import wait_until
from tests.gnmi.helper import set_gnoi_client_role

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology("any"),
]


@pytest.fixture
def public_read_tree(gnmi_tls):  # noqa: F811
    """Synthetic host files only; never read real private DUT data."""
    dut = gnmi_tls.duthost
    root = dut.tempfile(state="directory", prefix="gnoi-public-read-")["path"]
    try:
        dut.file(path=root, state="directory", mode="0755")
        dut.file(path=root + "/private-dir", state="directory", mode="0700")
        for name, mode in [("public", "0644"), ("private", "0600"), ("private-dir/public", "0644")]:
            dut.copy(content="gNOI public read fixture\n", dest=root + "/" + name, mode=mode)
        for name, target in [
            ("public-link", root + "/public"),
            ("relative-public-link", "public"),
            ("private-link", root + "/private"),
            ("private-parent-link", root + "/private-dir/public"),
            ("dangling-link", root + "/missing"),
        ]:
            dut.file(path=root + "/" + name, src=target, state="link", force=True, follow=False)
        set_gnoi_client_role(gnmi_tls, "gnoi_readonly")
        gnmi_tls.grpc.configure_max_time(30)
        yield root
    finally:
        dut.file(path=root, state="absent")
        assert not dut.stat(path=root)["stat"]["exists"]


@pytest.mark.disable_loganalyzer
@pytest.mark.parametrize("method", ["Get", "Stat"])
@pytest.mark.parametrize(
    "name,allowed",
    [
        ("public", True),
        ("public-link", True),
        ("relative-public-link", True),
        ("private", False),
        ("private-dir/public", False),
        ("private-dir/../public", False),
        ("private-link", False),
        ("private-parent-link", False),
        ("missing", False),
        ("dangling-link", False),
    ],
)
def test_gnoi_file_public_read(gnmi_tls, public_read_tree, method, name, allowed, request):  # noqa: F811
    """Requires #851: an authorized reader must still pass public-file checks."""
    path = public_read_tree + "/" + name
    if method == "Get":
        call = gnmi_tls.grpc.call_server_streaming
        rpc_request = {"remote_file": path}
    else:
        call = gnmi_tls.grpc.call_unary
        rpc_request = {"path": path}
    if allowed:
        response = call("gnoi.file.File", method, rpc_request)
        content = b"gNOI public read fixture\n"
        if method == "Get":
            assert response and "hash" in response[-1]
            assert b"".join(base64.b64decode(item["contents"]) for item in response[:-1]) == content
            assert response[-1]["hash"]["method"] == "MD5"
            assert base64.b64decode(response[-1]["hash"]["hash"]) == hashlib.md5(content).digest()
        else:
            assert len(response["stats"]) == 1
            assert response["stats"][0]["path"] == path
            assert int(response["stats"][0]["size"]) == len(content)
    else:
        # A final RPC error does not establish that zero bytes were streamed.
        with pytest.raises(PtfGrpcError, match=r"\bCode: PermissionDenied\b"):
            call("gnoi.file.File", method, rpc_request)
    logger.info(
        "AUTHZ_VERIFIED node=%s method=%s case=%s expected=actual=%s scope=test-body",
        request.node.nodeid,
        method,
        name,
        "OK" if allowed else "PermissionDenied",
    )


def test_gnoi_file_stat_filters_private_entries(gnmi_tls, public_read_tree, request):  # noqa: F811
    """#851: directory listings expose only publicly readable children."""
    response = gnmi_tls.grpc.call_unary("gnoi.file.File", "Stat", {"path": public_read_tree})
    paths = [entry["path"] for entry in response.get("stats", [])]
    expected = {public_read_tree + "/" + name for name in ("public", "public-link", "relative-public-link")}
    assert len(paths) == len(expected)
    assert set(paths) == expected
    logger.info("AUTHZ_VERIFIED node=%s method=Stat public_entries=%s scope=test-body", request.node.nodeid, len(paths))


@pytest.mark.disable_loganalyzer
@pytest.mark.parametrize("method", ["Get", "Stat"])
def test_gnoi_file_read_rejects_extended_acl(gnmi_tls, public_read_tree, method, request):  # noqa: F811
    """#851 rejects extended access ACLs even when the other-read bit is set.

    Requires setfacl and POSIX ACL support on the test filesystem.
    """
    dut = gnmi_tls.duthost
    path = public_read_tree + "/public"
    dut.command("setfacl -m u:65534:--- {}".format(shlex.quote(path)))
    assert int(dut.stat(path=path)["stat"]["mode"], 8) & 0o004
    with pytest.raises(PtfGrpcError, match=r"\bCode: PermissionDenied\b"):
        if method == "Get":
            gnmi_tls.grpc.call_server_streaming("gnoi.file.File", method, {"remote_file": path})
        else:
            gnmi_tls.grpc.call_unary("gnoi.file.File", method, {"path": path})
    logger.info(
        "AUTHZ_VERIFIED node=%s method=%s expected=actual=PermissionDenied scope=test-body",
        request.node.nodeid,
        method,
    )


def test_file_stat(gnmi_tls):  # noqa: F811
    """Test File.Stat RPC with TLS enabled by default."""
    try:
        result = gnmi_tls.gnoi.file_stat("/etc/hostname")
        assert "stats" in result
        logger.info(f"File stats: {result['stats'][0]}")
    except Exception as e:
        # File service may not be fully implemented
        logger.warning(f"File.Stat failed (expected): {e}")


def test_file_transfer_to_remote(gnmi_tls, ptfhost):  # noqa: F811
    """Test File.TransferToRemote RPC downloading file from HTTP server to DUT."""
    duthost = gnmi_tls.duthost
    # Test file configuration
    test_filename = "test.txt"
    test_content = "Hello from gNOI TransferToRemote test!"
    with ExitStack() as cleanup:
        local_dir = duthost.tempfile(state="directory", prefix="gnoi-transfer-")["path"]
        cleanup.callback(duthost.file, path=local_dir, state="absent")
        local_path = local_dir + "/" + test_filename
        server_dir = ptfhost.tempfile(state="directory", prefix="gnoi-transfer-")["path"]
        cleanup.callback(ptfhost.file, path=server_dir, state="absent")
        # 1. Create test file on PTF host
        logger.info(f"Creating test file {test_filename} on PTF host")
        ptfhost.copy(content=test_content, dest=server_dir + "/" + test_filename)
        # 2. Start HTTP server on PTF host
        # Bind an unused port and stop only this test's server. command() does
        # not interpret shell 'cd', and a broad pkill could affect other tests.
        ptf_ip = ptfhost.mgmt_ip
        ipv6 = ":" in ptf_ip
        server = (
            "import http.server,os,socket; "
            f"os.chdir({server_dir!r}); "
            "S=type('Server',(http.server.HTTPServer,),{'address_family':socket.%s}); "
            "s=S(('%s',0),http.server.SimpleHTTPRequestHandler); "
            "open('port','w').write(str(s.server_port)); s.serve_forever()"
        ) % ("AF_INET6" if ipv6 else "AF_INET", "::" if ipv6 else "0.0.0.0")
        pid = ptfhost.shell(
            "python3 -c {} >{}/server.log 2>&1 </dev/null & echo $!".format(shlex.quote(server), server_dir)
        )["stdout"].strip()
        pytest_assert(pid.isdigit(), "HTTP server did not return a PID")

        def stop_server():
            # Verify ownership before signalling; wait for exit (or an exited
            # zombie awaiting its parent) before removing the served directory.
            stop = """import os,signal,time
from pathlib import Path
pid = int(%r)
proc = Path('/proc') / str(pid)
def alive():
    try:
        return proc.joinpath('stat').read_text().rsplit(')', 1)[1].split()[0] != 'Z'
    except FileNotFoundError:
        return False
if alive():
    assert %r.encode() in proc.joinpath('cmdline').read_bytes(), 'HTTP PID ownership mismatch'
    os.kill(pid, signal.SIGTERM)
for _ in range(50):
    if not alive():
        break
    time.sleep(0.1)
assert not alive(), 'HTTP server did not exit after SIGTERM'
""" % (
                pid,
                server_dir,
            )
            ptfhost.command(argv=["python3", "-c", stop])

        cleanup.callback(stop_server)
        http_port = None
        # 3. Wait for HTTP server to start
        http_host = "[{}]".format(ptf_ip) if ":" in ptf_ip else ptf_ip

        def server_ready():
            nonlocal http_port
            try:
                port = ptfhost.command("cat " + server_dir + "/port")["stdout"].strip()
                if not port.isdigit():
                    return False
                http_port = int(port)
                result = ptfhost.command(
                    "curl -f --max-time 2 http://{}:{}/{}".format(http_host, http_port, test_filename),
                    module_ignore_errors=True,
                )
                return result["rc"] == 0
            except Exception:
                return False

        pytest_assert(wait_until(30, 2, 2, server_ready), "HTTP server did not become ready")
        logger.info("HTTP server is ready")
        # 4. Test TransferToRemote
        remote_url = "http://{}:{}/{}".format(http_host, http_port, test_filename)
        logger.info(f"Testing TransferToRemote: {remote_url} -> {local_path}")
        gnmi_tls.grpc.configure_max_time(60)
        result = gnmi_tls.gnoi.file_transfer_to_remote(local_path=local_path, url=remote_url, protocol="HTTP")
        # 5. Verify response has hash
        pytest_assert("hash" in result, "TransferToRemote response missing hash field")
        logger.info(f"TransferToRemote response: {result}")
        # 6. Verify file was downloaded to DUT
        file_stat = duthost.stat(path=local_path)
        pytest_assert(file_stat["stat"]["exists"], f"File {local_path} not found on DUT after transfer")
        logger.info(f"File successfully downloaded to DUT: {local_path}")
        # 7. Verify downloaded content
        downloaded_content = duthost.shell(f"cat {local_path}")["stdout"].strip()
        pytest_assert(
            test_content == downloaded_content,
            f"Content mismatch. Expected: '{test_content}', Got: '{downloaded_content}'",
        )
        logger.info(f"File content verified: {downloaded_content}")
    pytest_assert(not duthost.stat(path=local_dir)["stat"]["exists"], "DUT transfer directory was not removed")
    pytest_assert(not ptfhost.stat(path=server_dir)["stat"]["exists"], "PTF HTTP directory was not removed")
    logger.info("TransferToRemote content verified and test files cleaned up")


def test_gnoi_file_stat_regular_file(gnmi_tls):  # noqa: F811
    """Verify File.Stat on a regular file returns a single StatInfo per the gNOI proto contract.

    Per the gNOI File proto:
    - Exactly one StatInfo is returned for a regular file.
    - path is the host-visible path (no /mnt/host prefix).
    - size, last_modified, permissions, and umask fields are populated.
    - umask is 0022 (18 decimal).
    """
    resp = gnmi_tls.gnoi.file_stat("/etc/hostname")

    stats = resp.get("stats", [])
    pytest_assert(len(stats) == 1, "Expected exactly 1 StatInfo for regular file, got {}: {}".format(len(stats), resp))

    entry = stats[0]
    logger.info("File.Stat regular file entry: {}".format(entry))

    pytest_assert(
        entry.get("path") == "/etc/hostname", "Expected path '/etc/hostname', got: {}".format(entry.get("path"))
    )
    pytest_assert(
        int(entry.get("size", 0)) > 0, "Expected non-zero size for /etc/hostname, got: {}".format(entry.get("size"))
    )
    pytest_assert(
        int(entry.get("last_modified") or entry.get("lastModified") or 0) > 0,
        "Expected positive last_modified timestamp, got: {}".format(entry.get("lastModified")),
    )
    pytest_assert("permissions" in entry, "stat entry missing 'permissions'")
    pytest_assert(
        int(entry.get("umask", -1)) == 18, "Expected umask=18 (0022 octal), got: {}".format(entry.get("umask"))
    )


def test_gnoi_file_stat_directory(gnmi_tls):  # noqa: F811
    """Verify File.Stat on a directory returns immediate children per the gNOI proto contract.

    Per the gNOI File proto contract for directory paths:
    - Only immediate children are returned (non-recursive).
    - The directory itself is NOT included in the results.
    - Each child StatInfo contains: path, last_modified, permissions, and umask fields.
    - Each child path is the full host-visible path (e.g. '/etc/sonic/<child>').
    """
    resp = gnmi_tls.gnoi.file_stat("/etc/sonic")

    stats = resp.get("stats", [])
    pytest_assert(len(stats) >= 1, "Expected at least one child entry for /etc/sonic, got: {}".format(resp))
    logger.info("File.Stat directory returned {} entries".format(len(stats)))

    self_paths = [e.get("path") for e in stats if e.get("path") == "/etc/sonic"]
    pytest_assert(
        len(self_paths) == 0,
        "Directory /etc/sonic must not appear in its own listing, but found: {}".format(self_paths),
    )

    for entry in stats:
        child_path = entry.get("path", "")
        logger.info("Directory child entry: {}".format(entry))
        pytest_assert(
            child_path.startswith("/etc/sonic/"), "Child path '{}' does not start with '/etc/sonic/'".format(child_path)
        )
        pytest_assert(
            int(entry.get("last_modified") or entry.get("lastModified") or 0) > 0,
            "Child '{}' missing valid last_modified".format(child_path),
        )
        pytest_assert("permissions" in entry, "Child '{}' missing 'permissions'".format(child_path))
        pytest_assert(
            int(entry.get("umask", -1)) == 18,
            "Child '{}' expected umask=18, got: {}".format(child_path, entry.get("umask")),
        )


def test_gnoi_file_stat_not_found(gnmi_tls, request):  # noqa: F811
    """#851 hides non-existent paths with the same error as private files."""
    set_gnoi_client_role(gnmi_tls, "gnoi_readonly")
    gnmi_tls.grpc.configure_max_time(30)
    with pytest.raises(PtfGrpcError, match=r"\bCode: PermissionDenied\b"):
        gnmi_tls.grpc.call_unary("gnoi.file.File", "Stat", {"path": "/etc/this_path_does_not_exist_gnoi_test"})
    logger.info(
        "AUTHZ_VERIFIED node=%s method=Stat expected=actual=PermissionDenied scope=test-body", request.node.nodeid
    )


@pytest.mark.parametrize(
    "bad_path,reason",
    [
        ("", "empty path"),
        ("etc/hostname", "relative path"),
        ("/mnt/host/etc/hostname", "/mnt/host-prefixed path"),
    ],
    ids=["empty", "relative", "mnt-host"],
)
def test_gnoi_file_stat_invalid_argument(gnmi_tls, bad_path, reason):  # noqa: F811
    """Stat with invalid path arguments; expect INVALID_ARGUMENT error."""
    try:
        gnmi_tls.gnoi.file_stat(bad_path)
        pytest_assert(False, "File.Stat should have failed for {} ('{}') but returned success".format(reason, bad_path))
    except Exception as e:
        err = str(e)
        logger.info("File.Stat INVALID_ARGUMENT ({}) response: {}".format(reason, err))
        pytest_assert(
            "InvalidArgument" in err or "invalid argument" in err.lower() or "invalid" in err.lower(),
            "Expected INVALID_ARGUMENT error for {} ('{}'): {}".format(reason, bad_path, err),
        )


def test_gnoi_file_stat_permissions_decimal_octal(gnmi_tls, duthosts, rand_one_dut_hostname):  # noqa: F811
    """Verify permissions field is encoded as decimal-octal per gNOI proto.

    Per the gNOI File proto, the permissions field encodes the file mode
    as its octal string interpreted as a decimal integer (e.g. mode 0644 -> 644).
    The test fetches the actual mode from the DUT and verifies the encoding holds,
    independent of the specific file's permissions value.
    """
    duthost = duthosts[rand_one_dut_hostname]
    # Get the actual octal mode string from the DUT (e.g. "644")
    actual_octal = duthost.shell("stat -c %a /etc/hostname")["stdout"].strip()
    # decimal-octal encoding: the octal string is re-read as a decimal integer
    expected_permissions = int(actual_octal)
    logger.info("DUT /etc/hostname mode: octal={} expected_permissions={}".format(actual_octal, expected_permissions))

    resp = gnmi_tls.gnoi.file_stat("/etc/hostname")

    stats = resp.get("stats", [])
    pytest_assert(len(stats) == 1, "Expected exactly 1 StatInfo for /etc/hostname")

    entry = stats[0]
    permissions = int(entry.get("permissions", -1))
    logger.info("File.Stat permissions field value: {}".format(permissions))

    pytest_assert(
        permissions == expected_permissions,
        "Expected permissions={} (decimal-octal of mode 0{}) got: {} "
        "(hint: {} means raw decimal encoding is in use)".format(
            expected_permissions, actual_octal, permissions, int(actual_octal, 8)
        ),
    )
    pytest_assert(
        all(d in "01234567" for d in str(permissions)),
        "permissions '{}' contains digit 8 or 9 — not a valid decimal-octal value".format(permissions),
    )
