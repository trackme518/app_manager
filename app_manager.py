import configparser
import ctypes
from ctypes import wintypes
import hashlib
import json
import logging
import os
import shlex
import signal
import socket
import subprocess
import sys
import threading
import time
import secrets
from functools import wraps
from datetime import datetime, timedelta, timezone
import ipaddress

from flask import Flask, send_from_directory, request, jsonify, current_app
from werkzeug.serving import make_server

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID

IS_WINDOWS = os.name == "nt"

def resource_path(relative_path):
    if getattr(sys, 'frozen', False):
        base_path = os.path.dirname(sys.executable)
    else:
        base_path = os.path.abspath(".")
    return os.path.join(base_path, relative_path)


data_dir = resource_path("data")

# omit default console logs fromFlask server for /api/status endpoint that is being polled
class StatusEndpointFilter(logging.Filter):
    def filter(self, record):
        return "/api/status" not in record.getMessage()

def configure_request_logging():
    werkzeug_logger = logging.getLogger("werkzeug")
    werkzeug_logger.addFilter(StatusEndpointFilter())

def load_auth_config():
    config_path = os.path.join(data_dir, 'config.ini')
    if not os.path.exists(config_path):
        print('config.ini missing or unreadable.')
        sys.exit(4)

    parser = configparser.ConfigParser()
    parser.read(config_path, encoding='utf-8')
    return parser


def get_token_from_config(parser):
    token = parser.get('auth', 'token', fallback=None)
    if not token:
        print('config.ini must include an [auth] section with token=...')
        sys.exit(4)
    return token


def get_token_hash_from_config(parser):
    token = get_token_from_config(parser)
    return hashlib.sha256(token.encode('utf-8')).hexdigest()


def get_port_from_config(parser):
    try:
        return parser.getint('server', 'port', fallback=9999)
    except ValueError:
        print('config.ini server port must be an integer.')
        sys.exit(4)

def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.headers.get('Authorization', '')
        if not auth.startswith('Bearer '):
            return jsonify({'error': 'Unauthorized'}), 401
        token_hash = auth.split(' ', 1)[1]
        expected_hash = current_app.config.get('token_hash')
        if not expected_hash or token_hash != expected_hash:
            return jsonify({'error': 'Unauthorized'}), 401
        return f(*args, **kwargs)
    return decorated

def read_log_tail(log_path, max_lines=20):
    try:
        with open(log_path, 'r', encoding='utf-8', errors='replace') as handle:
            lines = handle.readlines()
        tail = lines[-max_lines:]
        return ''.join(tail).strip() or '(no log output yet)'
    except Exception as exc:
        return f"(failed to read log: {exc})"

def resolve_executable_path(arg):
    arg = os.path.expandvars(os.path.expanduser(arg))
    if not os.path.isabs(arg):
        arg = os.path.join(os.getcwd(), arg)
    path = os.path.abspath(arg)
    print("Resolved path:", path)
    if not os.path.isfile(path):
        raise FileNotFoundError(path)
    return path


class JOBOBJECT_BASIC_LIMIT_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("PerProcessUserTimeLimit", wintypes.LARGE_INTEGER),
        ("PerJobUserTimeLimit", wintypes.LARGE_INTEGER),
        ("LimitFlags", wintypes.DWORD),
        ("MinimumWorkingSetSize", ctypes.c_size_t),
        ("MaximumWorkingSetSize", ctypes.c_size_t),
        ("ActiveProcessLimit", wintypes.DWORD),
        ("Affinity", ctypes.c_size_t),
        ("PriorityClass", wintypes.DWORD),
        ("SchedulingClass", wintypes.DWORD),
    ]


class IO_COUNTERS(ctypes.Structure):
    _fields_ = [
        ("ReadOperationCount", ctypes.c_ulonglong),
        ("WriteOperationCount", ctypes.c_ulonglong),
        ("OtherOperationCount", ctypes.c_ulonglong),
        ("ReadTransferCount", ctypes.c_ulonglong),
        ("WriteTransferCount", ctypes.c_ulonglong),
        ("OtherTransferCount", ctypes.c_ulonglong),
    ]


class JOBOBJECT_EXTENDED_LIMIT_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BasicLimitInformation", JOBOBJECT_BASIC_LIMIT_INFORMATION),
        ("IoInfo", IO_COUNTERS),
        ("ProcessMemoryLimit", ctypes.c_size_t),
        ("JobMemoryLimit", ctypes.c_size_t),
        ("PeakProcessMemoryUsed", ctypes.c_size_t),
        ("PeakJobMemoryUsed", ctypes.c_size_t),
    ]


class JOBOBJECT_BASIC_PROCESS_ID_LIST(ctypes.Structure):
    _fields_ = [
        ("NumberOfAssignedProcesses", wintypes.DWORD),
        ("NumberOfProcessIdsInList", wintypes.DWORD),
        ("ProcessIdList", ctypes.c_size_t * 1),
    ]



class WindowsJobObject:
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000
    JOB_OBJECT_EXTENDED_LIMIT_INFORMATION = 9
    JOB_OBJECT_BASIC_PROCESS_ID_LIST = 3
    ERROR_MORE_DATA = 234
    PROCESS_SET_QUOTA = 0x0100
    PROCESS_TERMINATE = 0x0001


    def __init__(self):
        self.handle = None
        if IS_WINDOWS:
            self.kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            self.kernel32.CreateJobObjectW.argtypes = [wintypes.LPVOID, wintypes.LPCWSTR]
            self.kernel32.CreateJobObjectW.restype = wintypes.HANDLE
            self.kernel32.SetInformationJobObject.argtypes = [
                wintypes.HANDLE,
                wintypes.INT,
                wintypes.LPVOID,
                wintypes.DWORD,
            ]
            self.kernel32.SetInformationJobObject.restype = wintypes.BOOL
            self.kernel32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
            self.kernel32.AssignProcessToJobObject.restype = wintypes.BOOL
            self.kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
            self.kernel32.OpenProcess.restype = wintypes.HANDLE
            self.kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
            self.kernel32.CloseHandle.restype = wintypes.BOOL
            self.kernel32.QueryInformationJobObject.argtypes = [
                wintypes.HANDLE,
                wintypes.INT,
                wintypes.LPVOID,
                wintypes.DWORD,
                wintypes.LPVOID,
            ]
            self.kernel32.QueryInformationJobObject.restype = wintypes.BOOL

    def create(self):
        if self.handle:
            return
        handle = self.kernel32.CreateJobObjectW(None, None)
        if not handle:
            raise OSError(ctypes.get_last_error(), "Failed to create job object")

        info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION()

        info.BasicLimitInformation.LimitFlags = self.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE

        result = self.kernel32.SetInformationJobObject(
            handle,
            self.JOB_OBJECT_EXTENDED_LIMIT_INFORMATION,
            ctypes.byref(info),
            ctypes.sizeof(info),
        )
        if not result:
            self.kernel32.CloseHandle(handle)
            raise OSError(ctypes.get_last_error(), "Failed to set job object info")
        self.handle = handle

    def assign_process(self, pid):
        if not self.handle:
            raise RuntimeError("Job object is not initialized")
        proc_handle = self.kernel32.OpenProcess(
            self.PROCESS_SET_QUOTA | self.PROCESS_TERMINATE,
            False,
            pid,
        )
        if not proc_handle:
            raise OSError(ctypes.get_last_error(), f"Failed to open process {pid}")
        try:
            result = self.kernel32.AssignProcessToJobObject(self.handle, proc_handle)
            if not result:
                raise OSError(ctypes.get_last_error(), f"Failed to assign process {pid}")
        finally:
            self.kernel32.CloseHandle(proc_handle)

    def list_pids(self):
        if not self.handle:
            return []
        count = 32
        max_count = 2048
        while True:
            if count > max_count:
                print("ERROR: buffer size exceeded in list_pids(self)")
                return []

            buffer_size = ctypes.sizeof(JOBOBJECT_BASIC_PROCESS_ID_LIST) + (

                ctypes.sizeof(ctypes.c_size_t) * (count - 1)
            )

            buffer = ctypes.create_string_buffer(buffer_size)
            info_ptr = ctypes.cast(buffer, ctypes.POINTER(JOBOBJECT_BASIC_PROCESS_ID_LIST))

            result = self.kernel32.QueryInformationJobObject(
                self.handle,

                self.JOB_OBJECT_BASIC_PROCESS_ID_LIST,
                info_ptr,
                buffer_size,
                None,
            )
            if result:
                number = info_ptr.contents.NumberOfProcessIdsInList
                number = min(number, count)
                base_addr = (
                    ctypes.addressof(info_ptr.contents)
                    + ctypes.sizeof(JOBOBJECT_BASIC_PROCESS_ID_LIST)
                    - ctypes.sizeof(ctypes.c_size_t)
                )
                pid_array = (ctypes.c_size_t * count).from_address(base_addr)
                return [pid_array[i] for i in range(number)]

            error = ctypes.get_last_error()
            if error == self.ERROR_MORE_DATA:
                count *= 2
                continue
            return []

    def close(self):
        if self.handle:
            self.kernel32.CloseHandle(self.handle)
            self.handle = None


def build_popen_command(cmd_path, args):
    if IS_WINDOWS and cmd_path.lower().endswith((".bat", ".cmd")):
        return ["cmd.exe", "/c", cmd_path, *args]
    return [cmd_path, *args]

class Orchestrator:
    def __init__(self, config, logs_dir):
        self.config = config
        self.logs_dir = logs_dir
        self.lock = threading.RLock()
        self.current_running_app = None
        self.processes = []
        self.start_time = None
        self.shutdown_timeout = 5  # seconds, can be made configurable
        self.job_object = None

    def _ensure_job_or_cgroup(self):
        if IS_WINDOWS:
            if not self.job_object:
                self.job_object = WindowsJobObject()
                self.job_object.create()

    def _assign_to_job_or_cgroup(self, pid):
        if IS_WINDOWS:
            if not self.job_object:
                raise RuntimeError("Job object is not initialized")
            self.job_object.assign_process(pid)

    def _list_managed_pids(self):
        if IS_WINDOWS:
            return self.job_object.list_pids() if self.job_object else []
        return [
            entry['proc'].pid
            for entry in self.processes
            if entry['proc'].poll() is None
        ]

    def _cleanup_job_or_cgroup(self):
        if IS_WINDOWS:
            if self.job_object:
                self.job_object.close()
                self.job_object = None

    def _terminate_processes(self):
        for sig in (signal.SIGTERM, signal.SIGKILL):
            for entry in self.processes:
                proc = entry['proc']
                if proc.poll() is not None:
                    continue
                try:
                    os.killpg(proc.pid, sig)
                except ProcessLookupError:
                    continue
            if sig == signal.SIGTERM:
                time.sleep(self.shutdown_timeout)
            if all(entry['proc'].poll() is not None for entry in self.processes):
                break

    def _parse_command(self, cmd):
        if isinstance(cmd, str):
            cmd_args = shlex.split(cmd, posix=not IS_WINDOWS)
        else:
            cmd_args = list(cmd)

        if not cmd_args:
            return []

        cmd_path = resolve_executable_path(cmd_args[0])
        expanded_args = [os.path.expandvars(os.path.expanduser(arg)) for arg in cmd_args[1:]]
        return [cmd_path, *expanded_args]

    def _launch_process(self, cmd_args):
        cmd_path = cmd_args[0]
        cmd_dir = os.path.dirname(cmd_path)
        popen_cmd = build_popen_command(cmd_path, cmd_args[1:])
        popen_kwargs = {
            "stdout": None,
            "stderr": None,
            "cwd": cmd_dir
        }
        if IS_WINDOWS:
            popen_kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
        else:
            popen_kwargs["start_new_session"] = True
        return subprocess.Popen(popen_cmd, **popen_kwargs)

    def start_app(self, app_name):
        with self.lock:
            if app_name not in self.config['apps']:
                raise ValueError('App not found')
            if self.current_running_app == app_name:
                print(f"App '{app_name}' is already running.", flush=True)
                return 'Already running'
            print(f"Starting app '{app_name}'...", flush=True)
            print("Stopping any running app before start.", flush=True)
            self.stop_app()
            print("Stop step complete.", flush=True)

            app_info = self.config['apps'][app_name]
            self.processes = []
            log_file = None

            self._ensure_job_or_cgroup()
            try:
                for cmd in app_info['commands']:
                    cmd_args = self._parse_command(cmd)

                    if not cmd_args:
                        print(f"Skipping empty command for '{app_name}'.", flush=True)
                        continue

                    cmd_path = cmd_args[0]
                    print(f"Resolved command: {cmd_args}", flush=True)

                    if os.path.isabs(cmd_path) and not os.path.exists(cmd_path):
                        raise FileNotFoundError(f"Command not found: {cmd_path}")
                    if not IS_WINDOWS and os.path.isabs(cmd_path) and not os.access(cmd_path, os.X_OK):
                        raise PermissionError(f"Command is not executable: {cmd_path}")

                    print(f"Launching command with cwd={os.path.dirname(cmd_path)}", flush=True)

                    proc = self._launch_process(cmd_args)
                    self._assign_to_job_or_cgroup(proc.pid)
                    print(f"Started process PID={proc.pid} for app '{app_name}'.", flush=True)
                    time.sleep(0.5)

                    self.processes.append({
                        'proc': proc,
                        'log_file': log_file,
                        'command_path': cmd_path
                    })
            except Exception as exc:
                print(f"Failed to start '{app_name}': {exc}", flush=True)
                if IS_WINDOWS:
                    self._cleanup_job_or_cgroup()
                else:
                    self._terminate_processes()
                    self._cleanup_job_or_cgroup()

                for entry in self.processes:
                    handle = entry['log_file']
                    if not handle:
                        continue
                    try:
                        handle.close()
                    except Exception:
                        pass
                self.processes = []
                self.current_running_app = None
                self.start_time = None
                raise

            self.current_running_app = app_name
            self.start_time = time.time()
            print(f"App '{app_name}' started successfully.", flush=True)
            return 'Started'

    def stop_app(self):
        with self.lock:
            if not self.processes:
                self.current_running_app = None
                print("No app running to stop.", flush=True)
                return 'No app running'

            print(f"Stopping {len(self.processes)} process(es).", flush=True)

            if IS_WINDOWS:
                self._cleanup_job_or_cgroup()
            else:
                self._terminate_processes()
                self._cleanup_job_or_cgroup()

            for entry in self.processes:
                log_file = entry['log_file']
                if log_file:
                    log_file.close()
            print("All processes stopped.", flush=True)
            self.processes = []
            self.current_running_app = None
            self.start_time = None
            return 'Stopped'

    def status(self):
        with self.lock:
            managed_pids = self._list_managed_pids()
            return {
                'current_running_app': self.current_running_app,
                'processes': managed_pids,
                'child_processes': [],
                'uptime': (time.time() - self.start_time) if self.start_time else None
            }


WWW_DIR = resource_path("www")

CERT_FILE = os.path.join(data_dir, 'cert.pem')
KEY_FILE = os.path.join(data_dir, 'key.pem')
CA_CERT_FILE = os.path.join(data_dir, 'ca_cert.crt')
CA_KEY_FILE = os.path.join(data_dir, 'ca_key.pem')
CA_CERT_PUBLIC_FILE = os.path.join(WWW_DIR, 'ca-cert.crt')
DEFAULT_PORT = 9999

def ensure_www():
    if not os.path.exists(WWW_DIR):
        os.makedirs(WWW_DIR)
    index_path = os.path.join(WWW_DIR, 'index.html')
    if not os.path.exists(index_path):
        with open(index_path, 'w') as f:
            f.write('<!DOCTYPE html><html><body><h1>Orchestration Server</h1></body></html>')

def get_local_ipv4_addresses():
    ips = set(['127.0.0.1', 'localhost'])
    for iface in socket.if_nameindex():
        try:
            for fam, _, _, _, sockaddr in socket.getaddrinfo(None, 0, proto=socket.IPPROTO_TCP):
                if fam == socket.AF_INET:
                    ips.add(sockaddr[0])
        except Exception:
            continue
    return list(ips)

def create_ca_certificate(cert_file, key_file, public_cert_file, overwrite=False):
    if not overwrite and os.path.exists(cert_file) and os.path.exists(key_file):
        with open(cert_file, "rb") as cert_handle:
            ca_cert = x509.load_pem_x509_certificate(cert_handle.read())
        with open(key_file, "rb") as key_handle:
            ca_key = serialization.load_pem_private_key(key_handle.read(), password=None)
        if public_cert_file and (overwrite or not os.path.exists(public_cert_file)):
            os.makedirs(os.path.dirname(public_cert_file), exist_ok=True)
            with open(public_cert_file, "wb") as public_handle:
                public_handle.write(ca_cert.public_bytes(serialization.Encoding.PEM))
        return ca_cert, ca_key
    print("Generating CA certificate...")
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "State"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Local"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "AppManager"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "AppManager"),
        x509.NameAttribute(NameOID.COMMON_NAME, "AppManager CA"),
    ])
    now = datetime.now(timezone.utc)
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(ca_key.public_key())
        .serial_number(secrets.randbits(128))
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(ca_key, hashes.SHA256())
    )
    with open(cert_file, "wb") as cert_handle:
        cert_handle.write(ca_cert.public_bytes(serialization.Encoding.PEM))
    with open(key_file, "wb") as key_handle:
        key_handle.write(
            ca_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
    if public_cert_file:
        os.makedirs(os.path.dirname(public_cert_file), exist_ok=True)
        with open(public_cert_file, "wb") as public_handle:
            public_handle.write(ca_cert.public_bytes(serialization.Encoding.PEM))
    return ca_cert, ca_key


def generate_self_signed_cert(cert_file, key_file, overwrite=False):
    print("Generating self-signed certificate...")
    # Only generate new CA cert if overwrite is set to True or it does not exists yet
    ca_cert, ca_key = create_ca_certificate(CA_CERT_FILE, CA_KEY_FILE, CA_CERT_PUBLIC_FILE, overwrite)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "State"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Local"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "AppManager"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "AppManager"),
        x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
    ])
    san_list = []
    for name in get_local_ipv4_addresses():
        if name.count(".") == 3:
            san_list.append(x509.IPAddress(ipaddress.ip_address(name)))
        else:
            san_list.append(x509.DNSName(name))
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(secrets.randbits(128))
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
        .add_extension(x509.SubjectAlternativeName(san_list), critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    with open(cert_file, "wb") as cert_handle:
        cert_handle.write(cert.public_bytes(serialization.Encoding.PEM))
    with open(key_file, "wb") as key_handle:
        key_handle.write(
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )


def schedule_restart():
    print("Restart requested; scheduling server restart.", flush=True)
    current_app.config['restart_requested'] = True


def shutdown_server(server):
    if server is None:
        raise RuntimeError('Server shutdown not available')
    server.shutdown()


def wait_for_port_release(port, host="0.0.0.0", timeout=30.0, poll_interval=0.1):
    deadline = time.monotonic() + timeout
    while True:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as test_socket:
                if not IS_WINDOWS:
                    test_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                test_socket.bind((host, port))
            return
        except OSError:
            if time.monotonic() >= deadline:
                raise RuntimeError(f"Timed out waiting for port {port} to be released")
            time.sleep(poll_interval)


def create_app():
    app = Flask(__name__, static_folder=None)

    @app.route("/")
    def index():
        return send_from_directory(WWW_DIR, "index.html")

    @app.route("/index.html")
    def index_html():
        return send_from_directory(WWW_DIR, "index.html")

    @app.route("/static/<path:path>")
    def static_files(path):
        return send_from_directory(WWW_DIR, path)

    # --- API endpoints ---
    @app.route('/api/apps', methods=['GET'])
    @require_auth
    def api_apps():
        try:
            config = refresh_config()
        except Exception as exc:
            return jsonify({'error': f'Invalid config.json: {exc}'}), 400
        return jsonify(config['apps'])

    @app.route('/api/start/<app_name>', methods=['POST'])
    @require_auth
    def api_start(app_name):
        config = current_app.config.get('config')
        orchestrator = current_app.config.get('orchestrator')
        print(f"Received start request for '{app_name}'.", flush=True)
        if app_name not in config['apps']:
            return jsonify({'error': 'Invalid app name'}), 400
        try:
            result = orchestrator.start_app(app_name)
            return jsonify({'status': result})
        except Exception as e:
            print(f"Start request for '{app_name}' failed: {e}", flush=True)
            return jsonify({'error': str(e)}), 500

    @app.route('/api/stop', methods=['POST'])
    @require_auth
    def api_stop():
        orchestrator = current_app.config.get('orchestrator')
        try:
            result = orchestrator.stop_app()
            return jsonify({'status': result})
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    @app.route('/api/status', methods=['GET'])
    @require_auth
    def api_status():
        orchestrator = current_app.config.get('orchestrator')
        return jsonify(orchestrator.status())

    @app.route('/api/certificate', methods=['POST'])
    @require_auth
    def api_certificate():
        try:
            # Do not cahnge CA cert if it exists, only regenarate server cert with new IPs SAN list
            generate_self_signed_cert(CERT_FILE, KEY_FILE, overwrite=False) 
            schedule_restart()
            shutdown_server(current_app.config.get('server'))
        except Exception as exc:
            return jsonify({'error': f'Failed to generate certificate: {exc}'}), 500
        return jsonify({'status': 'restarting'})

    return app


def validate_config(config):
    if not isinstance(config, dict):
        raise ValueError('config.json must be a JSON object')
    apps = config.get('apps')
    if not isinstance(apps, dict):
        raise ValueError('config.json must contain an "apps" object')
    for app, info in apps.items():
        if not isinstance(info, dict):
            raise ValueError(f'App "{app}" must be an object')
        description = info.get('description')
        if not isinstance(description, str):
            raise ValueError(f'App "{app}" must have a string description')
        commands = info.get('commands')
        if not isinstance(commands, list):
            raise ValueError(f'App "{app}" commands must be a list')
        for command in commands:
            if not isinstance(command, str):
                raise ValueError(f'App "{app}" commands must be strings')


def load_config():
    config_path = os.path.join(data_dir, 'config.json')
    if not os.path.exists(config_path):
        raise FileNotFoundError("config.json missing in project root.")
    with open(config_path, 'r') as f:
        try:
            config = json.load(f)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Invalid JSON: {exc.msg}") from exc
    validate_config(config)
    return config


def refresh_config():
    config = load_config()
    current_app.config['config'] = config
    orchestrator = current_app.config.get('orchestrator')
    if orchestrator:
        orchestrator.config = config
    return config

def main():
    ensure_www()
    generate_self_signed_cert(CERT_FILE, KEY_FILE, overwrite=False)
    try:
        config = load_config()
    except FileNotFoundError:
        print("config.json missing in project root.")
        sys.exit(2)
    except Exception as e:
        print(f"Malformed config.json: {e}")
        sys.exit(3)
    logs_dir = os.path.join(os.path.dirname(__file__), 'logs')
    orchestrator = Orchestrator(config, logs_dir)
    auth_config = load_auth_config()
    token_hash = get_token_hash_from_config(auth_config)
    port = get_port_from_config(auth_config)
    app = create_app()
    app.config['orchestrator'] = orchestrator
    app.config['config'] = config
    app.config['auth_config'] = auth_config
    app.config['token_hash'] = token_hash
    app.config['restart_requested'] = False
    configure_request_logging()
    server = make_server("0.0.0.0", port, app, threaded=True, ssl_context=(CERT_FILE, KEY_FILE))
    app.config['server'] = server
    print(f"Server ready https://127.0.0.1:{port}", flush=True)
    try:
        server.serve_forever()
    except OSError as e:
        print(f"Failed to start server: {e}")
        sys.exit(1)
    finally:
        if app.config.get('restart_requested'):
            try:
                orchestrator.stop_app()
            except Exception as exc:
                print(f"Failed to stop subprocesses before restart: {exc}", flush=True)
            try:
                server.server_close()
            except Exception as exc:
                print(f"Failed to close server socket: {exc}", flush=True)
            wait_for_port_release(port)
            os.execv(sys.executable, [sys.executable] + sys.argv)

if __name__ == "__main__":
    main()
