import logging
import uuid
import re
from openevolve.evaluation_result import EvaluationResult
from typing import Tuple, Optional
import os
import shutil
import subprocess
import docker
import tempfile
import sys
import argparse
import paramiko
import yaml

EVALUATOR_SETUP_FOLDER = os.path.join(os.path.dirname(__file__), 'evaluator_setup')
DEFAULT_FORBIDDEN_DOMAIN = "cloudflare.com"
DEFAULT_ALLOWED_DOMAIN = "example.com"
DEFAULT_BLOCKED_FITNESS_FILE = "/workspace/fitness.txt"
DEFAULT_PACKETS_FILE = "/workspace/packets_stage2.pcap"


logging.basicConfig(format='%(asctime)s %(levelname)s: %(message)s', datefmt="%Y-%m-%d %H:%M:%S", level=logging.INFO)
logger = logging.getLogger(__name__)


def _log_script_output(source: str, label: str, output: str) -> None:
    """Log multi-line script output line-by-line with context."""
    if not output:
        return
    for line in output.splitlines():
        stripped = line.rstrip()
        if stripped:
            logger.info("%s [%s] %s", source, label, stripped)
        else:
            logger.info("%s [%s]", source, label)


def start_client_container(
    container_name: str,
    middlebox_ip: str,
    environment: Optional[dict] = None, 
    ) -> Tuple[Optional[object], Optional[str]]:
    """
    Start the client container using docker.

    Args:
        container_name: Name for the container
        middlebox_ip: IP address of the middlebox to route through
        environment: Optional environment variables to set in the container

    Returns:
        Tuple of (container object, IP address) or (None, None) on failure
    """
    client = docker.from_env()

    try:
        # Check if a container with this name already exists
        try:
            existing_container = client.containers.get(container_name)
            logger.info("Found existing container '%s', removing it...", container_name)
            existing_container.remove(force=True)
        except docker.errors.NotFound:
            pass

        # Only build the image if it doesn't exist
        image_exists = False
        try:
            client.images.get("client:latest")
            image_exists = True
            logger.info("Using existing 'client:latest' image")
        except docker.errors.ImageNotFound:
            pass

        if not image_exists:
            logger.info("Building 'client:latest' image...")
            client.images.build(
                path="./",
                dockerfile=os.path.join(EVALUATOR_SETUP_FOLDER, "client", "Dockerfile.client"),
                tag="client:latest",
                rm=True,
            )

        startup_cmd = [
            "bash",
            "-c",
            (
                "ip route del default 2>/dev/null || true && "
                f"ip route add default via {middlebox_ip} && "
                "tail -f /dev/null"
            ),
        ]

        container = client.containers.run(
            image="client:latest",
            name=container_name,
            command=startup_cmd,
            cap_add=["NET_ADMIN", "SYS_ADMIN", "NET_RAW", "SYS_PTRACE"],
            detach=True,
            environment=environment or {},
            labels={"org.openevolve.client": "true"},
        )

        logger.info("Created and started container '%s' successfully.", container_name)

        # Copy tests folder into the container at /workspace/
        tests_path = os.path.join(os.getcwd(), 'tests')
        if os.path.exists(tests_path):
            try:
                container.exec_run(["mkdir", "-p", "/workspace/"])
                _result = subprocess.run(
                    ["docker", "cp", f"{tests_path}/.", f"{container_name}:/workspace/"],
                    check=True,
                    text=True,
                    capture_output=True,
                )
                if _result.stdout:
                    logger.info("docker cp stdout: %s", _result.stdout)
                if _result.stderr:
                    logger.warning("docker cp stderr: %s", _result.stderr)
                logger.info("Copied tests folder into container at /workspace/")
            except Exception as exc:
                logger.warning("Failed to copy tests folder into container: %s", exc)
        else:
            logger.warning("Tests folder not found at %s, skipping copy", tests_path)

        container.reload()
        ip_address = container.attrs["NetworkSettings"]["Networks"]["bridge"]["IPAddress"]
        return container, ip_address
    except Exception as e:
        logger.error("Failed to start client container: %s", e)
        return None, None


def start_middlebox_container(
    container_name: str,
    config_volume_path: Optional[str] = None,
    force_rebuild: bool = False,
    ) -> Tuple[Optional[object], Optional[str]]:
    """
    Start or get the 'middlebox' container using docker-py.
    """
    client = docker.from_env()

    try:
        try:
            existing_container = client.containers.get(container_name)
            logger.info("Found existing container '%s', removing it...", container_name)
            existing_container.remove(force=True)
        except docker.errors.NotFound:
            pass

        # Only build the image if it doesn't exist or force_rebuild is True
        image_exists = False
        if not force_rebuild:
            try:
                client.images.get("opengfw:latest")
                image_exists = True
                logger.info("Using existing 'opengfw:latest' image (use force_rebuild=True to rebuild)")
            except docker.errors.ImageNotFound:
                pass

        if not image_exists:
            logger.info("Building 'opengfw:latest' image...")
            client.images.build(
                path="./",
                dockerfile=os.path.join(EVALUATOR_SETUP_FOLDER, "opengfw", "Dockerfile.opengfw"),
                tag="opengfw:latest",
                rm=True,
            )

        startup_cmd = [
            "sh",
            "-c",
            (
                "iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE && "
                "echo '[opengfw] Starting OpenGFW...' && "
                "exec opengfw -c /etc/opengfw/config.toml /etc/opengfw/rules.yaml"
            ),
        ]

        volume_path = config_volume_path or os.path.join(os.getcwd(), EVALUATOR_SETUP_FOLDER, 'opengfw', 'config')
        container = client.containers.run(
            image="opengfw:latest",
            name=container_name,
            command=startup_cmd,
            detach=True,
            labels={"org.openevolve.middlebox": "true"},
            hostname=container_name,
            cap_add=["NET_ADMIN", "SYS_ADMIN"],
            sysctls={"net.ipv4.ip_forward": "1"},
            volumes={
                volume_path: {
                    "bind": "/etc/opengfw",
                    "mode": "ro",
                }
            },
            network_mode="bridge",
        )

        logger.info("Created and started container '%s' successfully.", container_name)

    except Exception as e:
        logger.error("Failed to get/create '%s' container: %s", container_name, e)
        return None, None

    container.reload()
    ip_address = container.attrs["NetworkSettings"]["Networks"]["bridge"]["IPAddress"]
    return container, ip_address


def _prepare_opengfw_config(forbidden_domain: str) -> Tuple[str, bool]:
    """
    Prepare an OpenGFW configuration directory customized for the forbidden domain.
    """
    base_config_path = os.path.join(os.getcwd(), EVALUATOR_SETUP_FOLDER, 'opengfw', 'config')
    sanitized_domain = (forbidden_domain or "").strip() or DEFAULT_FORBIDDEN_DOMAIN

    temp_config_dir = tempfile.mkdtemp(prefix="opengfw-config-")
    shutil.copy2(
        os.path.join(base_config_path, 'config.toml'),
        os.path.join(temp_config_dir, 'config.toml'),
    )

    rules_template_path = os.path.join(base_config_path, 'rules.yaml')
    with open(rules_template_path, 'r', encoding='utf-8') as src:
        rules_template = src.read()

    placeholder = "{{FORBIDDEN_DOMAIN}}"
    if placeholder in rules_template:
        rules_content = rules_template.replace(placeholder, sanitized_domain)
    else:
        rules_content = rules_template.replace(DEFAULT_FORBIDDEN_DOMAIN, sanitized_domain)

    with open(os.path.join(temp_config_dir, 'rules.yaml'), 'w', encoding='utf-8') as dst:
        dst.write(rules_content)

    return temp_config_dir, True


def _safe_float(value: str, name: str) -> float:
    try:
        return float(value.strip())
    except (ValueError, AttributeError) as exc:
        raise RuntimeError(f"Failed to parse {name} from output: {value}") from exc


def _evaluate_dockerized(
    program_path: str,
    censor: str,
    persist_containers: bool,
    forbidden_domain: str,
    allowed_domain: str,
    censor_variant: str,
    censor_type: str = "in-path-modifier",
    program_id: str = None,
    expected_resolved_ip: str = "",
    ) -> EvaluationResult:
    
    logger.info("Evaluating program: %s", program_path)

    forbidden_domain = (forbidden_domain or "").strip() or DEFAULT_FORBIDDEN_DOMAIN
    allowed_domain = (allowed_domain or "").strip() or DEFAULT_ALLOWED_DOMAIN

    opengfw_config_path, opengfw_config_is_temp = _prepare_opengfw_config(forbidden_domain)

    middlebox_container = None
    client_container = None
    middlebox_ip: Optional[str] = None
    client_ip: Optional[str] = None

    # Use program_id for container naming if provided, otherwise use UUID
    # Sanitize program_id to be Docker-safe (lowercase, alphanumeric, hyphens, underscores only)
    if program_id:
        # Sanitize: lowercase, replace invalid chars with hyphens, limit length
        sanitized_id = program_id.lower()
        # Replace any characters that aren't alphanumeric, hyphens, or underscores with hyphens
        sanitized_id = re.sub(r'[^a-z0-9_-]', '-', sanitized_id)
        # Remove leading/trailing hyphens and periods
        sanitized_id = sanitized_id.strip('.-')
        # Limit to 50 chars to leave room for prefix
        if len(sanitized_id) > 50:
            sanitized_id = sanitized_id[:50]
        # Ensure it doesn't start with a hyphen or period
        if sanitized_id and sanitized_id[0] in ['-', '.']:
            sanitized_id = 'p' + sanitized_id
        unique_id = sanitized_id
    else:
        unique_id = str(uuid.uuid4())
    
    middlebox_name = f"middlebox-{unique_id}"
    client_name = f"client-{unique_id}"

    try:
        middlebox_container, middlebox_ip = start_middlebox_container(
            middlebox_name,
            config_volume_path=opengfw_config_path,
        )

        if middlebox_container is None or middlebox_ip is None:
            return EvaluationResult(
                metrics={"evasion_success": -1000, "combined_score": -1000},
                artifacts={"error": "Failed to start middlebox container"},
            )

        client_env = {
            "FORBIDDEN_DOMAIN": forbidden_domain,
            "ALLOWED_DOMAIN": allowed_domain,
            "CENSOR_TYPE": censor_type,
            "EXPECTED_RESOLVED_IP": expected_resolved_ip or "",
        }
        client_container, client_ip = start_client_container(
            client_name,
            middlebox_ip,
            environment=client_env,
        )
        if client_container is None or client_ip is None:
            return EvaluationResult(
                metrics={"evasion_success": -1000, "combined_score": -1000},
                artifacts={"error": "Failed to start client container"},
            )

        with open(program_path, "rb") as program_file:
            program_bytes = program_file.read()

        subprocess.run(
            [
                "docker",
                "exec",
                "-i",
                client_name,
                "bash",
                "-c",
                "cat > /workspace/dns_initial.py",
            ],
            input=program_bytes,
            check=True,
        )


        # Run the test script inside the container with appropriate censor type
        # The censor_type determines scoring logic and default server IP:
        # - "in-path-modifier": sends to real DNS (1.1.1.1), tests for response modification
        # - "on-path-injector": sends to non-DNS server, tests for injection
        
        # Generate unique source port for this evaluation to allow concurrent evaluations
        # Using ephemeral port range (49152-65535)
        import random
        source_port = random.randint(49152, 65535)
        
        test_cmd = [
            "python3", "/workspace/run_tests.py",
            "--stage", "2",  # Only run Stage 2 in Docker (Stage 1 already passed locally)
            "--program-path", "/workspace/dns_initial.py",
            "--censor-type", censor_type,
            "--port", "53",
            "--source-port", str(source_port),
            "--packets-file", DEFAULT_PACKETS_FILE,
            "--fitness-file", DEFAULT_BLOCKED_FITNESS_FILE,
        ]
        logger.info("Running test with censor_type=%s, source_port=%s", censor_type, source_port)
        
        score_exec_result = client_container.exec_run(
            test_cmd,
            workdir="/workspace",
        )
        score_stdout = score_exec_result.output.decode("utf-8", errors="ignore")
        _log_script_output(client_name, "blocked", score_stdout)

        fitness_blocked_raw = client_container.exec_run(["cat", DEFAULT_BLOCKED_FITNESS_FILE]).output.decode(
            "utf-8", errors="ignore"
        )
        packets_output = client_container.exec_run(
            ["tshark", "-r", DEFAULT_PACKETS_FILE, "-V", "-q", "-z", "io,stat,0"]
        ).output.decode("utf-8", errors="ignore")

        try:
            fitness_blocked = float(fitness_blocked_raw.strip())
        except:
            fitness_blocked = 0.0
             
        score = fitness_blocked

        logger.info("%s [blocked] Fitness: %s", client_name, fitness_blocked)
        logger.info("%s [blocked] Packets: %s", client_name, packets_output)

        artifacts = {
            "packet_capture": packets_output,
            "forbidden_domain": forbidden_domain,
        }

        return EvaluationResult(
            metrics={
                "combined_score": score,
                "evasion_success": fitness_blocked,
            },
            artifacts=artifacts,
        )
    finally:
        if not persist_containers:
            if client_container is not None:
                try:
                    client_container.remove(force=True)
                except Exception as exc:
                    logger.warning("Failed to remove client container during cleanup: %s", exc)

            if middlebox_container is not None:
                try:
                    middlebox_container.remove(force=True)
                except Exception as exc:
                    logger.warning("Failed to remove middlebox container during cleanup: %s", exc)

        if opengfw_config_is_temp and (not persist_containers or middlebox_container is None):
            shutil.rmtree(opengfw_config_path, ignore_errors=True)


# ============================================================================
# Remote Evaluation (SSH to VPS in censored country)
# ============================================================================

def _evaluate_remote(
    program_path: str,
    remote_host: str,
    remote_user: str,
    remote_key_path: Optional[str] = None,
    remote_password: Optional[str] = None,
    forbidden_domain: str = DEFAULT_FORBIDDEN_DOMAIN,
    allowed_domain: str = DEFAULT_ALLOWED_DOMAIN,
    persist_remote: bool = False,
    server_ip: str = "93.184.216.34",  # Non-DNS server for on-path-injector
    censor_type: str = "on-path-injector",
    program_id: str = None,
    interface: str = "eth0",
) -> EvaluationResult:
    """
    Evaluate a DNS censorship evasion program on a remote VPS.
    
    For remote evaluation (e.g., testing against China's GFW):
    - SSHs to the remote VPS
    - Uploads the program and test script
    - Runs the test and retrieves results
    
    Args:
        program_path: Path to the program file to evaluate
        remote_host: Remote VPS IP/Hostname
        remote_user: Remote VPS Username
        remote_key_path: Optional path to SSH private key
        remote_password: Optional SSH password
        forbidden_domain: Domain that should be blocked
        allowed_domain: Domain that should remain accessible
        persist_remote: Whether to keep remote workspace after evaluation
        server_ip: Target server IP to test against
        censor_type: Type of censor (on-path-injector or in-path-modifier)
        program_id: Optional ID to pass to the evaluator
        interface: Network interface for packet capture (e.g., eth0, ens3)
    
    Returns:
        EvaluationResult with metrics and artifacts
    """
    logger.info("Evaluating program remotely on %s: %s", remote_host, program_path)
    
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    try:
        logger.info("Connecting to remote host %s...", remote_host)
        connect_kwargs = {
            "hostname": remote_host,
            "username": remote_user,
            "timeout": 30,
        }
        if remote_key_path:
            connect_kwargs["key_filename"] = remote_key_path
        if remote_password:
            connect_kwargs["password"] = remote_password
            
        ssh.connect(**connect_kwargs)
        
        # Create temporary workspace on remote
        if program_id:
            remote_workspace = f"/tmp/dns_eval_{program_id}"
        else:
            remote_workspace = f"/tmp/dns_eval_{uuid.uuid4()}"
            
        ssh.exec_command(f"mkdir -p {remote_workspace}")
        
        try:
            sftp = ssh.open_sftp()
            
            # Upload program
            remote_program_path = f"{remote_workspace}/dns_initial.py"
            sftp.put(program_path, remote_program_path)
            logger.info("Uploaded program to %s", remote_program_path)
            
            # Upload run_tests.py
            local_tests_path = os.path.join(os.path.dirname(__file__), 'tests', 'run_tests.py')
            remote_tests_path = f"{remote_workspace}/run_tests.py"
            sftp.put(local_tests_path, remote_tests_path)
            logger.info("Uploaded run_tests.py to %s", remote_tests_path)
            
            # Pre-flight diagnostics: check tools and interfaces
            diag_cmd = (
                "echo '=== Remote Diagnostics ===' && "
                "echo -n 'tcpdump: ' && (which tcpdump || echo 'NOT FOUND') && "
                "echo -n 'tshark: ' && (which tshark || echo 'NOT FOUND') && "
                "echo -n 'python3: ' && (which python3 || echo 'NOT FOUND') && "
                "echo -n 'nc: ' && (which nc || echo 'NOT FOUND') && "
                "echo 'Interfaces:' && (ip link show 2>/dev/null || ifconfig 2>/dev/null | grep -E '^[a-z]' || echo 'Cannot list interfaces')"
            )
            stdin, stdout, stderr = ssh.exec_command(diag_cmd)
            diag_output = stdout.read().decode('utf-8', errors='ignore')
            logger.info("Remote diagnostics:\n%s", diag_output)
            
            # Run tests - ONLY Stage 2 (evasion test) on remote
            # Stage 1 (validity check) should have already run locally
            # Note: All file paths are relative to remote_workspace (current directory)
            pcap_filename = "packets_stage2.pcap"
            
            # Generate unique source port for this evaluation to allow concurrent evaluations
            # Using ephemeral port range (49152-65535)
            import random
            source_port = random.randint(49152, 65535)
            
            cmd = (
                f"cd {remote_workspace} && "
                f"FORBIDDEN_DOMAIN={forbidden_domain} "
                f"ALLOWED_DOMAIN={allowed_domain} "
                f"CENSOR_TYPE={censor_type} "
                f"PACKETS_FILE={pcap_filename} "
                f"python3 run_tests.py "
                f"--stage 2 "
                f"--censor-type {censor_type} "
                f"--program-path dns_initial.py "
                f"--fitness-file fitness.txt "
                f"--packets-file {pcap_filename} "
                f"--server-ip {server_ip} "
                f"--interface {interface} "
                f"--port 53 "
                f"--source-port {source_port}"
            )
            
            logger.info("Running remote command: %s", cmd)
            stdin, stdout, stderr = ssh.exec_command(cmd, timeout=120)
            
            # Wait for completion
            exit_status = stdout.channel.recv_exit_status()
            
            output = stdout.read().decode('utf-8', errors='ignore')
            error_output = stderr.read().decode('utf-8', errors='ignore')
            
            _log_script_output(remote_host, "run_tests", output)
            if error_output:
                _log_script_output(remote_host, "run_tests_err", error_output)
                
            # Retrieve results
            try:
                with sftp.open(f"{remote_workspace}/fitness.txt") as f:
                    fitness_raw = f.read().decode('utf-8').strip()
                    fitness_score = _safe_float(fitness_raw, "fitness_score")
            except IOError:
                logger.warning("Could not read fitness file from remote")
                fitness_score = 0.0
            except Exception as e:
                logger.warning("Error reading fitness: %s", e)
                fitness_score = 0.0
                
            # Try to get pcap analysis if tshark is available
            packets_output = ""
            pcap_path = f"{remote_workspace}/{pcap_filename}"
            
            # Check if pcap file exists and get its size
            pcap_check_cmd = f"ls -la {pcap_path} 2>&1 || echo 'PCAP FILE NOT FOUND'"
            stdin, stdout, stderr = ssh.exec_command(pcap_check_cmd)
            pcap_check = stdout.read().decode('utf-8', errors='ignore').strip()
            logger.info("PCAP check: %s", pcap_check)
            
            if "NOT FOUND" not in pcap_check:
                # Try tshark analysis
                tshark_cmd = f"tshark -r {pcap_path} -V -q -z io,stat,0 2>&1 || echo 'tshark failed or not installed'"
                stdin, stdout, stderr = ssh.exec_command(tshark_cmd)
                packets_output = stdout.read().decode('utf-8', errors='ignore')
                
                # Also get simple packet count
                count_cmd = f"tcpdump -r {pcap_path} -c 100 2>&1 | head -20 || echo 'tcpdump read failed'"
                stdin, stdout, stderr = ssh.exec_command(count_cmd)
                tcpdump_output = stdout.read().decode('utf-8', errors='ignore')
                logger.info("PCAP packet summary:\n%s", tcpdump_output)
            else:
                packets_output = f"PCAP file not created at {pcap_path}. Check if tcpdump has permission and interface '{interface}' is correct."
                logger.warning(packets_output)
                 
            artifacts = {
                "packet_capture": packets_output,
                "forbidden_domain": forbidden_domain,
                "remote_host": remote_host,
                "censor_type": censor_type,
                "test_output": output,
            }
            
            return EvaluationResult(
                metrics={
                    "combined_score": fitness_score,
                    "evasion_success": fitness_score,
                },
                artifacts=artifacts,
            )
            
        finally:
            # Cleanup
            if not persist_remote:
                logger.info("Cleaning up remote workspace %s", remote_workspace)
                ssh.exec_command(f"rm -rf {remote_workspace}")
            else:
                logger.info("Persisting remote workspace %s", remote_workspace)
            sftp.close()
            
    except Exception as e:
        logger.error("Remote evaluation failed: %s", e)
        import traceback
        return EvaluationResult(
            metrics={"evasion_success": -1000, "combined_score": -1000},
            artifacts={"error": f"Remote evaluation failed: {str(e)}", "traceback": traceback.format_exc()},
        )
    finally:
        ssh.close()


def load_config_from_yaml() -> dict:
    """Load configuration from config.yaml if it exists."""
    config_path = os.environ.get("OPENEVOLVE_CONFIG_PATH", os.path.join(os.getcwd(), "config.yaml"))
    if os.path.exists(config_path):
        try:
            with open(config_path, 'r') as f:
                return yaml.safe_load(f)
        except Exception as e:
            logger.warning(f"Failed to load config from {config_path}: {e}")
    return {}


# ============================================================================
# OpenEvolve Cascade Evaluation Functions
# ============================================================================
# These functions are called by OpenEvolve when cascade_evaluation=true
# Stage 1: Local DNS validity check (uncensored) - ensures packet is valid DNS
# Stage 2: Censored network evasion test - tests actual evasion

def evaluate_stage1(program_path: str, **kwargs) -> EvaluationResult:
    """
    Stage 1: Local DNS validity check using multiple resolvers.
    
    Runs the program and sends DNS to 3 public DNS resolvers:
    - 1.1.1.1 (Cloudflare)
    - 8.8.8.8 (Google)
    - 9.9.9.9 (Quad9)
    
    Scoring: 100 points for each successful resolution (max 300).
    Pass threshold: At least 1 resolver must succeed (score >= 100).
    
    This prevents evolution from gaming on-path-injector tests
    by simply not sending valid DNS packets.
    """
    logger.info("=== STAGE 1: Local DNS Validity Check (Multi-Resolver) ===")
    
    # Get forbidden domain from config - we must verify the response is for this domain
    config = load_config_from_yaml()
    scenario_config = config.get("scenario_config", {})
    forbidden_domain = scenario_config.get("forbidden_domain", os.environ.get("FORBIDDEN_DOMAIN", DEFAULT_FORBIDDEN_DOMAIN))
    
    # Get expected resolved IP(s) - if configured, we verify the DNS response contains this IP
    # This prevents cheating by ensuring the packet actually resolves to the correct IP
    expected_resolved_ip = scenario_config.get("expected_resolved_ip", os.environ.get("EXPECTED_RESOLVED_IP", ""))
    
    logger.info("Stage 1: Testing DNS resolution across 3 resolvers for domain: %s", forbidden_domain)
    if expected_resolved_ip:
        logger.info("Stage 1: Expected resolved IP: %s", expected_resolved_ip)
    
    # Run locally without middlebox - just check packet validity
    # We use a simple subprocess test here since we're checking locally
    import tempfile
    
    try:
        # Create temp directory for test outputs
        with tempfile.TemporaryDirectory() as tmpdir:
            packets_file = os.path.join(tmpdir, "packets_stage1.pcap")
            fitness_file = os.path.join(tmpdir, "fitness_stage1.txt")
            
            # Copy program to temp location
            temp_program = os.path.join(tmpdir, "dns_initial.py")
            shutil.copy2(program_path, temp_program)
            
            # Run test locally using subprocess (no Docker, no middlebox)
            # This tests against 3 DNS resolvers for robustness
            test_cmd = [
                sys.executable, "-c", f'''
import subprocess
import sys
import os
import signal
import time
import random

program_path = "{temp_program}"
# Multiple DNS resolvers to test against
DNS_RESOLVERS = [
    ("1.1.1.1", "Cloudflare"),
    ("8.8.8.8", "Google"),
    ("9.9.9.9", "Quad9"),
]
POINTS_PER_RESOLVER = 1  # 1 point for each successful resolution (max 3)

forbidden_domain = "{forbidden_domain}"
packets_file = "{packets_file}"
expected_resolved_ip = "{expected_resolved_ip}"  # If set, verify resolved IP contains this

def parse_name_at_offset(data, offset):
    """Parse a DNS name at a given offset, handling compression pointers. Returns (name, new_offset)."""
    labels = []
    original_offset = offset
    jumped = False
    jump_offset = None
    
    while offset < len(data):
        length = data[offset]
        if length == 0:
            if not jumped:
                offset += 1
            break
        # Handle compression pointer
        if length >= 192:
            if not jumped:
                jump_offset = offset + 2  # Save where to continue after pointer
            pointer = ((length & 0x3f) << 8) | data[offset + 1]
            offset = pointer
            jumped = True
            continue
        if offset + 1 + length > len(data):
            break
        labels.append(data[offset + 1:offset + 1 + length].decode("ascii", errors="ignore"))
        offset += length + 1
    
    name = ".".join(labels).lower().rstrip(".") if labels else None
    final_offset = jump_offset if jumped else offset
    return name, final_offset

def extract_all_qnames_from_response(data):
    """Extract ALL queried domain names (QNAMEs) from DNS response question section."""
    try:
        if len(data) < 12:
            return [], 0
        
        # Get question count from header (QDCOUNT at bytes 4-5)
        qdcount = (data[4] << 8) | data[5]
        
        qnames = []
        offset = 12  # Skip DNS header
        
        for _ in range(qdcount):
            if offset >= len(data):
                break
            name, offset = parse_name_at_offset(data, offset)
            if name:
                qnames.append(name)
            # Skip QTYPE (2) and QCLASS (2)
            offset += 4
        
        return qnames, offset
    except Exception as e:
        print("Warning: Could not parse QNAMEs from DNS response: {{e}}".format(e=e))
        return [], 12

def extract_qname_from_response(data):
    """Extract the first queried domain name (QNAME) from DNS response."""
    qnames, _ = extract_all_qnames_from_response(data)
    return qnames[0] if qnames else None

def domain_matches(qname, target):
    """Check if qname matches or is subdomain of target."""
    if not qname or not target:
        return False
    qname = qname.lower().rstrip(".")
    target = target.lower().rstrip(".")
    return qname == target or qname.endswith("." + target)

def extract_ips_for_domain(data, target_domain):
    """Extract IP addresses from DNS response A records that match the target domain."""
    try:
        ips = []
        if len(data) < 12:
            return []
        
        # Get counts from header
        qdcount = (data[4] << 8) | data[5]
        ancount = (data[6] << 8) | data[7]
        
        # Skip question section
        offset = 12
        for _ in range(qdcount):
            if offset >= len(data):
                break
            _, offset = parse_name_at_offset(data, offset)
            offset += 4  # Skip QTYPE and QCLASS
        
        # Parse answer section - only accept IPs for target domain
        for _ in range(ancount):
            if offset >= len(data):
                break
            
            # Parse NAME for this answer record
            answer_name, name_end = parse_name_at_offset(data, offset)
            offset = name_end
            
            if offset + 10 > len(data):
                break
            
            # Read TYPE (2 bytes), CLASS (2 bytes), TTL (4 bytes), RDLENGTH (2 bytes)
            rtype = (data[offset] << 8) | data[offset + 1]
            rdlength = (data[offset + 8] << 8) | data[offset + 9]
            offset += 10  # Move past fixed fields
            
            if offset + rdlength > len(data):
                break
            
            # TYPE 1 = A record (IPv4)
            # Only accept IPs if the answer NAME matches target domain
            if rtype == 1 and rdlength == 4:
                if answer_name and domain_matches(answer_name, target_domain):
                    ip = ".".join(str(data[offset + i]) for i in range(4))
                    ips.append(ip)
            
            offset += rdlength
        
        return ips
    except Exception as e:
        print("Warning: Could not parse IPs from DNS response: {{e}}".format(e=e))
        return []

def extract_ips_from_response(data):
    """Extract IP addresses from DNS response (A records). Legacy function for compatibility."""
    try:
        ips = []
        if len(data) < 12:
            return []
        
        # Get counts from header
        qdcount = (data[4] << 8) | data[5]
        ancount = (data[6] << 8) | data[7]
        
        # Skip question section
        offset = 12
        for _ in range(qdcount):
            if offset >= len(data):
                break
            _, offset = parse_name_at_offset(data, offset)
            offset += 4  # Skip QTYPE and QCLASS
        
        # Parse answer section
        for _ in range(ancount):
            if offset >= len(data):
                break
            
            # Skip NAME
            _, offset = parse_name_at_offset(data, offset)
            
            if offset + 10 > len(data):
                break
            
            # Read TYPE (2 bytes), CLASS (2 bytes), TTL (4 bytes), RDLENGTH (2 bytes)
            rtype = (data[offset] << 8) | data[offset + 1]
            rdlength = (data[offset + 8] << 8) | data[offset + 9]
            offset += 10
            
            if offset + rdlength > len(data):
                break
            
            # TYPE 1 = A record (IPv4)
            if rtype == 1 and rdlength == 4:
                ip = ".".join(str(data[offset + i]) for i in range(4))
                ips.append(ip)
            
            offset += rdlength
        
        return ips
    except Exception as e:
        print("Warning: Could not parse IPs from DNS response: {{e}}".format(e=e))
        return []

def verify_ip_serves_domain(ip, domain):
    """Verify that an IP actually serves the domain by checking response content contains domain identifier."""
    import http.client
    
    print("    Verifying IP {{ip}} serves {{domain}} via HTTP...".format(ip=ip, domain=domain))
    
    # Extract domain base for content matching (e.g., "pornhub" from "pornhub.com")
    domain_lower = domain.lower().replace("www.", "")
    domain_base = domain_lower.split(".")[0]
    
    try:
        conn = http.client.HTTPConnection(ip, 80, timeout=5)
        
        # Request root path with Host header set to the domain
        conn.request("GET", "/", headers={{"Host": domain, "User-Agent": "Mozilla/5.0"}})
        response = conn.getresponse()
        status = response.status
        body = response.read().decode('utf-8', errors='ignore').lower()
        
        # Check for redirect - if redirecting, check Location header
        location = ""
        if status in [301, 302, 303, 307, 308]:
            location = response.getheader('Location', '').lower()
        
        conn.close()
        
        print("      HTTP {{ip}}:80 -> Status: {{status}}".format(ip=ip, status=status))
        if body:
            print("      Response body preview: {{preview}}...".format(preview=body[:100].replace('\\n', ' ')))
        
        # Method 1: Check if response body contains domain identifier
        if domain_base in body or domain_lower in body:
            print("      SUCCESS: Response contains '{{db}}' - confirmed domain".format(db=domain_base))
            return True, status
        
        # Method 2: Check if redirect Location contains domain
        if location and (domain_base in location or domain_lower in location):
            print("      SUCCESS: Redirect to '{{loc}}' contains domain".format(loc=location[:50]))
            return True, status
        
        # Method 3: For some domains, the root page might not contain the domain name but server responds correctly
        # Check if we got a valid response (200 status)
        if status == 200 and len(body) > 0:
            # Server responds but doesn't contain domain name in content
            # This is weaker validation - log a warning
            print("      WARNING: Valid response but no domain identifier found")
            print("      Consider this a WEAK match - server responds but can't confirm domain")
            # Still return False for strict validation
            pass
        
        print("      FAIL: Response doesn't contain domain identifier '{{db}}'".format(db=domain_base))
        return False, status
            
    except Exception as e:
        print("      HTTP failed: {{e}}".format(e=str(e)[:50]))
    
    print("      FAIL: IP {{ip}} does not serve domain {{domain}}".format(ip=ip, domain=domain))
    return False, None

def test_resolver(packet_bytes, dns_server, resolver_name, source_port, expected_resolved_ip=None, forbidden_domain=None):
    """Test DNS resolution against a single resolver. Returns (success, ips, error_msg)."""
    import socket
    
    print()
    print("-" * 50)
    print("Testing resolver: {{resolver_name}} ({{dns_server}})".format(resolver_name=resolver_name, dns_server=dns_server))
    print("-" * 50)
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind(('', source_port))
    except:
        pass
    sock.settimeout(5)
    
    try:
        sock.sendto(packet_bytes, (dns_server, 53))
        print("  Sent DNS packet from port {{source_port}} to {{dns_server}}:53".format(source_port=source_port, dns_server=dns_server))
        response, _ = sock.recvfrom(4096)
        
        if len(response) > 0:
            print("  Received DNS response ({{len_response}} bytes)".format(len_response=len(response)))
            
            # Extract all IPs from A records in the response
            ips = extract_ips_from_response(response)
            print("  Resolved IPs: {{ips}}".format(ips=ips))
            
            if not ips:
                print("  FAIL: No IP addresses in response")
                return False, [], "No IPs in response"
            
            # If expected_resolved_ip is configured, verify at least one resolved IP matches
            if expected_resolved_ip:
                if expected_resolved_ip not in ips:
                    print("  FAIL: Expected IP '{{exp}}' not found in resolved IPs {{ips}}".format(
                        exp=expected_resolved_ip, ips=ips))
                    return False, [], "Expected IP not in resolved IPs - possible cheating"
                print("  Verified: Expected IP '{{exp}}' found in resolved IPs".format(exp=expected_resolved_ip))
                # Skip HTTP validation if expected_resolved_ip is provided
                print("  SUCCESS: {{resolver_name}} resolved domain successfully (expected IP verified, HTTP validation skipped)".format(resolver_name=resolver_name))
                return True, ips, None
            
            # HTTP validation: verify at least one IP actually serves the forbidden domain
            if forbidden_domain:
                print("  Verifying resolved IPs serve the forbidden domain...")
                http_verified = False
                for ip in ips:
                    verified, status = verify_ip_serves_domain(ip, forbidden_domain)
                    if verified:
                        http_verified = True
                        break
                
                if not http_verified:
                    print("  FAIL: None of the resolved IPs serve the forbidden domain")
                    return False, [], "HTTP validation failed - IPs don't serve the domain"
                
                print("  SUCCESS: {{resolver_name}} resolved domain successfully (HTTP verified)".format(resolver_name=resolver_name))
            else:
                print("  SUCCESS: {{resolver_name}} resolved domain successfully".format(resolver_name=resolver_name))
            return True, ips, None
        else:
            print("  FAIL: Empty response")
            return False, [], "Empty response"
    except socket.timeout:
        print("  FAIL: Timeout - no response from {{resolver_name}}".format(resolver_name=resolver_name))
        return False, [], "Timeout"
    except Exception as e:
        print("  FAIL: Error - {{e}}".format(e=e))
        return False, [], str(e)
    finally:
        sock.close()

# Run program to get hex output
try:
    print("=" * 60)
    print("STAGE 1: Multi-Resolver DNS Validity Check")
    print("=" * 60)
    print("Testing DNS packet against 3 public resolvers")
    if expected_resolved_ip:
        print("Expected resolved IP: {{ip}} (REQUIRED - must be in response)".format(ip=expected_resolved_ip))
    else:
        print("WARNING: No expected_resolved_ip configured - only checking for valid DNS response")
    print("Scoring: {{pts}} points per successful resolution (max {{max_pts}})".format(
        pts=POINTS_PER_RESOLVER, max_pts=POINTS_PER_RESOLVER * len(DNS_RESOLVERS)))
    print("Pass threshold: At least 1 resolver must succeed (>= 1 point)")
    print()
    
    result = subprocess.run(
        [sys.executable, program_path],
        capture_output=True, text=True, timeout=30
    )
    hex_output = result.stdout.strip()
    
    if not hex_output or result.returncode != 0:
        print("FAIL: Program did not produce output")
        print("stderr: {{result.stderr}}".format(result=result))
        with open("{fitness_file}", "w") as f:
            f.write("0.0")
        sys.exit(0)
    
    # Validate it is hex
    try:
        packet_bytes = bytes.fromhex(hex_output)
    except ValueError:
        print("FAIL: Output is not valid hex")
        with open("{fitness_file}", "w") as f:
            f.write("0.0")
        sys.exit(0)
    
    print("Program produced {{nbytes}} bytes of DNS packet data".format(nbytes=len(packet_bytes)))
    
    # Test against each resolver
    total_score = 0
    successful_resolvers = []
    failed_resolvers = []
    all_ips = set()
    
    for dns_server, resolver_name in DNS_RESOLVERS:
        # Use unique source port for each resolver test
        source_port = random.randint(49152, 65535)
        success, ips, error = test_resolver(packet_bytes, dns_server, resolver_name, source_port, expected_resolved_ip, forbidden_domain)
        
        if success:
            total_score += POINTS_PER_RESOLVER
            successful_resolvers.append((resolver_name, dns_server, ips))
            all_ips.update(ips)
        else:
            failed_resolvers.append((resolver_name, dns_server, error))
    
    # Print summary
    print()
    print("=" * 60)
    print("STAGE 1 SUMMARY")
    print("=" * 60)
    print("Total Score: {{total_score}} / {{max_score}}".format(
        total_score=total_score, max_score=POINTS_PER_RESOLVER * len(DNS_RESOLVERS)))
    print()
    
    if successful_resolvers:
        print("SUCCESSFUL RESOLVERS ({{count}}):".format(count=len(successful_resolvers)))
        for resolver_name, dns_server, ips in successful_resolvers:
            print("  + {{resolver_name}} ({{dns_server}}): {{ips}}".format(
                resolver_name=resolver_name, dns_server=dns_server, ips=ips))
    
    if failed_resolvers:
        print("FAILED RESOLVERS ({{count}}):".format(count=len(failed_resolvers)))
        for resolver_name, dns_server, error in failed_resolvers:
            print("  - {{resolver_name}} ({{dns_server}}): {{error}}".format(
                resolver_name=resolver_name, dns_server=dns_server, error=error))
    
    print()
    if total_score >= 1:
        print("STAGE 1 PASSED: At least one resolver succeeded")
        print("All resolved IPs: {{ips}}".format(ips=list(all_ips)))
        print("Stage 2 (evasion test) will proceed.")
    else:
        print("STAGE 1 FAILED: No resolvers succeeded (score < 1)")
        if expected_resolved_ip:
            print("Required expected IP '{{ip}}' was not found in DNS responses.".format(ip=expected_resolved_ip))
        else:
            print("The DNS packet may be malformed or invalid.")
        print("Stage 2 (evasion test) will NOT run.")
    
    print("=" * 60)
    
    with open("{fitness_file}", "w") as f:
        f.write(str(float(total_score)))
        
except Exception as e:
    print("ERROR: {{e}}".format(e=e))
    import traceback
    traceback.print_exc()
    with open("{fitness_file}", "w") as f:
        f.write("0.0")
'''
            ]
            
            result = subprocess.run(
                test_cmd,
                capture_output=True,
                text=True,
                timeout=120  # Increased timeout for 3 resolver tests
            )
            
            logger.info("Stage 1 output: %s", result.stdout)
            if result.stderr:
                logger.warning("Stage 1 stderr: %s", result.stderr)
            
            # Read fitness score
            try:
                with open(fitness_file, 'r') as f:
                    stage1_score = float(f.read().strip())
            except:
                stage1_score = 0.0
            
            logger.info("Stage 1 validity score: %s (pass threshold: 1)", stage1_score)
            
            # Pass threshold is 1 (at least 1 resolver must succeed)
            passed = stage1_score >= 1.0
            
            # Always include evasion_success metric (required by feature_dimensions)
            # If stage 1 fails (score < 1), evasion_success is -10
            # If stage 1 passes, evasion_success will be updated by stage 2
            return EvaluationResult(
                metrics={
                    "stage1_validity": stage1_score,
                    "combined_score": -10 if not passed else stage1_score,
                    "evasion_success": -10 if not passed else 0.0,  # Will be overwritten by stage 2 if it runs
                },
                artifacts={
                    "stage": "stage1_local_validity",
                    # "test_output": result.stdout,
                    # "resolvers_tested": 3,
                    "pass_threshold": 1,
                },
            )
            
    except Exception as e:
        logger.error("Stage 1 evaluation failed: %s", e)
        return EvaluationResult(
            metrics={"stage1_validity": 0.0, "combined_score": -10, "evasion_success": -10},
            artifacts={"error": str(e), "stage": "stage1_local_validity"},
        )


def evaluate_stage2(program_path: str, program_id: str = "", **kwargs) -> EvaluationResult:
    """
    Stage 2: Censored network evasion test.
    
    Uses remote SSH or local Docker based on config.
    Only runs if Stage 1 passes (packet is valid DNS).
    
    Args:
        program_path: Path to the program file
        program_id: Program ID from OpenEvolve for tracking remote evaluations
    """
    logger.info("=== STAGE 2: Censored Network Evasion Test ===")
    
    # Get settings from environment or config
    censor_type = os.environ.get("CENSOR_TYPE", "in-path-modifier")
    forbidden_domain = os.environ.get("FORBIDDEN_DOMAIN", DEFAULT_FORBIDDEN_DOMAIN)
    allowed_domain = os.environ.get("ALLOWED_DOMAIN", DEFAULT_ALLOWED_DOMAIN)
    
    # Load config and apply overrides (for both local and remote evaluation)
    config = load_config_from_yaml()
    scenario_config = config.get("scenario_config", {})
    eval_type = scenario_config.get("evaluation_type", "docker")
    
    # Override from scenario_config if present (applies to BOTH local and remote)
    if "censor_type" in scenario_config:
        censor_type = scenario_config["censor_type"]
    if "forbidden_domain" in scenario_config:
        forbidden_domain = scenario_config["forbidden_domain"]
    if "allowed_domain" in scenario_config:
        allowed_domain = scenario_config["allowed_domain"]
    
    # Get expected_resolved_ip for IP validation (optional)
    expected_resolved_ip = scenario_config.get("expected_resolved_ip", os.environ.get("EXPECTED_RESOLVED_IP", ""))
    if expected_resolved_ip:
        logger.info("Stage 2: Expected resolved IP: %s", expected_resolved_ip)
    
    if eval_type == "remote":
        # Use remote SSH evaluation
        remote_config = scenario_config.get("remote", {})
        remote_host = remote_config.get("host")
        remote_user = remote_config.get("user")
        remote_key_path = remote_config.get("key_path")
        remote_password = remote_config.get("password")
        persist_remote = remote_config.get("persist", False)
        server_ip = remote_config.get("server_ip", "93.184.216.34")
        interface = remote_config.get("interface", "eth0")
        
        logger.info("Stage 2: Using REMOTE evaluation (host=%s, program_id=%s, interface=%s)", remote_host, program_id, interface)
        
        return _evaluate_remote(
            program_path=program_path,
            remote_host=remote_host,
            remote_user=remote_user,
            remote_key_path=remote_key_path,
            remote_password=remote_password,
            forbidden_domain=forbidden_domain,
            allowed_domain=allowed_domain,
            persist_remote=persist_remote,
            server_ip=server_ip,
            censor_type=censor_type,
            program_id=program_id,
            interface=interface,
        )
    
    # Use local Docker evaluation
    # Check if persist_containers is enabled in config
    persist_containers = scenario_config.get("persist_containers", False)
    logger.info("Stage 2: Using LOCAL Docker evaluation (program_id=%s, persist_containers=%s)", program_id, persist_containers)
    return _evaluate_dockerized(
        program_path=program_path,
        censor="opengfw",
        persist_containers=persist_containers,
        forbidden_domain=forbidden_domain,
        allowed_domain=allowed_domain,
        censor_variant="censor1",
        censor_type=censor_type,
        program_id=program_id,
        expected_resolved_ip=expected_resolved_ip,
    )


def evaluate(
    program_path: str,
    censor: str = "opengfw",
    persist_containers: bool = False,
    forbidden_domain: str = DEFAULT_FORBIDDEN_DOMAIN,
    allowed_domain: str = DEFAULT_ALLOWED_DOMAIN,
    censor_variant: str = "censor1",
    censor_type: str = "in-path-modifier",
    remote_host: Optional[str] = None,
    remote_user: Optional[str] = None,
    remote_key_path: Optional[str] = None,
    remote_password: Optional[str] = None,
    persist_remote: bool = False,
    server_ip: str = "93.184.216.34",
    program_id: str = None,
    **kwargs
    ) -> EvaluationResult:
    """
    Main evaluation function - uses Docker locally or SSH to remote VPS.
    
    Checks scenario_config.evaluation_type in config.yaml:
    - "docker": Use local Docker evaluation with OpenGFW middlebox
    - "remote": SSH to remote VPS in censored country
    
    For on-path-injector, runs Stage 1 (validity) before Stage 2 (evasion).
    """
    # Initialize expected_resolved_ip (will be set from config if available)
    expected_resolved_ip = ""
    
    # Try to load remote config from YAML if not provided
    if not remote_host:
        config = load_config_from_yaml()
        scenario_config = config.get("scenario_config", {})
        
        # Check evaluation type
        eval_type = scenario_config.get("evaluation_type", "docker")
        
        # Get censor_type from config if not overridden
        if "censor_type" in scenario_config:
            censor_type = scenario_config["censor_type"]
        
        # Get domains from config
        if "forbidden_domain" in scenario_config:
            forbidden_domain = scenario_config["forbidden_domain"]
        if "allowed_domain" in scenario_config:
            allowed_domain = scenario_config["allowed_domain"]
        
        # Get expected_resolved_ip for IP validation (optional)
        expected_resolved_ip = scenario_config.get("expected_resolved_ip", "")
        
        if eval_type == "remote":
            remote_config = scenario_config.get("remote", {})
            remote_host = remote_config.get("host")
            remote_user = remote_config.get("user") or remote_user
            remote_key_path = remote_config.get("key_path") or remote_key_path
            remote_password = remote_config.get("password") or remote_password
            if not persist_remote:
                persist_remote = remote_config.get("persist", False)
            if "server_ip" in remote_config:
                server_ip = remote_config["server_ip"]
                
            logger.info("Using REMOTE evaluation mode (host=%s, censor_type=%s)", remote_host, censor_type)
    
    # Set environment for stage functions
    os.environ["CENSOR_TYPE"] = censor_type
    os.environ["FORBIDDEN_DOMAIN"] = forbidden_domain
    os.environ["ALLOWED_DOMAIN"] = allowed_domain
    
    # Use remote evaluation if configured
    if remote_host:
        logger.info("Running REMOTE evaluation on %s", remote_host)
        
        # For remote on-path-injector, do local validity check first
        if censor_type == "on-path-injector":
            logger.info("on-path-injector: Running local validity check first...")
            stage1_result = evaluate_stage1(program_path)
            
            if stage1_result.metrics.get("stage1_validity", 0.0) < 1.0:
                logger.warning("Stage 1 failed - DNS validation failed (score < 1). Stage 2 will NOT run.")
                return EvaluationResult(
                    metrics={
                        "stage1_validity": stage1_result.metrics.get("stage1_validity", 0.0),
                        "evasion_success": -10,
                        "combined_score": -10,
                    },
                    artifacts={
                        **stage1_result.artifacts,
                        "failure_reason": "Stage 1 failed - DNS packet did not resolve to expected IP or is invalid. Stage 2 blocked.",
                    },
                )
            
            logger.info("Stage 1 passed (score=%s) - proceeding to remote evasion test on %s", 
                       stage1_result.metrics.get("stage1_validity", 0.0), remote_host)
            
            # Run stage 2 and add stage1 score to combined_score
            stage2_result = _evaluate_remote(
                program_path=program_path,
                remote_host=remote_host,
                remote_user=remote_user,
                remote_key_path=remote_key_path,
                remote_password=remote_password,
                forbidden_domain=forbidden_domain,
                allowed_domain=allowed_domain,
                persist_remote=persist_remote,
                server_ip=server_ip,
                censor_type=censor_type,
                program_id=program_id,
            )
            
            # Add stage1 score to combined_score (evasion is primary, stage1 is decimal bonus)
            stage1_score = stage1_result.metrics.get("stage1_validity", 0.0)
            stage2_combined = stage2_result.metrics.get("combined_score", 0.0)
            # Formula: evasion_success + (stage1_validity * 0.1)
            # Don't add bonus if stage2 failed (-10 = stage1 fail, -1000 = infrastructure fail)
            if stage2_combined <= -10:
                combined_total = stage2_combined
            else:
                combined_total = stage2_combined + (stage1_score * 0.1)
            
            return EvaluationResult(
                metrics={
                    **stage2_result.metrics,
                    "stage1_validity": stage1_score,
                    "combined_score": combined_total,
                },
                artifacts={
                    **stage2_result.artifacts,
                    **stage1_result.artifacts,
                },
            )
        
        return _evaluate_remote(
            program_path=program_path,
            remote_host=remote_host,
            remote_user=remote_user,
            remote_key_path=remote_key_path,
            remote_password=remote_password,
            forbidden_domain=forbidden_domain,
            allowed_domain=allowed_domain,
            persist_remote=persist_remote,
            server_ip=server_ip,
            censor_type=censor_type,
            program_id=program_id,
        )
    
    # Use local Docker evaluation
    logger.info("Running LOCAL Docker evaluation (censor_type=%s)", censor_type)
    
    # For on-path-injector without cascade, run both stages
    if censor_type == "on-path-injector":
        logger.info("on-path-injector: Running validity check first...")
        stage1_result = evaluate_stage1(program_path)
        
        if stage1_result.metrics.get("stage1_validity", 0.0) < 1.0:
            logger.warning("Stage 1 failed - DNS validation failed (score < 1). Stage 2 will NOT run.")
            return EvaluationResult(
                metrics={
                    "stage1_validity": stage1_result.metrics.get("stage1_validity", 0.0),
                    "evasion_success": -10,
                    "combined_score": -10,
                },
                artifacts={
                    **stage1_result.artifacts,
                    "failure_reason": "Stage 1 failed - DNS packet did not resolve to expected IP or is invalid. Stage 2 blocked.",
                },
            )
        
        logger.info("Stage 1 passed (score=%s) - proceeding to evasion test", 
                   stage1_result.metrics.get("stage1_validity", 0.0))
        
        # Check if persist_containers is enabled in config (if not passed as arg)
        if not persist_containers:
            config = load_config_from_yaml()
            persist_containers = config.get("scenario_config", {}).get("persist_containers", False)
        
        # Run stage 2 and add stage1 score to combined_score
        stage2_result = _evaluate_dockerized(
            program_path=program_path,
            censor=censor,
            persist_containers=persist_containers,
            forbidden_domain=forbidden_domain,
            allowed_domain=allowed_domain,
            censor_variant=censor_variant,
            censor_type=censor_type,
            program_id=program_id,
            expected_resolved_ip=expected_resolved_ip,
        )
        
        # Add stage1 score to combined_score (evasion is primary, stage1 is decimal bonus)
        stage1_score = stage1_result.metrics.get("stage1_validity", 0.0)
        stage2_combined = stage2_result.metrics.get("combined_score", 0.0)
        # Formula: evasion_success + (stage1_validity * 0.1)
        # Don't add bonus if stage2 failed (-10 = stage1 fail, -1000 = infrastructure fail)
        if stage2_combined <= -10:
            combined_total = stage2_combined
        else:
            combined_total = stage2_combined + (stage1_score * 0.1)
        
        return EvaluationResult(
            metrics={
                **stage2_result.metrics,
                "stage1_validity": stage1_score,
                "combined_score": combined_total,
            },
            artifacts={
                **stage2_result.artifacts,
                **stage1_result.artifacts,
            },
        )
    
    # Check if persist_containers is enabled in config (if not passed as arg)
    if not persist_containers:
        config = load_config_from_yaml()
        persist_containers = config.get("scenario_config", {}).get("persist_containers", False)
    
    return _evaluate_dockerized(
        program_path=program_path,
        censor=censor,
        persist_containers=persist_containers,
        forbidden_domain=forbidden_domain,
        allowed_domain=allowed_domain,
        censor_variant=censor_variant,
        censor_type=censor_type,
        program_id=program_id,
        expected_resolved_ip=expected_resolved_ip,
    )

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Evaluate censorship evasion program")
    parser.add_argument("program_path", help="Path to the program file to evaluate")
    parser.add_argument(
        "--censor",
        default="opengfw",
        choices=["opengfw"],
        help="Censorship configuration to use (default: opengfw)",
    )
    parser.add_argument(
        "--persist-containers",
        action="store_true",
        default=False,
        help="Keep containers running after evaluation (default: False)",
    )
    parser.add_argument(
        "--forbidden-domain",
        default=DEFAULT_FORBIDDEN_DOMAIN,
        help=f"Domain expected to be blocked and tested for evasion (default: {DEFAULT_FORBIDDEN_DOMAIN})",
    )
    parser.add_argument(
        "--allowed-domain",
        default=DEFAULT_ALLOWED_DOMAIN,
        help=f"Domain expected to remain accessible (default: {DEFAULT_ALLOWED_DOMAIN})",
    )
    parser.add_argument(
        "--censor-variant",
        default="censor1",
        help="Select the censor variant",
    )
    parser.add_argument(
        "--censor-type",
        default="in-path-modifier",
        choices=["in-path-modifier", "on-path-injector"],
        help="Type of censor: 'in-path-modifier' (OpenGFW style, modifies responses) "
             "or 'on-path-injector' (China GFW style, injects fake responses) (default: in-path-modifier)",
    )
    
    args, unknown = parser.parse_known_args()

    result = evaluate(
        program_path=args.program_path,
        censor=args.censor,
        persist_containers=args.persist_containers,
        forbidden_domain=args.forbidden_domain,
        allowed_domain=args.allowed_domain,
        censor_variant=args.censor_variant,
        censor_type=args.censor_type,
    )
    logger.info("Evaluation result: %s", result)
    sys.exit(0)

