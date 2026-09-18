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
DEFAULT_FITNESS_FILE = "/workspace/fitness.txt"
DEFAULT_PACKETS_FILE = "/workspace/packets_stage2.pcap"
DEFAULT_SERVER_PORT = 80

# Counter for round-robin port selection
_port_selection_counter = 0
_port_selection_lock = None
_parsed_ports_cache = {}  # Cache parsed port ranges

def _parse_ports(ports_config) -> list:
    """
    Parse port configuration into a list of ports.
    
    Supports:
        - Single int: 80 -> [80]
        - List of ints: [80, 443, 8080] -> [80, 443, 8080]
        - Range string: "80-65535" -> [80, 81, 82, ..., 65535]
        - Range string: "1024-65535" -> [1024, 1025, ..., 65535]
        - Mixed list: [80, "443-445", 8080] -> [80, 443, 444, 445, 8080]
    
    Returns:
        List of port integers
    """
    if ports_config is None:
        return []
    
    # Check cache first (for range strings)
    cache_key = str(ports_config)
    if cache_key in _parsed_ports_cache:
        return _parsed_ports_cache[cache_key]
    
    result = []
    
    # Handle single int (including negative numbers from YAML misparse like 80-65535 -> -65455)
    if isinstance(ports_config, int):
        if ports_config < 0:
            # YAML might have interpreted "80-65535" as arithmetic (80 - 65535 = -65455)
            # This shouldn't happen with standard YAML, but handle it just in case
            logger.warning("Received negative port value %d, using default port 80", ports_config)
            return [DEFAULT_SERVER_PORT]
        return [ports_config]
    
    # Handle range string like "80-65535"
    if isinstance(ports_config, str):
        if '-' in ports_config and not ports_config.startswith('-'):
            try:
                start, end = ports_config.split('-', 1)
                start_port = int(start.strip())
                end_port = int(end.strip())
                if start_port > end_port:
                    start_port, end_port = end_port, start_port
                # Clamp to valid port range
                start_port = max(1, min(65535, start_port))
                end_port = max(1, min(65535, end_port))
                result = list(range(start_port, end_port + 1))
                logger.info("Parsed port range '%s' -> %d ports (%d-%d)", 
                           ports_config, len(result), start_port, end_port)
                _parsed_ports_cache[cache_key] = result
            except ValueError as e:
                logger.warning("Invalid port range '%s': %s", ports_config, e)
                return [DEFAULT_SERVER_PORT]
        else:
            # Single port as string
            try:
                port = int(ports_config.strip())
                if port < 1 or port > 65535:
                    logger.warning("Port %d out of range, using default", port)
                    return [DEFAULT_SERVER_PORT]
                return [port]
            except ValueError:
                logger.warning("Invalid port '%s', using default", ports_config)
                return [DEFAULT_SERVER_PORT]
        return result
    
    # Handle list (can contain ints, strings, or ranges)
    if isinstance(ports_config, list):
        for item in ports_config:
            if isinstance(item, int):
                if 1 <= item <= 65535:
                    result.append(item)
            elif isinstance(item, str):
                # Recursively parse (handles ranges in lists)
                result.extend(_parse_ports(item))
        if result:
            _parsed_ports_cache[cache_key] = result
            return result
        else:
            return [DEFAULT_SERVER_PORT]
    
    logger.warning("Unknown ports_config type: %s, using default", type(ports_config).__name__)
    return [DEFAULT_SERVER_PORT]


def _get_next_port(ports_config) -> int:
    """
    Get the next port from a port configuration using round-robin selection.
    Thread-safe for parallel evaluations.
    
    Args:
        ports_config: Can be:
            - List of ints: [80, 443, 8080]
            - Range string: "80-65535"
            - Mixed list: [80, "443-445", 8080]
    
    Returns:
        Next port in sequence
    """
    global _port_selection_counter, _port_selection_lock
    
    # Parse ports (handles ranges, lists, etc.)
    ports = _parse_ports(ports_config)
    
    if not ports:
        return DEFAULT_SERVER_PORT
    
    if len(ports) == 1:
        return ports[0]
    
    # Initialize lock if needed (lazy init for thread safety)
    if _port_selection_lock is None:
        import threading
        _port_selection_lock = threading.Lock()
    
    with _port_selection_lock:
        port = ports[_port_selection_counter % len(ports)]
        _port_selection_counter += 1
        # Only log occasionally for large ranges
        if len(ports) <= 10 or _port_selection_counter % 100 == 1:
            logger.info("Selected port %d (counter=%d, total_ports=%d)", 
                       port, _port_selection_counter, len(ports))
        return port


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

        client.images.build(
            path="./",
            dockerfile=os.path.join(EVALUATOR_SETUP_FOLDER, "client", "Dockerfile.client"),
            tag="http-client:latest",
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
            image="http-client:latest",
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

        client.images.build(
            path="./",
            dockerfile=os.path.join(EVALUATOR_SETUP_FOLDER, "opengfw", "Dockerfile.opengfw"),
            tag="http-opengfw:latest",
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
            image="http-opengfw:latest",
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

    temp_config_dir = tempfile.mkdtemp(prefix="opengfw-http-config-")
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
    server_port: int = DEFAULT_SERVER_PORT,
    ) -> EvaluationResult:
    
    logger.info("Evaluating HTTP program: %s", program_path)

    forbidden_domain = (forbidden_domain or "").strip() or DEFAULT_FORBIDDEN_DOMAIN
    allowed_domain = (allowed_domain or "").strip() or DEFAULT_ALLOWED_DOMAIN

    opengfw_config_path, opengfw_config_is_temp = _prepare_opengfw_config(forbidden_domain)

    middlebox_container = None
    client_container = None
    middlebox_ip: Optional[str] = None
    client_ip: Optional[str] = None

    # Use program_id for container naming if provided
    if program_id:
        sanitized_id = program_id.lower()
        sanitized_id = re.sub(r'[^a-z0-9_-]', '-', sanitized_id)
        sanitized_id = sanitized_id.strip('.-')
        if len(sanitized_id) > 50:
            sanitized_id = sanitized_id[:50]
        if sanitized_id and sanitized_id[0] in ['-', '.']:
            sanitized_id = 'p' + sanitized_id
        unique_id = sanitized_id
    else:
        unique_id = str(uuid.uuid4())
    
    middlebox_name = f"http-middlebox-{unique_id}"
    client_name = f"http-client-{unique_id}"

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
            "SERVER_PORT": str(server_port),
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
                "cat > /workspace/http_initial.py",
            ],
            input=program_bytes,
            check=True,
        )

        # Generate unique source port for this evaluation
        import random
        source_port = random.randint(49152, 65535)
        
        test_cmd = [
            "python3", "/workspace/run_tests.py",
            "--program-path", "/workspace/http_initial.py",
            "--censor-type", censor_type,
            "--port", str(server_port),
            "--source-port", str(source_port),
            "--packets-file", DEFAULT_PACKETS_FILE,
            "--fitness-file", DEFAULT_FITNESS_FILE,
        ]
        logger.info("Running test with censor_type=%s, source_port=%s", censor_type, source_port)
        
        score_exec_result = client_container.exec_run(
            test_cmd,
            workdir="/workspace",
        )
        score_stdout = score_exec_result.output.decode("utf-8", errors="ignore")
        _log_script_output(client_name, "http-test", score_stdout)

        fitness_raw = client_container.exec_run(["cat", DEFAULT_FITNESS_FILE]).output.decode(
            "utf-8", errors="ignore"
        )
        packets_output = client_container.exec_run(
            ["tshark", "-r", DEFAULT_PACKETS_FILE, "-x", "-q", "-z", "io,stat,0"]
        ).output.decode("utf-8", errors="ignore")

        try:
            fitness_score = float(fitness_raw.strip())
        except:
            fitness_score = 0.0
             
        score = fitness_score

        logger.info("%s [http] Fitness: %s", client_name, fitness_score)
        logger.info("%s [http] Packets: %s", client_name, packets_output)

        artifacts = {
            "packet_capture": packets_output,
            "forbidden_domain": forbidden_domain,
        }

        return EvaluationResult(
            metrics={
                "combined_score": score,
                "evasion_success": fitness_score,
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
    server_ip: str = "104.16.132.229",  # Cloudflare IP
    server_ports = DEFAULT_SERVER_PORT,  # Port(s) - int, list, or range string. Defaults to 80.
    censor_type: str = "on-path-resetter",
    program_id: str = None,
    interface: str = "eth0",
) -> EvaluationResult:
    """
    Evaluate an HTTP censorship evasion program on a remote VPS.
    
    Args:
        server_ports: Port configuration. Supports:
            - Single int: 80
            - List: [80, 443, 8080]
            - Range string: "80-65535"
            Defaults to port 80.
    """
    # Get the port to use (handles int, list, or range string)
    server_port = _get_next_port(server_ports)
    
    logger.info("Evaluating HTTP program remotely on %s: %s (port=%d)", remote_host, program_path, server_port)
    
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
            remote_workspace = f"/tmp/http_eval_{program_id}"
        else:
            remote_workspace = f"/tmp/http_eval_{uuid.uuid4()}"
            
        ssh.exec_command(f"mkdir -p {remote_workspace}")
        
        try:
            sftp = ssh.open_sftp()
            
            # Upload program
            remote_program_path = f"{remote_workspace}/http_initial.py"
            sftp.put(program_path, remote_program_path)
            logger.info("Uploaded program to %s", remote_program_path)
            
            # Upload run_tests.py
            local_tests_path = os.path.join(os.path.dirname(__file__), 'tests', 'run_tests.py')
            remote_tests_path = f"{remote_workspace}/run_tests.py"
            sftp.put(local_tests_path, remote_tests_path)
            logger.info("Uploaded run_tests.py to %s", remote_tests_path)
            
            # Pre-flight diagnostics
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
            
            pcap_filename = "packets_stage2.pcap"
            
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
                f"--program-path http_initial.py "
                f"--fitness-file fitness.txt "
                f"--packets-file {pcap_filename} "
                f"--server-ip {server_ip} "
                f"--interface {interface} "
                f"--port {server_port} "
                f"--source-port {source_port}"
            )
            
            logger.info("Running remote command: %s", cmd)
            stdin, stdout, stderr = ssh.exec_command(cmd, timeout=120)
            
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
                
            # Try to get pcap analysis
            packets_output = ""
            pcap_path = f"{remote_workspace}/{pcap_filename}"
            
            pcap_check_cmd = f"ls -la {pcap_path} 2>&1 || echo 'PCAP FILE NOT FOUND'"
            stdin, stdout, stderr = ssh.exec_command(pcap_check_cmd)
            pcap_check = stdout.read().decode('utf-8', errors='ignore').strip()
            logger.info("PCAP check: %s", pcap_check)
            
            if "NOT FOUND" not in pcap_check:
                tshark_cmd = f"tshark -r {pcap_path} -x -q -z io,stat,0 2>&1 || echo 'tshark failed or not installed'"
                stdin, stdout, stderr = ssh.exec_command(tshark_cmd)
                packets_output = stdout.read().decode('utf-8', errors='ignore')
                
                count_cmd = f"tcpdump -r {pcap_path} -c 100 2>&1 | head -20 || echo 'tcpdump read failed'"
                stdin, stdout, stderr = ssh.exec_command(count_cmd)
                tcpdump_output = stdout.read().decode('utf-8', errors='ignore')
                logger.info("PCAP packet summary:\n%s", tcpdump_output)
            else:
                packets_output = f"PCAP file not created at {pcap_path}."
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
# Legacy Stage Evaluation Functions - COMMENTED OUT (not used)
# ============================================================================
# 
# The following functions were used for cascade/multi-stage evaluation.
# They are no longer used in the main evaluation flow.
# Keeping them commented out for reference.
#
# def evaluate_stage1(program_path: str, **kwargs) -> EvaluationResult:
#     """Stage 1: Local HTTP validity check (uncensored) - NOT USED"""
#     pass
#
# def evaluate_stage2(program_path: str, program_id: str = "", **kwargs) -> EvaluationResult:
#     """Stage 2: Censored network evasion test - NOT USED"""
#     pass
#
# ============================================================================


def _legacy_evaluate_stage2(program_path: str, program_id: str = "", **kwargs) -> EvaluationResult:
    """
    Stage 2: Censored network evasion test.
    """
    logger.info("=== STAGE 2: Censored Network Evasion Test ===")
    
    censor_type = os.environ.get("CENSOR_TYPE", "on-path-resetter")
    forbidden_domain = os.environ.get("FORBIDDEN_DOMAIN", DEFAULT_FORBIDDEN_DOMAIN)
    allowed_domain = os.environ.get("ALLOWED_DOMAIN", DEFAULT_ALLOWED_DOMAIN)
    
    config = load_config_from_yaml()
    scenario_config = config.get("scenario_config", {})
    eval_type = scenario_config.get("evaluation_type", "docker")
    # server_ports defaults to 80, supports int, list, or range string
    server_ports = scenario_config.get("server_ports", DEFAULT_SERVER_PORT)
    
    if eval_type == "remote":
        remote_config = scenario_config.get("remote", {})
        remote_host = remote_config.get("host")
        remote_user = remote_config.get("user")
        remote_key_path = remote_config.get("key_path")
        remote_password = remote_config.get("password")
        persist_remote = remote_config.get("persist", False)
        server_ip = remote_config.get("server_ip", "104.16.132.229")
        interface = remote_config.get("interface", "eth0")
        # Override server_ports from remote config if specified
        if "server_ports" in remote_config:
            server_ports = remote_config["server_ports"]
        
        if "censor_type" in scenario_config:
            censor_type = scenario_config["censor_type"]
        if "forbidden_domain" in scenario_config:
            forbidden_domain = scenario_config["forbidden_domain"]
        if "allowed_domain" in scenario_config:
            allowed_domain = scenario_config["allowed_domain"]
        
        logger.info("Stage 2: Using REMOTE evaluation (host=%s, program_id=%s)", remote_host, program_id)
        
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
            server_ports=server_ports,
            censor_type=censor_type,
            program_id=program_id,
            interface=interface,
        )
    
    # For docker, get the port from server_ports config
    server_port = _get_next_port(server_ports)
    logger.info("Stage 2: Using LOCAL Docker evaluation (program_id=%s, port=%d)", program_id, server_port)
    return _evaluate_dockerized(
        program_path=program_path,
        censor="opengfw",
        persist_containers=False,
        forbidden_domain=forbidden_domain,
        allowed_domain=allowed_domain,
        censor_variant="censor1",
        censor_type=censor_type,
        program_id=program_id,
        server_port=server_port,
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
    server_ip: str = "104.16.132.229",
    server_ports = DEFAULT_SERVER_PORT,  # Port(s) - int, list, or range string. Defaults to 80.
    program_id: str = None,
    **kwargs
    ) -> EvaluationResult:
    """
    Main evaluation function - uses Docker locally or SSH to remote VPS.
    
    Args:
        server_ports: Port configuration. Supports:
            - Single int: 80
            - List: [80, 443, 8080]  
            - Range string: "80-65535"
            Defaults to port 80.
    """
    # Try to load config from YAML
    if not remote_host:
        config = load_config_from_yaml()
        scenario_config = config.get("scenario_config", {})
        
        eval_type = scenario_config.get("evaluation_type", "docker")
        
        if "censor_type" in scenario_config:
            censor_type = scenario_config["censor_type"]
        
        if "forbidden_domain" in scenario_config:
            forbidden_domain = scenario_config["forbidden_domain"]
        if "allowed_domain" in scenario_config:
            allowed_domain = scenario_config["allowed_domain"]
        if "server_ports" in scenario_config:
            server_ports = scenario_config["server_ports"]
            logger.info("Loaded server_ports from scenario_config: %s (type: %s)", server_ports, type(server_ports).__name__)
        
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
            # Override server_ports from remote config if specified
            if "server_ports" in remote_config:
                server_ports = remote_config["server_ports"]
                logger.info("Override server_ports from remote config: %s (type: %s)", server_ports, type(server_ports).__name__)
                
            logger.info("Using REMOTE evaluation mode (host=%s, censor_type=%s, server_ports=%s)", remote_host, censor_type, server_ports)
    
    os.environ["CENSOR_TYPE"] = censor_type
    os.environ["FORBIDDEN_DOMAIN"] = forbidden_domain
    os.environ["ALLOWED_DOMAIN"] = allowed_domain
    
    # Remote evaluation
    if remote_host:
        logger.info("Running REMOTE evaluation on %s", remote_host)
        
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
            server_ports=server_ports,
            censor_type=censor_type,
            program_id=program_id,
        )
    
    # Local Docker evaluation
    # For docker, get the port from server_ports config
    server_port = _get_next_port(server_ports)
    logger.info("Running LOCAL Docker evaluation (censor_type=%s, port=%d)", censor_type, server_port)
    
    return _evaluate_dockerized(
        program_path=program_path,
        censor=censor,
        persist_containers=persist_containers,
        forbidden_domain=forbidden_domain,
        allowed_domain=allowed_domain,
        censor_variant=censor_variant,
        censor_type=censor_type,
        program_id=program_id,
        server_port=server_port,
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Evaluate HTTP censorship evasion program")
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
        help=f"Domain expected to be blocked (default: {DEFAULT_FORBIDDEN_DOMAIN})",
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
        choices=["in-path-modifier", "on-path-resetter"],
        help="Type of censor (default: in-path-modifier)",
    )
    parser.add_argument(
        "--server-ports",
        default=str(DEFAULT_SERVER_PORT),
        help=f"Server port(s). Supports: single port (80), list (80,443), or range (80-65535). Default: {DEFAULT_SERVER_PORT}",
    )
    
    args, unknown = parser.parse_known_args()
    
    # Parse server_ports from CLI (could be "80", "80,443,8080", or "80-65535")
    server_ports_arg = args.server_ports
    if ',' in server_ports_arg:
        # List format: "80,443,8080"
        server_ports = [int(p.strip()) for p in server_ports_arg.split(',')]
    elif '-' in server_ports_arg and not server_ports_arg.startswith('-'):
        # Range format: "80-65535" (but not negative numbers)
        server_ports = server_ports_arg
    else:
        # Single port
        server_ports = int(server_ports_arg)

    result = evaluate(
        program_path=args.program_path,
        censor=args.censor,
        persist_containers=args.persist_containers,
        forbidden_domain=args.forbidden_domain,
        allowed_domain=args.allowed_domain,
        censor_variant=args.censor_variant,
        censor_type=args.censor_type,
        server_ports=server_ports,
    )
    logger.info("Evaluation result: %s", result)
    sys.exit(0)


