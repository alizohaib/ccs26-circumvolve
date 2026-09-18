import logging
import uuid
import random
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
import time
import select

EVALUATOR_SETUP_FOLDER = os.path.join(os.path.dirname(__file__), 'evaluator_setup')

# SSH command timeouts (in seconds)
SSH_TIMEOUT_SHORT = 30       # For quick commands like mkdir, pkill
SSH_TIMEOUT_MEDIUM = 60      # For moderate commands like file operations
SSH_TIMEOUT_LONG = 120       # For test execution
SSH_TIMEOUT_INSTALL = 300    # For package installation

# Strategy runner max runtime (5 minutes)
STRATEGY_MAX_RUNTIME = 300

# Cleanup wait times (in seconds)
CLEANUP_WAIT_PROCESS_KILL = 3    # Wait after sending kill signal
CLEANUP_WAIT_IPTABLES = 5        # Wait for iptables cleanup
DEFAULT_FORBIDDEN_DOMAIN = "blocked.com"
DEFAULT_ALLOWED_DOMAIN = "example.com"
DEFAULT_BLOCKED_FITNESS_FILE = "/workspace/fitness_blocked.txt"
DEFAULT_ALLOWED_FITNESS_FILE = "/workspace/fitness_allowed.txt"
DEFAULT_PACKETS_FILE = "/workspace/packets_blocked.pcap"

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


def _read_ssh_output_with_timeout(stdout, stderr, timeout: int = 60) -> Tuple[str, str]:
    """
    Read SSH command output with a timeout to prevent hanging.
    
    Args:
        stdout: SSH stdout channel
        stderr: SSH stderr channel  
        timeout: Maximum time to wait for output (seconds)
        
    Returns:
        Tuple of (stdout_content, stderr_content)
    """
    stdout_data = b""
    stderr_data = b""
    
    channel = stdout.channel
    start_time = time.time()
    
    while True:
        elapsed = time.time() - start_time
        if elapsed >= timeout:
            logger.warning("SSH output read timeout after %d seconds", timeout)
            break
            
        # Check if channel is ready
        if channel.exit_status_ready():
            # Read any remaining data
            while channel.recv_ready():
                stdout_data += channel.recv(4096)
            while channel.recv_stderr_ready():
                stderr_data += channel.recv_stderr(4096)
            break
            
        # Use select to wait for data with timeout
        remaining = timeout - elapsed
        readable, _, _ = select.select([channel], [], [], min(1.0, remaining))
        
        if readable:
            if channel.recv_ready():
                stdout_data += channel.recv(4096)
            if channel.recv_stderr_ready():
                stderr_data += channel.recv_stderr(4096)
        
    return stdout_data.decode('utf-8', errors='ignore'), stderr_data.decode('utf-8', errors='ignore')


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
            # No existing container, proceed to create new one
            pass

        client.images.build(
            path="./",
            dockerfile=os.path.join(EVALUATOR_SETUP_FOLDER, "client", "Dockerfile.client"),
            tag="tcp-client:latest",
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
            image="tcp-client:latest",
            name=container_name,
            command=startup_cmd,
            cap_add=["NET_ADMIN", "SYS_ADMIN", "NET_RAW", "SYS_PTRACE"],
            detach=True,
            environment=environment or {},
            labels={"org.openevolve.client": "true"},
            log_config={"type": "json-file", "config": {"max-size": "10m", "max-file": "3"}},
        )

        logger.info("Created and started container '%s' successfully.", container_name)

        # Copy tests folder into the container at /workspace/
        tests_path = os.path.join(os.getcwd(), 'tests')
        if os.path.exists(tests_path):
            try:
                # Ensure the target directory exists in the container
                container.exec_run(["mkdir", "-p", "/workspace/"])
                # Copy the tests folder into the container
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

        # Copy engine.py and score_test.py into the container
        for filename in ['engine.py', 'score_test.py', 'strategy_runner.py']:
            file_path = os.path.join(os.getcwd(), filename)
            if os.path.exists(file_path):
                try:
                    subprocess.run(
                        ["docker", "cp", file_path, f"{container_name}:/workspace/"],
                        check=True,
                        text=True,
                        capture_output=True,
                    )
                    logger.info("Copied %s into container at /workspace/", filename)
                except Exception as exc:
                    logger.warning("Failed to copy %s into container: %s", filename, exc)

        # Reload container to get updated network settings
        container.reload()
        # Get IP address from bridge network
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
    Removes any existing container with the same name and creates a new one.

    Args:
        container_name: Name for the container
        config_volume_path: Optional path to OpenGFW config directory

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
            # No existing container, proceed to create new one
            pass

        client.images.build(
            path="./",
            dockerfile=os.path.join(EVALUATOR_SETUP_FOLDER, "opengfw", "Dockerfile.opengfw"),
            tag="tcp-opengfw:latest",
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
            image="tcp-opengfw:latest",
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
            log_config={"type": "json-file", "config": {"max-size": "10m", "max-file": "3"}},
        )

        logger.info("Created and started container '%s' successfully.", container_name)

    except Exception as e:
        logger.error("Failed to get/create '%s' container: %s", container_name, e)
        return None, None

    # Reload container to get updated network settings
    container.reload()
    # Get IP address from bridge network
    ip_address = container.attrs["NetworkSettings"]["Networks"]["bridge"]["IPAddress"]
    return container, ip_address


def _prepare_opengfw_config(forbidden_domain: str) -> Tuple[str, bool]:
    """
    Prepare an OpenGFW configuration directory customized for the forbidden domain.

    Returns tuple of (config_path, is_temporary).
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
    """
    Safely convert a string representation of a float, raising a descriptive error if parsing fails.
    """
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
    server_ip: str,
    program_id: Optional[str] = None,
    ) -> EvaluationResult:
    """
    Evaluate a TCP/IP header manipulation strategy using Docker containers.

    Args:
        program_path: Path to the strategy.py file to evaluate
        censor: Type of censor to use ('opengfw')
        persist_containers: Whether to keep containers running after evaluation
        forbidden_domain: Domain that should be blocked
        allowed_domain: Domain that should remain accessible
        server_ip: Target server IP to test against
        program_id: Optional ID to use for container naming (uses UUID if not provided)

    Returns:
        EvaluationResult with metrics and artifacts
    """
    logger.info("Evaluating strategy: %s", program_path)

    forbidden_domain = (forbidden_domain or "").strip() or DEFAULT_FORBIDDEN_DOMAIN
    allowed_domain = (allowed_domain or "").strip() or DEFAULT_ALLOWED_DOMAIN

    opengfw_config_path, opengfw_config_is_temp = _prepare_opengfw_config(forbidden_domain)

    middlebox_container = None
    client_container = None
    middlebox_ip: Optional[str] = None
    client_ip: Optional[str] = None

    # Use program_id for container naming if provided, otherwise fall back to UUID
    if program_id:
        # Sanitize program_id to be Docker-compatible (alphanumeric, hyphens, underscores)
        sanitized_id = "".join(c if c.isalnum() or c in "-_" else "-" for c in str(program_id))
        container_id = sanitized_id[:50]  # Limit length for Docker compatibility
        logger.info("Using program_id for container naming: %s", container_id)
    else:
        container_id = str(uuid.uuid4())
        logger.info("No program_id provided, using UUID for container naming: %s", container_id)
    
    middlebox_name = f"tcp-middlebox-{container_id}"
    client_name = f"tcp-client-{container_id}"
    logger.info("Container names: middlebox=%s, client=%s", middlebox_name, client_name)

    try:
        middlebox_container, middlebox_ip = start_middlebox_container(
            middlebox_name,
            config_volume_path=opengfw_config_path,
        )

        if middlebox_container is None or middlebox_ip is None:
            return EvaluationResult(
                metrics={"evasion_success": 0, "combined_score": 0},
                artifacts={"error": "Failed to start middlebox container"},
            )

        client_env = {
            "FORBIDDEN_DOMAIN": forbidden_domain,
            "ALLOWED_DOMAIN": allowed_domain,
            "ENGINE_PROTO": "tcp",
            "ENGINE_DPORT": "80",
            "ENGINE_SPORT": "80",
            "ENGINE_LOG_DIR": "/workspace/logs",
        }
        client_container, client_ip = start_client_container(
            client_name,
            middlebox_ip,
            environment=client_env,
        )
        if client_container is None or client_ip is None:
            return EvaluationResult(
                metrics={"evasion_success": 0, "combined_score": 0},
                artifacts={"error": "Failed to start client container"},
            )

        # Copy strategy.py into the container
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
                "cat > /workspace/strategy.py",
            ],
            input=program_bytes,
            check=True,
        )

        # Start strategy_runner.py in the background
        logger.info("Starting strategy_runner.py in background...")
        client_container.exec_run(
            ["bash", "-c", "cd /workspace && python3 strategy_runner.py &"],
            workdir="/workspace",
            detach=True,
        )
        
        # Give the engine time to start and install iptables rules
        time.sleep(3)

        # Run the score test
        blocked_url = f"http://{forbidden_domain}"
        allowed_url = f"http://{allowed_domain}"
        
        score_exec_result = client_container.exec_run(
            [
                "python3", "/workspace/run_tests.py",
                allowed_url, blocked_url,
                server_ip if server_ip else "",
            ],
            workdir="/workspace",
        )
        score_stdout = score_exec_result.output.decode("utf-8", errors="ignore")
        _log_script_output(client_name, "score_test", score_stdout)

        # Read fitness results
        fitness_blocked_raw = client_container.exec_run(["cat", DEFAULT_BLOCKED_FITNESS_FILE]).output.decode(
            "utf-8", errors="ignore"
        )
        fitness_allowed_raw = client_container.exec_run(["cat", DEFAULT_ALLOWED_FITNESS_FILE]).output.decode(
            "utf-8", errors="ignore"
        )
        
        packets_output = ""
        try:
            logger.info("Attempting to read packet capture from %s", DEFAULT_PACKETS_FILE)
            
            # First check if the pcap file exists and get its size
            pcap_stat_result = client_container.exec_run(["stat", "-c", "%s", DEFAULT_PACKETS_FILE])
            pcap_stat = pcap_stat_result.output.decode("utf-8", errors="ignore").strip()
            logger.info("Packet capture file size: %s bytes", pcap_stat)
            
            # Read packet capture with tshark - use specific fields for concise, LLM-friendly output
            # Fields: frame#, time, src_ip, dst_ip, ttl, src_port, dst_port, tcp_flags, seq, ack, len, http_host
            tshark_result = client_container.exec_run([
                "tshark", "-r", DEFAULT_PACKETS_FILE,
                "-T", "fields",
                "-e", "frame.number", "-e", "frame.time_relative",
                "-e", "ip.src", "-e", "ip.dst", "-e", "ip.ttl",
                "-e", "tcp.srcport", "-e", "tcp.dstport", "-e", "tcp.flags.str", 
                "-e", "tcp.seq", "-e", "tcp.ack", "-e", "tcp.len",
                "-e", "http.host", "-e", "http.request.uri",
                "-E", "header=y", "-E", "separator=,"
            ])
            packets_output = tshark_result.output.decode("utf-8", errors="ignore")
            
            if packets_output:
                logger.info("Successfully read packet capture with tshark (%d chars)", len(packets_output))
                logger.info("Packet capture:\n%s", packets_output)
            else:
                logger.warning("Packet capture is empty after tshark processing")
                
        except Exception as e:
            logger.warning("Failed to read packet capture with tshark: %s", e)

        fitness_blocked = _safe_float(fitness_blocked_raw, "fitness_blocked") if fitness_blocked_raw.strip() else 0.0
        fitness_allowed = _safe_float(fitness_allowed_raw, "fitness_allowed") if fitness_allowed_raw.strip() else 0.0
        
        # Calculate combined score:
        # - Positive if we can access blocked domain (evasion success)
        # - Penalty if we break access to allowed domain
        evasion_success = fitness_blocked
        collateral_damage = max(0, 100 - fitness_allowed) if fitness_allowed > 0 else 100
        combined_score = evasion_success - (collateral_damage * 0.5)

        logger.info("%s Fitness blocked: %s, allowed: %s, combined: %s", 
                    client_name, fitness_blocked, fitness_allowed, combined_score)

        # Collect engine logs if available
        engine_logs = ""
        try:
            engine_logs_result = client_container.exec_run(["cat", "/workspace/logs/strategy_runner.log"])
            engine_logs = engine_logs_result.output.decode("utf-8", errors="ignore")
            logger.info("Collected engine logs (%d chars)", len(engine_logs))
        except Exception as e:
            logger.warning("Failed to collect engine logs: %s", e)

        # Build artifacts dictionary
        artifacts = {
            "packet_capture": packets_output,
            # "engine_logs": engine_logs,
            "forbidden_domain": forbidden_domain,
            "allowed_domain": allowed_domain,
            # "test_output": score_stdout,
        }
        
        # Log artifact summary for debugging
        logger.info("=" * 60)
        logger.info("ARTIFACTS SUMMARY FOR NEXT ITERATION:")
        logger.info("=" * 60)
        for key, value in artifacts.items():
            if isinstance(value, str):
                logger.info("  %s: %d chars %s", 
                           key, 
                           len(value), 
                           "(EMPTY)" if not value else "(has content)")
            else:
                logger.info("  %s: %s", key, value)
        logger.info("=" * 60)
        
        # Log packet_capture specifically since that's what we're tracking
        if packets_output:
            logger.info("PACKET CAPTURE ARTIFACT IS SET (%d chars)", len(packets_output))
        else:
            logger.warning("PACKET CAPTURE ARTIFACT IS EMPTY - will not be useful for LLM analysis")

        return EvaluationResult(
            metrics={
                "combined_score": combined_score,
                "evasion_success": evasion_success,
                "allowed_access": fitness_allowed,
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
                finally:
                    client_container = None

            if middlebox_container is not None:
                try:
                    middlebox_container.remove(force=True)
                except Exception as exc:
                    logger.warning("Failed to remove middlebox container during cleanup: %s", exc)
                finally:
                    middlebox_container = None

        if opengfw_config_is_temp and (not persist_containers or middlebox_container is None):
            shutil.rmtree(opengfw_config_path, ignore_errors=True)


# Marker file to track if packages have been installed on remote VPS
REMOTE_PACKAGES_MARKER = "/tmp/.tcp_evasion_packages_installed"


def _cleanup_remote_iptables(ssh, queue_nums: Optional[Tuple[int, int]] = None) -> int:
    """
    Remove NFQUEUE rules from INPUT and OUTPUT chains on remote VPS.
    
    Args:
        ssh: Paramiko SSH client
        queue_nums: Optional tuple of (in_queue, out_queue) numbers to specifically target.
                   If None, removes ALL NFQUEUE rules.
    
    Returns the number of rules that were removed.
    """
    total_removed = 0
    
    if queue_nums is not None:
        # Remove specific queue numbers only
        in_q, out_q = queue_nums
        logger.info("Cleaning up NFQUEUE rules for queues: in=%d, out=%d", in_q, out_q)
        
        # Remove INPUT rule with specific queue number
        stdin, stdout, stderr = ssh.exec_command(
            f"iptables -L INPUT -n --line-numbers 2>/dev/null | grep 'NFQUEUE.*num {in_q}' | head -1 | awk '{{print $1}}'",
            timeout=SSH_TIMEOUT_SHORT
        )
        line_num = stdout.read().decode('utf-8', errors='ignore').strip()
        if line_num and line_num.isdigit():
            ssh.exec_command(f"iptables -D INPUT {line_num} 2>/dev/null", timeout=SSH_TIMEOUT_SHORT)
            total_removed += 1
            logger.info("Removed INPUT NFQUEUE rule for queue %d", in_q)
        
        # Remove OUTPUT rule with specific queue number
        stdin, stdout, stderr = ssh.exec_command(
            f"iptables -L OUTPUT -n --line-numbers 2>/dev/null | grep 'NFQUEUE.*num {out_q}' | head -1 | awk '{{print $1}}'",
            timeout=SSH_TIMEOUT_SHORT
        )
        line_num = stdout.read().decode('utf-8', errors='ignore').strip()
        if line_num and line_num.isdigit():
            ssh.exec_command(f"iptables -D OUTPUT {line_num} 2>/dev/null", timeout=SSH_TIMEOUT_SHORT)
            total_removed += 1
            logger.info("Removed OUTPUT NFQUEUE rule for queue %d", out_q)
    else:
        # Remove ALL NFQUEUE rules (original behavior)
        # Count existing NFQUEUE rules
        # Use grep -c which outputs count (0 if no matches), then take first line only
        stdin, stdout, stderr = ssh.exec_command(
            "iptables -L INPUT -n --line-numbers 2>/dev/null | grep -c NFQUEUE || true",
            timeout=SSH_TIMEOUT_SHORT
        )
        input_raw = stdout.read().decode('utf-8', errors='ignore').strip().split('\n')[0]
        input_count = int(input_raw) if input_raw.isdigit() else 0
        
        stdin, stdout, stderr = ssh.exec_command(
            "iptables -L OUTPUT -n --line-numbers 2>/dev/null | grep -c NFQUEUE || true",
            timeout=SSH_TIMEOUT_SHORT
        )
        output_raw = stdout.read().decode('utf-8', errors='ignore').strip().split('\n')[0]
        output_count = int(output_raw) if output_raw.isdigit() else 0
        
        if input_count > 0 or output_count > 0:
            logger.info("Found %d INPUT and %d OUTPUT NFQUEUE rules to clean up", input_count, output_count)
            
            # Remove all NFQUEUE rules from INPUT chain (delete from highest line number first)
            # We loop because each deletion changes line numbers
            for _ in range(input_count):
                # Get the line number of first NFQUEUE rule
                stdin, stdout, stderr = ssh.exec_command(
                    "iptables -L INPUT -n --line-numbers 2>/dev/null | grep NFQUEUE | head -1 | awk '{print $1}'",
                    timeout=SSH_TIMEOUT_SHORT
                )
                line_num = stdout.read().decode('utf-8', errors='ignore').strip()
                if line_num and line_num.isdigit():
                    ssh.exec_command(f"iptables -D INPUT {line_num} 2>/dev/null", timeout=SSH_TIMEOUT_SHORT)
                    total_removed += 1
            
            # Remove all NFQUEUE rules from OUTPUT chain
            for _ in range(output_count):
                stdin, stdout, stderr = ssh.exec_command(
                    "iptables -L OUTPUT -n --line-numbers 2>/dev/null | grep NFQUEUE | head -1 | awk '{print $1}'",
                    timeout=SSH_TIMEOUT_SHORT
                )
                line_num = stdout.read().decode('utf-8', errors='ignore').strip()
                if line_num and line_num.isdigit():
                    ssh.exec_command(f"iptables -D OUTPUT {line_num} 2>/dev/null", timeout=SSH_TIMEOUT_SHORT)
                    total_removed += 1
            
            logger.info("Removed %d NFQUEUE rules from iptables", total_removed)
    
    return total_removed


def _generate_queue_numbers(program_id: Optional[str]) -> Tuple[int, int]:
    """
    Generate unique NFQUEUE numbers based on program_id to allow parallel evaluations.
    
    NFQUEUE numbers are 16-bit (0-65535), so we use a hash to generate unique pairs.
    We reserve queue 0-99 for potential manual use and use 100+ for auto-generated.
    
    Args:
        program_id: Optional program identifier (uses random UUID if not provided)
    
    Returns:
        Tuple of (in_queue, out_queue) numbers
    """
    import hashlib
    
    if program_id:
        # Use hash of program_id to generate deterministic queue numbers
        hash_input = str(program_id).encode('utf-8')
    else:
        # Generate random queue numbers
        hash_input = str(uuid.uuid4()).encode('utf-8')
    
    # Generate hash and convert to integer
    hash_value = int(hashlib.md5(hash_input).hexdigest()[:8], 16)
    
    # Map to queue number range: 100-65000 (leaving room at both ends)
    # We need two distinct queue numbers (in_q and out_q)
    base_q = 100 + (hash_value % 32000) * 2  # Even number base
    in_q = base_q
    out_q = base_q + 1
    
    logger.info("Generated queue numbers for program_id=%s: in_q=%d, out_q=%d", 
                program_id, in_q, out_q)
    
    return in_q, out_q

def _ensure_remote_packages(ssh) -> None:
    """
    Ensure required packages are installed on the remote VPS.
    Uses a marker file to avoid reinstalling on every evaluation.
    """
    # Check if packages were already installed (marker file exists)
    stdin, stdout, stderr = ssh.exec_command(
        f"test -f {REMOTE_PACKAGES_MARKER} && echo 'exists'",
        timeout=SSH_TIMEOUT_SHORT
    )
    marker_check = stdout.read().decode('utf-8', errors='ignore').strip()
    
    if marker_check == 'exists':
        logger.info("Remote packages already installed (marker file found)")
        return
    
    logger.info("Installing required packages on remote VPS (first-time setup)...")
    
    # Install system packages
    apt_packages = [
        "python3",
        "python3-pip", 
        "iptables",
        "tcpdump",
        "tshark",
        "libnetfilter-queue-dev",
        "build-essential",
        "python3-dev",
    ]
    
    apt_cmd = (
        "export DEBIAN_FRONTEND=noninteractive && "
        "apt-get update -qq && "
        f"apt-get install -y -qq {' '.join(apt_packages)} 2>&1"
    )
    
    logger.info("Installing system packages: %s", ", ".join(apt_packages))
    stdin, stdout, stderr = ssh.exec_command(apt_cmd, timeout=SSH_TIMEOUT_INSTALL)
    exit_status = stdout.channel.recv_exit_status()
    
    if exit_status != 0:
        apt_output = stdout.read().decode('utf-8', errors='ignore')
        apt_error = stderr.read().decode('utf-8', errors='ignore')
        logger.warning("apt-get may have had issues (exit %d): %s %s", exit_status, apt_output[-500:], apt_error[-500:])
    else:
        logger.info("System packages installed successfully")
    
    # Install Python packages
    pip_packages = ["netfilterqueue", "scapy", "requests"]
    
    pip_cmd = f"pip3 install --quiet --break-system-packages {' '.join(pip_packages)} 2>&1 || pip3 install --quiet {' '.join(pip_packages)} 2>&1"
    
    logger.info("Installing Python packages: %s", ", ".join(pip_packages))
    stdin, stdout, stderr = ssh.exec_command(pip_cmd, timeout=SSH_TIMEOUT_INSTALL)
    exit_status = stdout.channel.recv_exit_status()
    
    if exit_status != 0:
        pip_output = stdout.read().decode('utf-8', errors='ignore')
        pip_error = stderr.read().decode('utf-8', errors='ignore')
        logger.warning("pip install may have had issues (exit %d): %s %s", exit_status, pip_output[-500:], pip_error[-500:])
    else:
        logger.info("Python packages installed successfully")
    
    # Verify installation
    verify_cmd = "python3 -c 'from netfilterqueue import NetfilterQueue; from scapy.all import IP, TCP; import requests' 2>&1"
    stdin, stdout, stderr = ssh.exec_command(verify_cmd, timeout=SSH_TIMEOUT_SHORT)
    exit_status = stdout.channel.recv_exit_status()
    
    if exit_status == 0:
        logger.info("Package verification successful - all imports working")
        # Create marker file to skip installation next time
        ssh.exec_command(f"touch {REMOTE_PACKAGES_MARKER}", timeout=SSH_TIMEOUT_SHORT)
        logger.info("Created marker file: %s", REMOTE_PACKAGES_MARKER)
    else:
        verify_error = stderr.read().decode('utf-8', errors='ignore')
        logger.error("Package verification FAILED: %s", verify_error)
        raise RuntimeError(f"Required packages not properly installed on remote VPS: {verify_error}")


def _evaluate_remote(
    program_path: str,
    remote_host: str,
    remote_user: str,
    remote_key_path: Optional[str],
    remote_password: Optional[str],
    forbidden_domain: str,
    allowed_domain: str,
    persist_remote: bool = False,
    server_ip: str = "",
    program_id: str = None,
    use_all_dst_ports: bool = False,
) -> EvaluationResult:
    """
    Evaluate a strategy using a remote VPS as the client.

    Args:
        program_path: Path to the strategy.py file to evaluate
        remote_host: Remote VPS Hostname/IP
        remote_user: Remote VPS Username
        remote_key_path: Optional path to SSH private key
        remote_password: Optional SSH password
        forbidden_domain: Domain that should be blocked
        allowed_domain: Domain that should remain accessible
        persist_remote: Whether to keep remote workspace after evaluation
        server_ip: Target server IP to test against
        program_id: Optional ID to pass to the evaluator
        use_all_dst_ports: If True, use a random port (1-65535) instead of port 80

    Returns:
        EvaluationResult with metrics and artifacts
    """
    logger.info("Evaluating strategy remotely on %s: %s", remote_host, program_path)
    
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
        
        # Ensure required packages are installed on remote VPS
        _ensure_remote_packages(ssh)
        
        # Create temporary workspace on remote
        if program_id:
            remote_workspace = f"/tmp/tcp_evasion_eval_{program_id}"
        else:
            remote_workspace = f"/tmp/tcp_evasion_eval_{uuid.uuid4()}"
            
        ssh.exec_command(f"mkdir -p {remote_workspace}/logs", timeout=SSH_TIMEOUT_SHORT)
        
        try:
            sftp = ssh.open_sftp()
            
            # Upload strategy.py
            remote_strategy_path = f"{remote_workspace}/strategy.py"
            sftp.put(program_path, remote_strategy_path)
            
            # Upload engine.py, score_test.py, strategy_runner.py
            local_dir = os.path.dirname(__file__)
            for filename in ['engine.py', 'score_test.py', 'strategy_runner.py']:
                local_path = os.path.join(local_dir, filename)
                if os.path.exists(local_path):
                    sftp.put(local_path, f"{remote_workspace}/{filename}")
            
            # Upload run_tests.py from tests folder
            local_tests_path = os.path.join(local_dir, 'tests', 'run_tests.py')
            if os.path.exists(local_tests_path):
                sftp.put(local_tests_path, f"{remote_workspace}/run_tests.py")
            
            # Generate unique queue numbers for this evaluation to allow parallel runs
            in_q, out_q = _generate_queue_numbers(program_id)
            
            # Kill any stale strategy_runner processes from previous runs WITH SAME WORKSPACE
            # Use SIGKILL (-9) to ensure process termination even if hung
            logger.info("Killing any stale strategy_runner processes for workspace %s", remote_workspace)
            ssh.exec_command(
                f"pkill -9 -f 'strategy_runner.py.*{remote_workspace}' 2>/dev/null || true",
                timeout=SSH_TIMEOUT_SHORT
            )
            time.sleep(CLEANUP_WAIT_PROCESS_KILL)  # Let process fully terminate
            
            # Clean up specific queue numbers for this evaluation (in case of stale rules)
            stale_rules = _cleanup_remote_iptables(ssh, queue_nums=(in_q, out_q))
            if stale_rules > 0:
                logger.warning("Cleaned up %d stale NFQUEUE rules for queues %d/%d before starting engine", 
                              stale_rules, in_q, out_q)
            
            # Start strategy_runner in background with unique queue numbers and max runtime
            start_engine_cmd = (
                f"cd {remote_workspace} && "
                f"ENGINE_PROTO=tcp ENGINE_DPORT=80 ENGINE_SPORT=80 ENGINE_LOG_DIR={remote_workspace}/logs "
                f"ENGINE_IN_Q={in_q} ENGINE_OUT_Q={out_q} ENGINE_MAX_RUNTIME={STRATEGY_MAX_RUNTIME} "
                f"nohup python3 strategy_runner.py > /dev/null 2>&1 &"
            )
            logger.info("Starting engine with queue numbers: in_q=%d, out_q=%d, max_runtime=%ds", 
                       in_q, out_q, STRATEGY_MAX_RUNTIME)
            ssh.exec_command(start_engine_cmd, timeout=SSH_TIMEOUT_SHORT)
            time.sleep(3)  # Let engine start
            
            # Run tests
            blocked_url = f"http://{forbidden_domain}"
            allowed_url = f"http://{allowed_domain}"
            
            # Define output file paths in the workspace
            fitness_allowed_file = f"{remote_workspace}/fitness_allowed.txt"
            fitness_blocked_file = f"{remote_workspace}/fitness_blocked.txt"
            packets_file = f"{remote_workspace}/packets_blocked.pcap"
            
            # Generate random port if use_all_dst_ports is enabled
            dst_port = random.randint(1, 65535) if use_all_dst_ports else 80
            if use_all_dst_ports:
                logger.info("use_all_dst_ports enabled: using random destination port %d", dst_port)
            
            cmd = (
                f"cd {remote_workspace} && "
                f"python3 run_tests.py "
                f"'{allowed_url}' '{blocked_url}' "
                f"'{server_ip if server_ip else ''}' "
                f"'{fitness_allowed_file}' '{fitness_blocked_file}' '{packets_file}' "
                f"'{dst_port}'"
            )
            
            logger.info("Running remote command: %s", cmd)
            stdin, stdout, stderr = ssh.exec_command(cmd, timeout=SSH_TIMEOUT_LONG)
            
            # Read output with timeout to prevent hanging
            output, error_output = _read_ssh_output_with_timeout(stdout, stderr, timeout=SSH_TIMEOUT_LONG)
            
            _log_script_output(remote_host, "run_tests", output)
            if error_output:
                _log_script_output(remote_host, "run_tests_err", error_output)
            
            # Kill strategy_runner for this specific workspace
            # First try graceful termination (SIGTERM)
            logger.info("Sending SIGTERM to strategy_runner for workspace %s", remote_workspace)
            ssh.exec_command(
                f"pkill -f 'strategy_runner.py.*{remote_workspace}' 2>/dev/null || true",
                timeout=SSH_TIMEOUT_SHORT
            )
            time.sleep(CLEANUP_WAIT_IPTABLES)  # Give engine time to remove iptables rules via atexit handler
            
            # Force kill with SIGKILL if still running
            logger.info("Sending SIGKILL to ensure strategy_runner termination")
            ssh.exec_command(
                f"pkill -9 -f 'strategy_runner.py.*{remote_workspace}' 2>/dev/null || true",
                timeout=SSH_TIMEOUT_SHORT
            )
            time.sleep(CLEANUP_WAIT_PROCESS_KILL)  # Let process fully terminate
            
            # Force cleanup of specific NFQUEUE rules for this evaluation
            remaining_rules = _cleanup_remote_iptables(ssh, queue_nums=(in_q, out_q))
            if remaining_rules > 0:
                logger.warning("Engine cleanup incomplete - manually removed %d leftover NFQUEUE rules for queues %d/%d", 
                              remaining_rules, in_q, out_q)
            else:
                logger.info("iptables rules for queues %d/%d cleaned up successfully", in_q, out_q)
                
            # Retrieve results
            try:
                with sftp.open(f"{remote_workspace}/fitness_blocked.txt") as f:
                    fitness_blocked = _safe_float(f.read().decode('utf-8').strip(), "fitness_blocked")
            except IOError:
                logger.warning("Could not read fitness_blocked file from remote")
                fitness_blocked = 0.0

            try:
                with sftp.open(f"{remote_workspace}/fitness_allowed.txt") as f:
                    fitness_allowed = _safe_float(f.read().decode('utf-8').strip(), "fitness_allowed")
            except IOError:
                logger.warning("Could not read fitness_allowed file from remote")
                fitness_allowed = 0.0
                
            # Read packet capture
            packets_output = ""
            logger.info("Attempting to read packet capture from remote: %s/packets_blocked.pcap", remote_workspace)
            
            # First check pcap file size
            stat_cmd = f"stat -c %s {remote_workspace}/packets_blocked.pcap 2>/dev/null || echo 0"
            stdin, stdout, stderr = ssh.exec_command(stat_cmd, timeout=SSH_TIMEOUT_SHORT)
            pcap_size = stdout.read().decode('utf-8', errors='ignore').strip()
            logger.info("Remote packet capture file size: %s bytes", pcap_size)
            
            # Use tshark with specific fields for concise, LLM-friendly output
            # Fields: frame#, time, src_ip, dst_ip, ttl, src_port, dst_port, tcp_flags, seq, ack, len, http_host
            tshark_cmd = (
                f"tshark -r {remote_workspace}/packets_blocked.pcap "
                f"-T fields "
                f"-e frame.number -e frame.time_relative "
                f"-e ip.src -e ip.dst -e ip.ttl "
                f"-e tcp.srcport -e tcp.dstport -e tcp.flags.str -e tcp.seq -e tcp.ack -e tcp.len "
                f"-e http.host -e http.request.uri "
                f"-E header=y -E separator=',' "
                f"2>/dev/null || true"
            )
            stdin, stdout, stderr = ssh.exec_command(tshark_cmd, timeout=SSH_TIMEOUT_MEDIUM)
            tshark_output, _ = _read_ssh_output_with_timeout(stdout, stderr, timeout=SSH_TIMEOUT_MEDIUM)
            if tshark_output:
                packets_output = tshark_output
                logger.info("Successfully read packet capture with tshark (%d chars)", len(packets_output))
                logger.info("Packet capture:\n%s", packets_output)
            else:
                logger.warning("Packet capture is empty after tshark processing")

            engine_logs = ""
            try:
                with sftp.open(f"{remote_workspace}/logs/strategy_runner.log") as f:
                    engine_logs = f.read().decode('utf-8', errors='ignore')
                    logger.info("Collected engine logs (%d chars)", len(engine_logs))
            except IOError as e:
                logger.warning("Failed to collect engine logs: %s", e)
            
            evasion_success = fitness_blocked
            collateral_damage = max(0, 100 - fitness_allowed) if fitness_allowed > 0 else 100
            combined_score = evasion_success - (collateral_damage * 0.5)
            
            # Build artifacts dictionary
            artifacts = {
                "packet_capture": packets_output,
                # "engine_logs": engine_logs,
                "forbidden_domain": forbidden_domain,
                "allowed_domain": allowed_domain,
                # "test_output": output,
            }
            
            # Log artifact summary for debugging
            logger.info("=" * 60)
            logger.info("ARTIFACTS SUMMARY FOR NEXT ITERATION (REMOTE):")
            logger.info("=" * 60)
            for key, value in artifacts.items():
                if isinstance(value, str):
                    logger.info("  %s: %d chars %s", 
                               key, 
                               len(value), 
                               "(EMPTY)" if not value else "(has content)")
                else:
                    logger.info("  %s: %s", key, value)
            logger.info("=" * 60)
            
            # Log packet_capture specifically since that's what we're tracking
            if packets_output:
                logger.info("PACKET CAPTURE ARTIFACT IS SET (%d chars)", len(packets_output))
            else:
                logger.warning("PACKET CAPTURE ARTIFACT IS EMPTY - will not be useful for LLM analysis")
            
            return EvaluationResult(
                metrics={
                    "combined_score": combined_score,
                    "evasion_success": evasion_success,
                    "allowed_access": fitness_allowed,
                },
                artifacts=artifacts,
            )
            
        finally:
            # Cleanup
            if not persist_remote:
                logger.info("Cleaning up remote workspace %s", remote_workspace)
                ssh.exec_command(f"rm -rf {remote_workspace}", timeout=SSH_TIMEOUT_SHORT)
            else:
                logger.info("Persisting remote workspace %s", remote_workspace)
            sftp.close()
            
    except Exception as e:
        logger.error("Remote evaluation failed: %s", e)
        return EvaluationResult(
            metrics={"evasion_success": 0, "combined_score": 0, "allowed_access": 0},
            artifacts={"error": f"Remote evaluation failed: {str(e)}"},
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


def evaluate(
    program_path: str,
    censor: str = "opengfw",
    persist_containers: bool = False,
    forbidden_domain: str = DEFAULT_FORBIDDEN_DOMAIN,
    allowed_domain: str = DEFAULT_ALLOWED_DOMAIN,
    remote_host: Optional[str] = None,
    remote_user: Optional[str] = None,
    remote_key_path: Optional[str] = None,
    remote_password: Optional[str] = None,
    persist_remote: bool = False,
    server_ip: str = "",
    program_id: str = None,
    use_all_dst_ports: bool = False,
    ) -> EvaluationResult:
    """
    Evaluate a TCP/IP header manipulation strategy using Docker containers or Remote VPS.

    Args:
        program_path: Path to the strategy.py file to evaluate
        censor: Type of censor to use ('opengfw')
        persist_containers: Whether to keep containers running after evaluation
        forbidden_domain: Domain that should be blocked
        allowed_domain: Domain that should remain accessible
        remote_host: Remote VPS IP/Hostname (if set, uses remote evaluation instead of Docker)
        remote_user: Remote VPS Username
        remote_key_path: Remote VPS SSH Key Path
        remote_password: Remote VPS Password
        persist_remote: Whether to keep remote workspace after evaluation
        server_ip: Target server IP to test against
        program_id: Optional ID to pass to the evaluator
        use_all_dst_ports: If True, use a random port (1-65535) instead of port 80

    Returns:
        EvaluationResult with metrics and artifacts
    """
    # Try to load remote config from YAML if not provided
    if not remote_host:
        config = load_config_from_yaml()
        scenario_config = config.get("scenario_config", {})
        
        eval_type = scenario_config.get("evaluation_type", "docker")
        
        if eval_type == "remote":
            remote_config = scenario_config.get("remote", {})
            remote_host = remote_config.get("host")
            remote_user = remote_config.get("user") or remote_user
            remote_key_path = remote_config.get("key_path") or remote_key_path
            remote_password = remote_config.get("password") or remote_password
            if not persist_remote:
                persist_remote = remote_config.get("persist", False)
            
            server_ip = remote_config.get("server_ip", server_ip)
            if not use_all_dst_ports:
                use_all_dst_ports = remote_config.get("use_all_dst_ports", False)

            if not remote_host:
                logger.warning("Evaluation type is 'remote' but no host configured. Falling back to Docker.")

        # Override domains from config if they are still defaults
        if forbidden_domain == DEFAULT_FORBIDDEN_DOMAIN:
            forbidden_domain = scenario_config.get("forbidden_domain", forbidden_domain)
        if allowed_domain == DEFAULT_ALLOWED_DOMAIN:
            allowed_domain = scenario_config.get("allowed_domain", allowed_domain)
        if not server_ip:
            server_ip = scenario_config.get("server_ip", "")

    if remote_host:
        if not remote_user:
            raise ValueError("remote_user must be provided if remote_host is set (via args or config.yaml)")
        
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
            program_id=program_id,
            use_all_dst_ports=use_all_dst_ports,
        )
    
    return _evaluate_dockerized(
        program_path=program_path,
        censor=censor,
        persist_containers=persist_containers,
        forbidden_domain=forbidden_domain,
        allowed_domain=allowed_domain,
        server_ip=server_ip,
        program_id=program_id,
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Evaluate TCP/IP header manipulation strategy")
    parser.add_argument("program_path", help="Path to the strategy.py file to evaluate")
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
        "--server-ip",
        default="",
        help="Target server IP to test against (optional)",
    )
    
    # Remote VPS arguments
    parser.add_argument("--remote-host", help="Remote VPS IP/Hostname for evaluation")
    parser.add_argument("--remote-user", help="Remote VPS Username")
    parser.add_argument("--remote-key-path", help="Remote VPS SSH Key Path")
    parser.add_argument("--remote-password", help="Remote VPS Password")
    parser.add_argument(
        "--persist-remote",
        action="store_true",
        default=False,
        help="Keep remote workspace after evaluation (default: False)",
    )

    args = parser.parse_args()

    result = evaluate(
        program_path=args.program_path,
        censor=args.censor,
        persist_containers=args.persist_containers,
        forbidden_domain=args.forbidden_domain,
        allowed_domain=args.allowed_domain,
        server_ip=args.server_ip,
        remote_host=args.remote_host,
        remote_user=args.remote_user,
        remote_key_path=args.remote_key_path,
        remote_password=args.remote_password,
        persist_remote=args.persist_remote,
    )
    logger.info("Evaluation result: %s", result)
    sys.exit(0)
