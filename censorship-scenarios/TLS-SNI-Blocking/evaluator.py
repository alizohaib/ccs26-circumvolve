import logging
import uuid
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
DEFAULT_BLOCKED_FITNESS_FILE = "/workspace/fitness_blocked.txt"
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
    censor_variant: str,
    ) -> EvaluationResult:
    """
    Evaluate a program using Docker containers.

    Args:
        program_path: Path to the program file to evaluate
        censor: Type of censor to use ('opengfw' or 'geneva')
        persist_containers: Whether to keep containers running after evaluation
        forbidden_domain: Domain that should be blocked
        allowed_domain: Domain that should remain accessible
        censor_variant: Censor variant (e.g., censor1-censor10 for Geneva)

    Returns:
        EvaluationResult with metrics and artifacts
    """
    logger.info("Evaluating program: %s", program_path)

    forbidden_domain = (forbidden_domain or "").strip() or DEFAULT_FORBIDDEN_DOMAIN
    allowed_domain = (allowed_domain or "").strip() or DEFAULT_ALLOWED_DOMAIN

    opengfw_config_path, opengfw_config_is_temp = _prepare_opengfw_config(forbidden_domain)

    middlebox_container = None
    client_container = None
    middlebox_ip: Optional[str] = None
    client_ip: Optional[str] = None

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
                metrics={"evasion_success": 0, "combined_score": 0},
                artifacts={"error": "Failed to start middlebox container"},
            )

        client_env = {
            "FORBIDDEN_DOMAIN": forbidden_domain,
            "ALLOWED_DOMAIN": allowed_domain,
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
                "cat > /workspace/tls_initial.py",
            ],
            input=program_bytes,
            check=True,
        )


        score_exec_result = client_container.exec_run(
            ["python3", "/workspace/run_tests.py", "--server-ip", "1.1.1.1", "--port", "443"],
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

        fitness_blocked = _safe_float(fitness_blocked_raw, "fitness_blocked")
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


def _evaluate_remote(
    program_path: str,
    remote_host: str,
    remote_user: str,
    remote_key_path: Optional[str],
    remote_password: Optional[str],
    forbidden_domain: str,
    allowed_domain: str,
    persist_remote: bool = False,
    server_ip: str = "66.254.114.41",
    program_id: str = None,  
) -> EvaluationResult:
    """
    Evaluate a program using a remote VPS as the client.

    Args:
        program_path: Path to the program file to evaluate
        remote_host: Remote VPS Hostname/IP
        remote_user: Remote VPS Username
        remote_key_path: Optional path to SSH private key
        remote_password: Optional SSH password
        forbidden_domain: Domain that should be blocked
        allowed_domain: Domain that should remain accessible
        persist_remote: Whether to keep remote workspace after evaluation
        server_ip: Target server IP to test against
        program_id: Optional ID to pass to the evaluator

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
        # Use program_id if available, otherwise random UUID
        if program_id:
            remote_workspace = f"/tmp/circumvolve_eval_{program_id}"
        else:
            remote_workspace = f"/tmp/circumvolve_eval_{uuid.uuid4()}"
            
        ssh.exec_command(f"mkdir -p {remote_workspace}")
        
        try:
            sftp = ssh.open_sftp()
            
            # Upload program
            remote_program_path = f"{remote_workspace}/tls_initial.py"
            sftp.put(program_path, remote_program_path)
            
            # Upload run_tests.py
            local_tests_path = os.path.join(os.path.dirname(__file__), 'tests', 'run_tests.py')
            remote_tests_path = f"{remote_workspace}/run_tests.py"
            sftp.put(local_tests_path, remote_tests_path)
            
            # Run tests
            cmd = (
                f"cd {remote_workspace} && "
                f"FORBIDDEN_DOMAIN={forbidden_domain} "
                f"ALLOWED_DOMAIN={allowed_domain} "
                f"python3 run_tests.py "
                f"--tls-initial-path tls_initial.py "
                f"--packets-file packets.pcap "
                f"--fitness-file fitness.txt "
                f"--server-ip {server_ip} "
                f"--port 443"
            )
            
            logger.info("Running remote command: %s", cmd)
            stdin, stdout, stderr = ssh.exec_command(cmd)
            
            # Wait for completion and stream output
            _ = stdout.channel.recv_exit_status()
            
            output = stdout.read().decode('utf-8', errors='ignore')
            error_output = stderr.read().decode('utf-8', errors='ignore')
            
            _log_script_output(remote_host, "run_tests", output)
            if error_output:
                _log_script_output(remote_host, "run_tests_err", error_output)
                
            # Retrieve results
            try:
                with sftp.open(f"{remote_workspace}/fitness.txt") as f:
                    fitness_raw = f.read().decode('utf-8').strip()
                    fitness_blocked = _safe_float(fitness_raw, "fitness_blocked")
            except IOError:
                logger.warning("Could not read fitness file from remote")
                fitness_blocked = 0.0
                
            packets_output = ""
            # Try to get pcap analysis if tshark is installed on remote, or just download pcap?
            # The artifacts expect text output of tshark usually in this codebase (as per _evaluate_dockerized)
            # But run_tests.py produces a pcap file. 
            # _evaluate_dockerized runs tshark on the pcap to get text output for artifacts.
            # We should try to run tshark on remote if available to match behavior.
            
            tshark_cmd = f"tshark -r {remote_workspace}/packets.pcap -V -q -z io,stat,0"
            stdin, stdout, stderr = ssh.exec_command(tshark_cmd)
            if stdout.channel.recv_exit_status() == 0:
                packets_output = stdout.read().decode('utf-8', errors='ignore')
            else:
                logger.warning("Failed to run tshark on remote, artifacts will be empty packet capture")
                 
            score = fitness_blocked
            
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
            # Cleanup
            if not persist_remote:
                logger.info("Cleaning up remote workspace %s", remote_workspace)
                ssh.exec_command(f"rm -rf {remote_workspace}")
            else:
                logger.info("Persisting remote workspace %s", remote_workspace)
            sftp.close()
            
    except Exception as e:
        logger.error("Remote evaluation failed: %s", e)
        return EvaluationResult(
            metrics={"evasion_success": 0, "combined_score": 0},
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
    censor_variant: str = "censor1",
    remote_host: Optional[str] = None,
    remote_user: Optional[str] = None,
    remote_key_path: Optional[str] = None,
    remote_password: Optional[str] = None,
    persist_remote: bool = False,
    server_ip: str = "1.1.1.1",
    program_id: str = None,
    ) -> EvaluationResult:
    """
    Evaluate a censorship evasion program using Docker containers or Remote VPS.

    Args:
        program_path: Path to the program file to evaluate
        censor: Type of censor to use ('opengfw')
        persist_containers: Whether to keep containers running after evaluation
        forbidden_domain: Domain that should be blocked
        allowed_domain: Domain that should remain accessible
        censor_variant: Censor variant (e.g., censor1-censor10 for Geneva Mock Censors)
        remote_host: Remote VPS IP/Hostname (if set, uses remote evaluation instead of Docker)
        remote_user: Remote VPS Username
        remote_key_path: Remote VPS SSH Key Path
        remote_password: Remote VPS Password
        persist_remote: Whether to keep remote workspace after evaluation
        server_ip: Target server IP to test against (for remote eval)
        program_id: Optional ID to pass to the evaluator

    Returns:
        EvaluationResult with metrics and artifacts
    """
    # Try to load remote config from YAML if not provided
    if not remote_host:
        config = load_config_from_yaml()
        # Look for scenario_config which is outside 'evaluator' to avoid OpenEvolve validation errors
        scenario_config = config.get("scenario_config", {})
        
        # Check evaluation type
        eval_type = scenario_config.get("evaluation_type", "docker")
        
        if eval_type == "remote":
            remote_config = scenario_config.get("remote", {})
            remote_host = remote_config.get("host")
            remote_user = remote_config.get("user") or remote_user
            remote_key_path = remote_config.get("key_path") or remote_key_path
            remote_password = remote_config.get("password") or remote_password
            if not persist_remote:
                persist_remote = remote_config.get("persist", False)
            
            # Allow server_ip to be configured from remote config or scenario_config
            server_ip = remote_config.get("server_ip", server_ip)

            if not remote_host:
                logger.warning("Evaluation type is 'remote' but no host configured. Falling back to Docker.")

        # Override domains from config if they are still defaults
        if forbidden_domain == DEFAULT_FORBIDDEN_DOMAIN:
            forbidden_domain = scenario_config.get("forbidden_domain", forbidden_domain)
        if allowed_domain == DEFAULT_ALLOWED_DOMAIN:
            allowed_domain = scenario_config.get("allowed_domain", allowed_domain)

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
        )
    
    return _evaluate_dockerized(
        program_path=program_path,
        censor=censor,
        persist_containers=persist_containers,
        forbidden_domain=forbidden_domain,
        allowed_domain=allowed_domain,
        censor_variant=censor_variant,
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
        type=lambda value: value.strip().lower(),
        choices=[f"censor{i}" for i in range(1, 12)],
        help="Select the censor variant (censor1 through censor10, default: censor1)",
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
        censor_variant=args.censor_variant,
        remote_host=args.remote_host,
        remote_user=args.remote_user,
        remote_key_path=args.remote_key_path,
        remote_password=args.remote_password,
        persist_remote=args.persist_remote,
    )
    logger.info("Evaluation result: %s", result)
    sys.exit(0)
