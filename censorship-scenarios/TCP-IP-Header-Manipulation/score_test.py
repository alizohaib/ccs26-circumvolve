#!/usr/bin/env python3
"""
Score Test - Tests network connectivity and returns a fitness score
"""

import sys
import socket
import requests
import subprocess
import signal
import time
import os
from typing import Dict, Optional, Tuple
from urllib.parse import urlparse, urlunparse


DEFAULT_BLOCKED_FITNESS_FILE = os.getenv("BLOCKED_FITNESS_FILE", "/workspace/fitness_blocked.txt")
DEFAULT_ALLOWED_FITNESS_FILE = os.getenv("ALLOWED_FITNESS_FILE", "/workspace/fitness_allowed.txt")
DEFAULT_PACKETS_FILE = os.getenv("BLOCKED_PACKETS_FILE", "/workspace/packets_blocked.pcap")
RESPONSE_PREVIEW_LIMIT = int(os.getenv("RESPONSE_PREVIEW_LIMIT", "500"))


def _normalize_and_prepare_request(
    url: str, 
    server_ip: Optional[str],
    dst_port: int = 80,
) -> Tuple[str, Dict[str, str], str]:
    """
    Normalize a URL and build the target URL and headers for the request.
    Returns a tuple of (target_url, headers, display_url).
    
    Args:
        url: The URL to normalize
        server_ip: Optional server IP to use instead of the hostname
        dst_port: Destination port to use (default: 80)
    """
    if not url:
        raise ValueError("URL must not be empty")

    candidate = url if "://" in url else f"http://{url}"
    parsed = urlparse(candidate)

    scheme = parsed.scheme or "http"
    netloc = parsed.netloc or parsed.path
    if not netloc:
        raise ValueError(f"Invalid URL: {url}")

    # Extract hostname without any existing port
    original_host = netloc.split(":")[0] if ":" in netloc else netloc
    
    path = parsed.path or "/"
    target_host = server_ip.strip() if server_ip else original_host
    
    # Add port to target host if not the default port 80
    if dst_port != 80:
        target_host = f"{target_host}:{dst_port}"
    
    target_url = urlunparse((scheme, target_host, path, parsed.params, parsed.query, parsed.fragment))

    headers: Dict[str, str] = {}
    # Set Host header to original hostname (without port) when using server_ip
    if server_ip:
        headers["Host"] = original_host

    display_url = urlunparse((scheme, netloc, path, parsed.params, parsed.query, parsed.fragment))

    return target_url, headers, display_url


def _score_from_status(status_code: int) -> int:
    if status_code == 200:
        return 100
    if status_code in (301, 302, 303, 307, 308):
        return 50
    return 25


def _write_fitness(fitness_file: str, fitness: int, quiet: bool) -> None:
    directory = os.path.dirname(fitness_file)
    if directory:
        os.makedirs(directory, exist_ok=True)
    with open(fitness_file, "w", encoding="utf-8") as file_handle:
        file_handle.write(str(fitness))
    if not quiet:
        print(f"✍️  Wrote fitness score to: {fitness_file}")


def _preview_response_body(response: requests.Response) -> str:
    """
    Create a human-readable preview of the response body capped at RESPONSE_PREVIEW_LIMIT characters.
    """
    try:
        text = response.text
    except (UnicodeDecodeError, AttributeError):
        return "<unable to decode response body>"

    if RESPONSE_PREVIEW_LIMIT > 0 and len(text) > RESPONSE_PREVIEW_LIMIT:
        return f"{text[:RESPONSE_PREVIEW_LIMIT]}... [truncated]"
    return text


def _get_capture_interface() -> str:
    """
    Determine the best network interface for packet capture.
    Returns the interface name (defaults to 'any' if eth0 not found).
    """
    # Try common interface names in order of preference
    for iface in ["eth0", "ens3", "ens5", "enp0s3", "any"]:
        try:
            result = subprocess.run(
                ["ip", "link", "show", iface],
                capture_output=True,
                timeout=5,
            )
            if result.returncode == 0:
                return iface
        except (subprocess.TimeoutExpired, FileNotFoundError):
            continue
    return "any"


def _build_tcpdump_filter(target_host: str, dest_port: int = 80) -> str:
    """
    Build a tcpdump BPF filter string that captures traffic to/from the target host.
    
    Args:
        target_host: The target hostname or IP address
        dest_port: The destination port to filter on (default: 80)
    
    Returns:
        A BPF filter string for tcpdump
    """
    filter_parts = []
    
    # Try to resolve hostname to IP for more reliable filtering
    try:
        resolved_ip = socket.gethostbyname(target_host)
        filter_parts.append(f"host {resolved_ip}")
    except socket.gaierror:
        # If resolution fails, skip host filter
        pass
    
    filter_parts.append(f"tcp port {dest_port}")
    
    if filter_parts:
        return " and ".join(filter_parts)
    else:
        return f"tcp port {dest_port}"


def test_accessibility(
    url: str,
    *,
    server_ip: Optional[str] = None,
    timeout: int = 20,
    quiet: bool = False,
    fitness_file: str,
    capture_packets: bool = False,
    packets_file: Optional[str] = None,
    label: str = "accessibility",
    dst_port: int = 80,
) -> int:
    """
    Core accessibility test that supports optional packet capture and fitness recording.
    Returns the computed fitness score.
    
    Args:
        url: URL to test accessibility for
        server_ip: Optional server IP to connect to instead of resolving hostname
        timeout: Request timeout in seconds
        quiet: If True, suppress output
        fitness_file: Path to write fitness score
        capture_packets: If True, capture packets with tcpdump
        packets_file: Path to write packet capture (required if capture_packets=True)
        label: Label for the test (e.g., "allowed" or "blocked")
        dst_port: Destination port to use for the request (default: 80)
    """
    fitness = 0
    tcpdump_process: Optional[subprocess.Popen] = None

    try:
        target_url, headers, display_url = _normalize_and_prepare_request(url, server_ip, dst_port)

        if capture_packets:
            if not packets_file:
                raise ValueError("packets_file must be provided when capture_packets=True")
            packets_directory = os.path.dirname(packets_file)
            if packets_directory:
                os.makedirs(packets_directory, exist_ok=True)

            if not quiet:
                print("📡 Starting tcpdump packet capture...")

            # Determine the target host for filtering
            parsed = urlparse(target_url)
            capture_target = server_ip if server_ip else parsed.netloc
            # Remove port from netloc if present (e.g., "example.com:80" -> "example.com")
            if ":" in capture_target:
                capture_target = capture_target.split(":")[0]
            
            # Build host-based filter with the appropriate port
            capture_filter = _build_tcpdump_filter(capture_target, dest_port=dst_port)
            capture_interface = _get_capture_interface()
            
            if not quiet:
                print(f"📡 Capture filter: {capture_filter} on {capture_interface} (port: {dst_port})")

            tcpdump_cmd = [
                "tcpdump",
                "-i",
                capture_interface,
                "-w",
                packets_file,
                capture_filter,
            ]
            tcpdump_process = subprocess.Popen(
                tcpdump_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            time.sleep(1)

        if not quiet:
            print(f"📡 Testing {label} connectivity to: {display_url}")

        response = requests.get(
            target_url,
            timeout=timeout,
            headers=headers if headers else None,
            )

        if not quiet:
            print(f"📊 Response status: {response.status_code}")
            print(f"📏 Response length: {len(response.content)} bytes")
            preview = _preview_response_body(response)
            if preview:
                print(f"📝 Response preview: {preview}")

        fitness = _score_from_status(response.status_code)

        if not quiet:
            if fitness == 100:
                print(f"✅ Successfully reached the {label} target!")
            elif fitness == 50:
                print("🔄 Partial success (redirect)")
            else:
                print(f"⚠️  Some response received (status: {response.status_code})")

    except requests.exceptions.ConnectTimeout:
        fitness = -100
        if not quiet:
            print("⏰ Connection timeout")
    except requests.exceptions.ConnectionError:
        fitness = -90
        if not quiet:
            print("🔌 Connection error")
    except requests.exceptions.Timeout:
        fitness = -120
        if not quiet:
            print("⏰ Request timeout")
    except (requests.exceptions.HTTPError, requests.exceptions.RequestException) as exc:
        fitness = -80
        if not quiet:
            print(f"❌ HTTP/Request error: {exc}")
    finally:
        if capture_packets and tcpdump_process:
            time.sleep(2)
            tcpdump_process.send_signal(signal.SIGTERM)
            try:
                tcpdump_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                tcpdump_process.kill()

            if not quiet:
                print("📦 Packet capture completed")

    if not quiet:
        print(f"🏆 Final fitness score: {fitness}")

    _write_fitness(fitness_file, fitness, quiet)

    if capture_packets and not quiet and packets_file:
        print(f"✍️  Wrote packet capture to: {packets_file}")

    return fitness


def is_unblocked_accessible(
    url: str,
    server_ip: Optional[str] = None,
    timeout: int = 20,
    quiet: bool = False,
    fitness_file: str = DEFAULT_ALLOWED_FITNESS_FILE,
    dst_port: int = 80,
) -> int:
    """
    Test if the URL is unblocked and accessible.
    Returns the computed fitness score.
    """
    return test_accessibility(
        url,
        server_ip=server_ip,
        timeout=timeout,
        quiet=quiet,
        fitness_file=fitness_file,
        capture_packets=False,
        packets_file=None,
        label="allowed",
        dst_port=dst_port,
    )


def is_blocked_accessible(
    url: str,
    server_ip: Optional[str] = None,
    timeout: int = 20,
    quiet: bool = False,
    fitness_file: str = DEFAULT_BLOCKED_FITNESS_FILE,
    packets_file: str = DEFAULT_PACKETS_FILE,
    dst_port: int = 80,
) -> int:
    return test_accessibility(
        url,
        server_ip=server_ip,
        timeout=timeout,
        quiet=quiet,
        fitness_file=fitness_file,
        capture_packets=True,
        packets_file=packets_file,
        label="blocked",
        dst_port=dst_port,
    )


def run_allowed_and_blocked_tests(
    allowed_url: str,
    blocked_url: str,
    server_ip: Optional[str] = None,
    *,
    timeout: int = 20,
    quiet: bool = False,
    allowed_fitness_file: str = DEFAULT_ALLOWED_FITNESS_FILE,
    blocked_fitness_file: str = DEFAULT_BLOCKED_FITNESS_FILE,
    packets_file: str = DEFAULT_PACKETS_FILE,
    delay_between_tests: float = 1.0,
    dst_port: int = 80,
) -> Tuple[int, int]:
    """
    Run the allowed-domain test first followed by the blocked-domain test.
    Returns a tuple containing (allowed_fitness, blocked_fitness).
    
    Args:
        allowed_url: URL that should be accessible
        blocked_url: URL that is expected to be blocked (testing evasion)
        server_ip: Optional server IP to use instead of resolving hostname
        timeout: Request timeout in seconds
        quiet: If True, suppress output
        allowed_fitness_file: Path to write allowed test fitness score
        blocked_fitness_file: Path to write blocked test fitness score
        packets_file: Path to write packet capture
        delay_between_tests: Delay in seconds between the two tests
        dst_port: Destination port to use for requests (default: 80)
    """
    if not quiet:
        print(f"🚀 Starting allowed-domain accessibility test (port: {dst_port})")
    allowed_fitness = is_unblocked_accessible(
        allowed_url,
        server_ip=server_ip,
        timeout=timeout,
        quiet=quiet,
        fitness_file=allowed_fitness_file,
        dst_port=dst_port,
    )

    if delay_between_tests > 0:
        time.sleep(delay_between_tests)

    if not quiet:
        print(f"🚫 Starting blocked-domain evasion test (port: {dst_port})")
    blocked_fitness = is_blocked_accessible(
        blocked_url,
        server_ip=server_ip,
        timeout=timeout,
        quiet=quiet,
        fitness_file=blocked_fitness_file,
        packets_file=packets_file,
        dst_port=dst_port,
    )

    return allowed_fitness, blocked_fitness


def main():
    """Main entry point."""
    if len(sys.argv) < 3:
        print("Usage: python score_test.py <allowed_url> <blocked_url> [server_ip] "
              "[allowed_fitness_file] [blocked_fitness_file] [packets_file] [dst_port]")
        print("Example: python score_test.py http://allowed.example http://blocked.example 10.0.0.5")
        print("Example with custom port: python score_test.py http://allowed.example http://blocked.example 10.0.0.5 /path/allowed.txt /path/blocked.txt /path/packets.pcap 8080")
        sys.exit(1)

    allowed_url = sys.argv[1]
    blocked_url = sys.argv[2]

    server_ip = None
    if len(sys.argv) >= 4:
        candidate_server_ip = sys.argv[3].strip()
        if candidate_server_ip and candidate_server_ip.lower() not in {"none", "null"}:
            # Distinguish between legacy invocation where argument 3 is a test type.
            legacy_test_token = candidate_server_ip.upper()
            legacy_test_tokens = {"HTTP", "HTTPS", "DNS", "TCP", "UDP"}
            if legacy_test_token in legacy_test_tokens:
                print("Legacy invocation detected. Please update usage to provide allowed and blocked URLs.")
                sys.exit(2)
            server_ip = candidate_server_ip

    allowed_fitness_file = DEFAULT_ALLOWED_FITNESS_FILE
    blocked_fitness_file = DEFAULT_BLOCKED_FITNESS_FILE
    packets_file = DEFAULT_PACKETS_FILE
    dst_port = 80

    if len(sys.argv) >= 5:
        allowed_fitness_file = sys.argv[4]
    if len(sys.argv) >= 6:
        blocked_fitness_file = sys.argv[5]
    if len(sys.argv) >= 7:
        packets_file = sys.argv[6]
    if len(sys.argv) >= 8:
        try:
            dst_port = int(sys.argv[7])
            if dst_port < 1 or dst_port > 65535:
                print(f"⚠️  Invalid port {dst_port}, using default port 80")
                dst_port = 80
        except ValueError:
            print(f"⚠️  Invalid port value '{sys.argv[7]}', using default port 80")
            dst_port = 80

    if dst_port != 80:
        print(f"🔌 Using custom destination port: {dst_port}")

    allowed_fitness, blocked_fitness = run_allowed_and_blocked_tests(
        allowed_url=allowed_url,
        blocked_url=blocked_url,
        server_ip=server_ip,
        allowed_fitness_file=allowed_fitness_file,
        blocked_fitness_file=blocked_fitness_file,
        packets_file=packets_file,
        quiet=False,
        dst_port=dst_port,
    )

    print("\n✅ Test completed! Results written to:")
    print(f"   - Allowed fitness ({allowed_fitness}): {allowed_fitness_file}")
    print(f"   - Blocked fitness ({blocked_fitness}): {blocked_fitness_file}")
    print(f"   - Packets: {packets_file}")
    if dst_port != 80:
        print(f"   - Destination port used: {dst_port}")


if __name__ == "__main__":
    main()
