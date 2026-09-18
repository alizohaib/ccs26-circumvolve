#!/usr/bin/env python3
"""
DNS Censorship Evasion Test Runner

Supports multiple censor types with optional cascade evaluation:

1. in-path-modifier: Middlebox modifies DNS responses (e.g., OpenGFW)
   - Single stage: Sends to REAL DNS server through middlebox
   - Test: Did we get a real response or a poisoned one?

2. on-path-injector: Censor races to inject fake responses (e.g., China GFW)
   - CASCADE EVALUATION RECOMMENDED to prevent evolution gaming:
     - Stage 1 (Local): Send to REAL DNS server locally (uncensored)
       Must receive valid response - proves packet is valid DNS
     - Stage 2 (Remote): Send to NON-DNS server through censored network
       No response = evasion success
"""

import argparse
import subprocess
import sys
import os
import signal
import time
from typing import Dict, Optional, Tuple

# ============================================================================
# Configuration
# ============================================================================

# Real DNS servers for validity testing (Stage 1)
REAL_DNS_SERVERS = [
    "1.1.1.1",      # Cloudflare
    "8.8.8.8",      # Google
    "9.9.9.9",      # Quad9
]

# Non-DNS servers for injection testing (Stage 2)
# These are servers that won't respond to DNS queries on port 53
NON_DNS_SERVERS = [
    "93.184.216.34",   # example.com (HTTP only)
]

# Default paths
DEFAULT_PROGRAM_PATH = "/workspace/dns_initial.py"
DEFAULT_PACKETS_FILE = "/workspace/packets.pcap"
DEFAULT_FITNESS_FILE = "/workspace/fitness.txt"


# ============================================================================
# Core Test Execution
# ============================================================================

def run_dns_test(
    program_path: str,
    server_ip: str,
    port: int = 53,
    interface: str = "eth0",
    packets_file: str = DEFAULT_PACKETS_FILE,
    timeout_seconds: int = 3,
    source_port: Optional[int] = None,
) -> Tuple[bool, str, int, int]:
    """
    Execute DNS test: run program, send packet, capture response.
    
    Args:
        program_path: Path to the DNS packet generator program
        server_ip: Target server IP address
        port: Target server port (default 53)
        interface: Network interface for packet capture
        packets_file: Path to save pcap file
        timeout_seconds: Socket timeout for receiving response
        source_port: Optional source port to bind to. If provided, tcpdump will
                     filter by this port, allowing multiple concurrent evaluations.
                     If None, a random port is assigned by the OS.
    
    Returns:
        Tuple of (success, pcap_file_path, packets_sent, packets_received)
    """
    import socket
    import random
    
    tcpdump_process = None
    sock = None
    
    # Generate a unique source port if not provided (for concurrent evaluations)
    # Use ephemeral port range (49152-65535)
    if source_port is None:
        source_port = random.randint(49152, 65535)
    
    try:
        # Ensure packets directory exists
        packets_directory = os.path.dirname(packets_file)
        if packets_directory:
            os.makedirs(packets_directory, exist_ok=True)
        
        # Start packet capture with source port filter for isolation
        # This allows multiple concurrent evaluations without capturing each other's packets
        print(f"📡 Starting tcpdump on {interface} (src port {source_port}, dst port {port})...")
        tcpdump_filter = f"udp and (src port {source_port} or (dst port {source_port} and src host {server_ip}))"
        tcpdump_cmd = [
            "tcpdump", "-i", interface, "-w", packets_file, tcpdump_filter,
        ]
        tcpdump_process = subprocess.Popen(
            tcpdump_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        time.sleep(2)  # Give tcpdump time to start
        
        # Run program to get hex output
        print(f"🚀 Running {program_path} (src port {source_port} -> {server_ip}:{port})")
        
        program_process = subprocess.Popen(
            ["python3", program_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        program_stdout, program_stderr = program_process.communicate(timeout=30)
        
        if program_process.returncode != 0:
            print(f"⚠️  Program error: {program_stderr.decode()}", file=sys.stderr)
            return False, packets_file, 0, 0
        
        # Parse hex output
        hex_output = program_stdout.decode().strip()
        if not hex_output:
            print("⚠️  Program produced no output", file=sys.stderr)
            return False, packets_file, 0, 0
        
        try:
            packet_bytes = bytes.fromhex(hex_output)
        except ValueError as e:
            print(f"⚠️  Invalid hex output: {e}", file=sys.stderr)
            return False, packets_file, 0, 0
        
        # Create UDP socket and bind to specific source port
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(('', source_port))
        sock.settimeout(timeout_seconds)
        
        # Send packet
        sock.sendto(packet_bytes, (server_ip, port))
        print(f"📤 Sent {len(packet_bytes)} bytes from port {source_port}")
        
        # Try to receive response
        try:
            response, addr = sock.recvfrom(4096)
            print(f"📥 Received {len(response)} bytes from {addr}")
        except socket.timeout:
            print("⏱️  No response (timeout)")
        
        # Wait for any additional packets to be captured
        time.sleep(1)
        
        # Stop capture
        tcpdump_process.send_signal(signal.SIGTERM)
        try:
            tcpdump_process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            tcpdump_process.kill()
        
        # Count packets using tshark with source port filter
        if not os.path.exists(packets_file):
            return False, packets_file, 0, 0
        
        # Count sent packets (from our source port to server)
        sent = _count_packets(packets_file, f"udp and udp.srcport == {source_port} and ip.dst == {server_ip}")
        # Count received packets (from server to our source port)
        received = _count_packets(packets_file, f"udp and ip.src == {server_ip} and udp.dstport == {source_port}")
        
        return True, packets_file, sent, received
        
    except Exception as e:
        print(f"❌ Test execution error: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        if tcpdump_process:
            tcpdump_process.kill()
        return False, packets_file, 0, 0
    finally:
        if sock:
            sock.close()


# ============================================================================
# Stage 1: Local DNS Validity Check (Uncensored)
# ============================================================================

def _extract_dns_qname(pcap_file: str, server_ip: str) -> Optional[str]:
    """Extract the queried domain name (QNAME) from DNS response in pcap."""
    cmd = [
        "tshark", "-r", pcap_file,
        "-Y", f"dns.flags.response == 1 and ip.src == {server_ip}",
        "-T", "fields", "-e", "dns.qry.name"
    ]
    try:
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
        if result.returncode == 0:
            qnames = result.stdout.decode().strip().splitlines()
            if qnames:
                return qnames[0].lower().rstrip('.')
    except Exception:
        pass
    return None


def _domain_matches(qname: str, target_domain: str) -> bool:
    """Check if qname matches or is a subdomain of target_domain."""
    if not qname or not target_domain:
        return False
    qname = qname.lower().rstrip('.')
    target = target_domain.lower().rstrip('.')
    return qname == target or qname.endswith('.' + target)


def evaluate_stage1_local_validity(
    program_path: str,
    dns_server: str = REAL_DNS_SERVERS[0],
    packets_file: str = "/workspace/packets_stage1.pcap",
    forbidden_domain: Optional[str] = None,
    source_port: Optional[int] = None,
    interface: str = "eth0",
) -> Dict[str, float]:
    """
    Stage 1: Verify the program produces a VALID DNS packet for the FORBIDDEN domain.
    
    Sends to a REAL DNS server in an uncensored environment.
    The program MUST:
    1. Receive a valid DNS response
    2. The response must be for the forbidden domain (prevents cheating)
    
    This prevents evolution from gaming on-path-injector tests
    by simply not sending valid DNS packets or querying different domains.
    
    Args:
        source_port: Optional source port to bind to, allowing concurrent evaluations
        interface: Network interface for packet capture
    
    Returns:
        Dict with 'stage1_validity' score (0.0 or 1.0)
    """
    # Get forbidden domain from env if not provided
    if forbidden_domain is None:
        forbidden_domain = os.environ.get("FORBIDDEN_DOMAIN", "google.com")
    
    print("=" * 60)
    print("STAGE 1: Local DNS Validity Check")
    print("=" * 60)
    print(f"Purpose: Verify program sends valid DNS for forbidden domain")
    print(f"Server: {dns_server} (REAL DNS server)")
    print(f"Expected domain: {forbidden_domain}")
    if source_port:
        print(f"Source port: {source_port} (for concurrent evaluation isolation)")
    print()
    
    success, pcap_file, sent, received = run_dns_test(
        program_path=program_path,
        server_ip=dns_server,
        packets_file=packets_file,
        source_port=source_port,
        interface=interface,
    )
    
    print(f"📤 Packets sent: {sent}")
    print(f"📥 Packets received: {received}")
    
    if sent == 0:
        print("❌ STAGE 1 FAILED: No packets sent")
        print("   Program did not generate valid output")
        return {"stage1_validity": 0.0, "evasion_success": -10, "combined_score": -10, "stage1_sent": 0, "stage1_received": 0}
    
    if received == 0:
        print("❌ STAGE 1 FAILED: No response received")
        print("   Packet is NOT valid DNS (real server didn't respond)")
        return {"stage1_validity": 0.0, "evasion_success": -10, "combined_score": -10, "stage1_sent": float(sent), "stage1_received": 0}
    
    # Verify we got actual DNS response (not just any UDP)
    ips = _extract_dns_ips(pcap_file, dns_server)
    if not ips:
        print("⚠️  STAGE 1 WARNING: Response received but no DNS IPs extracted")
        print("   Response may not be valid DNS")
        # Still pass but with warning - at least something responded
    else:
        print(f"✅ DNS response received with IPs: {ips}")
    
    # CRITICAL: Check if response is for the forbidden domain
    qname = _extract_dns_qname(pcap_file, dns_server)
    print(f"📋 Response QNAME: {qname}")
    
    if not _domain_matches(qname, forbidden_domain):
        print(f"❌ STAGE 1 FAILED: Response is NOT for forbidden domain!")
        print(f"   Expected: {forbidden_domain}")
        print(f"   Got: {qname}")
        print("   (Program may be querying a different domain to cheat)")
        return {
            "stage1_validity": 0.0,
            "evasion_success": -10,
            "combined_score": -10,
            "stage1_sent": float(sent),
            "stage1_received": float(received),
            "wrong_domain": True,
        }
    
    print(f"✅ Response is for forbidden domain '{forbidden_domain}'")
    print("✅ STAGE 1 PASSED: Program produces valid DNS packets for forbidden domain")
    return {
        "stage1_validity": 1.0,
        "evasion_success": 0.0,  # Will be set by Stage 2
        "combined_score": 0.0,   # Will be set by Stage 2
        "stage1_sent": float(sent),
        "stage1_received": float(received),
    }


# ============================================================================
# Stage 2: Censored Network Evasion Test
# ============================================================================

def evaluate_stage2_evasion(
    program_path: str,
    censor_type: str = "on-path-injector",
    server_ip: Optional[str] = None,
    packets_file: str = "/workspace/packets_stage2.pcap",
    source_port: Optional[int] = None,
    interface: str = "eth0",
    expected_resolved_ip: Optional[str] = None,
) -> Dict[str, float]:
    """
    Stage 2: Test evasion against the actual censor.
    
    For on-path-injector (China GFW):
        - Sends to NON-DNS server
        - Any response = injection = FAIL
        - No response = evasion = SUCCESS
    
    For in-path-modifier (OpenGFW):
        - Sends to REAL DNS server through middlebox
        - No response = censor dropped = Score 0
        - Got response = Score +1 per response (if expected_resolved_ip matches)
    
    Args:
        source_port: Optional source port to bind to, allowing concurrent evaluations
        interface: Network interface for packet capture
        expected_resolved_ip: Optional IP that must be in DNS response for it to count as valid
    
    Returns:
        Dict with 'evasion_success' score
    """
    # Load expected_resolved_ip from environment if not provided
    if expected_resolved_ip is None:
        expected_resolved_ip = os.environ.get("EXPECTED_RESOLVED_IP", "")
    
    print()
    print("=" * 60)
    print("STAGE 2: Censored Network Evasion Test")
    print("=" * 60)
    print(f"Censor Type: {censor_type}")
    if source_port:
        print(f"Source port: {source_port} (for concurrent evaluation isolation)")
    if expected_resolved_ip:
        print(f"Expected resolved IP: {expected_resolved_ip} (required for valid response)")
    
    if censor_type == "on-path-injector":
        target_server = server_ip or NON_DNS_SERVERS[0]
        print(f"Server: {target_server} (NON-DNS server)")
        print("Test: Any response = injection detected = FAIL")
        print()
        
        success, pcap_file, sent, received = run_dns_test(
            program_path=program_path,
            server_ip=target_server,
            packets_file=packets_file,
            source_port=source_port,
            interface=interface,
        )
        
        print(f"📤 Packets sent: {sent}")
        print(f"📥 Packets received: {received}")
        
        if sent == 0:
            print("❌ No packets sent")
            return {"evasion_success": -1000.0, "combined_score": -1000.0, "stage2_sent": 0, "stage2_received": 0}
        
        if received > 0:
            ips = _extract_dns_ips(pcap_file, target_server)
            print(f"☠️  INJECTION DETECTED!")
            print(f"   Received response from NON-DNS server (must be censor injection)")
            if ips:
                print(f"   Injected IPs: {ips}")
            total_score = -1.0 * float(received)
            return {"evasion_success": total_score, "combined_score": total_score, "stage2_sent": float(sent), "stage2_received": float(received)}
        
        print("✅ EVASION SUCCESSFUL!")
        print("   No injection detected (censor did not recognize the packet)")
        return {"evasion_success": 1.0, "combined_score": 1.0, "stage2_sent": float(sent), "stage2_received": 0}
    
    elif censor_type == "in-path-modifier":
        import random
        
        # Test against ALL real DNS servers through the middlebox
        dns_servers = REAL_DNS_SERVERS
        print(f"Servers: {dns_servers} (REAL DNS through middlebox)")
        print("Test: In-path censor DROPS detected queries")
        print("      No response = DETECTED (censor dropped query)")
        print("      Got response = EVASION SUCCESS → Score: +1 per valid response")
        if expected_resolved_ip:
            print(f"      Expected IP validation: Response must contain {expected_resolved_ip}")
        print(f"      Testing against {len(dns_servers)} DNS servers (max score: {len(dns_servers)})")
        print()
        
        total_sent = 0
        total_received = 0
        valid_responses = 0  # Responses that pass IP validation (if configured)
        all_ips = []
        server_results = []
        
        for i, dns_server in enumerate(dns_servers):
            # Use unique source port for each server test
            test_source_port = source_port + i if source_port else random.randint(49152, 65535)
            test_packets_file = packets_file.replace(".pcap", f"_{i}.pcap") if packets_file else f"/workspace/packets_stage2_{i}.pcap"
            
            print(f"--- Testing {dns_server} (port {test_source_port}) ---")
            
            success, pcap_file, sent, received = run_dns_test(
                program_path=program_path,
                server_ip=dns_server,
                packets_file=test_packets_file,
                source_port=test_source_port,
                interface=interface,
            )
            
            total_sent += sent
            total_received += received
            
            if sent > 0 and received > 0:
                ips = _extract_dns_ips(pcap_file, dns_server)
                all_ips.extend(ips)
                
                # Validate expected_resolved_ip if configured
                if expected_resolved_ip:
                    if expected_resolved_ip in ips:
                        valid_responses += 1
                        server_results.append((dns_server, "✅ PASS", received, ips))
                        print(f"  ✅ Got {received} response(s): {ips}")
                        print(f"     Expected IP {expected_resolved_ip} found ✓")
                    else:
                        server_results.append((dns_server, "⚠️ WRONG IP", received, ips))
                        print(f"  ⚠️ Got response but wrong IP: {ips}")
                        print(f"     Expected IP {expected_resolved_ip} NOT found")
                else:
                    # No IP validation - any response counts
                    valid_responses += 1
                    server_results.append((dns_server, "✅ PASS", received, ips))
                    print(f"  ✅ Got {received} response(s): {ips}")
            elif sent > 0:
                server_results.append((dns_server, "❌ BLOCKED", 0, []))
                print(f"  ❌ No response (censor dropped)")
            else:
                server_results.append((dns_server, "⚠️ ERROR", 0, []))
                print(f"  ⚠️ Failed to send")
            print()
        
        # Summary
        print("=" * 50)
        print("STAGE 2 SUMMARY (In-Path Censor)")
        print("=" * 50)
        print(f"📤 Total packets sent: {total_sent}")
        print(f"📥 Total responses received: {total_received}")
        if expected_resolved_ip:
            print(f"✓  Valid responses (with expected IP {expected_resolved_ip}): {valid_responses}")
        print()
        
        for server, status, recv, ips in server_results:
            ip_str = f" → {ips}" if ips else ""
            print(f"  {status} {server}: {recv} response(s){ip_str}")
        print()
        
        if total_sent == 0:
            print("❌ No packets sent (program error)")
            return {"evasion_success": -1000.0, "combined_score": -1000.0, "stage2_sent": 0, "stage2_received": 0}
        
        if valid_responses == 0:
            if total_received == 0:
                print("☠️  ALL BLOCKED - Censor dropped all queries")
            else:
                print(f"☠️  NO VALID RESPONSES - Got {total_received} response(s) but none with expected IP")
            print("   Score: 0")
            return {"evasion_success": 0.0, "combined_score": 0.0, "stage2_sent": float(total_sent), "stage2_received": float(total_received)}
        
        # Got valid response(s) - evasion successful!
        # +1 point for each valid DNS response
        score = float(valid_responses)
        print(f"✅ EVASION SUCCESS - Got {valid_responses}/{len(dns_servers)} valid responses!")
        print(f"   Score: +{score}")
        if all_ips:
            unique_ips = list(set(all_ips))
            print(f"🔎 All resolved IPs: {unique_ips}")
        
        return {"evasion_success": score, "combined_score": score, "stage2_sent": float(total_sent), "stage2_received": float(valid_responses)}
    
    else:
        print(f"❌ Unknown censor type: {censor_type}")
        return {"evasion_success": -1000.0, "combined_score": -1000.0}


# ============================================================================
# OpenEvolve Cascade Evaluation Interface
# ============================================================================

def evaluate_stage1(program_path: str, source_port: Optional[int] = None, interface: str = "eth0") -> Dict[str, float]:
    """
    OpenEvolve Stage 1: Local DNS validity check.
    
    This is called automatically by OpenEvolve when cascade_evaluation=true.
    Program must pass this stage to proceed to stage 2.
    
    Args:
        source_port: Optional source port for concurrent evaluation isolation
        interface: Network interface for packet capture
    """
    return evaluate_stage1_local_validity(program_path, source_port=source_port, interface=interface)


def evaluate_stage2(program_path: str, packets_file: str = None, source_port: Optional[int] = None, interface: str = "eth0") -> Dict[str, float]:
    """
    OpenEvolve Stage 2: Censored network evasion test.
    
    This is called by OpenEvolve if stage 1 passes the threshold.
    Uses environment variables to configure test methodology.
    
    Args:
        source_port: Optional source port for concurrent evaluation isolation
        interface: Network interface for packet capture
    """
    censor_type = os.environ.get("CENSOR_TYPE", "on-path-injector")
    server_ip = os.environ.get("CENSOR_SERVER_IP")
    expected_resolved_ip = os.environ.get("EXPECTED_RESOLVED_IP", "")
    # Use provided packets_file, or from env, or default
    if packets_file is None:
        packets_file = os.environ.get("PACKETS_FILE", "/workspace/packets_stage2.pcap")
    return evaluate_stage2_evasion(program_path, censor_type, server_ip, packets_file, source_port=source_port, interface=interface, expected_resolved_ip=expected_resolved_ip)


def evaluate(program_path: str, source_port: Optional[int] = None, interface: str = "eth0") -> Dict[str, float]:
    """
    OpenEvolve fallback: Single-stage evaluation.
    
    Called when cascade_evaluation=false or as fallback.
    
    Args:
        source_port: Optional source port for concurrent evaluation isolation
        interface: Network interface for packet capture
    """
    censor_type = os.environ.get("CENSOR_TYPE", "in-path-modifier")
    
    if censor_type == "on-path-injector":
        # For on-path, we SHOULD use cascade, but if not, at least do both tests
        print("⚠️  WARNING: on-path-injector should use cascade evaluation!")
        print("   Running both stages sequentially...")
        
        stage1 = evaluate_stage1_local_validity(program_path, source_port=source_port, interface=interface)
        if stage1.get("stage1_validity", 0) < 1.0:
            # Failed validity check (need at least 1 resolver success = 1 point)
            return {
                "evasion_success": -10,
                "combined_score": -10,
                **stage1,
            }
        
        stage2 = evaluate_stage2_evasion(program_path, censor_type, source_port=source_port, interface=interface)
        return {
            **stage1,
            **stage2,
            "combined_score": stage2.get("evasion_success", -1000.0),
        }
    
    else:
        # For in-path-modifier, single stage is fine
        return evaluate_stage2_evasion(program_path, censor_type, source_port=source_port, interface=interface)


# ============================================================================
# Helper Functions
# ============================================================================

def _count_packets(pcap_file: str, filter_expr: str) -> int:
    """Count packets matching a tshark filter."""
    cmd = [
        "tshark", "-r", pcap_file, "-Y", filter_expr,
        "-T", "fields", "-e", "frame.number"
    ]
    try:
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
        if result.returncode == 0:
            lines = result.stdout.decode().strip().splitlines()
            return len([l for l in lines if l.strip()])
    except Exception:
        pass
    return 0


def _extract_dns_ips(pcap_file: str, server_ip: str) -> list:
    """Extract IP addresses from DNS responses."""
    cmd = [
        "tshark", "-r", pcap_file,
        "-Y", f"dns.flags.response == 1 and ip.src == {server_ip}",
        "-T", "fields", "-e", "dns.a", "-e", "dns.aaaa"
    ]
    try:
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
        if result.returncode == 0:
            ips = []
            for line in result.stdout.decode().splitlines():
                parts = line.split('\t')
                for part in parts:
                    if part:
                        ips.extend(part.split(','))
            return [ip.strip() for ip in ips if ip.strip()]
    except Exception:
        pass
    return []


def write_fitness_score(fitness_file: str, score: float) -> None:
    """Write fitness score to file."""
    directory = os.path.dirname(fitness_file)
    if directory:
        os.makedirs(directory, exist_ok=True)
    with open(fitness_file, "w", encoding="utf-8") as f:
        f.write(str(score))
    print(f"✍️  Wrote fitness score {score} to: {fitness_file}")


# ============================================================================
# CLI Interface
# ============================================================================

def parse_args():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="DNS Censorship Evasion Test Runner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Modes:
  --stage 1         Run Stage 1 only (local DNS validity check)
  --stage 2         Run Stage 2 only (censored network evasion)
  --stage all       Run both stages (cascade evaluation)
  (no --stage)      Single evaluation based on --censor-type

Censor Types:
  in-path-modifier  Middlebox modifies DNS responses (OpenGFW style)
  on-path-injector  Censor races to inject fake responses (China GFW style)
                    ** Should use cascade evaluation to prevent gaming **

Examples:
  # Full cascade evaluation for China GFW testing
  python run_tests.py --stage all --censor-type on-path-injector
  
  # Single evaluation for OpenGFW testing  
  python run_tests.py --censor-type in-path-modifier
"""
    )
    parser.add_argument(
        "--stage",
        type=str,
        choices=["1", "2", "all"],
        default=None,
        help="Which evaluation stage(s) to run"
    )
    parser.add_argument(
        "--censor-type",
        type=str,
        choices=["in-path-modifier", "on-path-injector"],
        default="in-path-modifier",
        help="Type of censor to test against (default: %(default)s)"
    )
    parser.add_argument(
        "--program-path",
        type=str,
        default=os.getenv("PROGRAM_PATH", DEFAULT_PROGRAM_PATH),
        help="Path to program to test"
    )
    parser.add_argument(
        "--fitness-file",
        type=str,
        default=os.getenv("BLOCKED_FITNESS_FILE", DEFAULT_FITNESS_FILE),
        help="Path to write fitness score"
    )
    parser.add_argument(
        "--packets-file",
        type=str,
        default=os.getenv("BLOCKED_PACKETS_FILE", DEFAULT_PACKETS_FILE),
        help="Path to save packet capture file"
    )
    parser.add_argument(
        "--server-ip",
        type=str,
        default=None,
        help="Override server IP for testing"
    )
    parser.add_argument(
        "--port",
        type=int,
        default=53,
        help="Server port (default: 53)"
    )
    parser.add_argument(
        "--interface",
        type=str,
        default="eth0",
        help="Network interface for capture"
    )
    parser.add_argument(
        "--source-port",
        type=int,
        default=None,
        help="Source port for UDP socket. If provided, tcpdump will filter by this port, "
             "allowing multiple concurrent evaluations. If not specified, a random port is used."
    )
    return parser.parse_args()


def main():
    """CLI entry point."""
    args = parse_args()
    
    # Set environment for cascade functions
    os.environ["CENSOR_TYPE"] = args.censor_type
    if args.server_ip:
        os.environ["CENSOR_SERVER_IP"] = args.server_ip
    if args.packets_file:
        os.environ["PACKETS_FILE"] = args.packets_file
    
    print(f"🎯 DNS Censorship Evasion Test")
    print(f"   Program: {args.program_path}")
    print(f"   Censor Type: {args.censor_type}")
    print(f"   Interface: {args.interface}")
    if args.source_port:
        print(f"   Source Port: {args.source_port} (for concurrent evaluation isolation)")
    if args.stage:
        print(f"   Stage(s): {args.stage}")
    print()
    
    try:
        if args.stage == "1":
            result = evaluate_stage1(args.program_path, source_port=args.source_port, interface=args.interface)
            score = result.get("stage1_validity", 0.0)
        elif args.stage == "2":
            result = evaluate_stage2(args.program_path, packets_file=args.packets_file, source_port=args.source_port, interface=args.interface)
            score = result.get("evasion_success", 0.0)
        elif args.stage == "all":
            # Cascade: Stage 1 must pass before Stage 2
            stage1_result = evaluate_stage1(args.program_path, source_port=args.source_port, interface=args.interface)
            if stage1_result.get("stage1_validity", 0.0) < 1.0:
                print()
                print("🛑 Stage 1 failed (score < 1) - skipping Stage 2")
                result = stage1_result
                score = 0.0
            else:
                stage2_result = evaluate_stage2(args.program_path, packets_file=args.packets_file, source_port=args.source_port, interface=args.interface)
                result = {**stage1_result, **stage2_result}
                score = stage2_result.get("evasion_success", 0.0)
        else:
            # Single evaluation (fallback)
            result = evaluate(args.program_path, source_port=args.source_port, interface=args.interface)
            score = result.get("evasion_success", result.get("combined_score", 0.0))
        
        print()
        print("=" * 60)
        print(f"FINAL SCORE: {score}")
        print("=" * 60)
        
        write_fitness_score(args.fitness_file, score)
        
    except Exception as e:
        print(f"❌ Error: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        write_fitness_score(args.fitness_file, 0.0)
        sys.exit(1)


if __name__ == "__main__":
    main()
