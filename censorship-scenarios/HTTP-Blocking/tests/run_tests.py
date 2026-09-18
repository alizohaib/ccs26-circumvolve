#!/usr/bin/env python3
"""
HTTP Censorship Evasion Test Runner

Supports multiple censor types:

1. in-path-modifier: Middlebox blocks/resets HTTP connections (e.g., OpenGFW)
   - Sends HTTP request through middlebox
   - Test: Did we get a valid HTTP response or was connection blocked?

2. on-path-resetter: Censor races to send RST packets (e.g., China GFW)
   - Sends HTTP request through censored network
   - Valid response = evasion success, RST/timeout = blocked
"""

import argparse
import subprocess
import sys
import os
import signal
import time
import socket
from typing import Dict, Optional, Tuple

# ============================================================================
# Configuration
# ============================================================================

# Default HTTP servers for testing
DEFAULT_SERVERS = {
    "cloudflare": "104.16.132.229",
    "example": "93.184.216.34",
}

# Default paths
DEFAULT_PROGRAM_PATH = "/workspace/http_initial.py"
DEFAULT_PACKETS_FILE = "/workspace/packets.pcap"
DEFAULT_FITNESS_FILE = "/workspace/fitness.txt"
DEFAULT_PORT = 80


# ============================================================================
# Core Test Execution
# ============================================================================

def run_http_test(
    program_path: str,
    server_ip: str,
    port: int = 80,
    interface: str = "eth0",
    packets_file: str = DEFAULT_PACKETS_FILE,
    timeout_seconds: int = 10,
    source_port: Optional[int] = None,
) -> Tuple[bool, str, int, int, bytes, bool]:
    """
    Execute HTTP test: run program, send TCP request, capture response.
    
    Args:
        program_path: Path to the HTTP request generator program
        server_ip: Target server IP address
        port: Target server port (default 80)
        interface: Network interface for packet capture
        packets_file: Path to save pcap file
        timeout_seconds: Socket timeout for receiving response
        source_port: Optional source port to bind to for concurrent evaluations.
    
    Returns:
        Tuple of (success, pcap_file_path, packets_sent, packets_received, response_bytes, got_rst)
    """
    import random
    
    tcpdump_process = None
    sock = None
    response = b""
    got_rst = False
    
    # Generate a unique source port if not provided
    if source_port is None:
        source_port = random.randint(49152, 65535)
    
    try:
        # Ensure packets directory exists
        packets_directory = os.path.dirname(packets_file)
        if packets_directory:
            os.makedirs(packets_directory, exist_ok=True)
        
        # Start packet capture with source port filter for isolation
        print(f"📡 Starting tcpdump on {interface} (src port {source_port}, dst port {port})...")
        tcpdump_filter = f"tcp and (port {source_port} or port {port})"
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
            return False, packets_file, 0, 0, b"", False
        
        # Parse hex output
        hex_output = program_stdout.decode().strip()
        if not hex_output:
            print("⚠️  Program produced no output", file=sys.stderr)
            return False, packets_file, 0, 0, b"", False
        
        try:
            request_bytes = bytes.fromhex(hex_output)
        except ValueError as e:
            print(f"⚠️  Invalid hex output: {e}", file=sys.stderr)
            return False, packets_file, 0, 0, b"", False
        
        print(f"📝 HTTP Request ({len(request_bytes)} bytes):")
        print(f"   {request_bytes[:200]}...")
        
        # Create TCP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        # Bind to specific source port
        try:
            sock.bind(('', source_port))
        except OSError as e:
            print(f"⚠️  Could not bind to port {source_port}: {e}")
            # Try with any port
            sock.bind(('', 0))
            source_port = sock.getsockname()[1]
            print(f"   Using port {source_port} instead")
        
        sock.settimeout(timeout_seconds)
        
        # Connect and send
        try:
            print(f"🔗 Connecting to {server_ip}:{port}...")
            sock.connect((server_ip, port))
            print(f"📤 Sending {len(request_bytes)} bytes...")
            sock.sendall(request_bytes)
            
            # Receive response
            response = b""
            while True:
                try:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    response += chunk
                    print(f"📥 Received {len(chunk)} bytes (total: {len(response)})")
                    # Don't read forever - stop after reasonable amount
                    if len(response) > 65536:
                        break
                except socket.timeout:
                    print("⏱️  Receive timeout (normal for HTTP)")
                    break
                    
        except ConnectionResetError:
            print("🚫 Connection RESET by peer (possible censor intervention)")
            got_rst = True
        except ConnectionRefusedError:
            print("🚫 Connection REFUSED")
        except socket.timeout:
            print("⏱️  Connection timeout")
        except Exception as e:
            print(f"❌ Connection error: {e}")
        
        # Wait for any additional packets to be captured
        time.sleep(1)
        
        # Stop capture
        tcpdump_process.send_signal(signal.SIGTERM)
        try:
            tcpdump_process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            tcpdump_process.kill()
        
        # Count packets using tshark
        if not os.path.exists(packets_file):
            return False, packets_file, 0, 0, response, got_rst
        
        # Count sent packets (SYN, data)
        sent = _count_packets(packets_file, f"tcp and ip.dst == {server_ip} and tcp.dstport == {port}")
        # Count received packets (SYN-ACK, data, RST)
        received = _count_packets(packets_file, f"tcp and ip.src == {server_ip} and tcp.srcport == {port}")
        
        # Check for RST packets
        rst_count = _count_packets(packets_file, f"tcp.flags.reset == 1 and ip.src == {server_ip}")
        if rst_count > 0:
            got_rst = True
            print(f"🚫 Detected {rst_count} RST packets from server")
        
        return True, packets_file, sent, received, response, got_rst
        
    except Exception as e:
        print(f"❌ Test execution error: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        if tcpdump_process:
            tcpdump_process.kill()
        return False, packets_file, 0, 0, b"", False
    finally:
        if sock:
            try:
                sock.close()
            except:
                pass


# ============================================================================
# Stage 1: Local HTTP Validity Check (Uncensored)
# ============================================================================

def evaluate_stage1_local_validity(
    program_path: str,
    server_ip: Optional[str] = None,
    port: int = DEFAULT_PORT,
    packets_file: str = "/workspace/packets_stage1.pcap",
    forbidden_domain: Optional[str] = None,
    source_port: Optional[int] = None,
    interface: str = "eth0",
) -> Dict[str, float]:
    """
    Stage 1: Verify the program produces a VALID HTTP request.
    
    Sends to a REAL server in an uncensored environment.
    The program MUST receive a valid HTTP response.
    
    Returns:
        Dict with 'stage1_validity' score (0.0 to 100.0)
    """
    # Get forbidden domain from env if not provided
    if forbidden_domain is None:
        forbidden_domain = os.environ.get("FORBIDDEN_DOMAIN", "cloudflare.com")
    
    # Resolve server IP if not provided
    if server_ip is None:
        try:
            server_ip = socket.gethostbyname(forbidden_domain)
            print(f"Resolved {forbidden_domain} to {server_ip}")
        except socket.gaierror:
            server_ip = DEFAULT_SERVERS.get("cloudflare", "104.16.132.229")
    
    print("=" * 60)
    print("STAGE 1: Local HTTP Validity Check")
    print("=" * 60)
    print(f"Purpose: Verify program sends valid HTTP request")
    print(f"Server: {server_ip}:{port}")
    print(f"Domain: {forbidden_domain}")
    if source_port:
        print(f"Source port: {source_port}")
    print()
    
    success, pcap_file, sent, received, response, got_rst = run_http_test(
        program_path=program_path,
        server_ip=server_ip,
        port=port,
        packets_file=packets_file,
        source_port=source_port,
        interface=interface,
    )
    
    print(f"📤 Packets sent: {sent}")
    print(f"📥 Packets received: {received}")
    print(f"📦 Response size: {len(response)} bytes")
    
    if sent == 0:
        print("❌ STAGE 1 FAILED: No packets sent")
        return {"stage1_validity": 0.0, "evasion_success": -1000.0, "combined_score": -1000.0}
    
    if got_rst:
        print("❌ STAGE 1 FAILED: Connection reset")
        return {"stage1_validity": 0.0, "evasion_success": -1000.0, "combined_score": -1000.0}
    
    if len(response) == 0:
        print("❌ STAGE 1 FAILED: No response received")
        return {"stage1_validity": 0.0, "evasion_success": -1000.0, "combined_score": -1000.0}
    
    # Parse HTTP response
    score = _score_http_response(response)
    
    if score >= 50.0:
        print(f"✅ STAGE 1 PASSED: Got valid HTTP response (score: {score})")
    else:
        print(f"❌ STAGE 1 FAILED: Invalid HTTP response (score: {score})")
    
    return {
        "stage1_validity": score,
        "evasion_success": 0.0 if score >= 50.0 else -1000.0,
        "combined_score": 0.0 if score >= 50.0 else -1000.0,
        "stage1_sent": float(sent),
        "stage1_received": float(received),
    }


# ============================================================================
# Stage 2: Censored Network Evasion Test
# ============================================================================

def evaluate_stage2_evasion(
    program_path: str,
    censor_type: str = "on-path-resetter",
    server_ip: Optional[str] = None,
    port: int = DEFAULT_PORT,
    packets_file: str = "/workspace/packets_stage2.pcap",
    source_port: Optional[int] = None,
    interface: str = "eth0",
) -> Dict[str, float]:
    """
    Stage 2: Test evasion against the actual censor.
    
    For on-path-resetter (China GFW):
        - Sends HTTP request through censored network
        - RST packet = blocked = FAIL
        - Valid HTTP response = evasion = SUCCESS
    
    For in-path-modifier (OpenGFW):
        - Sends HTTP request through middlebox
        - Connection blocked = FAIL
        - Valid HTTP response = SUCCESS
    
    Returns:
        Dict with 'evasion_success' score
    """
    forbidden_domain = os.environ.get("FORBIDDEN_DOMAIN", "cloudflare.com")
    
    # Resolve server IP if not provided
    if server_ip is None:
        try:
            server_ip = socket.gethostbyname(forbidden_domain)
        except socket.gaierror:
            server_ip = DEFAULT_SERVERS.get("cloudflare", "104.16.132.229")
    
    print()
    print("=" * 60)
    print("STAGE 2: Censored Network Evasion Test")
    print("=" * 60)
    print(f"Censor Type: {censor_type}")
    print(f"Server: {server_ip}:{port}")
    if source_port:
        print(f"Source port: {source_port}")
    
    success, pcap_file, sent, received, response, got_rst = run_http_test(
        program_path=program_path,
        server_ip=server_ip,
        port=port,
        packets_file=packets_file,
        source_port=source_port,
        interface=interface,
    )
    
    print(f"📤 Packets sent: {sent}")
    print(f"📥 Packets received: {received}")
    print(f"📦 Response size: {len(response)} bytes")
    print(f"🚫 Got RST: {got_rst}")
    
    if sent == 0:
        print("❌ No packets sent")
        return {"evasion_success": -1000.0, "combined_score": -1000.0}
    
    # Check for RST (censor signature)
    if got_rst:
        print("☠️  CONNECTION RESET DETECTED!")
        print("   Censor likely sent RST packet to kill connection")
        return {"evasion_success": -1.0, "combined_score": -1.0, "stage2_sent": float(sent), "stage2_received": float(received)}
    
    if len(response) == 0:
        print("⚠️  No response - connection may have been silently dropped")
        return {"evasion_success": 0.0, "combined_score": 0.0, "stage2_sent": float(sent), "stage2_received": float(received)}
    
    # Score the response
    score = _score_http_response(response)
    
    if score >= 50.0:
        print("✅ EVASION SUCCESSFUL!")
        print(f"   Got valid HTTP response (score: {score})")
        # Normalize to 0-1 range for evasion_success
        evasion_score = min(1.0, score / 100.0)
        return {"evasion_success": evasion_score, "combined_score": evasion_score, "stage2_sent": float(sent), "stage2_received": float(received)}
    else:
        print(f"❌ Response received but invalid (score: {score})")
        return {"evasion_success": score / 100.0, "combined_score": score / 100.0, "stage2_sent": float(sent), "stage2_received": float(received)}


# ============================================================================
# OpenEvolve Stage Evaluation Interface
# ============================================================================

def evaluate_stage1(program_path: str, source_port: Optional[int] = None, interface: str = "eth0") -> Dict[str, float]:
    """OpenEvolve Stage 1: Local HTTP validity check."""
    return evaluate_stage1_local_validity(program_path, source_port=source_port, interface=interface)


def evaluate_stage2(program_path: str, packets_file: str = None, source_port: Optional[int] = None, interface: str = "eth0") -> Dict[str, float]:
    """OpenEvolve Stage 2: Censored network evasion test."""
    censor_type = os.environ.get("CENSOR_TYPE", "on-path-resetter")
    server_ip = os.environ.get("CENSOR_SERVER_IP")
    port = int(os.environ.get("SERVER_PORT", DEFAULT_PORT))
    if packets_file is None:
        packets_file = os.environ.get("PACKETS_FILE", "/workspace/packets_stage2.pcap")
    return evaluate_stage2_evasion(program_path, censor_type, server_ip, port, packets_file, source_port=source_port, interface=interface)


def evaluate(program_path: str, source_port: Optional[int] = None, interface: str = "eth0") -> Dict[str, float]:
    """OpenEvolve single-stage evaluation - directly runs evasion test."""
    censor_type = os.environ.get("CENSOR_TYPE", "in-path-modifier")
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


def _score_http_response(response: bytes) -> float:
    """
    Score an HTTP response.
    
    Handles both HTTP/1.x (text-based) and HTTP/2 (binary protocol) responses.
    
    Returns:
        Score from 0.0 to 100.0
    """
    if not response:
        return 0.0
    
    # First, try to detect HTTP/1.x (text-based)
    try:
        response_text = response.decode('utf-8', errors='ignore')
        if response_text.startswith("HTTP/"):
            return _score_http1_response(response_text)
    except:
        pass
    
    # Check for HTTP/2 binary response
    if len(response) >= 9:  # Minimum HTTP/2 frame header size
        h2_score = _score_http2_response(response)
        if h2_score > 0:
            return h2_score
    
    # Unknown protocol - some response received but not recognized
    print(f"⚠️  Response does not match HTTP/1.x or HTTP/2 format")
    print(f"   First 50 bytes (hex): {response[:50].hex()}")
    return 10.0


def _score_http1_response(response_text: str) -> float:
    """
    Score an HTTP/1.x text-based response.
    
    Returns:
        Score from 0.0 to 100.0
    """
    print(f"📋 Detected HTTP/1.x response")
    
    # Extract status line
    first_line = response_text.split('\r\n')[0] if '\r\n' in response_text else response_text.split('\n')[0]
    print(f"   Status: {first_line}")
    
    # Parse status code
    parts = first_line.split(' ')
    if len(parts) < 2:
        return 20.0
    
    try:
        status_code = int(parts[1])
    except ValueError:
        return 20.0
    
    return _score_status_code(status_code)


def _score_http2_response(response: bytes) -> float:
    """
    Score an HTTP/2 binary response.
    
    HTTP/2 Frame Header (9 bytes):
        - Length: 3 bytes (payload length, not including header)
        - Type: 1 byte (0=DATA, 1=HEADERS, 4=SETTINGS, 7=GOAWAY, etc.)
        - Flags: 1 byte
        - Stream ID: 4 bytes (MSB is reserved)
    
    Returns:
        Score from 0.0 to 100.0, or 0.0 if not valid HTTP/2
    """
    # HTTP/2 frame types
    FRAME_DATA = 0x00
    FRAME_HEADERS = 0x01
    FRAME_PRIORITY = 0x02
    FRAME_RST_STREAM = 0x03
    FRAME_SETTINGS = 0x04
    FRAME_PUSH_PROMISE = 0x05
    FRAME_PING = 0x06
    FRAME_GOAWAY = 0x07
    FRAME_WINDOW_UPDATE = 0x08
    FRAME_CONTINUATION = 0x09
    
    VALID_FRAME_TYPES = {
        FRAME_DATA, FRAME_HEADERS, FRAME_PRIORITY, FRAME_RST_STREAM,
        FRAME_SETTINGS, FRAME_PUSH_PROMISE, FRAME_PING, FRAME_GOAWAY,
        FRAME_WINDOW_UPDATE, FRAME_CONTINUATION
    }
    
    frames_found = []
    status_code = None
    has_data = False
    has_goaway = False
    goaway_error_code = None
    offset = 0
    
    while offset + 9 <= len(response):
        # Parse frame header
        length = int.from_bytes(response[offset:offset+3], 'big')
        frame_type = response[offset+3]
        flags = response[offset+4]
        stream_id = int.from_bytes(response[offset+5:offset+9], 'big') & 0x7FFFFFFF
        
        # Validate frame type
        if frame_type not in VALID_FRAME_TYPES:
            # Not a valid HTTP/2 frame - might not be HTTP/2
            if offset == 0:
                return 0.0  # First frame invalid, not HTTP/2
            break  # Corrupted later, but we got some valid frames
        
        # Sanity check on length (max frame size default is 16384)
        if length > 16777215:  # Max possible length (2^24 - 1)
            if offset == 0:
                return 0.0
            break
        
        frame_name = {
            FRAME_DATA: "DATA", FRAME_HEADERS: "HEADERS", FRAME_PRIORITY: "PRIORITY",
            FRAME_RST_STREAM: "RST_STREAM", FRAME_SETTINGS: "SETTINGS",
            FRAME_PUSH_PROMISE: "PUSH_PROMISE", FRAME_PING: "PING",
            FRAME_GOAWAY: "GOAWAY", FRAME_WINDOW_UPDATE: "WINDOW_UPDATE",
            FRAME_CONTINUATION: "CONTINUATION"
        }.get(frame_type, f"UNKNOWN({frame_type})")
        
        frames_found.append((frame_name, stream_id, length))
        
        # Get frame payload
        payload_start = offset + 9
        payload_end = payload_start + length
        if payload_end > len(response):
            break  # Truncated frame
        
        payload = response[payload_start:payload_end]
        
        # Check for HEADERS frame with status
        if frame_type == FRAME_HEADERS and stream_id > 0:
            # Try to extract status from HPACK-encoded headers
            # The :status pseudo-header is usually near the beginning
            status_code = _extract_h2_status(payload)
        
        # Check for DATA frame
        if frame_type == FRAME_DATA and length > 0:
            has_data = True
        
        # Check for GOAWAY frame (connection termination)
        if frame_type == FRAME_GOAWAY:
            has_goaway = True
            if length >= 8:
                goaway_error_code = int.from_bytes(payload[4:8], 'big')
        
        offset = payload_end
    
    if not frames_found:
        return 0.0  # No valid frames found
    
    print(f"📋 Detected HTTP/2 response")
    print(f"   Frames: {[(f[0], f'stream={f[1]}', f'len={f[2]}') for f in frames_found[:5]]}")
    if len(frames_found) > 5:
        print(f"   ... and {len(frames_found) - 5} more frames")
    
    # Score based on what we found
    if status_code:
        print(f"   Status code: {status_code}")
        return _score_status_code(status_code)
    
    # No status code extracted, but we got valid HTTP/2 frames
    if has_goaway and goaway_error_code is not None:
        print(f"   GOAWAY received with error code: {goaway_error_code}")
        if goaway_error_code == 0:  # NO_ERROR
            return 50.0  # Clean shutdown, connection worked
        else:
            return 30.0  # Error during connection
    
    # Got SETTINGS frame (server acknowledged connection)
    if any(f[0] == "SETTINGS" for f in frames_found):
        if has_data:
            print(f"   Got SETTINGS + DATA frames (response likely successful)")
            return 80.0  # Got data, assume success
        print(f"   Got SETTINGS frame (connection established)")
        return 40.0  # Connection established but no response data
    
    # Some frames received
    print(f"   Got {len(frames_found)} HTTP/2 frame(s)")
    return 35.0


def _extract_h2_status(payload: bytes) -> Optional[int]:
    """
    Attempt to extract the :status pseudo-header from HPACK-encoded headers.
    
    This is a simplified extraction that looks for common patterns.
    HPACK uses indexed headers for common status codes.
    
    Returns:
        HTTP status code or None if not found
    """
    if not payload:
        return None
    
    # HPACK indexed header representations for common status codes
    # Index 8: :status 200
    # Index 9: :status 204
    # Index 10: :status 206
    # Index 11: :status 304
    # Index 12: :status 400
    # Index 13: :status 404
    # Index 14: :status 500
    
    INDEXED_STATUS = {
        0x88: 200,  # Indexed header field (index 8) - :status 200
        0x89: 204,  # Index 9 - :status 204
        0x8a: 206,  # Index 10 - :status 206
        0x8b: 304,  # Index 11 - :status 304
        0x8c: 400,  # Index 12 - :status 400
        0x8d: 404,  # Index 13 - :status 404
        0x8e: 500,  # Index 14 - :status 500
    }
    
    # Check if first byte matches indexed status
    first_byte = payload[0]
    if first_byte in INDEXED_STATUS:
        return INDEXED_STATUS[first_byte]
    
    # Look for literal header with :status
    # This is more complex due to HPACK encoding, try common patterns
    # Literal header with indexing, name index 8 (:status)
    if len(payload) >= 4 and payload[0] == 0x48:  # Literal with incremental indexing, name index 8
        # Next bytes are the value length and value
        try:
            value_len = payload[1] & 0x7F  # Remove Huffman flag
            if value_len <= 3 and len(payload) >= 2 + value_len:
                huffman = payload[1] & 0x80
                if not huffman:  # Plain text
                    status_str = payload[2:2+value_len].decode('ascii')
                    return int(status_str)
        except:
            pass
    
    # Try to find ":status" pattern in payload (for debugging/fallback)
    # This won't work for HPACK but helps identify malformed responses
    
    return None


def _score_status_code(status_code: int) -> float:
    """
    Score based on HTTP status code.
    
    Returns:
        Score from 0.0 to 100.0
    """
    if status_code == 200:
        return 100.0
    elif status_code in [301, 302, 303, 307, 308]:
        return 90.0  # Redirects are fine
    elif status_code == 304:
        return 85.0  # Not modified
    elif status_code in [400, 405, 411, 413, 414]:
        return 50.0  # Client errors - request reached server
    elif status_code in [401, 403]:
        return 60.0  # Auth/forbidden - but server responded
    elif status_code == 404:
        return 70.0  # Not found - server processed request
    elif status_code >= 500:
        return 40.0  # Server error
    else:
        return 30.0  # Unknown status


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
        description="HTTP Censorship Evasion Test Runner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Modes:
  --stage 1         Run Stage 1 only (local HTTP validity check)
  --stage 2         Run Stage 2 only (censored network evasion test)
  --stage all       Run both stages sequentially
  (no --stage)      Single-stage evasion evaluation

Censor Types:
  in-path-modifier  Middlebox blocks HTTP connections (OpenGFW style)
  on-path-resetter  Censor races to send RST packets (China GFW style)

Examples:
  # Evasion test against real censorship
  python run_tests.py --stage 2 --censor-type on-path-resetter
  
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
        choices=["in-path-modifier", "on-path-resetter"],
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
        default=os.getenv("FITNESS_FILE", DEFAULT_FITNESS_FILE),
        help="Path to write fitness score"
    )
    parser.add_argument(
        "--packets-file",
        type=str,
        default=os.getenv("PACKETS_FILE", DEFAULT_PACKETS_FILE),
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
        default=DEFAULT_PORT,
        help=f"Server port (default: {DEFAULT_PORT})"
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
        help="Source port for TCP socket. If provided, tcpdump will filter by this port."
    )
    return parser.parse_args()


def main():
    """CLI entry point."""
    args = parse_args()
    
    # Set environment for stage functions
    os.environ["CENSOR_TYPE"] = args.censor_type
    if args.server_ip:
        os.environ["CENSOR_SERVER_IP"] = args.server_ip
    if args.packets_file:
        os.environ["PACKETS_FILE"] = args.packets_file
    os.environ["SERVER_PORT"] = str(args.port)
    
    print(f"🎯 HTTP Censorship Evasion Test")
    print(f"   Program: {args.program_path}")
    print(f"   Censor Type: {args.censor_type}")
    print(f"   Interface: {args.interface}")
    print(f"   Port: {args.port}")
    if args.source_port:
        print(f"   Source Port: {args.source_port}")
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
            # Run both stages: Stage 1 must pass before Stage 2
            stage1_result = evaluate_stage1(args.program_path, source_port=args.source_port, interface=args.interface)
            if stage1_result.get("stage1_validity", 0.0) < 50.0:
                print()
                print("🛑 Stage 1 failed (score < 50) - skipping Stage 2")
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


