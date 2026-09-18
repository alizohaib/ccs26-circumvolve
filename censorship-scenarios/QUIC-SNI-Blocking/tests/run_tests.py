#!/usr/bin/env python3
"""
Score Test - Runs quic_initial.py and pipes output to xxd and nc, while capturing packets
"""

import argparse
import subprocess
import sys
import os
import signal
import time
import re

def check_quic_initial_from_server(pcap_file: str, server_ip: str = "1.1.1.1") -> float:
    """
    Check if the pcap file contains a Server Hello message from the server.
    
    Uses tshark with -V flag to get verbose output and searches for "Server Hello" text.
    
    :param pcap_file: Path to the pcap file
    :param server_ip: IP address of the server
    :return: Score based on Server Hello presence, packet count, and errors
    """
    if not os.path.exists(pcap_file):
        print(f"⚠️  Pcap file not found: {pcap_file}")
        return 0.0
    
    try:
        # Count packets from server
        count_cmd = [
            "tshark",
            "-r", pcap_file,
            "-Y", f"udp and ip.src == {server_ip}",
            "-T", "fields",
            "-e", "frame.number"
        ]
        count_result = subprocess.run(count_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
        packet_count = 0
        if count_result.returncode == 0:
            output_lines = count_result.stdout.decode().strip().splitlines()
            packet_count = len([l for l in output_lines if l.strip()])
        
        print(f"📦 Found {packet_count} packets from server {server_ip}")

        # Use tshark with -V flag to get verbose output and search for "Server Hello"
        tshark_cmd = [
            "tshark",
            "-r", pcap_file,
            "-Y", f"udp and ip.src == {server_ip}",
            "-V"
        ]
        
        result = subprocess.run(
            tshark_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10
        )
        
        if result.returncode != 0:
            print(f"⚠️  Error running tshark: {result.stderr.decode()}")
            return 0.0
        
        output = result.stdout.decode()
        if not output and packet_count == 0:
            print("📭 No UDP packets from server found")
            return 0.0
        
        score = 0.0

        # Search for "Server Hello" in the text output
        if "Server Hello" in output:
            print("✅ Found Server Hello from server!")
            score += 1.0
        
        if "Retry" in output or "RETRY" in output:
            print("✅ Found Retry in output")
            score += 0.8
        
        # Bonus for packet count
        score += (packet_count * 0.1)

        # Penalty for errors in pcap text
        if "ERROR" in output or "Malformed" in output:
            print("⚠️  Found Error/Malformed packet in pcap text")
            score -= 0.5
        
        return score

        
    except subprocess.TimeoutExpired:
        print("⚠️  tshark command timed out")
        return 0.0
    except Exception as e:
        print(f"⚠️  Error analyzing pcap: {e}")
        return 0.0


def check_quic_initial_from_server_on_path(pcap_file: str, server_ip: str = "1.1.1.1") -> float:
    """
    Check pcap file for QUIC responses from server - optimized for on-path censors.
    
    On-path censors may block server responses while allowing client packets through.
    This function compares client->server and server->client packet counts:
    - If equal: score = 5 (no packets blocked)
    - Otherwise: score = 5 - (missing server->client packets)
    
    :param pcap_file: Path to the pcap file
    :param server_ip: IP address of the server
    :return: Score based on packet balance (max 5, min 0)
    """
    if not os.path.exists(pcap_file):
        print(f"⚠️  Pcap file not found: {pcap_file}")
        return 0.0
    
    try:
        # Count client -> server packets (packets TO the server)
        client_to_server_cmd = [
            "tshark",
            "-r", pcap_file,
            "-Y", f"udp and ip.dst == {server_ip}",
            "-T", "fields",
            "-e", "frame.number"
        ]
        client_result = subprocess.run(
            client_to_server_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10
        )
        client_to_server_count = 0
        if client_result.returncode == 0:
            output_lines = client_result.stdout.decode().strip().splitlines()
            client_to_server_count = len([l for l in output_lines if l.strip()])
        
        # Count server -> client packets (packets FROM the server)
        server_to_client_cmd = [
            "tshark",
            "-r", pcap_file,
            "-Y", f"udp and ip.src == {server_ip}",
            "-T", "fields",
            "-e", "frame.number"
        ]
        server_result = subprocess.run(
            server_to_client_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10
        )
        server_to_client_count = 0
        if server_result.returncode == 0:
            output_lines = server_result.stdout.decode().strip().splitlines()
            server_to_client_count = len([l for l in output_lines if l.strip()])
        
        print(f"📤 Client -> Server packets: {client_to_server_count}")
        print(f"📥 Server -> Client packets: {server_to_client_count}")
        
        # Calculate score based on packet balance
        if client_to_server_count == 0:
            print("⚠️  No client packets sent, cannot score")
            return 0.0
        
        if client_to_server_count == server_to_client_count:
            score = 5.0
            print(f"✅ Packet counts are equal! Score: {score}")
        else:
            missing_packets = client_to_server_count - server_to_client_count
            score = max(0.0, 5.0 - missing_packets)
            print(f"⚠️  Missing {missing_packets} server->client packet(s)")
            print(f"📊 On-path score: {score:.2f}")
        
        # Additional diagnostic: check for Server Hello in server responses
        if server_to_client_count > 0:
            verbose_cmd = [
                "tshark",
                "-r", pcap_file,
                "-Y", f"udp and ip.src == {server_ip}",
                "-V"
            ]
            verbose_result = subprocess.run(
                verbose_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=30
            )
            if verbose_result.returncode == 0:
                output = verbose_result.stdout.decode()
                if "Server Hello" in output:
                    print("✅ Found Server Hello in response")
                if "Retry" in output or "RETRY" in output:
                    print("✅ Found Retry in response")
                if "Version Negotiation" in output:
                    print("✅ Found Version Negotiation in response")
        
        return score
        
    except subprocess.TimeoutExpired:
        print("⚠️  tshark command timed out")
        return 0.0
    except Exception as e:
        print(f"⚠️  Error analyzing pcap: {e}")
        return 0.0


def write_fitness_score(fitness_file: str, score: float) -> None:
    """Write fitness score to file."""
    directory = os.path.dirname(fitness_file)
    if directory:
        os.makedirs(directory, exist_ok=True)
    
    with open(fitness_file, "w", encoding="utf-8") as f:
        f.write(str(score))
    print(f"✍️  Wrote fitness score {score} to: {fitness_file}")


def parse_args():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Run quic_initial.py and pipe output to xxd and nc, while capturing packets"
    )
    parser.add_argument(
        "--quic-initial-path",
        type=str,
        default=os.getenv("QUIC_INITIAL_PATH", "/workspace/quic_initial.py"),
        help="Path to quic_initial.py script (default: %(default)s)"
    )
    parser.add_argument(
        "--packets-file",
        type=str,
        default=os.getenv("BLOCKED_PACKETS_FILE", "/workspace/packets_blocked.pcap"),
        help="Path to output pcap file (default: %(default)s)"
    )
    parser.add_argument(
        "--fitness-file",
        type=str,
        default=os.getenv("BLOCKED_FITNESS_FILE", "/workspace/fitness_blocked.txt"),
        help="Path to output fitness score file (default: %(default)s)"
    )
    parser.add_argument(
        "--server-ip",
        type=str,
        default="1.1.1.1",
        help="Server IP address (default: %(default)s)"
    )
    parser.add_argument(
        "--port",
        type=int,
        default=443,
        help="Server port (default: %(default)s)"
    )
    parser.add_argument(
        "--interface",
        type=str,
        default="eth0",
        help="Network interface for packet capture (default: %(default)s)"
    )
    parser.add_argument(
        "--censor-type",
        type=str,
        default="in-path",
        choices=["in-path", "on-path"],
        help="Type of censor: 'in-path' (drops/blocks packets) or 'on-path' (injects RST/forged packets) (default: %(default)s)"
    )
    return parser.parse_args()


def run_in_path_test(quic_initial_path: str, server_ip: str, port: int, interface: str, packets_file: str) -> None:
    """
    Run test for in-path censors (e.g., middleboxes that drop/block packets).
    
    In-path censors sit directly in the network path and can:
    - Drop packets entirely
    - Block connections
    - Modify packets in transit
    
    Test approach: Send single packet and wait for response.
    """
    tcpdump_process = None
    
    try:
        # Start packet capture with tcpdump
        packets_directory = os.path.dirname(packets_file)
        if packets_directory:
            os.makedirs(packets_directory, exist_ok=True)
        
        print("📡 Starting tcpdump packet capture...")
        print(f"   Interface: {interface}, Port: {port}, Output: {packets_file}")
        tcpdump_cmd = [
            "tcpdump",
            "-i",
            interface,
            "-w",
            packets_file,
            f"udp port {port}",
        ]
        print(f"   Command: {' '.join(tcpdump_cmd)}")
        tcpdump_process = subprocess.Popen(
            tcpdump_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        time.sleep(1)  # Give tcpdump time to start
        
        # Check if tcpdump started successfully
        if tcpdump_process.poll() is not None:
            # Process already exited - something went wrong
            _, stderr = tcpdump_process.communicate()
            print(f"⚠️  tcpdump failed to start: {stderr.decode()}", file=sys.stderr)
            tcpdump_process = None
        else:
            print("✅ tcpdump started successfully")
        
        # Run python3 quic_initial.py and pipe its stdout through xxd and nc
        quic_process = subprocess.Popen(
            ["python3", quic_initial_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=os.environ
        )
        
        # Pipe through xxd -r -p
        xxd_process = subprocess.Popen(
            ["xxd", "-r", "-p"],
            stdin=quic_process.stdout,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        
        # Close quic_process.stdout to allow it to receive a SIGPIPE if xxd exits
        quic_process.stdout.close()
        
        # Pipe through nc -u SERVER_IP PORT
        nc_process = subprocess.Popen(
            ["nc", "-u", server_ip, str(port), "-q", "0"],
            stdin=xxd_process.stdout,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        
        # Close xxd_process.stdout to allow it to receive a SIGPIPE if nc exits
        xxd_process.stdout.close()
        
        # Wait for all processes to complete
        _, quic_stderr = quic_process.communicate()
        _, xxd_stderr = xxd_process.communicate()
        _, nc_stderr = nc_process.communicate()
        
        # Give a moment for packets to be captured
        time.sleep(5)
        
        # Check for errors
        if quic_process.returncode != 0:
            print(f"Error running quic_initial.py: {quic_stderr.decode()}", file=sys.stderr)
            sys.exit(quic_process.returncode)
        
        if xxd_process.returncode != 0:
            print(f"Error running xxd: {xxd_stderr.decode()}", file=sys.stderr)
            sys.exit(xxd_process.returncode)
        
        if nc_process.returncode != 0:
            print(f"Error running nc: {nc_stderr.decode()}", file=sys.stderr)
            sys.exit(nc_process.returncode)
        
    finally:
        # Stop packet capture
        if tcpdump_process:
            print("🛑 Stopping tcpdump...")
            tcpdump_process.send_signal(signal.SIGTERM)
            try:
                tcpdump_process.wait(timeout=5)
                print("📦 Packet capture completed")
            except subprocess.TimeoutExpired:
                tcpdump_process.kill()
                tcpdump_process.wait()  # Wait for kill to complete
                print("⚠️  Forcefully stopped packet capture (tcpdump didn't respond to SIGTERM within 5s)")
            
            # Check if file was actually created
            print(f"✍️  Wrote packet capture to: {packets_file}")
            if os.path.exists(packets_file):
                file_size = os.path.getsize(packets_file)
                print(f"   File size: {file_size} bytes")
            else:
                print(f"⚠️  Warning: packets file not found at {packets_file}")
        else:
            print("⚠️  tcpdump was not running, no packet capture available")


def run_on_path_test(quic_initial_path: str, server_ip: str, port: int, interface: str, packets_file: str) -> None:
    """
    Run test for on-path censors
    
    On-path censors monitor traffic passively and let the client and server Initial packet pass through.
    But block subsequent packets. 
    """
    tcpdump_process = None
    
    try:
        # Start packet capture with tcpdump
        packets_directory = os.path.dirname(packets_file)
        if packets_directory:
            os.makedirs(packets_directory, exist_ok=True)
        
        print("📡 Starting tcpdump packet capture (on-path mode)...")
        print(f"   Interface: {interface}, Port: {port}, Output: {packets_file}")
        # Capture both UDP and ICMP for on-path censor detection
        tcpdump_cmd = [
            "tcpdump",
            "-i",
            interface,
            "-w",
            packets_file,
            f"udp port {port}",
        ]
        print(f"   Command: {' '.join(tcpdump_cmd)}")
        tcpdump_process = subprocess.Popen(
            tcpdump_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        time.sleep(1)  # Give tcpdump time to start
        
        # Check if tcpdump started successfully
        if tcpdump_process.poll() is not None:
            # Process already exited - something went wrong
            _, stderr = tcpdump_process.communicate()
            print(f"⚠️  tcpdump failed to start: {stderr.decode()}", file=sys.stderr)
            tcpdump_process = None
        else:
            print("✅ tcpdump started successfully")
        
        # For on-path censors, we may want to send multiple attempts
        # to detect injected packets vs legitimate responses
        num_attempts = 5
        attempt_delay = 1  # seconds between attempts
        
        for attempt in range(num_attempts):
            print(f"🔄 Attempt {attempt + 1}/{num_attempts}...")
            
            # Run python3 quic_initial.py and pipe its stdout through xxd and nc
            quic_process = subprocess.Popen(
                ["python3", quic_initial_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=os.environ
            )
            
            # Pipe through xxd -r -p
            xxd_process = subprocess.Popen(
                ["xxd", "-r", "-p"],
                stdin=quic_process.stdout,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            
            # Close quic_process.stdout to allow it to receive a SIGPIPE if xxd exits
            quic_process.stdout.close()
            
            # Pipe through nc -u SERVER_IP PORT
            nc_process = subprocess.Popen(
                ["nc", "-u", server_ip, str(port), "-q", "0"],
                stdin=xxd_process.stdout,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            
            # Close xxd_process.stdout to allow it to receive a SIGPIPE if nc exits
            xxd_process.stdout.close()
            
            # Wait for all processes to complete
            _, quic_stderr = quic_process.communicate()
            _, xxd_stderr = xxd_process.communicate()
            _, nc_stderr = nc_process.communicate()
            
            # Check for errors (but continue on subsequent attempts)
            if quic_process.returncode != 0:
                print(f"Error running quic_initial.py: {quic_stderr.decode()}", file=sys.stderr)
                if attempt == num_attempts - 1:
                    sys.exit(quic_process.returncode)
            
            if attempt < num_attempts - 1:
                time.sleep(attempt_delay)
        
        # Give a moment for final packets to be captured
        time.sleep(2)
        
    finally:
        # Stop packet capture
        if tcpdump_process:
            print("🛑 Stopping tcpdump...")
            tcpdump_process.send_signal(signal.SIGTERM)
            try:
                tcpdump_process.wait(timeout=5)
                print("📦 Packet capture completed (on-path mode)")
            except subprocess.TimeoutExpired:
                tcpdump_process.kill()
                tcpdump_process.wait()  # Wait for kill to complete
                print("⚠️  Forcefully stopped packet capture (tcpdump didn't respond to SIGTERM within 20s)")
            
            # Check if file was actually created
            print(f"✍️  Wrote packet capture to: {packets_file}")
            if os.path.exists(packets_file):
                file_size = os.path.getsize(packets_file)
                print(f"   File size: {file_size} bytes")
            else:
                print(f"⚠️  Warning: packets file not found at {packets_file}")
        else:
            print("⚠️  tcpdump was not running, no packet capture available")


def main():
    """Run python3 quic_initial.py and pipe stdout to xxd -r -p | nc -u SERVER_IP PORT, while capturing packets"""
    args = parse_args()
    
    packets_file = args.packets_file
    fitness_file = args.fitness_file
    quic_initial_path = args.quic_initial_path
    server_ip = args.server_ip
    port = args.port
    interface = args.interface
    censor_type = args.censor_type
    
    print(f"🎯 Running test with censor type: {censor_type}")
    
    try:
        # Run appropriate test based on censor type
        if censor_type == "in-path":
            run_in_path_test(quic_initial_path, server_ip, port, interface, packets_file)
        elif censor_type == "on-path":
            run_on_path_test(quic_initial_path, server_ip, port, interface, packets_file)
        else:
            print(f"⚠️  Unknown censor type: {censor_type}, defaulting to in-path")
            run_in_path_test(quic_initial_path, server_ip, port, interface, packets_file)
        
    except FileNotFoundError as e:
        print(f"Error: Required command not found: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    finally:
        # Analyze pcap and write fitness score
        if os.path.exists(packets_file):
            print("🔍 Analyzing captured packets for QUIC Initial from server...")
            if censor_type == "in-path":
                score = check_quic_initial_from_server(packets_file, server_ip)
                write_fitness_score(fitness_file, score)
            elif censor_type == "on-path":
                score = check_quic_initial_from_server_on_path(packets_file, server_ip)
                write_fitness_score(fitness_file, score)
            else:
                print(f"⚠️  Unknown censor type: {censor_type}, defaulting to in-path")
                score = check_quic_initial_from_server(packets_file, server_ip)
                write_fitness_score(fitness_file, score)
        else:
            print("⚠️  Pcap file not found, writing score 0")
            write_fitness_score(fitness_file, 0)


if __name__ == "__main__":
    main()
