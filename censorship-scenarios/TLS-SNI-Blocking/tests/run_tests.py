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

def check_tls_initial_from_server(pcap_file: str, server_ip: str = "1.1.1.1") -> float:
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
            "-Y", f"tcp and ip.src == {server_ip}",
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
            "-Y", f"tcp and ip.src == {server_ip}",
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
            print("📭 No TCP packets from server found")
            return 0.0
        
        score = 0.0

        # Search for "Server Hello" in the text output
        if "Server Hello" in output:
            print("✅ Found Server Hello from server!")
            score += 1.0
        elif "ERROR" in output or "Malformed" in output: # Penalty for errors in pcap text only if not accepted by server
            print("⚠️  Found Error/Malformed packet in pcap text")
            score -= 0.5

        if "Alert" in output:
            print("Found Alert from server!")
            score -= 0.4

        if "Retry" in output or "RETRY" in output:
            print("✅ Found Retry in output")
            score -= 0.2

        if "Reset: Set" in output:
            rst_count = output.count("Reset: Set")
            print("Found", rst_count, "RST(s) from the server!")
            score -= rst_count * 0.1

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
        description="Run tls_initial.py and pipe output to xxd and nc, while capturing packets"
    )
    parser.add_argument(
        "--tls-initial-path",
        type=str,
        default=os.getenv("TLS_INITIAL_PATH", "/workspace/tls_initial.py"),
        help="Path to tls_initial.py script (default: %(default)s)"
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
    return parser.parse_args()


def main():
    """Run python3 tls_initial.py and pipe stdout to xxd -r -p | nc -c SERVER_IP PORT, while capturing packets"""
    args = parse_args()
    
    packets_file = args.packets_file
    fitness_file = args.fitness_file
    tls_initial_path = args.tls_initial_path
    server_ip = args.server_ip
    port = args.port
    interface = args.interface
    tcpdump_process = None
    
    try:
        # Start packet capture with tcpdump
        packets_directory = os.path.dirname(packets_file)
        if packets_directory:
            os.makedirs(packets_directory, exist_ok=True)
        
        print("📡 Starting tcpdump packet capture...")
        tcpdump_cmd = [
            "tcpdump",
            "-i",
            interface,
            "-w",
            packets_file,
            f"tcp port {port}",
        ]
        tcpdump_process = subprocess.Popen(
            tcpdump_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        time.sleep(1)  # Give tcpdump time to start
        
        # Run python3 quic_initial.py and pipe its stdout through xxd and nc
        tls_process = subprocess.Popen(
            ["python3", tls_initial_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=os.environ
        )
        
        # Pipe through xxd -r -p
        xxd_process = subprocess.Popen(
            ["xxd", "-r", "-p"],
            stdin=tls_process.stdout,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        
        # Close quic_process.stdout to allow it to receive a SIGPIPE if xxd exits
        tls_process.stdout.close()
        
        # Pipe through nc SERVER_IP PORT
        nc_process = subprocess.Popen(
            ["nc", server_ip, str(port), "-q", "0"],
            stdin=xxd_process.stdout,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        
        # Close xxd_process.stdout to allow it to receive a SIGPIPE if nc exits
        xxd_process.stdout.close()
        
        # Wait for all processes to complete
        _, tls_stderr = tls_process.communicate()
        _, xxd_stderr = xxd_process.communicate()
        _, nc_stderr = nc_process.communicate()
        
        # Give a moment for packets to be captured
        time.sleep(5)
        
        # Check for errors
        if tls_process.returncode != 0:
            print(f"Error running tls_initial.py: {tls_stderr.decode()}", file=sys.stderr)
            sys.exit(tls_process.returncode)
        
        if xxd_process.returncode != 0:
            print(f"Error running xxd: {xxd_stderr.decode()}", file=sys.stderr)
            sys.exit(xxd_process.returncode)
        
        if nc_process.returncode != 0:
            print(f"Error running nc: {nc_stderr.decode()}", file=sys.stderr)
            sys.exit(nc_process.returncode)
        
    except FileNotFoundError as e:
        print(f"Error: Required command not found: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    finally:
        # Stop packet capture
        if tcpdump_process:
            tcpdump_process.send_signal(signal.SIGTERM)
            try:
                tcpdump_process.wait(timeout=5)
                print("📦 Packet capture completed")
                print(f"✍️  Wrote packet capture to: {packets_file}")
            except subprocess.TimeoutExpired:
                tcpdump_process.kill()
                print("⚠️  Forcefully stopped packet capture")
            
            # Analyze pcap and write fitness score
            if os.path.exists(packets_file):
                print("🔍 Analyzing captured packets for TLS Initial from server...")
                score = check_tls_initial_from_server(packets_file, server_ip)
                write_fitness_score(fitness_file, score)
            else:
                print("⚠️  Pcap file not found, writing score 0")
                write_fitness_score(fitness_file, 0)


if __name__ == "__main__":
    main()
