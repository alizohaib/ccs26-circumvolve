#!/usr/bin/env python3
"""
Run HTTP censorship evasion evaluation.

Supports two modes:
  - local: Run dockerized evaluation locally (with OpenGFW middlebox)
  - remote: Run evaluation on remote VPSes in censored countries

Usage:
    python run_evaluation.py local --iterations 100
    python run_evaluation.py remote --country china
    python run_evaluation.py remote --country all
"""

import argparse
import sys
import os
import subprocess
import signal
import yaml
import shutil
from datetime import datetime

# Ensure the current directory is in sys.path for imports
current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.insert(0, current_dir)

from run_country_eval import main as run_remote_eval


def run_local_eval(args):
    base_dir = os.path.dirname(os.path.abspath(__file__))
    config_path = os.path.join(base_dir, args.config)
    openevolve_script = os.path.abspath(os.path.join(base_dir, "../../openevolve/openevolve-run.py"))
    
    # Parse config to get model name
    model_name = "default_model"
    try:
        with open(config_path, 'r', encoding='utf-8') as f:
            config = yaml.safe_load(f)
            
        llm_config = config.get("llm", {})
        if "models" in llm_config and isinstance(llm_config["models"], list) and len(llm_config["models"]) > 0:
            # Extract all model names and join them
            model_names = []
            for m in llm_config["models"]:
                name = m.get("name", "unknown")
                # Sanitize model name
                name = str(name).replace("/", "_").replace("\\", "_")
                model_names.append(name)
            model_name = "_".join(model_names)
    except Exception as e:
        print(f"Warning: Could not parse config for model name: {e}")

    # Construct output directory: local_evaluation/{model_name}/{timestamp}
    current_date = datetime.now().strftime("%Y-%m-%d_%H-%M")
    output_dir = os.path.join(base_dir, args.output, model_name, current_date)
    os.makedirs(output_dir, exist_ok=True)
    
    # Update Log Directory in config and save to output directory
    log_dir = os.path.join(output_dir, "logs/")
    config["log_dir"] = log_dir
    
    # Add persist_containers flag to scenario_config if specified
    if args.persist_containers:
        if "scenario_config" not in config:
            config["scenario_config"] = {}
        config["scenario_config"]["persist_containers"] = True
    
    output_config_path = os.path.join(output_dir, "config.yaml")
    with open(output_config_path, 'w', encoding='utf-8') as f:
        yaml.dump(config, f)
    
    # Copy http_initial.py to output directory
    http_initial_src = os.path.join(base_dir, "http_initial.py")
    http_initial_dst = os.path.join(output_dir, "http_initial.py")
    if os.path.exists(http_initial_src):
        shutil.copy2(http_initial_src, http_initial_dst)
        print(f"Copied http_initial.py to {http_initial_dst}")

        # If forbidden_domain is defined in the config, replace default domain in the copied file
        forbidden_domain = config.get("scenario_config", {}).get("forbidden_domain")
        if forbidden_domain:
            try:
                with open(http_initial_dst, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                # Replace the default domain placeholder
                default_domain = "blocked.com"
                if default_domain in content:
                    new_content = content.replace(default_domain, forbidden_domain)
                    with open(http_initial_dst, 'w', encoding='utf-8') as f:
                        f.write(new_content)
                    print(f"Replaced '{default_domain}' with '{forbidden_domain}' in {http_initial_dst}")
            except Exception as e:
                print(f"Warning: Failed to replace domain in {http_initial_dst}: {e}")
    else:
        print(f"Warning: {http_initial_src} not found, could not copy.")
    
    cmd = [
        sys.executable,
        openevolve_script,
        http_initial_dst,
        os.path.join(base_dir, "evaluator.py"),
        "--config", output_config_path,
        "--output", output_dir,
        "--iterations", str(args.iterations)
    ]
    
    env = os.environ.copy()
    env["OPENEVOLVE_CONFIG_PATH"] = output_config_path
    
    print("Starting local evaluation...")
    print(f"Output directory: {output_dir}")
    print(f"Command: {' '.join(cmd)}")
    
    try:
        # Redirect stdout/stderr to a file in output_dir
        log_file_path = os.path.join(output_dir, "execution.log")
        print(f"Logging to {log_file_path}")
        
        with open(log_file_path, "w", encoding='utf-8') as log_file:
            process = subprocess.Popen(
                cmd,
                cwd=base_dir,
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                # Start process in its own process group so we can signal it properly
                start_new_session=False
            )
            
            # Set up signal handlers to forward signals to child process
            def signal_handler(signum, frame):
                print(f"\nReceived signal {signum}, forwarding to child process...")
                if process.poll() is None:  # Process is still running
                    process.send_signal(signum)
            
            original_sigint = signal.signal(signal.SIGINT, signal_handler)
            original_sigterm = signal.signal(signal.SIGTERM, signal_handler)
            
            try:
                if process.stdout:
                    for line in process.stdout:
                        sys.stdout.write(line)
                        sys.stdout.flush()
                        log_file.write(line)
                        log_file.flush()
                
                return_code = process.wait()
            finally:
                # Restore original signal handlers
                signal.signal(signal.SIGINT, original_sigint)
                signal.signal(signal.SIGTERM, original_sigterm)
            
            if return_code != 0 and return_code != -2:  # -2 is SIGINT
                raise subprocess.CalledProcessError(return_code, cmd)

        print("Local evaluation completed successfully.")
        
        # Move evolution_trace.jsonl if it exists in base_dir
        trace_filename = "evolution_trace.jsonl"
        source_trace = os.path.join(base_dir, trace_filename)
        
        if os.path.exists(source_trace):
            target_trace = os.path.join(output_dir, trace_filename)
            shutil.move(source_trace, target_trace)
            print(f"Moved {trace_filename} to {output_dir}")
        

    except KeyboardInterrupt:
        print("\nInterrupted by user. Waiting for graceful shutdown...")
        if 'process' in locals() and process.poll() is None:
            process.send_signal(signal.SIGINT)
            try:
                process.wait(timeout=30)  # Wait up to 30 seconds for graceful shutdown
            except subprocess.TimeoutExpired:
                print("Graceful shutdown timed out. Force killing...")
                process.kill()
                process.wait()
        print("Evaluation stopped.")
        sys.exit(0)
    except subprocess.CalledProcessError as e:
        print(f"Local evaluation failed with error: {e}")
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description="Run evaluation for HTTP-Blocking scenario",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    # Run local dockerized evaluation
    python run_evaluation.py local --iterations 100
    
    # Run local evaluation with persistent containers (for debugging)
    python run_evaluation.py local --iterations 10 --persist-containers
    
    # Run remote evaluation for all countries
    python run_evaluation.py remote --country all
    
    # Run remote evaluation for specific country
    python run_evaluation.py remote --country china --iterations 200
"""
    )
    subparsers = parser.add_subparsers(dest="mode", required=True, help="Evaluation mode")

    # Local mode arguments
    local_parser = subparsers.add_parser("local", help="Run local dockerized evaluation")
    local_parser.add_argument("--config", default="config.yaml", help="Path to config file")
    local_parser.add_argument("--output", default="local_evaluation", help="Base output directory")
    local_parser.add_argument("--iterations", type=int, default=100, help="Number of iterations")
    local_parser.add_argument(
        "--persist-containers",
        action="store_true",
        default=False,
        help="Keep Docker containers running after each evaluation (useful for debugging)"
    )

    # Remote mode arguments
    remote_parser = subparsers.add_parser("remote", help="Run remote country evaluation")
    remote_parser.add_argument(
        "--country", "-c",
        default="all",
        help="Specific country to evaluate (or 'all')"
    )
    remote_parser.add_argument(
        "--iterations", "-i",
        type=int,
        default=150,
        help="Number of iterations (default: 150)"
    )
    remote_parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print what would be run without executing"
    )

    args = parser.parse_args()

    if args.mode == "local":
        run_local_eval(args)
    elif args.mode == "remote":
        # Build arguments for run_country_eval
        remote_args = ["--country", args.country, "--iterations", str(args.iterations)]
        if args.dry_run:
            remote_args.append("--dry-run")
        run_remote_eval(remote_args)


if __name__ == "__main__":
    main()
