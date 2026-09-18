#!/usr/bin/env python3
"""
Run evaluation for TCP-IP-Header-Manipulation scenario.

Usage:
    # Local Docker-based evaluation (full OpenEvolve evolution)
    python run_evaluation.py local --iterations 100
    
    # Test evaluator directly (single evaluation, no LLM)
    python run_evaluation.py test --strategy strategy.py
    
    # Remote evaluation on a specific country's VPS
    python run_evaluation.py remote --country pakistan
    
    # Remote evaluation on all configured countries
    python run_evaluation.py remote --country all
"""

import argparse
import sys
import os
import subprocess
import yaml
import shutil
from datetime import datetime

# Ensure the current directory is in sys.path
current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.insert(0, current_dir)

from run_country_eval import main as run_country_eval_main


def run_local_eval(args):
    """Run local Docker-based evaluation using OpenEvolve."""
    base_dir = os.path.dirname(os.path.abspath(__file__))
    config_path = os.path.join(base_dir, args.config)
    openevolve_script = os.path.abspath(os.path.join(base_dir, "../../openevolve/openevolve-run.py"))
    
    if not os.path.exists(openevolve_script):
        print(f"Error: OpenEvolve script not found at {openevolve_script}")
        sys.exit(1)
    
    # Parse config to get model name
    model_name = "default_model"
    try:
        with open(config_path, 'r', encoding='utf-8') as f:
            config = yaml.safe_load(f)
            
        llm_config = config.get("llm", {})
        if "models" in llm_config and isinstance(llm_config["models"], list) and len(llm_config["models"]) > 0:
            model_names = []
            for m in llm_config["models"]:
                name = m.get("name", "unknown")
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
    
    # Ensure evaluation_type is docker for local
    if "scenario_config" not in config:
        config["scenario_config"] = {}
    config["scenario_config"]["evaluation_type"] = "docker"
    
    output_config_path = os.path.join(output_dir, "config.yaml")
    with open(output_config_path, 'w', encoding='utf-8') as f:
        yaml.dump(config, f)
    
    # Copy strategy.py to output directory
    strategy_src = os.path.join(base_dir, "strategy.py")
    strategy_dst = os.path.join(output_dir, "strategy.py")
    if os.path.exists(strategy_src):
        shutil.copy2(strategy_src, strategy_dst)
        print(f"Copied strategy.py to {strategy_dst}")
    else:
        print(f"Error: {strategy_src} not found")
        sys.exit(1)
    
    cmd = [
        sys.executable,
        openevolve_script,
        strategy_dst,
        os.path.join(base_dir, "evaluator.py"),
        "--config", output_config_path,
        "--output", output_dir,
        "--iterations", str(args.iterations)
    ]
    
    env = os.environ.copy()
    env["OPENEVOLVE_CONFIG_PATH"] = output_config_path
    
    print("="*60)
    print("STARTING LOCAL DOCKER EVALUATION")
    print("="*60)
    print(f"Output directory: {output_dir}")
    print(f"Iterations: {args.iterations}")
    print(f"Command: {' '.join(cmd)}")
    print("="*60)
    
    try:
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
                bufsize=1
            )
            
            if process.stdout:
                for line in process.stdout:
                    sys.stdout.write(line)
                    sys.stdout.flush()
                    log_file.write(line)
                    log_file.flush()
            
            return_code = process.wait()
            
            if return_code != 0:
                raise subprocess.CalledProcessError(return_code, cmd)

        print("\n" + "="*60)
        print("LOCAL EVALUATION COMPLETED SUCCESSFULLY")
        print("="*60)
        print(f"Results in: {output_dir}")
        
        # Move evolution_trace.jsonl if it exists in base_dir
        trace_filename = "evolution_trace.jsonl"
        source_trace = os.path.join(base_dir, trace_filename)
        
        if os.path.exists(source_trace):
            target_trace = os.path.join(output_dir, trace_filename)
            shutil.move(source_trace, target_trace)
            print(f"Moved {trace_filename} to {output_dir}")
        

    except subprocess.CalledProcessError as e:
        print(f"\nLocal evaluation failed with error: {e}")
        sys.exit(1)


def run_test_eval(args):
    """Test the evaluator directly without OpenEvolve (single evaluation)."""
    base_dir = os.path.dirname(os.path.abspath(__file__))
    strategy_path = os.path.join(base_dir, args.strategy) if not os.path.isabs(args.strategy) else args.strategy
    
    if not os.path.exists(strategy_path):
        print(f"Error: Strategy file not found: {strategy_path}")
        sys.exit(1)
    
    print("="*60)
    print("TESTING EVALUATOR (Single Evaluation)")
    print("="*60)
    print(f"Strategy: {strategy_path}")
    print(f"Forbidden domain: {args.forbidden_domain}")
    print(f"Allowed domain: {args.allowed_domain}")
    print(f"Persist containers: {args.persist}")
    print("="*60)
    
    # Import and run the evaluator directly
    from evaluator import evaluate
    
    result = evaluate(
        program_path=strategy_path,
        persist_containers=args.persist,
        forbidden_domain=args.forbidden_domain,
        allowed_domain=args.allowed_domain,
        server_ip=args.server_ip,
    )
    
    print("\n" + "="*60)
    print("EVALUATION RESULT")
    print("="*60)
    print(f"Metrics:")
    for key, value in result.metrics.items():
        print(f"  {key}: {value}")
    
    print(f"\nArtifacts keys: {list(result.artifacts.keys())}")
    
    if "test_output" in result.artifacts:
        print("\n--- Test Output ---")
        output = result.artifacts["test_output"]
        print(output[:3000] if len(output) > 3000 else output)
    
    if "engine_logs" in result.artifacts and result.artifacts["engine_logs"]:
        print("\n--- Engine Logs (last 1500 chars) ---")
        print(result.artifacts["engine_logs"][-1500:])
    
    if "error" in result.artifacts:
        print(f"\n--- Error ---")
        print(result.artifacts["error"])
    
    print("="*60)
    
    return result


def run_remote_eval(args):
    """Run remote evaluation on VPS(es) defined in remote_vpses.yaml."""
    # Delegate to run_country_eval
    remote_args = []
    if args.country != "all":
        remote_args.extend(["--country", args.country])
    remote_args.extend(["--iterations", str(args.iterations)])
    
    print("="*60)
    print("STARTING REMOTE EVALUATION")
    print("="*60)
    print(f"Country: {args.country}")
    print(f"Iterations: {args.iterations}")
    print("="*60)
    
    run_country_eval_main(remote_args)


def main():
    parser = argparse.ArgumentParser(
        description="Run evaluation for TCP-IP-Header-Manipulation scenario",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Run full OpenEvolve evolution locally using Docker containers
  python run_evaluation.py local --iterations 100
  
  # Quick test of evaluator with the base strategy (no LLM needed)
  python run_evaluation.py test --strategy strategy.py
  
  # Test with containers persisted for debugging
  python run_evaluation.py test --strategy strategy.py --persist
  
  # Run on a specific country's VPS (configure in remote_vpses.yaml)
  python run_evaluation.py remote --country pakistan
  
  # Run on all configured countries
  python run_evaluation.py remote --country all
"""
    )
    subparsers = parser.add_subparsers(dest="mode", required=True, help="Evaluation mode")

    # -------------------------
    # Local mode (Docker + OpenEvolve)
    # -------------------------
    local_parser = subparsers.add_parser(
        "local", 
        help="Run local Docker-based OpenEvolve evolution"
    )
    local_parser.add_argument(
        "--config", 
        default="config.yaml", 
        help="Path to config file (default: config.yaml)"
    )
    local_parser.add_argument(
        "--output", 
        default="local_evaluation", 
        help="Base output directory (default: local_evaluation)"
    )
    local_parser.add_argument(
        "--iterations", 
        type=int, 
        default=100, 
        help="Number of iterations (default: 100)"
    )

    # -------------------------
    # Test mode (single evaluation)
    # -------------------------
    test_parser = subparsers.add_parser(
        "test", 
        help="Test evaluator directly (single run, no LLM)"
    )
    test_parser.add_argument(
        "--strategy", 
        default="strategy.py", 
        help="Path to strategy file (default: strategy.py)"
    )
    test_parser.add_argument(
        "--persist", 
        action="store_true", 
        help="Keep containers running after test for debugging"
    )
    test_parser.add_argument(
        "--forbidden-domain", 
        default="blocked.com", 
        help="Domain to test evasion against (default: blocked.com)"
    )
    test_parser.add_argument(
        "--allowed-domain", 
        default="example.com", 
        help="Domain that should remain accessible (default: example.com)"
    )
    test_parser.add_argument(
        "--server-ip", 
        default="", 
        help="Target server IP (optional, uses DNS if not set)"
    )

    # -------------------------
    # Remote mode (VPS evaluation)
    # -------------------------
    remote_parser = subparsers.add_parser(
        "remote", 
        help="Run remote VPS-based OpenEvolve evolution"
    )
    remote_parser.add_argument(
        "--country", "-c",
        default="all", 
        help="Country to evaluate (from remote_vpses.yaml) or 'all' (default: all)"
    )
    remote_parser.add_argument(
        "--iterations",
        type=int,
        default=150,
        help="Number of iterations per country (default: 150)"
    )

    args = parser.parse_args()

    if args.mode == "local":
        run_local_eval(args)
    elif args.mode == "test":
        run_test_eval(args)
    elif args.mode == "remote":
        run_remote_eval(args)


if __name__ == "__main__":
    main()
