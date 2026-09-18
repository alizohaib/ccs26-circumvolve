#!/usr/bin/env python3
import argparse
import sys
import os
import subprocess
import yaml
import shutil
from datetime import datetime

# Ensure the current directory is in sys.path so we can import run_country_eval
# regardless of where the script is called from
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
    
    output_config_path = os.path.join(output_dir, "config.yaml")
    with open(output_config_path, 'w', encoding='utf-8') as f:
        yaml.dump(config, f)
    
    seed_programs = []
    if config.get("seed_programs_paths") is not None:
        seed_program_dir = os.path.join(output_dir, "seed_programs")
        os.makedirs(seed_program_dir, exist_ok=True)
        for program in config["seed_programs_paths"]:
            tls_initial_src = os.path.join(base_dir, program)
            tls_initial_dst = os.path.join(seed_program_dir, os.path.basename(program))    
            if os.path.exists(tls_initial_src):
                shutil.copy2(tls_initial_src, tls_initial_dst)
                seed_programs.append(tls_initial_dst)
                print(f"Copied {program} to {tls_initial_dst}")
                forbidden_domain = config.get("scenario_config", {}).get("forbidden_domain")
                if forbidden_domain:
                    try:
                        with open(tls_initial_dst, 'r', encoding='utf-8') as f:
                            content = f.read()
                        
                        if 'blocked.com' in content:
                            new_content = content.replace('blocked.com', forbidden_domain)
                            with open(tls_initial_dst, 'w', encoding='utf-8') as f:
                                f.write(new_content)
                            print(f"Replaced 'blocked.com' with '{forbidden_domain}' in {tls_initial_dst}")
                    except Exception as e:
                        print(f"Warning: Failed to replace domain in {tls_initial_dst}: {e}")
            else:
                print(f"Warning: {tls_initial_src} not found, could not copy.")
    else:
        # Copy tls_initial.py to output directory
        tls_initial_src = os.path.join(base_dir, "tls_initial.py")
        tls_initial_dst = os.path.join(output_dir, "tls_initial.py")
        if os.path.exists(tls_initial_src):
            shutil.copy2(tls_initial_src, tls_initial_dst)
            print(f"Copied tls_initial.py to {tls_initial_dst}")

            # If forbidden_domain is defined in the config, replace 'blocked.com' in the copied file
            forbidden_domain = config.get("scenario_config", {}).get("forbidden_domain")
            if forbidden_domain:
                try:
                    with open(tls_initial_dst, 'r', encoding='utf-8') as f:
                        content = f.read()
                    
                    if 'blocked.com' in content:
                        new_content = content.replace('blocked.com', forbidden_domain)
                        with open(tls_initial_dst, 'w', encoding='utf-8') as f:
                            f.write(new_content)
                        print(f"Replaced 'blocked.com' with '{forbidden_domain}' in {tls_initial_dst}")
                except Exception as e:
                    print(f"Warning: Failed to replace domain in {tls_initial_dst}: {e}")
        else:
            print(f"Warning: {tls_initial_src} not found, could not copy.")
    
    cmd = [
        sys.executable,
        openevolve_script,
        tls_initial_dst,
        os.path.join(base_dir, "evaluator.py"),
        "--config", output_config_path,
        "--output", output_dir,
        "--iterations", str(args.iterations)
    ]

    if len(seed_programs) != 0:
        # seed_program_paths = config["seed_programs_paths"]  # should be a list of strings
        cmd.append("--seed-programs")
        cmd.extend(seed_programs)
    # print(cmd)
    # exit()
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

        print("Local evaluation completed successfully.")
        
        # Move evolution_trace.jsonl if it exists in base_dir
        trace_filename = "evolution_trace.jsonl"
        source_trace = os.path.join(base_dir, trace_filename)
        
        if os.path.exists(source_trace):
            target_trace = os.path.join(output_dir, trace_filename)
            shutil.move(source_trace, target_trace)
            print(f"Moved {trace_filename} to {output_dir}")

    except subprocess.CalledProcessError as e:
        print(f"Local evaluation failed with error: {e}")
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(description="Run evaluation for TLS-SNI-Blocking scenario")
    subparsers = parser.add_subparsers(dest="mode", required=True, help="Evaluation mode")

    # Local mode arguments
    local_parser = subparsers.add_parser("local", help="Run local dockerized evaluation")
    local_parser.add_argument("--config", default="config.yaml", help="Path to config file")
    local_parser.add_argument("--output", default="local_evaluation", help="Base output directory")
    local_parser.add_argument("--iterations", type=int, default=100, help="Number of iterations")

    # Remote mode arguments
    remote_parser = subparsers.add_parser("remote", help="Run remote country evaluation")
    remote_parser.add_argument("--country", "-c", default="all", help="Specific country to evaluate (or 'all')")

    args = parser.parse_args()

    if args.mode == "local":
        run_local_eval(args)
    elif args.mode == "remote":
        # Pass arguments to the remote evaluation script
        remote_args = []
        if args.country != "all":
            remote_args.extend(["--country", args.country])
        run_remote_eval(remote_args)

if __name__ == "__main__":
    main()
