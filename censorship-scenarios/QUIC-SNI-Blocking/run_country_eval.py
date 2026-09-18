#!/usr/bin/env python3
import os
import yaml
import subprocess
import sys
import shutil
import argparse
from datetime import datetime

def main(input_args=None):
    parser = argparse.ArgumentParser(description="Run country-wise evaluation")
    parser.add_argument("--country", "-c", help="Specific country to evaluate (or 'all')", default="all")
    parser.add_argument("--iterations", "-i", type=int, help="Number of iterations to run", default=150)
    args = parser.parse_args(input_args)

    # Paths
    base_dir = os.path.dirname(os.path.abspath(__file__))
    vps_file = os.path.join(base_dir, "remote_vpses.yaml")
    config_template = os.path.join(base_dir, "config.yaml")
    outputs_dir = os.path.join(base_dir, "remote_evaluation")

    # Check files
    if not os.path.exists(vps_file):
        print(f"Error: {vps_file} not found.")
        sys.exit(1)
    if not os.path.exists(config_template):
        print(f"Error: {config_template} not found.")
        sys.exit(1)

    # Load VPS configs
    try:
        with open(vps_file, 'r', encoding='utf-8') as f:
            countries = yaml.safe_load(f)
    except Exception as e:
        print(f"Error loading {vps_file}: {e}")
        sys.exit(1)

    if not countries:
        print("No countries found in remote_vpses.yaml")
        sys.exit(0)

    # Load Config Template
    try:
        with open(config_template, 'r', encoding='utf-8') as f:
            base_config = yaml.safe_load(f)
    except Exception as e:
        print(f"Error loading {config_template}: {e}")
        sys.exit(1)

    # Extract model name for directory structure
    model_name = "default_model"
    try:
        llm_config = base_config.get("llm", {})
        if "models" in llm_config and isinstance(llm_config["models"], list) and len(llm_config["models"]) > 0:
            # Extract all model names and join them
            model_names = []
            for m in llm_config["models"]:
                name = m.get("name", "unknown")
                # Sanitize model name
                name = str(name).replace("/", "_").replace("\\", "_")
                model_names.append(name)
            model_name = "_".join(model_names)
    except Exception:
        pass

    # Ensure output directory exists
    os.makedirs(outputs_dir, exist_ok=True)

    for entry in countries:
        country = entry.get("country")
        if not country:
            print("Skipping entry without country name")
            continue

        if args.country.lower() != "all" and args.country.lower() != country.lower():
            continue

        print(f"Processing country: {country} (Model: {model_name})")
        
        # Create country specific output dir
        current_date = datetime.now().strftime("%Y-%m-%d_%H-%M")
        country_dir = os.path.join(outputs_dir, model_name, country, current_date)
        os.makedirs(country_dir, exist_ok=True)
        
        # Prepare country config
        country_config = base_config.copy()
        
        # Ensure scenario_config exists
        if "scenario_config" not in country_config:
            country_config["scenario_config"] = {}
        
        country_config["scenario_config"]["evaluation_type"] = "remote"
        
        # Construct remote config from entry
        remote_settings = {
            "host": entry.get("host"),
            "user": entry.get("user"),
            "key_path": entry.get("key_path"),
            "password": entry.get("password"),
            "persist": entry.get("persist", False)
        }
        
        if "server_ip" in entry:
            remote_settings["server_ip"] = entry["server_ip"]
            
        country_config["scenario_config"]["remote"] = remote_settings
        
        # Add domain configuration if present
        if "forbidden_domain" in entry:
            country_config["scenario_config"]["forbidden_domain"] = entry["forbidden_domain"]
        if "allowed_domain" in entry:
            country_config["scenario_config"]["allowed_domain"] = entry["allowed_domain"]
        
        # Add censor type configuration (in-path or on-path)
        if "censor_type" in entry:
            country_config["scenario_config"]["censor_type"] = entry["censor_type"]

        # Add server port range for unique port selection (useful for on-path censors)
        if "server_port_range" in entry:
            country_config["scenario_config"]["server_port_range"] = entry["server_port_range"]

        # Update Log Directory
        log_dir = os.path.join(country_dir, "logs/")
        country_config["log_dir"] = log_dir
        
        # Write country config
        country_config_path = os.path.join(country_dir, "config.yaml")
        with open(country_config_path, 'w', encoding='utf-8') as f:
            yaml.dump(country_config, f)
        
        print(f"  Config written to {country_config_path}")
        
        # Copy quic_initial.py to output directory
        quic_initial_src = os.path.join(base_dir, "quic_initial.py")
        quic_initial_dst = os.path.join(country_dir, "quic_initial.py")
        if os.path.exists(quic_initial_src):
            shutil.copy2(quic_initial_src, quic_initial_dst)
            print(f"  Copied quic_initial.py to {quic_initial_dst}")

            # If forbidden_domain is defined in the config, replace 'blocked.com' in the copied file
            forbidden_domain = country_config.get("scenario_config", {}).get("forbidden_domain")
            if forbidden_domain:
                try:
                    with open(quic_initial_dst, 'r', encoding='utf-8') as f:
                        content = f.read()
                    
                    if 'blocked.com' in content:
                        new_content = content.replace('blocked.com', forbidden_domain)
                        with open(quic_initial_dst, 'w', encoding='utf-8') as f:
                            f.write(new_content)
                        print(f"  Replaced 'blocked.com' with '{forbidden_domain}' in {quic_initial_dst}")
                except Exception as e:
                     print(f"  Warning: Failed to replace domain in {quic_initial_dst}: {e}")
        else:
            print(f"  Warning: {quic_initial_src} not found, could not copy.")
        
        # Run OpenEvolve
        print(f"  Starting evaluation for {country}...")
        
        # We run openevolve-run with the config file
        # python3 ../../openevolve/openevolve-run.py ./quic_initial.py evaluator.py --config config.yaml --iterations 100
        openevolve_script = os.path.abspath(os.path.join(base_dir, "../../openevolve/openevolve-run.py"))
        
        cmd = [
            sys.executable, 
            openevolve_script, 
            quic_initial_dst, 
            "evaluator.py", 
            "--config", country_config_path, 
            "--iterations", str(args.iterations),
            "--output", country_dir,
        ]
        
        env = os.environ.copy()
        # Still setting env var just in case, though command line arg should take precedence if supported
        env["OPENEVOLVE_CONFIG_PATH"] = country_config_path
        
        try:
            # Redirect stdout/stderr to a file in country_dir
            log_file_path = os.path.join(country_dir, "execution.log")
            print(f"  Logging to {log_file_path}")
            
            with open(log_file_path, "w", encoding='utf-8') as log_file:
                # Run in base_dir so openevolve-run finds local files like evaluator.py
                # Use Popen to stream output to both console and file
                process = subprocess.Popen(
                    cmd, 
                    cwd=base_dir, 
                    env=env, 
                    stdout=subprocess.PIPE, 
                    stderr=subprocess.STDOUT,
                    text=True,
                    bufsize=1
                )
                
                # Read output line by line
                if process.stdout:
                    for line in process.stdout:
                        sys.stdout.write(line)
                        sys.stdout.flush()
                        log_file.write(line)
                        log_file.flush()
                
                return_code = process.wait()
                
                if return_code != 0:
                    raise subprocess.CalledProcessError(return_code, cmd)
            
            print(f"  Evaluation completed for {country}. Logs in {log_file_path}")
            
            # Move evolution_trace.jsonl if it exists in base_dir
            trace_filename = "evolution_trace.jsonl"
            source_trace = os.path.join(base_dir, trace_filename)
            
            if os.path.exists(source_trace):
                target_trace = os.path.join(country_dir, trace_filename)
                shutil.move(source_trace, target_trace)
                print(f"  Moved {trace_filename} to {country_dir}")

        except subprocess.CalledProcessError as e:
            print(f"  Error running evaluation for {country}. Check execution.log for details.")
            # Continue to next country
            
        except Exception as e:
            print(f"  Unexpected error for {country}: {e}")

if __name__ == "__main__":
    main()

