#!/usr/bin/env python3
"""
Run HTTP censorship evasion evaluation across multiple countries.

Reads VPS configurations from remote_vpses.yaml and runs OpenEvolve
evaluations for each country with appropriate censor type settings.

Usage:
    python run_country_eval.py                    # Run all countries
    python run_country_eval.py --country china    # Run specific country
    python run_country_eval.py --country pakistan --iterations 200
"""

import os
import yaml
import subprocess
import sys
import shutil
import argparse
from datetime import datetime


def main(input_args=None):
    parser = argparse.ArgumentParser(
        description="Run country-wise HTTP censorship evasion evaluation",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    python run_country_eval.py                        # All countries
    python run_country_eval.py --country china        # Specific country
    python run_country_eval.py --country all --iterations 200
"""
    )
    parser.add_argument(
        "--country", "-c",
        help="Specific country to evaluate (or 'all')",
        default="all"
    )
    parser.add_argument(
        "--iterations", "-i",
        type=int,
        default=150,
        help="Number of evolution iterations (default: 150)"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print what would be run without executing"
    )
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
            model_names = []
            for m in llm_config["models"]:
                name = m.get("name", "unknown")
                name = str(name).replace("/", "_").replace("\\", "_")
                model_names.append(name)
            model_name = "_".join(model_names)
    except Exception:
        pass

    # Ensure output directory exists
    os.makedirs(outputs_dir, exist_ok=True)

    # Track results
    results = []

    for entry in countries:
        country = entry.get("country")
        if not country:
            print("Skipping entry without country name")
            continue

        # Skip placeholder entries
        if "YOUR_" in str(entry.get("host", "")):
            print(f"Skipping {country}: placeholder configuration (update remote_vpses.yaml)")
            continue

        if args.country.lower() != "all" and args.country.lower() != country.lower():
            continue

        censor_type = entry.get("censor_type", "on-path-resetter")
        
        print("=" * 70)
        print(f"COUNTRY: {country}")
        print(f"  Model: {model_name}")
        print(f"  Censor Type: {censor_type}")
        print(f"  Host: {entry.get('host')}")
        print(f"  Forbidden Domain: {entry.get('forbidden_domain', 'cloudflare.com')}")
        print("=" * 70)
        
        # Create country specific output dir
        current_date = datetime.now().strftime("%Y-%m-%d_%H-%M")
        country_dir = os.path.join(outputs_dir, model_name, country, current_date)
        
        if args.dry_run:
            print(f"  [DRY RUN] Would create: {country_dir}")
            continue
            
        os.makedirs(country_dir, exist_ok=True)
        
        # Prepare country config
        country_config = base_config.copy()
        
        # Ensure scenario_config exists
        if "scenario_config" not in country_config:
            country_config["scenario_config"] = {}
        
        country_config["scenario_config"]["evaluation_type"] = "remote"
        
        # Set censor type from VPS config
        country_config["scenario_config"]["censor_type"] = censor_type
        
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
        if "interface" in entry:
            remote_settings["interface"] = entry["interface"]
        if "server_ports" in entry:
            remote_settings["server_ports"] = entry["server_ports"]
            
        country_config["scenario_config"]["remote"] = remote_settings
        
        # Add domain configuration if present
        if "forbidden_domain" in entry:
            country_config["scenario_config"]["forbidden_domain"] = entry["forbidden_domain"]
        if "allowed_domain" in entry:
            country_config["scenario_config"]["allowed_domain"] = entry["allowed_domain"]
        if "server_ports" in entry:
            country_config["scenario_config"]["server_ports"] = entry["server_ports"]

        # Update Log Directory
        log_dir = os.path.join(country_dir, "logs/")
        country_config["log_dir"] = log_dir
        
        # Handle seed programs for islands if specified
        if "seed_programs_paths" in entry:
            seed_paths = entry["seed_programs_paths"]
            if seed_paths and isinstance(seed_paths, list):
                # Create seed_programs directory in country output
                seed_programs_dir = os.path.join(country_dir, "seed_programs")
                os.makedirs(seed_programs_dir, exist_ok=True)
                
                # Get forbidden domain for replacement
                forbidden_domain = country_config.get("scenario_config", {}).get("forbidden_domain")
                
                # Copy and process each seed program
                resolved_paths = []
                for seed_path in seed_paths:
                    if not os.path.isabs(seed_path):
                        src_path = os.path.join(base_dir, seed_path)
                    else:
                        src_path = seed_path
                    
                    if os.path.exists(src_path):
                        # Copy to output directory
                        dst_path = os.path.join(seed_programs_dir, os.path.basename(src_path))
                        shutil.copy2(src_path, dst_path)
                        
                        # Replace 'blocked.com' with forbidden_domain if specified
                        if forbidden_domain:
                            try:
                                with open(dst_path, 'r', encoding='utf-8') as f:
                                    content = f.read()
                                if 'blocked.com' in content:
                                    new_content = content.replace('blocked.com', forbidden_domain)
                                    with open(dst_path, 'w', encoding='utf-8') as f:
                                        f.write(new_content)
                            except Exception as e:
                                print(f"  Warning: Failed to replace domain in {dst_path}: {e}")
                        
                        resolved_paths.append(dst_path)
                    else:
                        print(f"  Warning: Seed program not found: {seed_path}")
                
                if resolved_paths:
                    # Ensure database config exists
                    if "database" not in country_config:
                        country_config["database"] = {}
                    country_config["database"]["seed_programs_paths"] = resolved_paths
                    print(f"  Using {len(resolved_paths)} seed program(s) for islands:")
                    for i, p in enumerate(resolved_paths):
                        domain_note = f" (domain: {forbidden_domain})" if forbidden_domain else ""
                        print(f"    Island {i}: {os.path.basename(p)}{domain_note}")
        
        # Write country config
        country_config_path = os.path.join(country_dir, "config.yaml")
        with open(country_config_path, 'w', encoding='utf-8') as f:
            yaml.dump(country_config, f)
        
        print(f"  Config written to {country_config_path}")
        
        # Copy http_initial.py to output directory
        http_initial_src = os.path.join(base_dir, "http_initial.py")
        http_initial_dst = os.path.join(country_dir, "http_initial.py")
        if os.path.exists(http_initial_src):
            shutil.copy2(http_initial_src, http_initial_dst)
            print(f"  Copied http_initial.py to {http_initial_dst}")

            # Replace 'blocked.com' with the forbidden_domain
            forbidden_domain = country_config.get("scenario_config", {}).get("forbidden_domain")
            if forbidden_domain:
                try:
                    with open(http_initial_dst, 'r', encoding='utf-8') as f:
                        content = f.read()
                    
                    if 'blocked.com' in content:
                        new_content = content.replace('blocked.com', forbidden_domain)
                        with open(http_initial_dst, 'w', encoding='utf-8') as f:
                            f.write(new_content)
                        print(f"  Replaced 'blocked.com' with '{forbidden_domain}' in {http_initial_dst}")
                except Exception as e:
                    print(f"  Warning: Failed to replace domain in {http_initial_dst}: {e}")
        else:
            print(f"  Warning: {http_initial_src} not found, could not copy.")
            continue
        
        # Run OpenEvolve
        print(f"  Starting evaluation for {country}...")
        
        openevolve_script = os.path.abspath(os.path.join(base_dir, "../../openevolve/openevolve-run.py"))
        
        cmd = [
            sys.executable, 
            openevolve_script, 
            http_initial_dst, 
            "evaluator.py", 
            "--config", country_config_path, 
            "--iterations", str(args.iterations),
            "--output", country_dir,
        ]
        
        env = os.environ.copy()
        env["OPENEVOLVE_CONFIG_PATH"] = country_config_path
        # Pass censor type to evaluator
        env["CENSOR_TYPE"] = censor_type
        if "forbidden_domain" in entry:
            env["FORBIDDEN_DOMAIN"] = entry["forbidden_domain"]
        if "allowed_domain" in entry:
            env["ALLOWED_DOMAIN"] = entry["allowed_domain"]
        
        try:
            # Redirect stdout/stderr to a file in country_dir
            log_file_path = os.path.join(country_dir, "execution.log")
            print(f"  Logging to {log_file_path}")
            
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
            
            print(f"  ✅ Evaluation completed for {country}. Logs in {log_file_path}")
            results.append((country, "SUCCESS", country_dir))
            
            # Move evolution_trace.jsonl if it exists in base_dir
            trace_filename = "evolution_trace.jsonl"
            source_trace = os.path.join(base_dir, trace_filename)
            
            if os.path.exists(source_trace):
                target_trace = os.path.join(country_dir, trace_filename)
                shutil.move(source_trace, target_trace)
                print(f"  Moved {trace_filename} to {country_dir}")

        except subprocess.CalledProcessError as e:
            print(f"  ❌ Error running evaluation for {country}. Check execution.log for details.")
            results.append((country, "FAILED", country_dir))
            
        except Exception as e:
            print(f"  ❌ Unexpected error for {country}: {e}")
            results.append((country, "ERROR", str(e)))

    # Summary
    if results:
        print("\n" + "=" * 70)
        print("EVALUATION SUMMARY")
        print("=" * 70)
        for country, status, info in results:
            emoji = "✅" if status == "SUCCESS" else "❌"
            print(f"  {emoji} {country}: {status}")
            if status == "SUCCESS":
                print(f"      Output: {info}")
        print("=" * 70)


if __name__ == "__main__":
    main()
