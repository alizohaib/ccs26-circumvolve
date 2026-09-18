# Automated Discovery of Censorship Evasion Strategies Using Large Language Models

This repository contains the source code, experiment data and results for the paper: [*CircumVolve: Automated Discovery of Censorship Evasion Strategies Using Large Language Models*](https://gfw.report/publications/ccs26/en/) (ACM CCS 2026).

---

## Repository Structure

```
├── README.md                    # This file
├── requirements.txt             # Python dependencies
├── censorship-scenarios/        # Censorship evasion experiments
│   ├── DNS-Blocking/           # DNS query manipulation strategies
│   ├── HTTP-Blocking/          # HTTP header evasion techniques
│   ├── TLS-SNI-Blocking/       # TLS ClientHello SNI manipulation
│   ├── QUIC-SNI-Blocking/      # QUIC Initial packet manipulation
│   └── TCP-IP-Header-Manipulation/  # TCP/IP manipulation
└── openevolve/                  # Evolutionary coding agent framework
```

---

## Installation

```bash
# Create a virtual environment
python -m venv ./venv
source ./venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

---

## LLM Configuration

### Setting Your API Key

Set your OpenAI API key as an environment variable:

```bash
export OPENAI_API_KEY="your-api-key-here"
```

For Azure OpenAI, you can also set a custom API base in the scenario's `config.yaml`:

```yaml
llm:
  api_base: "https://your-resource.openai.azure.com/openai/v1"
  models:
    - name: "gpt-5.1"
      weight: 1
```

Or use environment variable substitution:

```yaml
llm:
  api_base: "${OPENAI_API_BASE}"
  models:
    - name: "gpt-5.1"
      weight: 1
      # api_key: "${OPENAI_API_KEY}"  # Optional per-model override
```

---

## Running Experiments

Each scenario provides a `run_evaluation.py` script that supports both local (Docker-based) and remote (VPS-based) evaluation modes.

### Local Evaluation (Docker)

Local evaluation uses Docker containers with OpenGFW as a simulated censor middlebox:

```bash
cd censorship-scenarios/TLS-SNI-Blocking

# Run local evaluation with 100 iterations
python run_evaluation.py local --iterations 100

# Run with custom config file
python run_evaluation.py local --config config.yaml --iterations 100

# Keep Docker containers running after evaluation (for debugging)
python run_evaluation.py local --iterations 10 --persist-containers
```

**Requirements for local evaluation:**
- Docker installed and running
- Sufficient permissions to create containers with `NET_ADMIN` capabilities

### Remote Evaluation (VPS)

Remote evaluation runs experiments on VPS instances located in censored countries, testing against real-world censors:

```bash
cd censorship-scenarios/HTTP-Blocking

# Run remote evaluation for a specific country
python run_evaluation.py remote --country china

# Run remote evaluation for all configured countries
python run_evaluation.py remote --country all

# Run with custom iteration count
python run_evaluation.py remote --country pakistan --iterations 200

# Dry run (shows what would be executed without running)
python run_evaluation.py remote --country china --dry-run
```

### Configuring Remote VPSes

Edit the `remote_vpses.yaml` file in each scenario directory to configure your VPS instances:

```yaml
- country: "china"
  host: "YOUR_VPS_IP"           # VPS IP address
  user: "root"                   # SSH username
  key_path: "~/.ssh/your_key"   # Path to SSH private key
  # password: "your_password"   # Alternative: SSH password
  persist: true                  # Keep workspace after evaluation
  forbidden_domain: "blocked-domain.com"
  allowed_domain: "example.com"
  server_ip: "YOUR_TEST_SERVER_IP"
  interface: "eth0"
  censor_type: "on-path-resetter"
```

---

## Results

Successful evasion strategies are saved in each scenario's `successful_programs/` directory.
