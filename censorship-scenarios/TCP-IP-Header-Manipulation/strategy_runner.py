from typing import Optional, Dict, Any
from scapy.packet import Packet
from scapy.layers.inet import IP, TCP
from copy import copy as _copy
import os, sys
import argparse
import importlib.util
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine import Engine, _build_logger, IptRuleConfig
import time
import atexit
import signal
import threading


def load_strategy_from_path(strategy_path: str):
    """
    Dynamically load a Strategy class from the given file path.
    
    Args:
        strategy_path: Path to the strategy.py file
        
    Returns:
        Strategy class instance
    """
    if not os.path.exists(strategy_path):
        raise FileNotFoundError(f"Strategy file not found: {strategy_path}")
    
    spec = importlib.util.spec_from_file_location("strategy_module", strategy_path)
    if spec is None or spec.loader is None:
        raise ImportError(f"Failed to load spec from {strategy_path}")
    
    module = importlib.util.module_from_spec(spec)
    sys.modules["strategy_module"] = module
    spec.loader.exec_module(module)
    
    if not hasattr(module, "Strategy"):
        raise AttributeError(f"Strategy file {strategy_path} does not contain a 'Strategy' class")
    
    return module.Strategy()

# Global flag to prevent double cleanup
_cleanup_done = False

# Maximum runtime in seconds (default 5 minutes, configurable via ENV)
MAX_RUNTIME_SECONDS = int(os.getenv("ENGINE_MAX_RUNTIME", "300"))

if __name__ == "__main__":
    # Parse command line arguments
    parser = argparse.ArgumentParser(description="Run a packet manipulation strategy")
    parser.add_argument(
        "strategy_path",
        nargs="?",
        default=None,
        help="Path to the strategy.py file (default: ./strategy.py in current directory)"
    )
    args = parser.parse_args()
    
    # Get log directory from environment or use default
    log_dir = os.getenv("ENGINE_LOG_DIR", "/workspace/logs")
    
    logger = _build_logger(name="strategy_runner", log_dir=log_dir)

    cfg = IptRuleConfig(
        proto=os.getenv("ENGINE_PROTO", "tcp"),
        dport=int(os.getenv("ENGINE_DPORT", "80")),
        sport=int(os.getenv("ENGINE_SPORT", "80")),
        queue_bypass=os.getenv("ENGINE_QUEUE_BYPASS", "1").lower() in ("1", "true", "yes", "y"),
        include_forward=os.getenv("ENGINE_INCLUDE_FORWARD", "0").lower() in ("1", "true", "yes", "y"),
        enable_ipv6=os.getenv("ENGINE_ENABLE_IPV6", "0").lower() in ("1", "true", "yes", "y"),
        # Optional extras via ENV, e.g. " -m conntrack --ctstate NEW "
        extra_matches=tuple(
            x for x in os.getenv("ENGINE_EXTRA_MATCHES", "").split() if x.strip()
        ),
        iif=os.getenv("ENGINE_IIF") or None,
        oif=os.getenv("ENGINE_OIF") or None,
    )

    in_q = int(os.getenv("ENGINE_IN_Q", "0"))
    out_q = int(os.getenv("ENGINE_OUT_Q", "1"))

    # Load strategy from path or default to local strategy.py
    if args.strategy_path:
        logger.info("Loading strategy from: %s", args.strategy_path)
        strategy = load_strategy_from_path(args.strategy_path)
    else:
        # Fall back to importing from local strategy.py
        try:
            from strategy import Strategy
            strategy = Strategy()
            logger.info("Loaded strategy from local strategy.py")
        except ImportError as e:
            logger.error("No strategy path provided and no local strategy.py found: %s", e)
            sys.exit(1)

    eng = Engine(None, None, in_q=in_q, out_q=out_q, ipt=cfg, logger=None, strategy=strategy, log_dir=log_dir)

    # --- Optional forward queue via ENV ---
    if cfg.include_forward:
        fwd_q_env = os.getenv("ENGINE_FWD_Q")
        fwd_q = int(fwd_q_env) if fwd_q_env is not None else None

        def cb_fwd(payload):
            logger.debug("FWD queue hit", extra={"id": getattr(payload, "id", None)})
            payload.accept()

        eng.add_forward_queue(cb_fwd, qnum=fwd_q)

    # --- Cleanup handling ---
    def cleanup():
        """Ensures graceful shutdown and cleanup of iptables and NFQUEUE."""
        global _cleanup_done
        if _cleanup_done:
            return
        _cleanup_done = True
        
        logger.info("Running cleanup for queues in=%d, out=%d...", in_q, out_q)
        try:
            eng.stop()
            logger.info("Cleanup completed successfully")
        except Exception as e:
            logger.warning("Error during cleanup: %s", e)
            # Force remove iptables rules even if engine stop fails
            # Use the actual configured queue numbers, not hardcoded values
            try:
                import subprocess
                subprocess.run(["iptables", "-D", "INPUT", "-p", "tcp", "-m", "tcp", 
                               "--sport", str(cfg.sport), "-j", "NFQUEUE", "--queue-num", str(in_q), 
                               "--queue-bypass"], capture_output=True, timeout=5)
                subprocess.run(["iptables", "-D", "OUTPUT", "-p", "tcp", "-m", "tcp",
                               "--dport", str(cfg.dport), "-j", "NFQUEUE", "--queue-num", str(out_q),
                               "--queue-bypass"], capture_output=True, timeout=5)
                logger.info("Forced iptables rule removal for queues in=%d, out=%d", in_q, out_q)
            except Exception as e2:
                logger.warning("Failed to force remove iptables rules: %s", e2)

    atexit.register(cleanup)

    def handle_signal(signum, _frame):
        logger.info("Caught signal %s; shutting down gracefully", signum)
        # Don't ignore further signals - allow force quit if cleanup hangs
        cleanup()
        os._exit(0)  # Force exit without raising SystemExit

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    # --- Watchdog timer for maximum runtime ---
    def watchdog_timeout():
        """Automatically terminate after MAX_RUNTIME_SECONDS to prevent hanging."""
        logger.warning("Watchdog timeout reached after %d seconds. Forcing shutdown.", MAX_RUNTIME_SECONDS)
        print(f"[!] Watchdog timeout: Engine auto-terminating after {MAX_RUNTIME_SECONDS}s")
        cleanup()
        os._exit(1)  # Force exit

    watchdog = threading.Timer(MAX_RUNTIME_SECONDS, watchdog_timeout)
    watchdog.daemon = True
    watchdog.start()
    logger.info("Watchdog timer set for %d seconds", MAX_RUNTIME_SECONDS)

    # --- Start engine ---
    try:
        eng.start()
        logger.info("Engine started. Rules installed.",
                    extra={"in_q": in_q, "out_q": out_q, "ipt_cfg": vars(cfg)})
        print("Engine started. INPUT→q{in_q} (sport {sport}), OUTPUT→q{out_q} (dport {dport}) rules installed."
              .format(in_q=in_q, out_q=out_q, sport=cfg.sport, dport=cfg.dport))
        start_time = time.time()
        while True:
            time.sleep(0.5)
            # Also check elapsed time in the loop as a backup
            elapsed = time.time() - start_time
            if elapsed >= MAX_RUNTIME_SECONDS:
                logger.warning("Max runtime reached in main loop (%d seconds)", MAX_RUNTIME_SECONDS)
                break
    except KeyboardInterrupt:
        logger.info("Interrupted by user")
    except (RuntimeError, OSError) as e:
        logger.exception("Fatal exception: %s", e)
        print(f"[!] Exception: {e}")
    finally:
        watchdog.cancel()  # Cancel the watchdog if we exit normally
        cleanup()
