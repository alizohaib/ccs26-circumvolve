#!/usr/bin/env python3
import threading
import subprocess
import shutil
import time
import os
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional, Sequence, Tuple, Union
import logging
from logging.handlers import RotatingFileHandler
from netfilterqueue import NetfilterQueue
from strategy import Strategy, Scheduled
from scapy.packet import Packet
from scapy.config import conf
from scapy.all import IP, TCP, UDP
from scapy.utils import wrpcap

Callback = Callable  # (payload) -> None

_logger_lock = threading.Lock()

def _build_logger(name: str = "nfq.engine", log_dir: Optional[str] = None) -> logging.Logger:
    with _logger_lock:
        logger = logging.getLogger(name)
        
        # Only skip if handlers exist AND log_dir was not provided
        if logger.handlers and log_dir is None:
            return logger
        
        logger.setLevel(logging.DEBUG)
        formatter = logging.Formatter(
            fmt="%(asctime)s %(levelname)s [%(name)s] %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        )
        
        # Console handler - add if not exists
        has_console = any(isinstance(h, logging.StreamHandler) for h in logger.handlers)
        if not has_console:
            console_handler = logging.StreamHandler()
            console_handler.setLevel(logging.INFO)
            console_handler.setFormatter(formatter)
            logger.addHandler(console_handler)
        
        # File handler (if log_dir is provided and doesn't exist yet)
        if log_dir is not None:
            has_file = any(isinstance(h, RotatingFileHandler) for h in logger.handlers)
            if not has_file:
                os.makedirs(log_dir, exist_ok=True)
                # Use logger name for file name (replace dots with underscores)
                log_filename = name.replace(".", "_") + ".log"
                log_file = os.path.join(log_dir, log_filename)
                file_handler = RotatingFileHandler(
                    log_file, maxBytes=5 * 1024 * 1024, backupCount=5
                )
                file_handler.setLevel(logging.DEBUG)
                file_handler.setFormatter(formatter)
                logger.addHandler(file_handler)
                logger.info(f"Logging to file: {log_file}")
        
        return logger


# -----------------------------
# IPTables rule config
# -----------------------------
@dataclass
class IptRuleConfig:
    proto: Optional[str] = None           # e.g. "tcp", "udp"
    dport: Optional[int] = None           # used for OUTPUT/FORWARD matches
    sport: Optional[int] = None           # used for INPUT/FORWARD matches
    iif:   Optional[str] = None           # e.g. "eth0"
    oif:   Optional[str] = None           # e.g. "wlan0"
    extra_matches: Tuple[str, ...] = ()   # e.g. ("-m", "conntrack", "--ctstate", "NEW")
    queue_bypass: bool = True
    include_forward: bool = False
    enable_ipv6: bool = False


class Engine:
    """
    Engine that:
      1) installs iptables/ip6tables rules to send packets to NFQUEUE
      2) binds NetfilterQueue callbacks to those queue numbers
      3) runs one thread per queue
      4) removes rules & unbinds on stop()
    """

    def __init__(self,
                 cb_in: Callback,
                 cb_out: Callback,
                 in_q: int = 0,
                 out_q: int = 1,
                 *,
                 ipt: IptRuleConfig = IptRuleConfig(),
                 strategy: Optional[Strategy] = None,
                 logger: Optional[logging.Logger] = None,
                 log_dir: Optional[str] = None):
        self.cb_in = self.cb_in_handler if cb_in is None else cb_in
        self.cb_out = self.cb_out_handler if cb_out is None else cb_out
        self.in_q = in_q
        self.out_q = out_q
        self.cfg = ipt

        # Validate queue numbers are unique
        if in_q == out_q:
            raise ValueError(f"in_q and out_q must be different queue numbers (both are {in_q})")

        self._nfqs: Dict[int, NetfilterQueue] = {}
        self._threads: Dict[int, threading.Thread] = {}
        self._added_rules: List[Tuple[str, List[str]]] = []
        self._running = False

        self._forward_q: Optional[int] = None
        self._cb_fwd: Optional[Callback] = None

        self.log = logger or _build_logger(log_dir=log_dir)
        self.strategy = strategy
        if self.strategy is None:
            raise ValueError("Strategy is required")
        # Use duck typing - check for required methods instead of isinstance
        # This allows dynamically loaded Strategy classes to work
        if not (hasattr(self.strategy, 'on_incoming_packet') or hasattr(self.strategy, 'on_outgoing_packet')):
            raise ValueError("Strategy must have at least one of: on_incoming_packet, on_outgoing_packet methods")
        
        self.socket = conf.L3socket()


    # ---------------- Public API ----------------

    def add_forward_queue(self, cb_fwd: Callback, qnum: int):
        """Enable FORWARD interception (routing) on the specified queue number.
        
        Args:
            cb_fwd: Callback function for forwarded packets
            qnum: Queue number (must be different from in_q and out_q)
        """
        if qnum == self.in_q or qnum == self.out_q:
            raise ValueError(f"Forward queue {qnum} must be different from in_q ({self.in_q}) and out_q ({self.out_q})")
        self._cb_fwd = cb_fwd
        self._forward_q = qnum
        self.log.info(f"Forward queue enabled on queue {qnum}")

    def cb_in_handler(self, nfpacket):
        try:
            pkt = IP(nfpacket.get_payload())
            # Log packet details at INFO level
            tcp_info = ""
            if pkt.haslayer(TCP):
                tcp_info = f" sport={pkt[TCP].sport} dport={pkt[TCP].dport} flags={pkt[TCP].flags}"
            self.log.info(f"[IN] {pkt.src} -> {pkt.dst}{tcp_info}")
            
            packets: Optional[List[Union[Packet, Scheduled]]] = self.strategy.on_incoming_packet(pkt)
            if packets is None:
                self.log.debug(f"Incoming packet dropped by strategy: {pkt.summary()}")
                nfpacket.drop()
                return
            
            if len(packets) > 1:
                self.log.warning(f"Incoming packet generated {len(packets)} packets, dropping original")
                nfpacket.drop()
                return
            elif len(packets) == 1:
                if isinstance(packets[0], Scheduled):
                    delay_ms = packets[0].delay_ms
                    self.log.debug(f"Scheduling incoming packet with {delay_ms}ms delay")
                    time.sleep(delay_ms / 1000)
                    nfpacket.set_payload(bytes(packets[0].packet))
                    nfpacket.accept()
                    self.log.debug("Scheduled incoming packet accepted")
                    return
                else:
                    if bytes(packets[0]) != bytes(pkt):
                        self.log.debug("Incoming packet modified by strategy")
                        for layer in (IP, TCP, UDP):
                            if packets[0].haslayer(layer):
                                for f in ("len", "chksum"):
                                    if hasattr(packets[0][layer], f):
                                        try: delattr(packets[0][layer], f)
                                        except AttributeError: pass
                        nfpacket.set_payload(bytes(packets[0]))
                    else:
                        self.log.debug("Incoming packet unmodified")
                    nfpacket.accept()
                    self.log.debug("Incoming packet accepted")
                    return
            else:
                self.log.debug("Incoming packet dropped (no output from strategy)")
                nfpacket.drop()
            
        except Exception as e:
            self.log.error(f"Error processing incoming packet: {e}", exc_info=True)
        
    
    def _send_delayed_packet(self, packet: Packet, delay_ms: int):
        """Send a packet after a delay using a timer thread (non-blocking)."""
        def send():
            try:
                self.socket.send(packet)
                self.log.debug(f"Delayed packet sent after {delay_ms}ms")
            except Exception as e:
                self.log.error(f"Error sending delayed packet: {e}")
        
        timer = threading.Timer(delay_ms / 1000.0, send)
        timer.daemon = True
        timer.start()

    def cb_out_handler(self, nfpacket):
        try:
            # Parse the raw packet payload with Scapy
            pkt = IP(nfpacket.get_payload())
            # Log packet details at INFO level
            tcp_info = ""
            if pkt.haslayer(TCP):
                tcp_info = f" sport={pkt[TCP].sport} dport={pkt[TCP].dport} flags={pkt[TCP].flags}"
            self.log.info(f"[OUT] {pkt.src} -> {pkt.dst}{tcp_info}")
            
            packets: Optional[List[Union[Packet, Scheduled]]] = self.strategy.on_outgoing_packet(pkt)
            if packets is not None and len(packets) > 0:
                packet_count = len(packets)
                self.log.debug(f"Strategy generated {packet_count} packet(s) for outgoing traffic")
                
                for i, packet in enumerate(packets):
                    if isinstance(packet, Scheduled):
                        delay_ms = packet.delay_ms
                        self.log.debug(f"Scheduling packet {i+1}/{packet_count} with {delay_ms}ms delay")
                        self._send_delayed_packet(packet.packet, delay_ms)
                    else:
                        self.log.debug(f"Sending packet {i+1}/{packet_count}")
                        try:
                            self.socket.send(packet)
                        except Exception as e:
                            self.log.error(f"Error sending packet {i+1}/{packet_count}: {e}")
            else:
                self.log.debug(f"Outgoing packet dropped by strategy: {pkt.summary()}")
        except Exception as e:
            self.log.error(f"Error processing outgoing packet: {e}", exc_info=True)
        finally:
            nfpacket.drop()
            self.log.debug("Outgoing packet dropped from queue")

        
    def start(self):
        if self._running:
            self.log.debug("Engine.start called but already running")
            return
        self.log.info("Starting engine")
        self._install_rules()
        self._bind_queues()
        self._running = True
        self.log.info("Engine started")

    def stop(self):
        """Gracefully unbind all NFQUEUEs and remove iptables rules."""
        if not self._running:
            self.log.debug("Engine.stop called but not running")
            return

        self.log.info("Stopping engine...")
        self._running = False

        # Remove iptables rules FIRST to stop new packets from hitting queues
        self._remove_rules()
        self.log.info("iptables rules removed")

        # Close the raw socket
        try:
            if self.socket:
                self.socket.close()
                self.log.debug("Raw socket closed")
        except Exception as e:
            self.log.warning(f"Failed to close socket: {e}")

        # Don't try to unbind NFQUEUEs - it blocks forever if threads are in nfq.run()
        # Since threads are daemon threads, they'll be killed when process exits
        # Just clear our references and let the process exit handle cleanup
        self._nfqs.clear()
        self._threads.clear()

        self.log.info("Engine stopped.")

    def join(self, timeout: Optional[float] = None):
        self._join_threads(timeout)

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, exc_t, exc, tb):
        self.stop()

    # ---------------- Internals ----------------

    def _bin_exists(self, name: str) -> bool:
        return shutil.which(name) is not None

    def _iptables_bin(self, v6: bool) -> str:
        return "ip6tables" if v6 else "iptables"

    def _install_rules(self):
        fams = [False] + ([True] if self.cfg.enable_ipv6 else [])
        for v6 in fams:
            self._add_family_rules(v6)

    def _add_family_rules(self, v6: bool):
        bin_name = self._iptables_bin(v6)
        if not self._bin_exists(bin_name):
            if v6:
                self.log.info("ip6tables not found; skipping IPv6 rules")
                return
            raise RuntimeError(f"{bin_name} not found in PATH")

        # INPUT → in_q
        r_in = self._build_rule("INPUT", self.in_q, direction="in")
        self._add_rule(bin_name, r_in)
        # OUTPUT → out_q
        r_out = self._build_rule("OUTPUT", self.out_q, direction="out")
        self._add_rule(bin_name, r_out)
        # FORWARD (optional)
        if self.cfg.include_forward and self._forward_q is not None and self._cb_fwd is not None:
            r_fwd = self._build_rule("FORWARD", self._forward_q, direction="fwd")
            self._add_rule(bin_name, r_fwd)

    def _build_rule(self, chain: str, qnum: int, *, direction: str) -> List[str]:
        args: List[str] = ["-I", chain]

        if direction in ("in", "fwd") and self.cfg.iif:
            args += ["-i", self.cfg.iif]
        if direction in ("out", "fwd") and self.cfg.oif:
            args += ["-o", self.cfg.oif]

        if self.cfg.proto:
            args += ["-p", self.cfg.proto]

        using_ports = (self.cfg.dport is not None) or (self.cfg.sport is not None)
        if using_ports and self.cfg.proto in ("tcp", "udp"):
            args += ["-m", self.cfg.proto]

        if self.cfg.dport is not None and direction in ("out", "fwd"):
            args += ["--dport", str(self.cfg.dport)]
        if self.cfg.sport is not None and direction in ("in", "fwd"):
            args += ["--sport", str(self.cfg.sport)]

        if self.cfg.extra_matches:
            args += list(self.cfg.extra_matches)

        args += ["-j", "NFQUEUE", "--queue-num", str(qnum)]
        if self.cfg.queue_bypass:
            args += ["--queue-bypass"]

        rule_str = " ".join(args)
        self.log.debug(f"Built iptables rule: {rule_str}")
        return args

    def _run_iptables(self, bin_name: str, args: Sequence[str]) -> None:
        cmd = [bin_name] + list(args)
        cmd_str = " ".join(cmd)
        self.log.info(f"Running iptables command: {cmd_str}")
        res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
        if res.returncode != 0:
            self.log.error(f"iptables command failed: {res.stderr.strip()}")
            raise RuntimeError(f"{' '.join(cmd)} failed: {res.stderr.strip()}")
        else:
            self.log.debug("iptables command succeeded")

    def _add_rule(self, bin_name: str, args: List[str]):
        self._run_iptables(bin_name, args)

        self._added_rules.append((bin_name, args))
        rule_type = args[1] if len(args) > 1 else "unknown"
        self.log.info(f"Added iptables rule to chain: {rule_type}")


    def _remove_rules(self):
        rule_count = len(self._added_rules)
        self.log.debug(f"Removing {rule_count} iptables rule(s)")
        for bin_name, args in reversed(self._added_rules):
            try:
                del_args = ["-D"] + args[1:]
                rule_type = args[1] if len(args) > 1 else "unknown"
                self._run_iptables(bin_name, del_args)
                self.log.info(f"Removed iptables rule from chain: {rule_type}")
            except Exception as e:
                self.log.warning(f"Failed to remove iptables rule: {e}")
        self._added_rules.clear()
        self.log.debug("All iptables rules removed")

    def _bind_queues(self):
        self.log.info("Binding NFQUEUEs")

        nfq_in = NetfilterQueue()
        nfq_in.bind(self.in_q, self.cb_in)
        t_in = threading.Thread(target=self._run_queue, args=(nfq_in,), name=f"nfqueue-{self.in_q}", daemon=True)
        self._nfqs[self.in_q] = nfq_in
        self._threads[self.in_q] = t_in
        t_in.start()
        self.log.debug(f"Inbound queue {self.in_q} bound and thread started")

        nfq_out = NetfilterQueue()
        nfq_out.bind(self.out_q, self.cb_out)
        t_out = threading.Thread(target=self._run_queue, args=(nfq_out,), name=f"nfqueue-{self.out_q}", daemon=True)
        self._nfqs[self.out_q] = nfq_out
        self._threads[self.out_q] = t_out
        t_out.start()
        self.log.debug(f"Outbound queue {self.out_q} bound and thread started")

        if self.cfg.include_forward and self._forward_q is not None and self._cb_fwd is not None:
            nfq_fwd = NetfilterQueue()
            nfq_fwd.bind(self._forward_q, self._cb_fwd)
            t_fwd = threading.Thread(target=self._run_queue, args=(nfq_fwd,),
                                     name=f"nfqueue-{self._forward_q}", daemon=True)
            self._nfqs[self._forward_q] = nfq_fwd
            self._threads[self._forward_q] = t_fwd
            t_fwd.start()
            self.log.debug(f"Forward queue {self._forward_q} bound and thread started")

    def _run_queue(self, nfq: NetfilterQueue):
        thread_name = threading.current_thread().name
        self.log.debug(f"NFQUEUE loop started in thread: {thread_name}")
        try:
            nfq.run()
        except KeyboardInterrupt:
            self.log.info(f"NFQUEUE loop interrupted by user in thread: {thread_name}")
        except Exception as e:
            self.log.exception(f"Exception inside NFQUEUE loop in thread: {thread_name}: {e}")
        finally:
            self.log.debug(f"NFQUEUE loop exited in thread: {thread_name}")

    def _join_threads(self, timeout: Optional[float] = 1.0):
        thread_count = len(self._threads)
        self.log.debug(f"Joining {thread_count} thread(s)")
        for t in list(self._threads.values()):
            if t.is_alive():
                self.log.debug(f"Joining thread: {t.name}")
                t.join(timeout=timeout)
                if t.is_alive():
                    self.log.warning(f"Thread {t.name} did not exit cleanly within {timeout}s timeout")
                else:
                    self.log.debug(f"Thread {t.name} joined successfully")


