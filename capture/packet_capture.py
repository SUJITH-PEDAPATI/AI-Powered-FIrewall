from scapy.all import TCP, sniff, UDP, ICMP, IP
from datetime import datetime
import os
import json
import sys
import traceback
import time

PID_FILE   = "logs/capture.pid"
LOG_FILE   = "logs/security.jsonl"
ERROR_LOG  = "logs/capture_error.log"

FLUSH_EVERY = 100   # force-flush to disk every N packets


class PacketCapture:
    def __init__(self):
        self.FILE_PATH   = LOG_FILE
        self.write_count = 0
        os.makedirs("logs", exist_ok=True)

        # Keep the file open for the lifetime of the capture instead of
        # opening/closing on every packet — eliminates I/O contention.
        self._file = open(self.FILE_PATH, "a", encoding="utf-8", buffering=1)

    def close(self):
        try:
            self._file.flush()
            self._file.close()
        except Exception:
            pass

    def process_packet(self, packet):
        if IP not in packet:
            return

        timeStamp        = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")
        source_ip        = packet[IP].src
        destination_ip   = packet[IP].dst
        protocol         = packet[IP].proto
        packet_size      = len(packet)

        source_port      = None
        destination_port = None
        flags            = None

        if TCP in packet:
            protocol         = 6
            source_port      = packet[TCP].sport
            destination_port = packet[TCP].dport
            flags            = str(packet[TCP].flags)

        elif UDP in packet:
            protocol         = 17
            source_port      = packet[UDP].sport
            destination_port = packet[UDP].dport

        elif ICMP in packet:
            protocol = "ICMP"

        packet_data = {
            "timestamp":        timeStamp,
            "source_ip":        source_ip,
            "destination_ip":   destination_ip,
            "source_port":      source_port,
            "destination_port": destination_port,
            "protocol":         protocol,
            "packet_size":      packet_size,
            "flags":            flags,
        }

        try:
            self._file.write(json.dumps(packet_data) + "\n")
            self.write_count += 1
            # Periodically force OS flush so data isn't stuck in buffers
            if self.write_count % FLUSH_EVERY == 0:
                self._file.flush()
        except Exception as exc:
            _log_error(f"Write error: {exc}")


def _log_error(msg: str):
    """Append a timestamped error line to the capture error log."""
    os.makedirs("logs", exist_ok=True)
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(ERROR_LOG, "a", encoding="utf-8") as f:
        f.write(f"[{ts}] {msg}\n")


if __name__ == "__main__":
    os.makedirs("logs", exist_ok=True)

    # Write PID so the dashboard can stop us
    with open(PID_FILE, "w") as f:
        f.write(str(os.getpid()))

    print(f"[PacketCapture] PID {os.getpid()} — capturing on Wi-Fi...")
    _log_error(f"START pid={os.getpid()}")

    MAX_RETRIES = 5
    retry       = 0

    while retry < MAX_RETRIES:
        pc = PacketCapture()
        try:
            sniff(
                iface="Wi-Fi",
                prn=pc.process_packet,
                store=False,
            )
            # sniff() returned normally (only happens if stopped externally)
            break

        except KeyboardInterrupt:
            print("[PacketCapture] KeyboardInterrupt — stopping.")
            break

        except Exception as exc:
            retry += 1
            err_msg = traceback.format_exc()
            print(f"[PacketCapture] Error (attempt {retry}/{MAX_RETRIES}): {exc}", file=sys.stderr)
            _log_error(f"CRASH attempt={retry}: {err_msg}")

            pc.close()

            if retry < MAX_RETRIES:
                wait = retry * 2   # back-off: 2s, 4s, 6s …
                print(f"[PacketCapture] Restarting in {wait}s…", file=sys.stderr)
                time.sleep(wait)
            else:
                print("[PacketCapture] Too many retries — giving up.", file=sys.stderr)
                _log_error("FATAL: too many retries, exiting.")

        finally:
            pc.close()

    # Clean up PID file on exit
    if os.path.exists(PID_FILE):
        os.remove(PID_FILE)

    _log_error("STOP")
    print("[PacketCapture] Stopped.")
