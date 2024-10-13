from bcc import BPF
import ctypes as ct
import datetime
from prometheus_client import start_http_server, Gauge

# eBPF program
prog = """
#include <linux/skbuff.h>
#include <uapi/linux/ip.h>

#define MAX_NB_PACKETS 1000
#define LEGAL_DIFF_TIMESTAMP_PACKETS 1000000

BPF_HASH(rcv_packets);

struct detectionPackets {
    u64 nb_ddos_packets;
};

BPF_PERF_OUTPUT(events);

int detect_ddos(struct pt_regs *ctx, void *skb) {
    struct detectionPackets detectionPacket = {};
    u64 rcv_packets_nb_index = 0, rcv_packets_nb_inter = 1, *rcv_packets_nb_ptr;
    u64 rcv_packets_ts_index = 1, rcv_packets_ts_inter = 0, *rcv_packets_ts_ptr;

    rcv_packets_nb_ptr = rcv_packets.lookup(&rcv_packets_nb_index);
    rcv_packets_ts_ptr = rcv_packets.lookup(&rcv_packets_ts_index);
    if (rcv_packets_nb_ptr != 0 && rcv_packets_ts_ptr != 0) {
        rcv_packets_nb_inter = *rcv_packets_nb_ptr;
        rcv_packets_ts_inter = bpf_ktime_get_ns() - *rcv_packets_ts_ptr;
        if (rcv_packets_ts_inter < LEGAL_DIFF_TIMESTAMP_PACKETS) {
            rcv_packets_nb_inter++;
        } else {
            rcv_packets_nb_inter = 0;
        }
        if (rcv_packets_nb_inter > MAX_NB_PACKETS) {
            detectionPacket.nb_ddos_packets = rcv_packets_nb_inter;
            events.perf_submit(ctx, &detectionPacket, sizeof(detectionPacket));
        }
    }
    rcv_packets_ts_inter = bpf_ktime_get_ns();
    rcv_packets.update(&rcv_packets_nb_index, &rcv_packets_nb_inter);
    rcv_packets.update(&rcv_packets_ts_index, &rcv_packets_ts_inter);
    return 0;
}
"""

# Loads eBPF program
b = BPF(text=prog)

# Attach kprobe to ip_rcv for DDOS detection
b.attach_kprobe(event="ip_rcv", fn_name="detect_ddos")

class DetectionPacket(ct.Structure):
    _fields_ = [("nb_ddos_packets", ct.c_ulonglong)]

# Prometheus metric
ddos_gauge = Gauge('ddos_packets_detected', 'Number of DDOS packets detected')

# Start Prometheus metrics server on port 8000
start_http_server(8000)

def detect_ddos_event(cpu, data, size):
    event = ct.cast(data, ct.POINTER(DetectionPacket)).contents
    ddos_gauge.set(event.nb_ddos_packets)

# Open perf buffer to monitor events
b["events"].open_perf_buffer(detect_ddos_event)

# Run loop
while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
