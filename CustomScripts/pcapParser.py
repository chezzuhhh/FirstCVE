# Tool for parsing pcaps for specified fields

import subprocess
from pathlib import Path

pcap_dir = Path(".")
fields = [
    "frame.number", "frame.time", "frame.len", "frame.protocols",
        #L2
    "eth.src", "eth.dst",
        #L3
    "ip.src", "ip.dst", "ip.ttl", "ip.proto",
        #L4
    "tcp.srcport", "tcp.dstport", "tcp.flags", "tcp.len", "tcp.window_size",
    "udp.srcport", "udp.dstport", "udp.length",
        #dns
    "dns.qry.name", "dns.resp.name", "dns.flags.response",
    "mdns.name", "mdns.type", "mdns.txt",
        #http
    "http.request.method", "http.request.full_uri", "http.host",
    "http.user_agent", "http.response.code", "http.content_type", "http.content_length",
        #tls
    "tls.handshake.extensions_server_name",
    "tls.handshake.ciphersuite",
    "tls.handshake.certificate", # leaf cert
    "tls.record.content_type",
        # STUN/WebRTC/ICE
    "stun.type", "stun.message.type", "stun.attr.type",
    "stun.binding.request", "stun.binding.response",
        # json payloads
    "data.data", "json.value",
        # MQTT
    "mqtt.topic", "mqtt.msg", "mqtt.qos",
        # Misc.
    "expert.message"
]

tshark_cmd_base = [
    "tshark", "-T", "fields",
    "-E", "separator=,",
    "-E", "quote=d",
    "-E", "occurrence=f",
    "-E", "header=y" # csv headers
]

for field in fields:
    tshark_cmd_base.extend(["-e", field])

print("starting pcap processing...\n")

filter_expr = None

for pcap_path in sorted(pcap_dir.glob("*.pcapng")):
    output_csv = pcap_path.with_name(f"{pcap_path.stem}_extract.csv")
    print(f"{pcap_path.name} -> {output_csv.name}")

    cmd = tshark_cmd_base.copy()
    cmd.extend(["-r", str(pcap_path)])
    if filter_expr:
        cmd.extend(["-Y", filter_expr])

    try:
        with open(output_csv, "w", encoding="utf-8", newline="") as f:
            result = subprocess.run(
                cmd,
                stdout=f,
                stderr=subprocess.PIPE,
                text=True,
                check=True
            )
        size_kb = output_csv.stat().st_size / 1024
        print(f"done, {size_kb:.1f} KB")

    except subprocess.CalledProcessError as e:
        print(f"error processing {pcap_path.name}")
        print(e.stderr.strip())
    except FileNotFoundError:
        print("tshark not found")
        break

print("\nDone")