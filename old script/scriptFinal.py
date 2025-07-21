import pyshark
import pandas as pd
from datetime import datetime

pyshark.tshark.tshark.get_tshark_path = lambda: '/usr/bin/tshark'

# List of pcap files
pcap_files = [
    "jul3pcap/rotation_pcap_jul3/dump.pcap00",
    "jul3pcap/rotation_pcap_jul3/dump.pcap01",
    "jul3pcap/rotation_pcap_jul3/dump.pcap02",
    "jul3pcap/rotation_pcap_jul3/dump.pcap03",
    "jul3pcap/rotation_pcap_jul3/dump.pcap04",
    "jul3pcap/rotation_pcap_jul3/dump.pcap05",
    "jul3pcap/rotation_pcap_jul3/dump.pcap06",
    "jul3pcap/rotation_pcap_jul3/dump.pcap07"
]

def normalize(val):
    return val.strip().lower() if val else None

def reverse_conn_key(key):
    return (key[3], key[4], key[1], key[2])  # dst -> src (reverse)

# Global stores
all_records = []
matched = []

submit_sm = {}
submit_sm_resp = {}
deliver_sm = {}
deliver_sm_resp = {}
msgid_to_deliver = {}

printed_keys = set()

counters = {
    'submit_sm': 0,
    'submit_sm_resp': 0,
    'deliver_sm': 0,
    'deliver_sm_resp': 0,
    'matched_submit_pair': 0,
    'matched_submit_to_deliver': 0,
    'matched_deliver_pair': 0,
    'unmatched_submit_seq': 0,
    'unmatched_submit_msgid': 0,
    'unmatched_deliver_seq': 0,
    'matched_message_id': 0,
    'unmatched_message_id': 0
}

# Loop over all files
for file in pcap_files:
    print(f"🔍 Processing {file}")
    try:
        cap = pyshark.FileCapture(
            file,
            display_filter="smpp",
            use_json=True,
            include_raw=True,
            keep_packets=False
        )

        for pkt in cap:
            try:
                smpp = pkt['smpp']
                fields = smpp._all_fields

                cmd = fields.get('smpp.command_id')
                seq = fields.get('smpp.sequence_number')
                msg_id = normalize(fields.get('smpp.message_id'))

                if cmd not in ['0x00000004', '0x80000004', '0x00000005', '0x80000005']:
                    continue  # Skip non-relevant PDU types

                src_ip = pkt.ip.src
                dst_ip = pkt.ip.dst
                src_port = pkt.tcp.srcport
                dst_port = pkt.tcp.dstport
                timestamp = datetime.fromtimestamp(float(pkt.sniff_timestamp)).strftime('%d/%m/%y %H:%M:%S')

                key = (cmd, seq)
                if key not in printed_keys:
                    print(f"Parsed: {cmd} | Seq: {seq} | MsgID: {msg_id} | {src_ip}:{src_port} -> {dst_ip}:{dst_port} at {timestamp}")
                    printed_keys.add(key)

                record = {
                    'command_id': cmd,
                    'sequence_number': seq,
                    'message_id': msg_id,
                    'src_ip': src_ip,
                    'src_port': src_port,
                    'dst_ip': dst_ip,
                    'dst_port': dst_port,
                    'timestamp': timestamp
                }
                all_records.append(record)

                conn_key = (seq, src_ip, src_port, dst_ip, dst_port)

                if cmd == '0x00000004':
                    submit_sm[conn_key] = record
                    counters['submit_sm'] += 1
                elif cmd == '0x80000004':
                    submit_sm_resp[conn_key] = record
                    counters['submit_sm_resp'] += 1
                elif cmd == '0x00000005':
                    deliver_sm[conn_key] = record
                    msgid_to_deliver.setdefault(msg_id, []).append((conn_key, record))
                    counters['deliver_sm'] += 1
                elif cmd == '0x80000005':
                    deliver_sm_resp[conn_key] = record
                    counters['deliver_sm_resp'] += 1

            except Exception:
                continue

        cap.close()

    except Exception as e:
        print(f"❌ Failed to parse {file}: {e}")

# === MATCHING LOGIC ===

for key in submit_sm:
    reverse_key = reverse_conn_key(key)
    if reverse_key in submit_sm_resp:
        matched.append({
            'match_type': 'submit_sm ↔ submit_sm_resp',
            'sequence_number': key[0],
            'message_id': submit_sm_resp[reverse_key]['message_id'],
            'src_ip': key[1], 'src_port': key[2],
            'dst_ip': key[3], 'dst_port': key[4],
            'timestamp_req': submit_sm[key]['timestamp'],
            'timestamp_resp': submit_sm_resp[reverse_key]['timestamp']
        })
        counters['matched_submit_pair'] += 1
    else:
        counters['unmatched_submit_seq'] += 1

for key, resp in submit_sm_resp.items():
    msg_id = resp['message_id']
    if not msg_id:
        counters['unmatched_submit_msgid'] += 1
        continue

    possible_delivers = msgid_to_deliver.get(msg_id, [])
    found = False
    for dkey, drec in possible_delivers:
        if reverse_conn_key(key) == dkey:
            matched.append({
                'match_type': 'submit_sm_resp ↔ deliver_sm (msg_id)',
                'message_id': msg_id,
                'sequence_number': f"{key[0]} ↔ {dkey[0]}",
                'src_ip': key[1], 'src_port': key[2],
                'dst_ip': key[3], 'dst_port': key[4],
                'timestamp_req': resp['timestamp'],
                'timestamp_resp': drec['timestamp']
            })
            counters['matched_submit_to_deliver'] += 1
            counters['matched_message_id'] += 1
            found = True
            break
    if not found:
        counters['unmatched_message_id'] += 1

for key in deliver_sm:
    reverse_key = reverse_conn_key(key)
    if reverse_key in deliver_sm_resp:
        matched.append({
            'match_type': 'deliver_sm ↔ deliver_sm_resp',
            'sequence_number': key[0],
            'message_id': deliver_sm[key]['message_id'],
            'src_ip': key[1], 'src_port': key[2],
            'dst_ip': key[3], 'dst_port': key[4],
            'timestamp_req': deliver_sm[key]['timestamp'],
            'timestamp_resp': deliver_sm_resp[reverse_key]['timestamp']
        })
        counters['matched_deliver_pair'] += 1
    else:
        counters['unmatched_deliver_seq'] += 1

# === OUTPUT ===
pd.DataFrame(all_records).to_csv("all_smpp_packets.csv", index=False)
pd.DataFrame(matched).to_csv("matched_smpp.csv", index=False)
pd.DataFrame([counters]).to_csv("smpp_stats_summary.csv", index=False)

# === SUMMARY ===
print("\n✅ Summary:")
for key, val in counters.items():
    print(f"{key.replace('_',' ').capitalize()}: {val}")
print("📁 Output:")
print("- all_smpp_packets.csv")
print("- matched_smpp.csv")
print("- smpp_stats_summary.csv")
