import pyshark
import pandas as pd
from datetime import datetime

pyshark.tshark.tshark.get_tshark_path = lambda: '/usr/bin/tshark'

# Process only one file for debugging
pcap_file = "jul3pcap/rotation_pcap_jul3/dump.pcap00"

# Store packets by type and connection
submit_sm = {}
submit_sm_resp = {}
deliver_sm = {}
deliver_sm_resp = {}
msgid_to_deliver = {}

# Final outputs
all_records = []
matched_records = []
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


def normalize(val):
    return val.strip().lower() if val else None


def reverse_flow_key(key):
    return (key[0], key[1], key[3], key[4], key[2])


print(f"\n🔍 Parsing {pcap_file}\n")
try:
    cap = pyshark.FileCapture(
        pcap_file,
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
            src_ip, dst_ip = pkt.ip.src, pkt.ip.dst
            src_port, dst_port = pkt.tcp.srcport, pkt.tcp.dstport
            ts = datetime.fromtimestamp(float(pkt.sniff_timestamp)).strftime('%d/%m/%y %H:%M:%S')

            if cmd not in ['0x00000004', '0x80000004', '0x00000005', '0x80000005']:
                continue

            record = {
                'command_id': cmd,
                'sequence_number': seq,
                'message_id': msg_id,
                'src_ip': src_ip,
                'src_port': src_port,
                'dst_ip': dst_ip,
                'dst_port': dst_port,
                'timestamp': ts
            }
            all_records.append(record)
            flow_key = (seq, src_ip, src_port, dst_ip, dst_port)

            if cmd == '0x00000004':
                submit_sm[flow_key] = record
                counters['submit_sm'] += 1
            elif cmd == '0x80000004':
                submit_sm_resp[flow_key] = record
                counters['submit_sm_resp'] += 1
            elif cmd == '0x00000005':
                deliver_sm[flow_key] = record
                msgid_to_deliver.setdefault(msg_id, []).append((flow_key, record))
                counters['deliver_sm'] += 1
            elif cmd == '0x80000005':
                deliver_sm_resp[flow_key] = record
                counters['deliver_sm_resp'] += 1
        except Exception:
            continue
    cap.close()

except Exception as e:
    print(f"❌ Error parsing {pcap_file}: {e}")

# Match submit_sm ↔ submit_sm_resp
for key, req in submit_sm.items():
    reverse_key = (key[0], key[3], key[4], key[1], key[2])
    resp = submit_sm_resp.get(reverse_key)
    if resp:
        matched_records.append({
            'match_type': 'submit_sm ↔ submit_sm_resp',
            'sequence_number': key[0],
            'message_id': resp['message_id'],
            'timestamp_req': req['timestamp'],
            'timestamp_resp': resp['timestamp']
        })
        counters['matched_submit_pair'] += 1
    else:
        counters['unmatched_submit_seq'] += 1

# Match submit_sm_resp ↔ deliver_sm by message_id + reversed connection
for key, resp in submit_sm_resp.items():
    msg_id = resp['message_id']
    if not msg_id:
        counters['unmatched_submit_msgid'] += 1
        continue

    reversed_key = (key[0], key[3], key[4], key[1], key[2])
    candidates = msgid_to_deliver.get(msg_id, [])
    matched = False
    for dkey, drec in candidates:
        if dkey[1:] == reversed_key[1:]:
            matched_records.append({
                'match_type': 'submit_sm_resp ↔ deliver_sm',
                'sequence_number': f"{key[0]} ↔ {dkey[0]}",
                'message_id': msg_id,
                'timestamp_req': resp['timestamp'],
                'timestamp_resp': drec['timestamp']
            })
            counters['matched_submit_to_deliver'] += 1
            counters['matched_message_id'] += 1
            matched = True
            break
    if not matched:
        counters['unmatched_message_id'] += 1

# Match deliver_sm ↔ deliver_sm_resp
for key, req in deliver_sm.items():
    reverse_key = (key[0], key[3], key[4], key[1], key[2])
    resp = deliver_sm_resp.get(reverse_key)
    if resp:
        matched_records.append({
            'match_type': 'deliver_sm ↔ deliver_sm_resp',
            'sequence_number': key[0],
            'message_id': req['message_id'],
            'timestamp_req': req['timestamp'],
            'timestamp_resp': resp['timestamp']
        })
        counters['matched_deliver_pair'] += 1
    else:
        counters['unmatched_deliver_seq'] += 1

# Save outputs
pd.DataFrame(all_records).to_csv("all_smpp_packets.csv", index=False)
pd.DataFrame(matched_records).to_csv("matched_smpp.csv", index=False)
pd.DataFrame([counters]).to_csv("smpp_stats_summary.csv", index=False)

print("\n✅ Matching complete. Summary:")
for k, v in counters.items():
    print(f"{k.replace('_',' ').capitalize()}: {v}")
print("\n📁 Files saved:")
print("- all_smpp_packets.csv")
print("- matched_smpp.csv")
print("- smpp_stats_summary.csv")
