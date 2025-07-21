import pyshark
import pandas as pd
from datetime import datetime

pyshark.tshark.tshark.get_tshark_path = lambda: '/usr/bin/tshark'

# Process only one file for debugging
pcap_file = "v2smpp33.pcap"

# Store packets by type and connection
submit_sm = {}
submit_sm_resp = {}
deliver_sm = {}
deliver_sm_resp = {}
msgid_to_deliver = {}

# Final outputs
all_records = []
chain_records = []
counters = {
    'submit_sm': 0,
    'submit_sm_resp': 0,
    'deliver_sm': 0,
    'deliver_sm_resp': 0,
    'full_chains': 0,
    'partial_chains': 0
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

# Match full chains and build rows
used_deliver_keys = set()
used_resp_keys = set()

for sub_key, sub in submit_sm.items():
    reverse_key = (sub_key[0], sub_key[3], sub_key[4], sub_key[1], sub_key[2])
    resp = submit_sm_resp.get(reverse_key)
    msg_id = resp['message_id'] if resp else None

    deliver = None
    deliver_key = None
    if msg_id:
        for dk, drec in msgid_to_deliver.get(msg_id, []):
            if dk[1:] == reverse_key[1:]:
                deliver = drec
                deliver_key = dk
                used_deliver_keys.add(dk)
                break

    dresp = None
    if deliver_key:
        rev_deliver_key = (deliver_key[0], deliver_key[3], deliver_key[4], deliver_key[1], deliver_key[2])
        dresp = deliver_sm_resp.get(rev_deliver_key)
        if dresp:
            used_resp_keys.add(rev_deliver_key)

    row = {
        'submit_sm_seq': sub_key[0],
        'submit_sm_time': sub['timestamp'],
        'submit_src': f"{sub['src_ip']}:{sub['src_port']}",
        'submit_dst': f"{sub['dst_ip']}:{sub['dst_port']}",
        'submit_resp_seq': resp['sequence_number'] if resp else None,
        'submit_resp_time': resp['timestamp'] if resp else None,
        'message_id': msg_id,
        'deliver_seq': deliver_key[0] if deliver_key else None,
        'deliver_time': deliver['timestamp'] if deliver else None,
        'deliver_src': f"{deliver['src_ip']}:{deliver['src_port']}" if deliver else None,
        'deliver_dst': f"{deliver['dst_ip']}:{deliver['dst_port']}" if deliver else None,
        'deliver_resp_seq': dresp['sequence_number'] if dresp else None,
        'deliver_resp_time': dresp['timestamp'] if dresp else None
    }

    if resp and deliver and dresp:
        counters['full_chains'] += 1
    else:
        counters['partial_chains'] += 1

    chain_records.append(row)

# Save outputs
pd.DataFrame(all_records).to_csv("all_smpp_packets.csv", index=False)
pd.DataFrame(chain_records).to_csv("smpp_full_chains.csv", index=False)
pd.DataFrame([counters]).to_csv("smpp_stats_summary.csv", index=False)

print("\n✅ Matching complete. Summary:")
for k, v in counters.items():
    print(f"{k.replace('_',' ').capitalize()}: {v}")
print("\n📁 Files saved:")
print("- all_smpp_packets.csv")
print("- smpp_full_chains.csv")
print("- smpp_stats_summary.csv")
