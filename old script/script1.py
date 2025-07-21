import pyshark
import pandas as pd
from datetime import datetime

pyshark.tshark.tshark.get_tshark_path = lambda: '/usr/bin/tshark'

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

def connection_key(pkt):
    return (pkt['src_ip'], pkt['src_port'], pkt['dst_ip'], pkt['dst_port'])

# Stores
all_records = []
matched = []

submit_sm = {}
submit_sm_resp = {}
deliver_sm = {}
deliver_sm_resp = {}
msgid_to_deliver = {}

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

# Load packets first
for file in pcap_files:
    print(f"🔍 Processing {file}")
    try:
        cap = pyshark.FileCapture(
            file,
            display_filter="smpp",
            use_json=True,
            include_raw=True,
            keep_packets=False  # Helps avoid memory blow-up
        )

        for pkt in cap:
            try:
                smpp = pkt['smpp']
                fields = smpp._all_fields

                cmd = fields.get('smpp.command_id')
                seq = fields.get('smpp.sequence_number')
                msg_id = normalize(fields.get('smpp.message_id'))

                src_ip = pkt.ip.src
                dst_ip = pkt.ip.dst
                src_port = pkt.tcp.srcport
                dst_port = pkt.tcp.dstport
                timestamp = datetime.fromtimestamp(float(pkt.sniff_timestamp)).strftime('%d/%m/%y %H:%M:%S')

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
                key = (seq, src_ip, src_port, dst_ip, dst_port)

                if cmd == '0x00000004':
                    submit_sm[key] = record
                    counters['submit_sm'] += 1
                elif cmd == '0x80000004':
                    submit_sm_resp[key] = record
                    counters['submit_sm_resp'] += 1
                elif cmd == '0x00000005':
                    deliver_sm[key] = record
                    msgid_to_deliver.setdefault(msg_id, []).append((key, record))
                    counters['deliver_sm'] += 1
                elif cmd == '0x80000005':
                    deliver_sm_resp[key] = record
                    counters['deliver_sm_resp'] += 1

            except Exception as e:
                continue

        cap.close()

    except Exception as e:
        print(f"❌ Failed to parse {file}: {e}")

# Match 1: submit_sm ↔ submit_sm_resp (by seq + connection)
for key in submit_sm:
    if key in submit_sm_resp:
        matched.append({
            'match_type': 'submit_sm ↔ submit_sm_resp',
            'sequence_number': key[0],
            'message_id': submit_sm_resp[key]['message_id'],
            'src_ip': key[1], 'src_port': key[2],
            'dst_ip': key[3], 'dst_port': key[4],
            'timestamp_req': submit_sm[key]['timestamp'],
            'timestamp_resp': submit_sm_resp[key]['timestamp']
        })
        counters['matched_submit_pair'] += 1
    else:
        counters['unmatched_submit_seq'] += 1

# Match 2: submit_sm_resp ↔ deliver_sm (by msg_id + connection)
for key, resp in submit_sm_resp.items():
    msg_id = resp['message_id']
    if not msg_id:
        counters['unmatched_submit_msgid'] += 1
        continue

    possible_delivers = msgid_to_deliver.get(msg_id, [])
    found = False
    for dkey, drec in possible_delivers:
        if connection_key(resp) == connection_key(drec):
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

# Match 3: deliver_sm ↔ deliver_sm_resp (by seq + connection)
for key in deliver_sm:
    if key in deliver_sm_resp:
        matched.append({
            'match_type': 'deliver_sm ↔ deliver_sm_resp',
            'sequence_number': key[0],
            'message_id': deliver_sm[key]['message_id'],
            'src_ip': key[1], 'src_port': key[2],
            'dst_ip': key[3], 'dst_port': key[4],
            'timestamp_req': deliver_sm[key]['timestamp'],
            'timestamp_resp': deliver_sm_resp[key]['timestamp']
        })
        counters['matched_deliver_pair'] += 1
    else:
        counters['unmatched_deliver_seq'] += 1

# Save everything
pd.DataFrame(all_records).to_csv("all_smpp_packets.csv", index=False)
pd.DataFrame(matched).to_csv("matched_smpp.csv", index=False)
pd.DataFrame([counters]).to_csv("smpp_stats_summary.csv", index=False)

print("\n✅ Summary:")
for key, val in counters.items():
    print(f"{key.replace('_',' ').capitalize()}: {val}")
print("📁 Output:")
print("- all_smpp_packets.csv")
print("- matched_smpp.csv")
print("- smpp_stats_summary.csv")
