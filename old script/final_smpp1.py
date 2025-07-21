import pyshark
import pandas as pd
import os
from datetime import datetime

# Parse all files for full run
pcap_files = [
    f"v2smpp33.pcap"
    for i in range(1, 8)
]

submit_sm = {}
submit_sm_resp = {}
deliver_sm = {}
deliver_sm_resp = {}
chains = []

def get_tuple_key(pkt, seq):
    try:
        ip = pkt.ip
        tcp = pkt.tcp
        return (ip.src, tcp.srcport, ip.dst, tcp.dstport, seq)
    except:
        return None

def reverse_tuple(t):
    return (t[2], t[3], t[0], t[1], t[4])

def normalize_msg_id(msg_id):
    return msg_id.replace(' ', '').lower() if msg_id else None

def extract_message_id_from_short_message(fields):
    short_msg = fields.get('smpp.short_message') or fields.get('smpp.message_payload')
    if not short_msg:
        return None
    try:
        hex_data = short_msg.replace(':', '')
        start = hex_data.find("69643a")
        end = hex_data.find("737562")
        if start != -1 and end != -1 and end > start:
            id_hex = hex_data[start + 6:end]
            bytes_data = bytes.fromhex(id_hex)
            return bytes_data.decode('utf-8', errors='ignore')
    except:
        pass
    return None

def load_packets_from_file(file_path):
    print(f"\n🔍 Processing {file_path}")
    try:
        cap = pyshark.FileCapture(file_path, display_filter='smpp', use_json=True, include_raw=True)
    except Exception as e:
        print(f"❌ Failed to load pcap: {e}")
        return

    count = 0

    for pkt in cap:
        try:
            if 'smpp' not in pkt:
                continue

            smpp = pkt.smpp
            fields = smpp._all_fields
            command_id = fields.get('smpp.command_id')
            seq_number = int(fields.get('smpp.sequence_number', -1))
            message_id = fields.get('smpp.message_id')
            ts = pkt.sniff_time.strftime('%Y-%m-%d %H:%M:%S.%f')
            ts_raw = float(pkt.sniff_timestamp)

            key = get_tuple_key(pkt, seq_number)
            if not key:
                print(f"⚠️ Could not build key for packet #{count}")
                continue

            if command_id == '0x00000004':  # submit_sm
                submit_sm[key] = {'timestamp': ts, 'ts_raw': ts_raw}
                print(f"📨 submit_sm seq={seq_number} at {ts}")

            elif command_id == '0x80000004':  # submit_sm_resp
                reversed_key = reverse_tuple(key)
                submit_sm_resp[reversed_key] = {
                    'message_id': normalize_msg_id(message_id),
                    'timestamp': ts,
                    'ts_raw': ts_raw
                }
                print(f"📬 submit_sm_resp seq={seq_number} at {ts} msg_id={message_id}")

            elif command_id == '0x00000005':  # deliver_sm
                extracted_id = extract_message_id_from_short_message(fields)
                deliver_sm[key] = {
                    'message_id': normalize_msg_id(extracted_id),
                    'timestamp': ts,
                    'ts_raw': ts_raw
                }
                print(f"📨 deliver_sm seq={seq_number} at {ts} extracted_msg_id={extracted_id}")

            elif command_id == '0x80000005':  # deliver_sm_resp
                deliver_sm_resp[reverse_tuple(key)] = {'timestamp': ts, 'ts_raw': ts_raw}
                print(f"📬 deliver_sm_resp seq={seq_number} at {ts}")

            count += 1

        except Exception as e:
            print(f"⚠️ Error parsing packet #{count}: {e}")
            continue

    print(f"✅ Finished parsing {count} SMPP packets from {file_path}")
    cap.close()

# Parse all files
for file in pcap_files:
    if os.path.exists(file):
        load_packets_from_file(file)
    else:
        print(f"❌ File does not exist: {file}")

# Match & record
print("\n🔗 Matching packets...")
for key, req in submit_sm.items():
    resp = submit_sm_resp.get(key)
    msg_id = normalize_msg_id(resp['message_id']) if resp else None
    fallback_id = msg_id if msg_id else f"unknown_msgid_{key[4]}"
    delta_submit = round(resp['ts_raw'] - req['ts_raw'], 3) if resp else None

    chains.append({
        'type': 'submit',
        'seq': key[4],
        'message_id': fallback_id,
        'request_time': req['timestamp'],
        'response_time': resp['timestamp'] if resp else None,
        'delta_sec': delta_submit,
        'src_ip': key[0],
        'src_port': key[1],
        'dst_ip': key[2],
        'dst_port': key[3]
    })

for key, req in deliver_sm.items():
    resp = deliver_sm_resp.get(key)
    delta_deliver = round(resp['ts_raw'] - req['ts_raw'], 3) if resp else None

    chains.append({
        'type': 'deliver',
        'seq': key[4],
        'message_id': req['message_id'],
        'request_time': req['timestamp'],
        'response_time': resp['timestamp'] if resp else None,
        'delta_sec': delta_deliver,
        'src_ip': key[0],
        'src_port': key[1],
        'dst_ip': key[2],
        'dst_port': key[3]
    })

# Save chain file
chain_df = pd.DataFrame(chains)
chain_df.to_csv("combined_smpp_chain.csv", index=False)
print("\n📁 Saved chain summary to combined_smpp_chain.csv")

# Save delta stats
if not chain_df.empty and 'delta_sec' in chain_df:
    delta_df = chain_df.dropna(subset=['delta_sec'])
    delta_summary = {
        'submit_avg': delta_df[delta_df['type'] == 'submit']['delta_sec'].mean(),
        'submit_median': delta_df[delta_df['type'] == 'submit']['delta_sec'].median(),
        'deliver_avg': delta_df[delta_df['type'] == 'deliver']['delta_sec'].mean(),
        'deliver_median': delta_df[delta_df['type'] == 'deliver']['delta_sec'].median(),
    }
    pd.DataFrame([delta_summary]).to_csv("delta_summary.csv", index=False)
    print("📁 Saved delta summary to delta_summary.csv")
else:
    print("⚠️ No delta data found.")
    # 🟨 Split matched and unmatched into separate CSVs
    # 🟨 Split matched and unmatched into separate CSVs
matched_df = chain_df.dropna(subset=["response_time"])
unmatched_df = chain_df[chain_df["response_time"].isna()]

# Save them
matched_df.to_csv("matched_smpp_chain.csv", index=False)
unmatched_df.to_csv("unmatched_smpp_chain.csv", index=False)

print(f"📂 matched_smpp_chain.csv: {len(matched_df)} rows")
print(f"📂 unmatched_smpp_chain.csv: {len(unmatched_df)} rows")


# Final Stats
print("\n📊 Match Summary:")
print(f"  ✅ submit_sm matched    : {len([c for c in chains if c['type']=='submit' and c['response_time']])}")
print(f"  ❌ submit_sm unmatched  : {len([c for c in chains if c['type']=='submit' and not c['response_time']])}")
print(f"  ✅ deliver_sm matched   : {len([c for c in chains if c['type']=='deliver' and c['response_time']])}")
print(f"  ❌ deliver_sm unmatched : {len([c for c in chains if c['type']=='deliver' and not c['response_time']])}")

