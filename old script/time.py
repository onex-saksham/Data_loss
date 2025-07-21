import pyshark
import pandas as pd
import os
from datetime import datetime

pyshark.tshark.tshark.get_tshark_path = lambda: '/usr/bin/tshark'

pcap_files = [
    "jul3pcap/rotation_pcap_jul3/dump.pcap00",
    # "jul3pcap/rotation_pcap_jul3/dump.pcap01",
    # "jul3pcap/rotation_pcap_jul3/dump.pcap02",
    # "jul3pcap/rotation_pcap_jul3/dump.pcap03",
    # "jul3pcap/rotation_pcap_jul3/dump.pcap04",
    # "jul3pcap/rotation_pcap_jul3/dump.pcap05",
    # "jul3pcap/rotation_pcap_jul3/dump.pcap06",
    # "jul3pcap/rotation_pcap_jul3/dump.pcap07"
]

chains = {}

def normalize_msg_id(msg_id):
    return msg_id.strip().lower() if msg_id else None

def extract_message_id_from_short_message(fields):
    try:
        hex_field = fields.get('smpp.message_raw')
        if isinstance(hex_field, list):
            hex_str = hex_field[0]
        elif isinstance(hex_field, str):
            hex_str = hex_field
        else:
            return None

        hex_str = hex_str.replace(':', '').replace(' ', '').lower()
        start = hex_str.find('69643a')
        end = hex_str.find('737562')

        if start != -1 and end != -1 and end > start:
            msg_id_hex = hex_str[start + 6:end]
            ascii_id = bytearray.fromhex(msg_id_hex).decode('ascii', errors='ignore').strip()
            return ascii_id
    except Exception as e:
        print(f"[ERROR] message_id extraction failed: {e}")
    return None

for pcap_file in pcap_files:
    print(f"🔍 Processing {pcap_file}")
    try:
        cap = pyshark.FileCapture(
            pcap_file,
            display_filter='smpp',
            use_json=True,
            include_raw=True
        )

        submit_sm = {}
        submit_sm_resp = {}
        deliver_sm = {}
        deliver_sm_resp = {}

        for packet in cap:
            try:
                smpp = packet['smpp']
                fields = smpp._all_fields
                command_id = fields.get('smpp.command_id')
                seq_number = fields.get('smpp.sequence_number')
                message_id = fields.get('smpp.message_id')
                timestamp_raw = float(packet.sniff_timestamp)
                timestamp = datetime.fromtimestamp(timestamp_raw).strftime('%d/%m/%y %H:%M:%S')

                if command_id == '0x00000004':
                    submit_sm[seq_number] = {'timestamp': timestamp, 'ts_raw': timestamp_raw}
                elif command_id == '0x80000004':
                    submit_sm_resp[seq_number] = {
                        'message_id': normalize_msg_id(message_id),
                        'timestamp': timestamp,
                        'ts_raw': timestamp_raw
                    }
                elif command_id == '0x00000005':
                    extracted_id = extract_message_id_from_short_message(fields)
                    deliver_sm[seq_number] = {
                        'message_id': normalize_msg_id(extracted_id),
                        'timestamp': timestamp,
                        'ts_raw': timestamp_raw
                    }
                elif command_id == '0x80000005':
                    deliver_sm_resp[seq_number] = {'timestamp': timestamp, 'ts_raw': timestamp_raw}
            except Exception as e:
                print(f"⚠️ Error parsing packet: {e}")
                continue

        for seq, req in submit_sm.items():
            if seq not in submit_sm_resp:
                continue  # Skip if there's no matching submit_sm_resp with same seq

            resp = submit_sm_resp[seq]
            msg_id = normalize_msg_id(resp['message_id']) if resp else None
            fallback_id = msg_id if msg_id else f"unknown_msgid_{seq}"
            delta_submit = round(resp['ts_raw'] - req['ts_raw'], 3) if resp else None

            if fallback_id not in chains:
                chains[fallback_id] = {
                    'msg_id/Teckco': fallback_id,
                    'submit_sm': seq,
                    'submit_sm_time': req['timestamp'],
                    'submit_response': seq if resp else None,
                    'submit_response_time': resp['timestamp'] if resp else None,
                    'submit_delta': delta_submit
                }
            else:
                chains[fallback_id].update({
                    'submit_sm': seq,
                    'submit_sm_time': req['timestamp'],
                    'submit_response': seq if resp else None,
                    'submit_response_time': resp['timestamp'] if resp else None,
                    'submit_delta': delta_submit
                })

        for seq, d in deliver_sm.items():
            msg_id = d['message_id']
            if not msg_id:
                continue

            if seq not in deliver_sm_resp:
                continue  # Skip if there's no matching deliver_sm_resp with same seq

            delta_deliver = round(deliver_sm_resp[seq]['ts_raw'] - d['ts_raw'], 3)

            if msg_id not in chains:
                chains[msg_id] = {
                    'msg_id/Teckco': msg_id,
                    'deliver_sm': seq,
                    'deliver_sm_time': d['timestamp'],
                    'deliver_sm_resp': seq,
                    'deliver_sm_resp_time': deliver_sm_resp[seq]['timestamp'],
                    'deliver_delta': delta_deliver
                }
            else:
                chains[msg_id].update({
                    'deliver_sm': seq,
                    'deliver_sm_time': d['timestamp'],
                    'deliver_sm_resp': seq,
                    'deliver_sm_resp_time': deliver_sm_resp[seq]['timestamp'],
                    'deliver_delta': delta_deliver
                })

        cap.close()
        del cap

    except Exception as e:
        print(f"❌ Error loading {pcap_file}: {e}")

columns = [
    'msg_id/Teckco',
    'submit_sm', 'submit_sm_time',
    'submit_response', 'submit_response_time',
    'submit_delta',
    'deliver_sm', 'deliver_sm_time',
    'deliver_sm_resp', 'deliver_sm_resp_time',
    'deliver_delta'
]

df = pd.DataFrame(list(chains.values()), columns=columns)
df.to_csv("Xcombined_smpp_chain.csv", index=False)

summary_data = {
    'submit_avg_delta': df['submit_delta'].dropna().mean(),
    'submit_median_delta': df['submit_delta'].dropna().median(),
    'deliver_avg_delta': df['deliver_delta'].dropna().mean(),
    'deliver_median_delta': df['deliver_delta'].dropna().median()
}

pd.DataFrame([summary_data]).to_csv("delta_summary.csv", index=False)

print("\n✅ DONE! All PCAPs processed. Output saved as 'Xcombined_smpp_chain.csv' and 'delta_summary.csv'")
import pyshark
import pandas as pd

# Force correct tshark path
pyshark.tshark.tshark.get_tshark_path = lambda: '/usr/bin/tshark'

pcap_file = 'jul3pcap/rotation_pcap_jul3/dump.pcap03'
cap = pyshark.FileCapture(
    pcap_file,
    display_filter='smpp',
    use_json=True,
    include_raw=True
)

# Storage
submit_sm = {}
submit_sm_resp = {}
deliver_sm = {}
deliver_sm_resp = {}

matched_records = []
unmatched_records = []

# Counters
counters = {
    'submit_sm': 0,
    'submit_sm_resp': 0,
    'deliver_sm': 0,
    'deliver_sm_resp': 0,
    'matched_submit_seq': 0,
    'unmatched_submit_seq': 0,
    'matched_submit_msgid': 0,
    'unmatched_submit_msgid': 0,
    'matched_deliver_seq': 0,
    'unmatched_deliver_seq': 0,
}

def normalize_msg_id(msg_id):
    return msg_id.strip().lower() if msg_id else None

def extract_message_id_from_short_message(fields):
    try:
        hex_field = fields.get('smpp.message_raw')
        if isinstance(hex_field, list):
            hex_str = hex_field[0]
        elif isinstance(hex_field, str):
            hex_str = hex_field
        else:
            return None

        hex_str = hex_str.replace(':', '').replace(' ', '').lower()
        start = hex_str.find('69643a')  # 'id:'
        end = hex_str.find('737562')   # 'sub'
        if start != -1 and end != -1 and end > start:
            msg_id_hex = hex_str[start + 6:end]
            ascii_id = bytearray.fromhex(msg_id_hex).decode('ascii', errors='ignore').strip()
            return ascii_id
    except Exception as e:
        print(f"[ERROR] Failed to extract message_id: {e}")
    return None

def response_within_threshold(ts1, ts2, threshold=2):
    return abs(ts2 - ts1) <= threshold

# Parse packets
for packet in cap:
    try:
        smpp = packet['smpp']
        fields = smpp._all_fields
        command_id = fields.get('smpp.command_id')
        seq_number = fields.get('smpp.sequence_number')
        message_id = fields.get('smpp.message_id')
        timestamp = float(packet.sniff_timestamp)

        if command_id == '0x00000004':
            counters['submit_sm'] += 1
            submit_sm[seq_number] = {'type': 'submit_sm', 'message_id': None, 'timestamp': timestamp}

        elif command_id == '0x80000004':
            counters['submit_sm_resp'] += 1
            submit_sm_resp[seq_number] = {
                'type': 'submit_sm_resp',
                'message_id': normalize_msg_id(message_id),
                'timestamp': timestamp
            }

        elif command_id == '0x00000005':
            counters['deliver_sm'] += 1
            extracted_id = extract_message_id_from_short_message(fields)
            deliver_sm[seq_number] = {
                'type': 'deliver_sm',
                'message_id': normalize_msg_id(extracted_id),
                'timestamp': timestamp
            }
            print(f"[DEBUG] deliver_sm {seq_number} → message_id: {extracted_id}")

        elif command_id == '0x80000005':
            counters['deliver_sm_resp'] += 1
            deliver_sm_resp[seq_number] = {
                'type': 'deliver_sm_resp',
                'message_id': normalize_msg_id(message_id),
                'timestamp': timestamp
            }

    except Exception as e:
        print(f"⚠️ Error parsing packet: {e}")
        continue

# 1. Match submit_sm ↔ submit_sm_resp (within 2 seconds)
for seq in set(submit_sm.keys()).union(submit_sm_resp.keys()):
    req = submit_sm.get(seq)
    resp = submit_sm_resp.get(seq)
    if req and resp:
        if response_within_threshold(req['timestamp'], resp['timestamp']):
            counters['matched_submit_seq'] += 1
            matched_records.append({
                'match_type': 'submit_sm ↔ submit_sm_resp',
                'sequence_number': seq,
                'request_type': req['type'],
                'response_type': resp['type'],
                'message_id': resp['message_id']
            })
        else:
            counters['unmatched_submit_seq'] += 1
            unmatched_records.append({
                'unmatched_type': 'submit_sm_resp timeout (>2s)',
                'sequence_number': seq,
                'message_id': resp['message_id']
            })
    else:
        counters['unmatched_submit_seq'] += 1
        unmatched_records.append({
            'unmatched_type': 'submit_sm_resp missing' if req else 'submit_sm missing',
            'sequence_number': seq,
            'message_id': resp['message_id'] if resp else None
        })

# 2. Match submit_sm_resp ↔ deliver_sm by message_id
used_delivery_seq = set()
for seq, resp in submit_sm_resp.items():
    msg_id = normalize_msg_id(resp['message_id'])
    if not msg_id:
        counters['unmatched_submit_msgid'] += 1
        unmatched_records.append({
            'unmatched_type': 'submit_sm_resp missing message_id',
            'sequence_number': seq,
            'message_id': None
        })
        continue
    matched = False
    for dseq, deliver in deliver_sm.items():
        if normalize_msg_id(deliver['message_id']) == msg_id and dseq not in used_delivery_seq:
            matched = True
            counters['matched_submit_msgid'] += 1
            matched_records.append({
                'match_type': 'submit_sm_resp ↔ deliver_sm (msg_id)',
                'sequence_number': f"{seq} ↔ {dseq}",
                'request_type': 'submit_sm_resp',
                'response_type': 'deliver_sm',
                'message_id': msg_id
            })
            used_delivery_seq.add(dseq)
            break
    if not matched:
        counters['unmatched_submit_msgid'] += 1
        unmatched_records.append({
            'unmatched_type': 'deliver_sm missing for message_id',
            'sequence_number': seq,
            'message_id': msg_id
        })

# 3. Match deliver_sm ↔ deliver_sm_resp (within 2 seconds)
for seq in set(deliver_sm.keys()).union(deliver_sm_resp.keys()):
    req = deliver_sm.get(seq)
    resp = deliver_sm_resp.get(seq)
    if req and resp:
        if response_within_threshold(req['timestamp'], resp['timestamp']):
            counters['matched_deliver_seq'] += 1
            matched_records.append({
                'match_type': 'deliver_sm ↔ deliver_sm_resp',
                'sequence_number': seq,
                'request_type': req['type'],
                'response_type': resp['type'],
                'message_id': req['message_id']
            })
        else:
            counters['unmatched_deliver_seq'] += 1
            unmatched_records.append({
                'unmatched_type': 'deliver_sm_resp timeout (>2s)',
                'sequence_number': seq,
                'message_id': req['message_id']
            })
    else:
        counters['unmatched_deliver_seq'] += 1
        unmatched_records.append({
            'unmatched_type': 'deliver_sm_resp missing' if req else 'deliver_sm missing',
            'sequence_number': seq,
            'message_id': req['message_id'] if req else (resp['message_id'] if resp else None)
        })

# Save results
pd.DataFrame(matched_records).to_csv('matched_smpp.csv', index=False)
pd.DataFrame(unmatched_records).to_csv('unmatched_smpp.csv', index=False)

# Summary
print("\n=== Summary ===")
for key, value in counters.items():
    print(f"{key.replace('_', ' ').capitalize()}: {value}")
print("\n✅ Matched records saved to 'matched_smpp.csv'")
print("⚠️ Unmatched records saved to 'unmatched_smpp.csv'")
