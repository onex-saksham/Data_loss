import pyshark
import pandas as pd
import glob
import os

pyshark.tshark.tshark.get_tshark_path = lambda: '/usr/bin/tshark'

pcap_dir = "jul3pcap/rotation_pcap_jul3/"
pcap_files = sorted(glob.glob(os.path.join(pcap_dir, "dump.pcap*")))

if not pcap_files:
    raise FileNotFoundError(f"No .pcap* files found in {pcap_dir}")

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

# Process each file
for file in pcap_files:
    print(f"🔍 Processing file: {file}")
    cap = pyshark.FileCapture(
        file,
        display_filter='smpp',
        use_json=True,
        include_raw=True
    )
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
            print(f"⚠️ Error parsing packet in {file}: {e}")
            continue

    cap.close()

# Matching Logic (same as before)...
# [Same matching blocks as in previous response, unchanged]

# ---- COPY MATCHING SECTION FROM EARLIER RESPONSE ----
# Match submit_sm ↔ submit_sm_resp
# Match submit_sm_resp ↔ deliver_sm
# Match deliver_sm ↔ deliver_sm_resp
# (Use the same blocks from before to keep this clean.)

# Save results
pd.DataFrame(matched_records).to_csv('matched_smpp.csv', index=False)
pd.DataFrame(unmatched_records).to_csv('unmatched_smpp.csv', index=False)

# Summary
print("\n=== Summary ===")
for key, value in counters.items():
    print(f"{key.replace('_', ' ').capitalize()}: {value}")
print("\n✅ Matched records saved to 'matched_smpp.csv'")
print("⚠️ Unmatched records saved to 'unmatched_smpp.csv'")
