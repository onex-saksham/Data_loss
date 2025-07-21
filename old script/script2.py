import pyshark
import pandas as pd
import os
from datetime import datetime

pyshark.tshark.tshark.get_tshark_path = lambda: '/usr/bin/tshark'

pcap_files = [
    "jul3pcap/rotation_pcap_jul3/dump.pcap00",
]

chains = {}

# Count packets
counters = {
    "submit_sm": 0,
    "submit_sm_resp": 0,
    "deliver_sm": 0,
    "deliver_sm_resp": 0,
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
        start = hex_str.find('69643a')
        end = hex_str.find('737562')
        if start != -1 and end != -1 and end > start:
            msg_id_hex = hex_str[start + 6:end]
            ascii_id = bytearray.fromhex(msg_id_hex).decode('ascii', errors='ignore').strip()
            return ascii_id
    except Exception as e:
        print(f"[ERROR] message_id extraction failed: {e}")
    return None

def time_diff_ok(t1, t2, threshold=2):
    try:
        dt1 = datetime.strptime(t1, "%d/%m/%y %H:%M:%S")
        dt2 = datetime.strptime(t2, "%d/%m/%y %H:%M:%S")
        return abs((dt2 - dt1).total_seconds()) > threshold
    except:
        return False

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
                timestamp = datetime.fromtimestamp(float(packet.sniff_timestamp)).strftime('%d/%m/%y %H:%M:%S')

                if command_id == '0x00000004':
                    submit_sm[seq_number] = {'timestamp': timestamp}
                    counters["submit_sm"] += 1

                elif command_id == '0x80000004':
                    submit_sm_resp[seq_number] = {
                        'message_id': normalize_msg_id(message_id),
                        'timestamp': timestamp
                    }
                    counters["submit_sm_resp"] += 1

                elif command_id == '0x00000005':
                    extracted_id = extract_message_id_from_short_message(fields)
                    deliver_sm[seq_number] = {
                        'message_id': normalize_msg_id(extracted_id),
                        'timestamp': timestamp
                    }
                    counters["deliver_sm"] += 1

                elif command_id == '0x80000005':
                    deliver_sm_resp[seq_number] = {'timestamp': timestamp}
                    counters["deliver_sm_resp"] += 1

            except Exception as e:
                print(f"⚠️ Error parsing packet: {e}")
                continue

        for seq, req in submit_sm.items():
            resp = submit_sm_resp.get(seq)
            if resp and time_diff_ok(req['timestamp'], resp['timestamp']):
                msg_id = normalize_msg_id(resp['message_id']) if resp else None
                fallback_id = msg_id if msg_id else f"unknown_msgid_{seq}"
                if fallback_id not in chains:
                    chains[fallback_id] = {
                        'msg_id/Teckco': fallback_id,
                        'submit_sm': seq,
                        'submit_sm_time': req['timestamp'],
                        'submit_response': seq,
                        'submit_response_time': resp['timestamp']
                    }
                else:
                    chains[fallback_id].update({
                        'submit_sm': seq,
                        'submit_sm_time': req['timestamp'],
                        'submit_response': seq,
                        'submit_response_time': resp['timestamp']
                    })

        for seq, d in deliver_sm.items():
            msg_id = d['message_id']
            if not msg_id:
                continue
            chain = chains.get(msg_id)
            if chain and time_diff_ok(chain.get('submit_response_time', '01/01/00 00:00:00'), d['timestamp']):
                chain.update({
                    'deliver_sm': seq,
                    'deliver_sm_time': d['timestamp']
                })
            else:
                chains[msg_id] = {
                    'msg_id/Teckco': msg_id,
                    'deliver_sm': seq,
                    'deliver_sm_time': d['timestamp']
                }

        for seq, d in deliver_sm.items():
            if seq in deliver_sm_resp:
                msg_id = d.get('message_id')
                if not msg_id:
                    continue
                resp_time = deliver_sm_resp[seq]['timestamp']
                if time_diff_ok(d['timestamp'], resp_time):
                    if msg_id not in chains:
                        chains[msg_id] = {
                            'msg_id/Teckco': msg_id,
                            'deliver_sm': seq,
                            'deliver_sm_time': d['timestamp'],
                            'deliver_sm_resp': seq,
                            'deliver_sm_resp_time': resp_time
                        }
                    else:
                        chains[msg_id].update({
                            'deliver_sm_resp': seq,
                            'deliver_sm_resp_time': resp_time
                        })

        cap.close()
        del cap
    except Exception as e:
        print(f"❌ Error loading {pcap_file}: {e}")

# Final output
columns = [
    'msg_id/Teckco',
    'submit_sm', 'submit_sm_time',
    'submit_response', 'submit_response_time',
    'deliver_sm', 'deliver_sm_time',
    'deliver_sm_resp', 'deliver_sm_resp_time'
]

df = pd.DataFrame(list(chains.values()), columns=columns)
df.to_csv("combined_smpp_chain.csv", index=False)

print("\n✅ DONE! All PCAPs processed. Output saved as 'combined_smpp_chain.csv'")
print("\n📊 Counters:")
for k, v in counters.items():
    print(f"{k}: {v}")
