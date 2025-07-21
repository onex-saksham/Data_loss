import pyshark
import pandas as pd
import struct
from datetime import datetime
import os

# Set correct tshark path
pyshark.tshark.tshark.get_tshark_path = lambda: '/usr/bin/tshark'

# Multiple PCAP files
pcap_files = [f"jul3pcap/rotation_pcap_jul3/dump.pcap0{i}" for i in range(0, 5)]

# Format for timestamps
fmt = '%d/%m/%y %H:%M:%S'
output_dir = "smpp_outputs"
os.makedirs(output_dir, exist_ok=True)

# Data stores
submit_sm = {}
submit_sm_resp = {}
deliver_sm = {}
deliver_sm_resp = {}
msgid_to_deliver = {}

all_records = []
chain_records = []
counters = {
    'submit_sm': 0,
    'submit_sm_resp': 0,
    'deliver_sm': 0,
    'deliver_sm_resp': 0,
    'full_chains': 0,
    'partial_chains': 0,
    'submit_resp_matched': 0,
    'resp_deliver_matched': 0,
    'deliver_resp_matched': 0
}

delta_submit_resp = []
delta_resp_deliver = []
delta_deliver_resp = []

def clean_payload(raw_payload):
    try:
        if isinstance(raw_payload, list):
            raw_payload = ''.join(raw_payload)
        cleaned = raw_payload.replace(':', '').replace(' ', '').strip()
        _ = bytes.fromhex(cleaned)  # Validate
        return cleaned
    except Exception as e:
        print(f"⚠️ Skipping malformed payload: {e}")
        return None

def extract_pdus_from_payload(payload_hex):
    pdus = []
    try:
        payload = bytes.fromhex(payload_hex)
    except ValueError:
        return pdus

    i = 0
    while i + 4 <= len(payload):
        try:
            pdu_len = struct.unpack('!I', payload[i:i+4])[0]
            if pdu_len < 16 or i + pdu_len > len(payload):
                break
            pdus.append(payload[i:i+pdu_len])
            i += pdu_len
        except:
            break
    return pdus

def parse_single_pdu(pdu_bytes, pkt_info):
    try:
        if len(pdu_bytes) < 16:
            return None

        cmd = f"0x{struct.unpack('!I', pdu_bytes[4:8])[0]:08x}"
        seq = str(struct.unpack('!I', pdu_bytes[12:16])[0])
        msg_id = None

        if cmd == '0x00000005':
            sm_hex = pdu_bytes.hex()
            start = sm_hex.find("69643a")  # 'id:'
            end = sm_hex.find("737562")    # 'sub'
            if start != -1 and end > start:
                try:
                    msg_id_hex = sm_hex[start+6:end]
                    msg_id = bytes.fromhex(msg_id_hex).decode('utf-8', errors='ignore').strip().lower()
                except:
                    pass

        elif cmd == '0x80000004':
            try:
                parts = pdu_bytes[16:].split(b'\x00')
                if parts:
                    msg_id = parts[0].decode('utf-8', errors='ignore').strip().lower()
            except:
                pass

        return {
            'command_id': cmd,
            'sequence_number': seq,
            'message_id': msg_id,
            'src_ip': pkt_info['src_ip'],
            'src_port': pkt_info['src_port'],
            'dst_ip': pkt_info['dst_ip'],
            'dst_port': pkt_info['dst_port'],
            'timestamp': pkt_info['timestamp']
        }

    except Exception as e:
        print(f"⚠️ parse_single_pdu error: {e}")
        return None

# Start parsing
for pcap_file in pcap_files:
    print(f"\n🔍 Parsing {pcap_file}\n")
    cap = pyshark.FileCapture(pcap_file, display_filter="smpp", use_json=True, include_raw=True, keep_packets=False)

    for pkt in cap:
        try:
            raw_payload = getattr(pkt.tcp, 'segment_data', None) or getattr(pkt.tcp, 'payload', None)
            if not raw_payload:
                continue

            payload_hex = clean_payload(raw_payload)
            if not payload_hex:
                continue

            pkt_info = {
                'src_ip': pkt.ip.src,
                'dst_ip': pkt.ip.dst,
                'src_port': pkt.tcp.srcport,
                'dst_port': pkt.tcp.dstport,
                'timestamp': datetime.fromtimestamp(float(pkt.sniff_timestamp)).strftime(fmt)
            }

            pdus = extract_pdus_from_payload(payload_hex)
            for pdu in pdus:
                rec = parse_single_pdu(pdu, pkt_info)
                if not rec:
                    continue

                all_records.append(rec)
                key = (rec['sequence_number'], rec['src_ip'], rec['src_port'], rec['dst_ip'], rec['dst_port'])
                cmd = rec['command_id']
                mid = rec['message_id']

                if cmd == '0x00000004':
                    submit_sm[key] = rec
                    counters['submit_sm'] += 1
                elif cmd == '0x80000004':
                    submit_sm_resp[key] = rec
                    counters['submit_sm_resp'] += 1
                elif cmd == '0x00000005':
                    deliver_sm[key] = rec
                    if mid:
                        msgid_to_deliver.setdefault(mid, []).append((key, rec))
                    counters['deliver_sm'] += 1
                elif cmd == '0x80000005':
                    deliver_sm_resp[key] = rec
                    counters['deliver_sm_resp'] += 1
        except Exception as e:
            print(f"⚠️ Error parsing packet: {e}")

    cap.close()

# Match chains
for sub_key, sub in submit_sm.items():
    rev_key = (sub_key[0], sub_key[3], sub_key[4], sub_key[1], sub_key[2])
    resp = submit_sm_resp.get(rev_key)
    if resp:
        counters['submit_resp_matched'] += 1

    msg_id = resp['message_id'] if resp else None

    drec = None
    dkey = None
    if msg_id:
        for dk, v in msgid_to_deliver.get(msg_id, []):
            if dk[1:] == rev_key[1:]:
                dkey = dk
                drec = v
                counters['resp_deliver_matched'] += 1
                break

    dresp = None
    if dkey:
        rev_dkey = (dkey[0], dkey[3], dkey[4], dkey[1], dkey[2])
        dresp = deliver_sm_resp.get(rev_dkey)
        if dresp:
            counters['deliver_resp_matched'] += 1

    row = {
        'submit_sm_seq': sub_key[0],
        'submit_sm_time': sub['timestamp'],
        'submit_src': f"{sub['src_ip']}:{sub['src_port']}",
        'submit_dst': f"{sub['dst_ip']}:{sub['dst_port']}",
        'submit_resp_seq': resp['sequence_number'] if resp else None,
        'submit_resp_time': resp['timestamp'] if resp else None,
        'submit_resp_src': f"{resp['src_ip']}:{resp['src_port']}" if resp else None,
        'submit_resp_dst': f"{resp['dst_ip']}:{resp['dst_port']}" if resp else None,
        'message_id': msg_id,
        'deliver_seq': dkey[0] if dkey else None,
        'deliver_time': drec['timestamp'] if drec else None,
        'deliver_src': f"{drec['src_ip']}:{drec['src_port']}" if drec else None,
        'deliver_dst': f"{drec['dst_ip']}:{drec['dst_port']}" if drec else None,
        'deliver_resp_seq': dresp['sequence_number'] if dresp else None,
        'deliver_resp_time': dresp['timestamp'] if dresp else None,
        'deliver_resp_src': f"{dresp['src_ip']}:{dresp['src_port']}" if dresp else None,
        'deliver_resp_dst': f"{dresp['dst_ip']}:{dresp['dst_port']}" if dresp else None
    }

    if resp and drec and dresp:
        counters['full_chains'] += 1
    else:
        counters['partial_chains'] += 1

    try:
        if resp:
            delta_submit_resp.append((datetime.strptime(resp['timestamp'], fmt) - datetime.strptime(sub['timestamp'], fmt)).total_seconds())
        if resp and drec:
            delta_resp_deliver.append((datetime.strptime(drec['timestamp'], fmt) - datetime.strptime(resp['timestamp'], fmt)).total_seconds())
        if drec and dresp:
            delta_deliver_resp.append((datetime.strptime(dresp['timestamp'], fmt) - datetime.strptime(drec['timestamp'], fmt)).total_seconds())
    except:
        pass

    chain_records.append(row)

# Save CSVs
pd.DataFrame(all_records).to_csv(os.path.join(output_dir, "all_smpp_packets.csv"), index=False)
pd.DataFrame(chain_records).to_csv(os.path.join(output_dir, "smpp_full_chains.csv"), index=False)
pd.DataFrame([counters]).to_csv(os.path.join(output_dir, "smpp_stats_summary.csv"), index=False)

# ✅ Additional requested CSVs
full_chain_only = [row for row in chain_records if row['submit_resp_seq'] and row['deliver_seq'] and row['deliver_resp_seq']]
submit_unmatched = [rec for key, rec in submit_sm.items() if not any((key[0], key[3], key[4], key[1], key[2]) == rkey for rkey in submit_sm_resp)]
deliver_not_in_chains = [rec for key, rec in deliver_sm.items() if not any(row['deliver_seq'] == key[0] for row in chain_records)]
submit_resp_no_delivery = [row for row in chain_records if row['submit_resp_seq'] and not row['deliver_seq']]
deliver_no_resp = [rec for key, rec in deliver_sm.items() if not any((key[0], key[3], key[4], key[1], key[2]) == dkey for dkey in deliver_sm_resp)]

pd.DataFrame(full_chain_only).to_csv(os.path.join(output_dir, "full_chain_records.csv"), index=False)
pd.DataFrame(submit_unmatched).to_csv(os.path.join(output_dir, "submit_sm_unmatched.csv"), index=False)
pd.DataFrame(deliver_not_in_chains).to_csv(os.path.join(output_dir, "deliver_only_records.csv"), index=False)
pd.DataFrame(submit_resp_no_delivery).to_csv(os.path.join(output_dir, "submit_chain_no_delivery.csv"), index=False)
pd.DataFrame(deliver_no_resp).to_csv(os.path.join(output_dir, "deliver_no_resp.csv"), index=False)

# Stats
print("\n✅ Chain matching complete. Summary:")
for k, v in counters.items():
    print(f"  {k}: {v}")

def print_stats(name, data):
    if data:
        avg = round(sum(data) / len(data), 6)
        median = round(sorted(data)[len(data)//2], 6)
        print(f"\n⏱ {name} deltas:\n  Avg   : {avg}s\n  Median: {median}s")
    else:
        print(f"\n⚠️ No {name} delta data.")

print_stats("Submit→Resp", delta_submit_resp)
print_stats("Resp→Deliver", delta_resp_deliver)
print_stats("Deliver→Resp", delta_deliver_resp)

print(f"\n📁 Files saved to: {output_dir}")
