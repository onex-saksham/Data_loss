import pyshark
import pandas as pd
import struct
from datetime import datetime
import os

# Ensure TShark path is correct
pyshark.tshark.tshark.get_tshark_path = lambda: '/usr/bin/tshark'

# Prepare file list with zero-padded filenames (00–12)
pcap_files = [f'jio1131/dump.pcap{str(i).zfill(2)}' for i in range(22)]

# Format for timestamps
fmt = '%d/%m/%y %H:%M:%S'

# SMPP packet containers
submit_sm = {}
submit_sm_resp = {}
deliver_sm = {}
deliver_sm_resp = {}
msgid_to_deliver = {}

# Output collections
all_records = []
chain_records = []

# Counters
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

# Tracking unmatched types
extra_submit_no_resp = []
extra_submit_and_resp_no_deliver = []
extra_deliver_resp_matched_pairs = []
extra_deliver_unmatched_submit = []
extra_deliver_no_resp = []

# Delta times
delta_submit_resp = []
delta_resp_deliver = []
delta_deliver_resp = []

def clean_payload(raw_payload):
    try:
        if isinstance(raw_payload, list):
            raw_payload = ''.join(raw_payload)
        return raw_payload.replace(':', '').replace(' ', '').strip()
    except:
        return None

def extract_pdus_from_payload(payload_hex):
    pdus = []
    try:
        payload = bytes.fromhex(payload_hex)
        i = 0
        while i + 4 <= len(payload):
            pdu_len = struct.unpack('!I', payload[i:i+4])[0]
            if pdu_len < 16 or i + pdu_len > len(payload):
                break
            pdus.append(payload[i:i+pdu_len])
            i += pdu_len
    except:
        pass
    return pdus

def parse_single_pdu(pdu_bytes, pkt_info):
    try:
        if len(pdu_bytes) < 16:
            return None
        cmd = f"0x{struct.unpack('!I', pdu_bytes[4:8])[0]:08x}"
        seq = str(struct.unpack('!I', pdu_bytes[12:16])[0])
        msg_id = None

        if cmd == '0x00000005':  # deliver_sm
            sm_hex = pdu_bytes.hex()
            start = sm_hex.find("69643a")  # 'id:'
            end = sm_hex.find("737562")    # 'sub'
            if start != -1 and end > start:
                try:
                    msg_id_hex = sm_hex[start+6:end]
                    msg_id = bytes.fromhex(msg_id_hex).decode('utf-8', errors='ignore').strip().lower()
                except:
                    pass

        elif cmd == '0x80000004':  # submit_sm_resp
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

    except:
        return None

# Begin parsing all pcap files
for pcap_file in pcap_files:
    if not os.path.exists(pcap_file):
        print(f"⚠️ File not found: {pcap_file}")
        continue

    print(f"🔍 Parsing {pcap_file}")
    try:
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

                for pdu in extract_pdus_from_payload(payload_hex):
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
                print(f"⚠️ Packet error: {e}")
        cap.close()
    except Exception as e:
        print(f"❌ Failed to process {pcap_file}: {e}")

# Chain matching logic (unchanged)
for sub_key, sub in submit_sm.items():
    rev_key = (sub_key[0], sub_key[3], sub_key[4], sub_key[1], sub_key[2])
    resp = submit_sm_resp.get(rev_key)
    if resp:
        counters['submit_resp_matched'] += 1

    msg_id = resp['message_id'] if resp else None

    drec, dkey = None, None
    if msg_id:
        for dk, v in msgid_to_deliver.get(msg_id, []):
            if dk[1:] == rev_key[1:]:
                dkey, drec = dk, v
                counters['resp_deliver_matched'] += 1
                break

    dresp = deliver_sm_resp.get((dkey[0], dkey[3], dkey[4], dkey[1], dkey[2])) if dkey else None
    if dresp:
        counters['deliver_resp_matched'] += 1

    chain_records.append({
        'submit_sm_seq': sub_key[0],
        'submit_sm_time': sub['timestamp'],
        'submit_src': f"{sub['src_ip']}:{sub['src_port']}",
        'submit_dst': f"{sub['dst_ip']}:{sub['dst_port']}",
        'submit_resp_seq': resp['sequence_number'] if resp else None,
        'submit_resp_time': resp['timestamp'] if resp else None,
        'message_id': msg_id,
        'deliver_seq': dkey[0] if dkey else None,
        'deliver_time': drec['timestamp'] if drec else None,
        'deliver_resp_seq': dresp['sequence_number'] if dresp else None,
        'deliver_resp_time': dresp['timestamp'] if dresp else None
    })

    if resp:
        delta_submit_resp.append((datetime.strptime(resp['timestamp'], fmt) - datetime.strptime(sub['timestamp'], fmt)).total_seconds())
    if resp and drec:
        delta_resp_deliver.append((datetime.strptime(drec['timestamp'], fmt) - datetime.strptime(resp['timestamp'], fmt)).total_seconds())
    if drec and dresp:
        delta_deliver_resp.append((datetime.strptime(dresp['timestamp'], fmt) - datetime.strptime(drec['timestamp'], fmt)).total_seconds())

# Final unmatched deliver_sm matching
for dkey, drec in deliver_sm.items():
    rev_key = (dkey[0], dkey[3], dkey[4], dkey[1], dkey[2])
    dresp = deliver_sm_resp.get(rev_key)
    if dresp:
        extra_deliver_resp_matched_pairs.append({**drec, **dresp})

# Save outputs
pd.DataFrame(all_records).to_csv("all_smpp_packets.csv", index=False)
pd.DataFrame(chain_records).to_csv("smpp_full_chains.csv", index=False)
pd.DataFrame([counters]).to_csv("smpp_stats_summary.csv", index=False)

pd.DataFrame(extra_deliver_resp_matched_pairs).to_csv("deliver_resp_matched.csv", index=False)

print("\n✅ Completed parsing and matching. Summary:")
for k, v in counters.items():
    print(f"  {k}: {v}")
