import pyshark
import pandas as pd
import struct
from datetime import datetime
import os
import glob
# Set tshark path if needed
pyshark.tshark.tshark.get_tshark_path = lambda: '/usr/bin/tshark'
 
# Load PCAP files (0 to 7 only)
pcap_files = sorted(glob.glob("*.pcap*"))
 
# Timestamp format
fmt = '%d/%m/%y %H:%M:%S'
 
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
        _ = bytes.fromhex(cleaned)
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
 
    except Exception as e:
        print(f"⚠️ parse_single_pdu error: {e}")
        return None
 
# Start parsing PCAPs
for pcap_file in pcap_files:
    print(f"\n🔍 Parsing {pcap_file}")
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
 
    except Exception as e:
        print(f"❌ Skipping file due to error: {pcap_file}")
        print(f"   ↳ Reason: {e}")
        continue
 
# Match chains
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
 
 
# Prepare final output lists
matched_chains = []
submit_resp_no_submit = []
deliver_pair_no_submit_resp = []
submit_chain_no_deliver = []
deliver_no_response = []
 
for row in chain_records:
    if row['submit_resp_seq'] and row['deliver_seq'] and row['deliver_resp_seq']:
        matched_chains.append(row)
    elif row['submit_resp_seq'] and not row['deliver_seq']:
        submit_chain_no_deliver.append(row)
 
for key, resp in submit_sm_resp.items():
    rev_key = (key[0], key[3], key[4], key[1], key[2])
    if rev_key not in submit_sm:
        submit_resp_no_submit.append({
            'sequence_number': resp['sequence_number'],
            'timestamp': resp['timestamp'],
            'src': f"{resp['src_ip']}:{resp['src_port']}",
            'dst': f"{resp['dst_ip']}:{resp['dst_port']}"
        })
 
seen_msg_ids = {resp['message_id'] for resp in submit_sm_resp.values()}
for dkey, dsm in deliver_sm.items():
    rev_dkey = (dkey[0], dkey[3], dkey[4], dkey[1], dkey[2])
    dresp = deliver_sm_resp.get(rev_dkey)
    if dresp and (dsm['message_id'] not in seen_msg_ids):
        deliver_pair_no_submit_resp.append({
            'deliver_seq': dkey[0],
            'deliver_time': dsm['timestamp'],
            'deliver_src': f"{dsm['src_ip']}:{dsm['src_port']}",
            'deliver_dst': f"{dsm['dst_ip']}:{dsm['dst_port']}",
            'deliver_resp_seq': dresp['sequence_number'],
            'deliver_resp_time': dresp['timestamp'],
            'deliver_resp_src': f"{dresp['src_ip']}:{dresp['src_port']}",
            'deliver_resp_dst': f"{dresp['dst_ip']}:{dresp['dst_port']}",
            'message_id': dsm['message_id']
        })
 
for dkey, dsm in deliver_sm.items():
    rev_dkey = (dkey[0], dkey[3], dkey[4], dkey[1], dkey[2])
    if rev_dkey not in deliver_sm_resp:
        deliver_no_response.append({
            'sequence_number': dkey[0],
            'timestamp': dsm['timestamp'],
            'src': f"{dsm['src_ip']}:{dsm['src_port']}",
            'dst': f"{dsm['dst_ip']}:{dsm['dst_port']}",
            'message_id': dsm['message_id']
        })
 
# Save CSVs
output_dir = os.path.join(os.getcwd(), "output")
os.makedirs(output_dir, exist_ok=True)

pd.DataFrame(matched_chains).to_csv(f"{output_dir}/matched_full_chains.csv", index=False)
pd.DataFrame(submit_resp_no_submit).to_csv(f"{output_dir}/submit_sm_resp_without_submit.csv", index=False)
pd.DataFrame(deliver_pair_no_submit_resp).to_csv(f"{output_dir}/deliver_chain_without_submit_resp.csv", index=False)
pd.DataFrame(submit_chain_no_deliver).to_csv(f"{output_dir}/submit_chain_without_delivery.csv", index=False)
pd.DataFrame(deliver_no_response).to_csv(f"{output_dir}/deliver_sm_without_response.csv", index=False)
 
print("\n✅ CSVs generated:")
print("- matched_full_chains.csv")
print("- submit_sm_resp_without_submit.csv")
print("- deliver_chain_without_submit_resp.csv")
print("- submit_chain_without_delivery.csv")
print("- deliver_sm_without_response.csv")
 
print("\n📊 Summary Statistics:")
print(f"Total Submit SM             : {counters['submit_sm']}")
print(f"Total Submit SM Responses   : {counters['submit_sm_resp']}")
print(f"Total Deliver SM            : {counters['deliver_sm']}")
print(f"Total Deliver SM Responses  : {counters['deliver_sm_resp']}")
print(f"✅ Fully Matched Chains      : {counters['full_chains']}")
print(f"⚠️  Partially Matched Chains : {counters['partial_chains']}")
if delta_submit_resp:
    print(f"\n⏱ Avg Time Submit → Submit_Resp: {sum(delta_submit_resp)/len(delta_submit_resp):.3f}s")
if delta_resp_deliver:
    print(f"⏱ Avg Time Submit_Resp → Deliver: {sum(delta_resp_deliver)/len(delta_resp_deliver):.3f}s")
if delta_deliver_resp:
    print(f"⏱ Avg Time Deliver → Deliver_Resp: {sum(delta_deliver_resp)/len(delta_deliver_resp):.3f}s")
 