import pandas as pd

# Load CSV
df = pd.read_csv("all_smpp_packets.csv")

# Filter packets by SMPP command_id
submit_sm        = df[df['command_id'] == '0x00000004'].copy()
submit_sm_resp   = df[df['command_id'] == '0x80000004'].copy()
deliver_sm       = df[df['command_id'] == '0x00000005'].copy()
deliver_sm_resp  = df[df['command_id'] == '0x80000005'].copy()

# Normalize data types for matching
for d in [submit_sm, submit_sm_resp, deliver_sm, deliver_sm_resp]:
    for col in ['sequence_number', 'message_id', 'src_ip', 'dst_ip', 'src_port', 'dst_port']:
        d[col] = d[col].astype(str)

# Rename deliver_sm fields
deliver_sm = deliver_sm.rename(columns={
    'sequence_number': 'deliver_sequence_number',
    'message_id': 'deliver_message_id',
    'src_ip': 'deliver_src_ip',
    'src_port': 'deliver_src_port',
    'dst_ip': 'deliver_dst_ip',
    'dst_port': 'deliver_dst_port',
    'timestamp': 'deliver_timestamp'
})

# Rename deliver_sm_resp fields
deliver_sm_resp = deliver_sm_resp.rename(columns={
    'sequence_number': 'deliver_resp_sequence_number',
    'src_ip': 'deliver_resp_src_ip',
    'src_port': 'deliver_resp_src_port',
    'dst_ip': 'deliver_resp_dst_ip',
    'dst_port': 'deliver_resp_dst_port',
    'timestamp': 'deliver_resp_timestamp'
})

# ✅ Step 1: submit_sm ↔ submit_sm_resp
submit_match = pd.merge(
    submit_sm,
    submit_sm_resp,
    left_on=['sequence_number', 'src_ip', 'src_port'],
    right_on=['sequence_number', 'dst_ip', 'dst_port'],
    suffixes=('_submit', '_submit_resp')
)
print(f"✅ Step 1: submit_sm ↔ submit_sm_resp matched: {len(submit_match)} / {len(submit_sm)}")

# ✅ Step 2: submit_sm_resp ↔ deliver_sm via message_id
submit_deliver_match = pd.merge(
    submit_match,
    deliver_sm,
    left_on='message_id_submit_resp',
    right_on='deliver_message_id'
)
print(f"✅ Step 2: submit_sm_resp ↔ deliver_sm matched (message_id): {len(submit_deliver_match)} / {len(submit_match)}")

# ✅ Step 3: deliver_sm ↔ deliver_sm_resp on sequence/IP/port
full_chain = pd.merge(
    submit_deliver_match,
    deliver_sm_resp,
    left_on=['deliver_sequence_number', 'deliver_src_ip', 'deliver_src_port'],
    right_on=['deliver_resp_sequence_number', 'deliver_resp_dst_ip', 'deliver_resp_dst_port']
)
print(f"✅ Step 3: deliver_sm ↔ deliver_sm_resp matched: {len(full_chain)} / {len(submit_deliver_match)}")

# 🔢 Summary stats
print("\n📊 Matching Summary:")
print(f"- Total submit_sm packets:       {len(submit_sm)}")
print(f"- Matched submit_sm_responses:  {len(submit_match)}")
print(f"- Matched deliver_sm packets:   {len(submit_deliver_match)}")
print(f"- Fully matched SMPP chains:    {len(full_chain)}")
print(f"- Partial chains (missing deliver_resp): {len(submit_deliver_match) - len(full_chain)}")
print(f"- Incomplete submit_sm responses: {len(submit_sm) - len(submit_match)}")

# Final output formatting
output_df = full_chain[[
    'sequence_number', 'message_id_submit_resp',
    'src_ip_submit', 'src_port_submit', 'dst_ip_submit', 'dst_port_submit', 'timestamp_submit',
    'src_ip_submit_resp', 'src_port_submit_resp', 'dst_ip_submit_resp', 'dst_port_submit_resp', 'timestamp_submit_resp',
    'deliver_src_ip', 'deliver_src_port', 'deliver_dst_ip', 'deliver_dst_port', 'deliver_timestamp',
    'deliver_resp_src_ip', 'deliver_resp_src_port', 'deliver_resp_dst_ip', 'deliver_resp_dst_port', 'deliver_resp_timestamp',
    'deliver_sequence_number', 'deliver_resp_sequence_number'
]]

output_df.columns = [
    'submit_sm_seq', 'message_id',
    'submit_sm_src_ip', 'submit_sm_src_port', 'submit_sm_dst_ip', 'submit_sm_dst_port', 'submit_sm_time',
    'submit_sm_resp_src_ip', 'submit_sm_resp_src_port', 'submit_sm_resp_dst_ip', 'submit_sm_resp_dst_port', 'submit_sm_resp_time',
    'deliver_sm_src_ip', 'deliver_sm_src_port', 'deliver_sm_dst_ip', 'deliver_sm_dst_port', 'deliver_sm_time',
    'deliver_sm_resp_src_ip', 'deliver_sm_resp_src_port', 'deliver_sm_resp_dst_ip', 'deliver_sm_resp_dst_port', 'deliver_sm_resp_time',
    'deliver_sm_seq', 'deliver_sm_resp_seq'
]

# Save to CSV
output_df.to_csv("matched_smpp_lifecycle.csv", index=False)
print("\n✅ Matching complete. Output saved to matched_smpp_lifecycle.csv")
