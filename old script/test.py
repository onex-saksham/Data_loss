import pyshark

# Path to tshark
pyshark.tshark.tshark.get_tshark_path = lambda: '/usr/bin/tshark'

# Load capture with only deliver_sm PDUs
cap = pyshark.FileCapture(
    'v2smpp33.pcap',
    display_filter='smpp.command_id == 0x00000005',
    use_json=True,
    include_raw=True
)

# Loop through deliver_sm packets
for packet in cap:
    try:
        smpp = packet['smpp']
        fields = smpp._all_fields

        print("\n📦 deliver_sm Packet:")

        # Print all fields
        print("🔍 All SMPP Fields:")
        for field, value in fields.items():
            print(f"  {field}: {value}")

        # Print only short_message-related fields
        print("💬 Fields containing 'short_message':")
        found = False
        for field, value in fields.items():
            if 'short_message' in field.lower():
                print(f"  {field}: {value}")
                found = True
        if not found:
            print("  ⚠️ No 'short_message' fields found.")

    except Exception as e:
        print(f"⚠️ Error parsing packet: {e}")
