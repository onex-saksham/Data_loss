import pandas as pd
import matplotlib.pyplot as plt
from datetime import datetime

# Load the original CSV
df = pd.read_csv('combined_smpp_chain.csv')

# Convert string timestamps to datetime objects
def to_dt(ts):
    try:
        return datetime.strptime(ts, "%d/%m/%y %H:%M:%S")
    except:
        return None

df['submit_sm_time_dt'] = df['submit_sm_time'].apply(to_dt)
df['submit_response_time_dt'] = df['submit_response_time'].apply(to_dt)
df['deliver_sm_time_dt'] = df['deliver_sm_time'].apply(to_dt)
df['deliver_sm_resp_time_dt'] = df['deliver_sm_resp_time'].apply(to_dt)

# Compute deltas in seconds
df['submit_delta'] = (df['submit_response_time_dt'] - df['submit_sm_time_dt']).dt.total_seconds()
df['deliver_delta'] = (df['deliver_sm_resp_time_dt'] - df['deliver_sm_time_dt']).dt.total_seconds()

# Save to new CSV
df[['msg_id/Teckco', 'submit_delta', 'deliver_delta']].to_csv('timing_deltas.csv', index=False)

# Print stats
print("\n=== Delta Statistics ===")
print(f"Submit Δ - Average: {df['submit_delta'].mean():.3f} sec, Median: {df['submit_delta'].median():.3f} sec")
print(f"Deliver Δ - Average: {df['deliver_delta'].mean():.3f} sec, Median: {df['deliver_delta'].median():.3f} sec")

# Plotting
plt.figure(figsize=(12, 6))
plt.plot(df['submit_delta'], label='Submit Delta (s)', marker='o', linestyle='-', alpha=0.7)
plt.plot(df['deliver_delta'], label='Deliver Delta (s)', marker='x', linestyle='--', alpha=0.7)
plt.title('Submit vs Deliver Time Differences')
plt.xlabel('Message Index')
plt.ylabel('Time Delta (seconds)')
plt.legend()
plt.grid(True)
plt.tight_layout()
plt.savefig("delta_plot.png")
plt.show()