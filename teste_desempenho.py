import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

# Data manually inserted based on MQTT execution results
data = [
    ("100B", 1, 0.015752, 0.009058),
    ("100B", 4, 0.046937, 0.032423),
    ("100B", 8, 0.055462, 0.070877),
    ("1KB", 1, 0.014122, 0.008345),
    ("1KB", 4, 0.028776, 0.033660),
    ("1KB", 8, 0.077793, 0.081880),
    ("10KB", 1, 0.009141, 0.008901),
    ("10KB", 4, 0.028841, 0.049368),
    ("10KB", 8, 0.078184, 0.060271),
]

# Create DataFrame
df = pd.DataFrame(data, columns=["Data Size", "Number of Attributes", "Encryption Time (s)", "Decryption Time (s)"])
df["Total Time (s)"] = df["Encryption Time (s)"] + df["Decryption Time (s)"]

# Create plot
plt.figure(figsize=(12, 6))
sns.barplot(data=df, x="Number of Attributes", y="Total Time (s)", hue="Data Size")

plt.title("Total Processing Time by Number of Attributes and Message Size", fontsize=14)
plt.xlabel("Number of Attributes", fontsize=12)
plt.ylabel("Total Time (s)", fontsize=12)
plt.legend(title="Message Size")
plt.grid(True)
plt.tight_layout()

# Save as image
plt.savefig("total_processing_time_chart.png", dpi=300)
print("✅ Chart saved as 'total_processing_time_chart.png'")
