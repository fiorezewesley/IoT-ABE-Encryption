
import json
import time
import base64
import paho.mqtt.client as mqtt
from charm.toolbox.pairinggroup import PairingGroup, G1
from charm.schemes.abenc.abenc_waters09 import CPabe09


groupObj = PairingGroup('SS512')
abe = CPabe09(groupObj)
master_secret_key, public_key = abe.setup()

BROKER = "localhost"
PORT = 1883
TOPIC = "iot/sensor_data"

data_sizes = {
    "100B": 100,
    "1KB": 1024,
    "10KB": 10 * 1024
}
attribute_counts = [10, 20, 30, 40, 50, 60]
total_runs = 5

# Geração de lista de atributos  '001' a '060'
all_attributes = sorted([str(i).zfill(3) for i in range(1, 61)])

def serialize_component(value):
    if isinstance(value, dict):
        return {k: serialize_component(v) for k, v in value.items()}
    if isinstance(value, list):
        return [serialize_component(v) for v in value]
    try:
        if isinstance(value, bytes):
            return base64.b64encode(value).decode('utf-8')
        if groupObj.ismember(value):
            serialized = groupObj.serialize(value)
            return base64.b64encode(serialized).decode('utf-8')
        else:
            return str(value)
    except Exception:
        return str(value)

def serialize_public_key(public_key):
    return {k: serialize_component(v) for k, v in public_key.items()}

def on_connect(client, userdata, flags, rc):
    print(f"[Publisher] Connected to MQTT Broker (Code: {rc})")

    for run_id in range(1, total_runs + 1):
        for size_label, size_bytes in data_sizes.items():
            sensor_data = "D" * size_bytes
            M_g1 = groupObj.hash(sensor_data, G1)
            M_gt = groupObj.pair_prod(M_g1, M_g1)

            for num_attrs in attribute_counts:
                policy = " AND ".join(all_attributes[:num_attrs])
                start_enc = time.time()
                ciphertext = abe.encrypt(public_key, M_gt, policy)
                end_enc = time.time()
                encryption_time = round(end_enc - start_enc, 6)

                serialized_ciphertext = {k: serialize_component(v) for k, v in ciphertext.items()}
                serialized_public_key = serialize_public_key(public_key)

                payload = {
                    "ciphertext": serialized_ciphertext,
                    "policy": policy,
                    "public_key": serialized_public_key,
                    "timestamp_sent": time.time(),
                    "encryption_time": encryption_time,
                    "data_size": size_label,
                    "num_attributes": num_attrs,
                    "run_id": run_id
                }

                client.publish(TOPIC, json.dumps(payload))
                print(f"[Publisher] Run {run_id} - Sent: {size_label}, {num_attrs} attrs")
                time.sleep(0.1)

    client.disconnect()

# MQTT client setup
client = mqtt.Client(protocol=mqtt.MQTTv311)
client.on_connect = on_connect
client.connect(BROKER, PORT, 60)
client.loop_forever()
