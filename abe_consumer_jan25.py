
import json
import time
import csv
import paho.mqtt.client as mqtt
from charm.toolbox.pairinggroup import PairingGroup, G1
from charm.schemes.abenc.abenc_waters09 import CPabe09
import base64
import os

groupObj = PairingGroup('SS512')
abe = CPabe09(groupObj)
master_secret_key, public_key = abe.setup()


BROKER = "localhost"
PORT = 1883
TOPIC = "iot/sensor_data"

# CSV simples
CSV_FILE = "results_log.csv"
if not os.path.exists(CSV_FILE):
    with open(CSV_FILE, mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(["Run ID", "Data Size", "Num Attributes", "Encryption Time (s)", "Decryption Time (s)", "End-to-End Latency (s)"])

def deserialize_component(value):
    try:
        if isinstance(value, dict):
            return {k: deserialize_component(v) for k, v in value.items()}
        if isinstance(value, list):
            return [deserialize_component(v) for v in value]
        if isinstance(value, str):
            decoded = base64.b64decode(value.encode('utf-8'))
            return groupObj.deserialize(decoded)
        return value
    except:
        return value

def reconstruct_public_key(serialized_public_key):
    return {k: deserialize_component(v) for k, v in serialized_public_key.items()}

# Callback de conexão
def on_connect(client, userdata, flags, rc):
    print(f"[Consumer] Connected to MQTT Broker (Code: {rc})")
    client.subscribe(TOPIC)

# Callback de mensagem
def on_message(client, userdata, msg):
    print("[Consumer] Mensagem recebida! Processando...\n")

    payload = json.loads(msg.payload)

    serialized_ciphertext = payload["ciphertext"]
    serialized_public_key = payload["public_key"]
    policy = payload["policy"]
    timestamp_sent = payload["timestamp_sent"]
    encryption_time = payload["encryption_time"]
    size_label = payload["data_size"]
    num_attrs = payload["num_attributes"]
    run_id = payload["run_id"]

    public_key = reconstruct_public_key(serialized_public_key)
    ciphertext = {k: deserialize_component(v) for k, v in serialized_ciphertext.items()}
    ciphertext["policy"] = policy

    attributes = sorted([str(i).zfill(3) for i in range(1, 61)])  # Alterado para 60 atributos
    user_attrs = sorted(attributes[:num_attrs])
    secret_key = abe.keygen(public_key, master_secret_key, user_attrs)

    start_dec = time.time()
    decrypted = abe.decrypt(public_key, secret_key, ciphertext)
    end_dec = time.time()

    decryption_time = round(end_dec - start_dec, 6)
    end_to_end_latency = round(time.time() - timestamp_sent, 6)

    print(f"[Consumer] Run {run_id} - {size_label}, {num_attrs} attrs | Enc: {encryption_time}s | Dec: {decryption_time}s")
    print(f"[Consumer] Decrypted: {decrypted}\n")

    
    with open(CSV_FILE, mode='a', newline='') as file:
        writer = csv.writer(file)
        writer.writerow([run_id, size_label, num_attrs, encryption_time, decryption_time, end_to_end_latency])

client = mqtt.Client(protocol=mqtt.MQTTv311)
client.on_connect = on_connect
client.on_message = on_message
client.connect(BROKER, PORT, 60)
print("[Consumer] Waiting for messages...")
client.loop_forever()
