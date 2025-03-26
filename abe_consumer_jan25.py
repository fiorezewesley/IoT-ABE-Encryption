import json
import time
import csv
import os
import paho.mqtt.client as mqtt
from charm.toolbox.pairinggroup import PairingGroup, G1
from charm.schemes.abenc.abenc_waters09 import CPabe09
import base64

groupObj = PairingGroup('SS512')
abe = CPabe09(groupObj)
master_secret_key, public_key = abe.setup()

BROKER = "localhost"
PORT = 1883
TOPIC = "iot/sensor_data"
CSV_FILE = "resultados_mqtt.csv"

# Atributos usados para satisfazer todas as políticas
attributes = sorted(["111", "222", "333", "444", "555", "666", "777", "888"])

# Desserialização
def deserialize_component(value):
    try:
        if isinstance(value, dict):
            return {k: deserialize_component(v) for k, v in value.items()}
        if isinstance(value, list):
            return [deserialize_component(v) for v in value]
        if isinstance(value, str):
            return groupObj.deserialize(base64.b64decode(value.encode('utf-8')))
        return value
    except:
        return value

def reconstruct_public_key(serialized_public_key):
    return {k: deserialize_component(v) for k, v in serialized_public_key.items()}

# Cria CSV se ainda não existir
if not os.path.exists(CSV_FILE):
    with open(CSV_FILE, mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(["Data Size", "Num Attributes", "Encryption Time (s)", "Decryption Time (s)"])

# Callback MQTT
def on_message(client, userdata, msg):
    payload = json.loads(msg.payload)

    # Extrair campos
    size = payload["data_size"]
    num_attrs = payload["num_attributes"]
    encryption_time = payload["encryption_time"]
    timestamp_sent = payload["timestamp_sent"]
    policy = payload["policy"]

    serialized_ciphertext = payload["ciphertext"]
    serialized_public_key = payload["public_key"]

    public_key = reconstruct_public_key(serialized_public_key)
    ciphertext = {k: deserialize_component(v) for k, v in serialized_ciphertext.items()}
    ciphertext["policy"] = policy

    # Gerar chave
    user_attrs = sorted(attributes[:num_attrs])
    secret_key = abe.keygen(public_key, master_secret_key, user_attrs)

    # Descriptografar
    start_dec = time.time()
    decrypted = abe.decrypt(public_key, secret_key, ciphertext)
    end_dec = time.time()

    decryption_time = round(end_dec - start_dec, 6)
    total_time = round(time.time() - timestamp_sent, 6)

    print(f"[Consumer] {size}, {num_attrs} atributos | Enc: {encryption_time}s | Dec: {decryption_time}s")
    print(f"[Consumer] Dados descriptografados: {decrypted}")

    # Salvar resultado
    with open(CSV_FILE, mode='a', newline='') as file:
        writer = csv.writer(file)
        writer.writerow([size, num_attrs, encryption_time, decryption_time])

# MQTT
client = mqtt.Client()
client.on_message = on_message
client.connect(BROKER, PORT, 60)
client.subscribe(TOPIC)
print("[Consumer] Aguardando mensagens...")
client.loop_forever()
