import json
import time
import paho.mqtt.client as mqtt
from charm.toolbox.pairinggroup import PairingGroup, G1
from charm.schemes.abenc.abenc_waters09 import CPabe09
import base64

# Charm setup
groupObj = PairingGroup('SS512')
abe = CPabe09(groupObj)
master_secret_key, public_key = abe.setup()

# MQTT
BROKER = "localhost"
PORT = 1883
TOPIC = "iot/sensor_data"

# Tamanhos dos dados (em bytes)
data_sizes = {
    "100B": 100,
    "1KB": 1024,
    "10KB": 10 * 1024
}

# Políticas com diferentes números de atributos
policies = {
    1: "111",
    4: "(111 AND 222 AND 333 AND 444)",
    8: "(111 AND 222 AND 333 AND 444 AND 555 AND 666 AND 777 AND 888)"
}

def serialize_component(value):
    if isinstance(value, dict):
        return {k: serialize_component(v) for k, v in value.items()}
    if isinstance(value, list):
        return [serialize_component(v) for v in value]
    try:
        if isinstance(value, bytes):
            return base64.b64encode(value).decode('utf-8')
        if groupObj.ismember(value):
            return base64.b64encode(groupObj.serialize(value)).decode('utf-8')
        return str(value)
    except:
        return str(value)

def serialize_public_key(pk):
    return {k: serialize_component(v) for k, v in pk.items()}

# MQTT
client = mqtt.Client()

def on_connect(client, userdata, flags, rc):
    print(f"[Publisher] Conectado ao MQTT (Código: {rc})")
    for size_label, size in data_sizes.items():
        for num_attrs, policy in policies.items():
            # Geração de dados simulados
            sensor_data = "X" * size
            data_payload = json.dumps({"payload": sensor_data})

            # Hash + emparelhamento
            M_g1 = groupObj.hash(data_payload, G1)
            M_gt = groupObj.pair_prod(M_g1, M_g1)

            # Criptografar
            start_enc = time.time()
            ciphertext = abe.encrypt(public_key, M_gt, policy)
            end_enc = time.time()

            serialized_ciphertext = {k: serialize_component(v) for k, v in ciphertext.items()}
            serialized_public_key = serialize_public_key(public_key)

            # Montar payload MQTT
            full_payload = {
                "ciphertext": serialized_ciphertext,
                "policy": policy,
                "public_key": serialized_public_key,
                "timestamp_sent": start_enc,
                "encryption_time": round(end_enc - start_enc, 6),
                "data_size": size_label,
                "num_attributes": num_attrs
            }

            client.publish(TOPIC, json.dumps(full_payload))
            print(f"[Publisher] Enviado: {size_label}, {num_attrs} atributos")
            time.sleep(1.5)  # Tempo entre envios para evitar congestionamento
    client.disconnect()

client.on_connect = on_connect
client.connect(BROKER, PORT, 60)
client.loop_forever()
