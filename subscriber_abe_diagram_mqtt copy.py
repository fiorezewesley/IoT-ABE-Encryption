import json
import paho.mqtt.client as mqtt
from charm.toolbox.pairinggroup import PairingGroup, G1, GT
from charm.schemes.abenc.abenc_waters09 import CPabe09
import base64

# Configuração da biblioteca Charm-Crypto
groupObj = PairingGroup('SS512')
abe = CPabe09(groupObj)

# Configuração do broker MQTT
BROKER = "localhost"
PORT = 1883
TOPIC = "iot/sensor_data"

# Configuração de atributos e geração de chaves
simulando_atributos = {
    "Subscriber1": ["000", "000", "000"],
    "Subscriber2": ["111", "222", "333"]
}

master_secret_key, public_key = abe.setup()
secret_keys = {
    subscriber: abe.keygen(public_key, master_secret_key, atributos)
    for subscriber, atributos in simulando_atributos.items()
}

# Corrigir strings Base64 com padding incompleto
def fix_base64_padding(value):
    """Corrige o preenchimento de strings Base64."""
    missing_padding = len(value) % 4
    if missing_padding:
        value += '=' * (4 - missing_padding)
    return value

# Desserializar componentes do ciphertext
def deserialize_component(value):
    """Desserializa componentes enviados pelo Publisher."""
    if isinstance(value, dict):
        return {k: deserialize_component(v) for k, v in value.items()}
    if isinstance(value, str):
        try:
            value = fix_base64_padding(value)
            decoded = base64.b64decode(value)
            return groupObj.deserialize(decoded)
        except Exception as e:
            raise ValueError(f"Erro ao desserializar componente: {e}")
    return value

# Função para processar mensagens recebidas
def on_message(client, userdata, msg):
    print(f"Mensagem recebida no tópico {msg.topic}")
    payload = json.loads(msg.payload)

    # Desserializar o ciphertext
    serialized_ciphertext = payload["ciphertext"]
    ciphertext = {k: deserialize_component(v) for k, v in serialized_ciphertext.items()}

    # Tentativa de descriptografia
    for subscriber, secret_key in secret_keys.items():
        print(f"\n{subscriber} tentando descriptografar...")
        try:
            decrypted_message = abe.decrypt(public_key, secret_key, ciphertext)

            # Reconstrói o M_gt esperado
            sensor_data = {
                "temperature": "25.5°C",
                "humidity": "60%",
                "production": "1200 units"
            }
            M_g1 = groupObj.hash(json.dumps(sensor_data), G1)
            expected_M_gt = groupObj.pair_prod(M_g1, M_g1)

            if decrypted_message == expected_M_gt:
                print(f"{subscriber}: Dados descriptografados com sucesso!")
                print("Dados recebidos:", sensor_data)
            else:
                print(f"{subscriber}: Erro ao verificar os dados.")
        except Exception as e:
            print(f"{subscriber}: Acesso negado ou atributos incompatíveis. Erro: {e}")

# Configuração do cliente MQTT
client = mqtt.Client()
client.on_message = on_message
client.connect(BROKER, PORT, 60)
client.subscribe(TOPIC)
print("Esperando mensagens...")
client.loop_forever()
