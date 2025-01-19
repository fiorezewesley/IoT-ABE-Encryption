import json
import paho.mqtt.client as mqtt
from charm.toolbox.pairinggroup import PairingGroup, GT, G1
from charm.schemes.abenc.abenc_waters09 import CPabe09
import base64

# Configuração da biblioteca Charm-Crypto
groupObj = PairingGroup('SS512')
abe = CPabe09(groupObj)

# Configuração do broker MQTT
BROKER = "localhost"
PORT = 1883
TOPIC = "iot/sensor_data"

# Geração de chaves
master_secret_key, public_key = abe.setup()

# Dados do sensor e política de acesso
sensor_data = {
    "temperature": "25.5°C",
    "humidity": "60%",
    "production": "1200 units"
}
policy = "((111 AND 333) OR (111 AND 444))"

# Preparação dos dados para criptografia
print("IoT Device: Criptografando os dados...")
sensor_data_str = json.dumps(sensor_data)
M_g1 = groupObj.hash(sensor_data_str, G1)
M_gt = groupObj.pair_prod(M_g1, M_g1)

# Criptografar os dados
ciphertext = abe.encrypt(public_key, M_gt, policy)

# Inspecionar os componentes do ciphertext
print("Componentes do ciphertext:")
for k, v in ciphertext.items():
    print(f"{k}: {type(v)}")

# Função para serializar componentes
def serialize_component(value):
    """Serializa elementos reconhecidos pelo Charm-Crypto."""
    if isinstance(value, dict):
        # Serializa recursivamente os dicionários
        return {k: serialize_component(v) for k, v in value.items()}
    if isinstance(value, list):
        # Serializa recursivamente as listas
        return [serialize_component(v) for v in value]
    try:
        # Verifica se o valor pertence ao grupo de emparelhamento
        if groupObj.ismember(value):
            serialized = groupObj.serialize(value)
            return base64.b64encode(serialized).decode('utf-8')
        else:
            # Converte valores não serializáveis para string
            return str(value)
    except Exception as e:
        # Captura qualquer erro e converte para string
        return str(value)

# Serializar todos os componentes do ciphertext
try:
    serialized_ciphertext = {k: serialize_component(v) for k, v in ciphertext.items()}
except Exception as e:
    print(f"Erro ao serializar ciphertext: {e}")
    raise

# Montar o payload para publicação no MQTT
encrypted_payload = {
    "ciphertext": serialized_ciphertext,
    "policy": policy
}

# Função de conexão ao broker MQTT
def on_connect(client, userdata, flags, rc):
    print(f"Conectado ao broker MQTT com código {rc}")
    print("Publicando dados criptografados...")
    client.publish(TOPIC, json.dumps(encrypted_payload))
    print("Dados publicados.")
    client.disconnect()

# Configuração do cliente MQTT
client = mqtt.Client()
client.on_connect = on_connect
client.connect(BROKER, PORT, 60)
client.loop_forever()
