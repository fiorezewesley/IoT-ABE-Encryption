import json
import paho.mqtt.client as mqtt
from charm.toolbox.pairinggroup import PairingGroup, G1
from charm.schemes.abenc.abenc_waters09 import CPabe09
import base64

# Configuração da biblioteca Charm-Crypto
groupObj = PairingGroup('SS512')
abe = CPabe09(groupObj)

# Geração de chaves (para fins de teste)
master_secret_key, public_key = abe.setup()

# Configuração do broker MQTT
BROKER = "localhost"
PORT = 1883
TOPIC = "iot/sensor_data"

# Função para desserializar componentes
def deserialize_component(value):
    """Desserializa elementos reconhecidos pelo Charm-Crypto."""
    try:
        if isinstance(value, dict):
            return {k: deserialize_component(v) for k, v in value.items()}
        if isinstance(value, list):
            return [deserialize_component(v) for v in value]
        if isinstance(value, str):
            decoded = base64.b64decode(value.encode('utf-8'))
            return groupObj.deserialize(decoded)
        return value
    except Exception as e:
        return value

# Função para reconstruir a chave pública
def reconstruct_public_key(serialized_public_key):
    """Reconstrói a chave pública a partir do dicionário serializado."""
    return {k: deserialize_component(v) for k, v in serialized_public_key.items()}

# Callback para processamento das mensagens
def on_message(client, userdata, msg):
    print("Dados recebidos do MQTT...")
    payload = json.loads(msg.payload)
    
    serialized_ciphertext = payload["ciphertext"]
    policy = payload["policy"]  # A política já é enviada como string
    serialized_public_key = payload["public_key"]
    
    # Reconstruir a chave pública
    public_key = reconstruct_public_key(serialized_public_key)
    
    # Recriar o ciphertext
    ciphertext = {k: deserialize_component(v) for k, v in serialized_ciphertext.items()}
    
    # Gerar chave secreta
    attributes = sorted(["111", "333"])  # Atributos autorizados como lista ordenada
    secret_key = abe.keygen(public_key, master_secret_key, attributes)
    
    # Descriptografar os dados
    ciphertext["policy"] = policy  # Adiciona a política como string no ciphertext
    M_gt = abe.decrypt(public_key, secret_key, ciphertext)
    print(f"Dados descriptografados: {M_gt}")

# Configuração do cliente MQTT
client = mqtt.Client()
client.on_message = on_message
client.connect(BROKER, PORT, 60)
client.subscribe(TOPIC)
client.loop_forever()
