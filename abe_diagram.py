import json
from charm.toolbox.pairinggroup import PairingGroup, GT, G1
from charm.schemes.abenc.abenc_waters09 import CPabe09

groupObj = PairingGroup('SS512')
abe = CPabe09(groupObj)

# ============================
# Fase 1: Árvore de atributos
# ===========================
print("Fase 1: Geração dos atributos")
simulando_atributos = {
    "IoT_device": ["111", "222", "333"],
    "Subscriber1": ["000", "000", "000"],
    "Subscriber2": ["111", "222", "333"]
}
for i, atributos in simulando_atributos.items():#teste
    print(f"{i}: {atributos}")

# =========================
# Fase 2: Distribuiacao de chaves
# ______________________
print("\nFase 2: Distribuição de chaves")

print("Gerando Master Secret Key e Public Key...")
master_secret_key, public_key = abe.setup()

# Gerando secret keys para os subscribers
print("Gerando Secret Keys para Subscribers...")
secret_keys = {}
for subscriber, atributos in simulando_atributos.items():
    if "Subscriber" in subscriber:  # Apenas subscribers recebem secret Keys
        secret_keys[subscriber] = abe.keygen(public_key, master_secret_key, atributos)
        print(f"{subscriber}: Secret Key gerada.")

# Distribuindo a PK p/ dispositivos
iot_device_pk = public_key

# ============================
# Fase 3: Produção de Dados
# ============================
print("\nFase 3: Produção de Dados")

sensor_data = {
    "temperature": "25.5°C",
    "humidity": "60%",
    "production": "1200 units"
}
policy = "((111 AND 333) OR (111 AND 444))"

print(f"Dados do sensor: {json.dumps(sensor_data)}")
print(f"Política de acesso necessarias: {policy}")


dispositivo_capaz_criptografar= True  # simlação

if dispositivo_capaz_criptografar:
    print("IoT Device: Criptografando os dados com Public Key (PK)...")
    # preciso criar esse hash/gambiarra com o JSON, usanndo o grupo de pares g1, senão dá problema de parse -- pensar nisso depois
    hashed_data_g1 = groupObj.hash(json.dumps(sensor_data), G1)
    hashed_data_gt = groupObj.pair_prod(hashed_data_g1, hashed_data_g1)  # Elevação para GT
    ciphertext = abe.encrypt(iot_device_pk, hashed_data_gt, policy)
else:
    print("IoT Device: Delegando criptografia para o Módulo.")
    # Aqui, o módulo faria a criptografia -- pensar nisso :S

# Mensagem criptografada é enviada
print("Dados criptografados enviados ao broker.")

# =================
# Fase 4: Consumo de Dados
# ============================
print("\nFase 4: Consumo de Dados")
for subscriber, secret_key in secret_keys.items():
    print(f"\n{subscriber} tentando descriptografar...")
    try:
        decrypted_message = abe.decrypt(public_key, secret_key, ciphertext)
        if decrypted_message == hashed_data_gt:
            print(f"Dados descriptografados pelo {subscriber}: {json.dumps(sensor_data)}")
        else:
            print(f"Erro ({subscriber}): Dados corrompidos ou não autorizados.")
    except Exception as e:
        print(f"Erro ({subscriber}): Acesso negado ou atributos incompatíveis.")
