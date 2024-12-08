from charm.toolbox.pairinggroup import PairingGroup, GT
from charm.schemes.abenc.abenc_waters09 import CPabe09

groupObj = PairingGroup('SS512')
abe = CPabe09(groupObj)

print("1 gerando chaves")
(master_secret_key, public_key) = abe.setup()

policy = '((123) OR (456))'
print(f"\npolítica de Acesso: {policy}")

attributes_subscriber1 = ['123', '456']
print(f"\nsubscriber 1: Atributos -> {attributes_subscriber1}")

attributes_subscriber2 = ['999']
print(f"Subscriber 2: Atributos -> {attributes_subscriber2}")

print("\n2. gerando chves privadas para cada sub..")
secret_key_subscriber1 = abe.keygen(public_key, master_secret_key, attributes_subscriber1)
secret_key_subscriber2 = abe.keygen(public_key, master_secret_key, attributes_subscriber2)

message = groupObj.random(GT)

print("\n3. msg original:", message)

print("\n4.criptograafando a msg")
ciphertext = abe.encrypt(public_key, message, policy)

print("\n5. Subscriber 1 tentando descriptografar...")
try:
    decrypted_message1 = abe.decrypt(public_key, secret_key_subscriber1, ciphertext)
    print("msg descriptogrfada pelo subscriber 1:", decrypted_message1)

except Exception as eroou:
    print("Erro (Subscriber 1):", e)

print("\n6. Subscriber 2 tentando descriptografar...")
try:
    decrypted_message2 = abe.decrypt(public_key, secret_key_subscriber2, ciphertext)
    print("Mensagem descriptografada pelo Subscriber 2:", decrypted_message2)

except Exception as e:
    print("Erro (Subscriber 2):", e)
