# -*- coding: utf-8 -*-
from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, G2, GT, pair
from charm.schemes.abenc.abenc_waters09 import CPabe09

groupObj = PairingGroup('SS512') 

#resolve problemas de controle de acesso em cenários c/ permissões dinâmicas e baseadas em atributos. 
#chave privada vai conter os atributo do 
abe = CPabe09(groupObj)

#Geração de chaves públicas e mestres
print("1. Gerando chaves...")
(master_secret_key, public_key) = abe.setup()

policy = '((A and B) or (C and D))' #ex gerente Siemens OR CEO Brasken, etc
user_attributes = ['A', 'B']  

# Geração da chave privada com base nos atributos do usuário
print("2. Gerando chave privada para os atributos:", user_attributes)
secret_key = abe.keygen(public_key, master_secret_key, user_attributes)
#se iot_device for quem vai cripto, recbe a secret_key

# msg aleatória p/ ser criptografada. Teqnho que testar c/ com JSON de dados
message = groupObj.random(GT) 
print("3. Mensagem original:", message)


print("4. Criptografando mensagem...")
ciphertext = abe.encrypt(public_key, message, policy)


print("5. Descriptografando mensagem...")
try:
    decrypted_message = abe.decrypt(public_key, secret_key, ciphertext)
    print("Mensagem descriptografada:", decrypted_message)


    assert message == decrypted_message, "Erro: Mensagem descriptografada não coincide!"
    print("Teste concluído com sucesso! A mensagem foi recuperada corretamente.")
except Exception as e:
    print("Erro durante a descriptografia:", e)
