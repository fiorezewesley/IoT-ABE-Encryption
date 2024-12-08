from charm.toolbox.pairinggroup import PairingGroup, G1, pair
from charm.schemes.abenc.abenc_waters09 import CPabe09

# Inicializa o grupo de emparelhamento
groupObj = PairingGroup('SS512')

# Inicializa o esquema de ABE de Waters (2009)
abe = CPabe09(groupObj)

# 1. Geração de chaves públicas e mestres
print("1. Gerando chaves...")
(master_secret_key, public_key) = abe.setup()

# 2. Definindo a política de acesso
policy = '(dep1 AND func1)'
print("2. Política de acesso definida:", policy)

# 3. Gerando a chave privada para um usuário que atende à política
user_attributes = ['dep1', 'func1']
print("3. Gerando chave privada para os atributos do usuário:", user_attributes)
secret_key = abe.keygen(public_key, master_secret_key, user_attributes)

# 4. Mensagem simples a ser criptografada
message = "Mensagem confidencial"
print("\n4. Mensagem a ser criptografada:", message)

# Convertendo a string para um hash em G1 e depois para GT
message_hashed_g1 = groupObj.hash(message, G1)  # Hash para G1
message_element = pair(message_hashed_g1, message_hashed_g1)  # Elevação para GT
print("\nMensagem no espaço GT:", message_element)

# 5. Criptografando a mensagem com a política de acesso
print("\n5. Criptografando a mensagem com a política de acesso...")
ciphertext = abe.encrypt(public_key, message_element, policy)

# 6. Tentativa de descriptografia com os atributos do usuário
print("\n6. Tentando acessar a mensagem...")
try:
    decrypted_element = abe.decrypt(public_key, secret_key, ciphertext)

    # Verifica se a descriptografia foi bem-sucedida
    if decrypted_element == message_element:
        print("\nMensagem descriptografada com sucesso:")
        print("Mensagem original:", message)
        print("\nAcesso permitido: O usuário atendeu à política de acesso.")
    else:
        print("\nErro: Mensagem descriptografada não coincide com a mensagem original.")
except Exception as e:
    print("\nAcesso negado: O usuário não atende à política de acesso!", e)
