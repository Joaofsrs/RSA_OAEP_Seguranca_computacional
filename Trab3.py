##############################################################################
# Universidade de de Brasilia                                                #
# Instituto de Ciencia Exatas                                                #
# Departamento de Ciencia da Computacao                                      #
#                                                                            #
# Seguranca Computacional - 2021/1                            			     #
# Trabalho 3                                                                 #
# Alunos: Joao Francisco Gomes Targino                                       #
#         Joao Gabriel Fevolta_reira Saraiva                                 #
# Matriculas: 180102991                                                      #
#             180103016                                                      #
# Versao do Compilador:  Python 3.9.7                                        #
#                                                                            #
##############################################################################

import random 
import math
import hashlib
from Crypto.Util.number import * 
import binascii

def base64_decifra(mensagem):
    decifrada = ''
    completas = ''
    caracteresb64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    i = len(mensagem)-1
    while(mensagem[i] == '='):
        i = i-1
        completas += 'A'

    mensagem = mensagem[0: len(mensagem) - len(completas)] + completas

    for c in range(0, len(mensagem), 4): 
        n = (caracteresb64.index(mensagem[c]) << 18) + (caracteresb64.index(mensagem[c+1]) << 12) + (caracteresb64.index(mensagem[c+2]) << 6) + caracteresb64.index(mensagem[c+3])
        decifrada += bytes([(n >> 16) & 255, (n >> 8) & 255, n & 255]).decode('utf-8')

    return decifrada[0: len(decifrada) - len(completas)]

def base64_cifra(mensagem):
    caracteresb64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    r = ""; 
    completas = ""; 
    c = len(mensagem) % 3

    if (c > 0): 
        for _ in range(c,3):
            completas += '='
            mensagem += "\0"

    for c in range(0,len(mensagem),3):       

        n = (ord(mensagem[c]) << 16) + (ord(mensagem[c+1]) << 8) + ord(mensagem[c+2])
        n = [(n >> 18) & 63, (n >> 12) & 63, (n >> 6) & 63, n & 63]
        r += caracteresb64[n[0]] + caracteresb64[n[1]] + caracteresb64[n[2]] + caracteresb64[n[3]]
    
    return r[0:len(r) - len(completas)] + completas

def miller_rabin(n):
    cont = 0
    s = n-1

    if n == 2:
        return True

    if n%2 == 0 or n < 2:
        return False

    while s % 2 == 0:
        cont += 1
        s //= 2

    for i in range(40):
        band = 0
        auxc = cont
        a = random.randrange(2, n - 1)
        x = pow(a, s, n)

        if x == 1:
            band = 1
            continue

        while auxc != 0:
            if x == n - 1:
                band = 1
                break

            x = pow(x, 2, n)
            auxc -= 1

        if band == 0: 
            return False
        
    return True

def gerador():
    num = random.getrandbits(1024)
    while(miller_rabin(num) != True):
        num = random.getrandbits(1024)

    return num

def menos2(num):
    return num[2:len(num)]

def i2osp(num):
    return "".join([chr((num >> (8 * i)) & 0xFF) for i in reversed(range(4))])

def mascara(texto , tamanho):
    """Mask generation function."""
    contador = 0
    saida = ""
    
    while len(saida) < tamanho:
        C = i2osp(contador)
        teste = texto+str(C)
        hash = hashlib.new("sha3_512", teste.encode())
        saida += hash.hexdigest()
        contador += 1
        
    return saida  

def oaepDecifra(cifrada, mensagem, d, n, r):
    tamanho_chave = size(n)
    tamanho_msg = len(mensagem)*2
    k0 = size(r)
    k1 = tamanho_chave - k0 - tamanho_msg
    XYfim = int(pow(int(cifrada, 16), d, n))
    
    X = (pow(2, 8 * (k0 + k1 + tamanho_msg + 1)) - 1) & XYfim
    Y = (pow(2, 8 * k0) - 1) & (XYfim >> 8 * (k0 + k1 + tamanho_msg + 1))
    volta_r = int(mascara(menos2(hex(X)), k0), 16) ^ Y

    if r != volta_r:
        return False

    mensagem_completas = int(mascara(menos2(hex(volta_r)), k0 + k1 + tamanho_msg + 1), 16) ^ X
    mensagem = (pow(2, 8 * tamanho_msg) - 1) & mensagem_completas
    
    return binascii.unhexlify(menos2(hex(mensagem))).decode()

def oaepCifra(mensagem, e, n, r):
    lista_zeros = []
    menhash = hashlib.new("sha3_512", mensagem.encode())
    menhash = menhash.hexdigest()
    tamanho_msg = len(mensagem)*2
    tamanho_chave = size(n)
    k0 = size(r)
    k1 = tamanho_chave - k0 - tamanho_msg

    if k1 < 0:
        print('Tamanho da mensagem muito grande')
        return False

    while len(lista_zeros) < 2 * k1:
        lista_zeros.append("0")

    lista_zeros = "".join(lista_zeros)
    completas = int(menhash + lista_zeros + "01" + mensagem, 16)
    tamanho_mascara = k0 + k1 + tamanho_msg + 1
    G = mascara(menos2(hex(r)), tamanho_mascara)
    X = int(G, 16) ^ completas
    Xhex= menos2(hex(X))
    Y = int(mascara(Xhex, k0), 16) ^ r
    Yhex = menos2(hex(Y))
    XY = "00" + Yhex + Xhex
    XYfim = int(XY, 16)
    MensagemCifrada = hex(pow(XYfim, e, n))

    return menos2(MensagemCifrada)

def assinatura(mensagem, d, n):
    menhash = hashlib.new("sha3_512", mensagem.encode())
    menhash = menhash.hexdigest()
    mensagem_cifrada = hex(pow(int(menhash,16), d, n))
    mensagem_base64 = base64_cifra(mensagem_cifrada)
    print('Assinatura feita com sucesso!!!\n')
    return mensagem_base64

def verifica(mensagem_decifrada, assinatura, e, n):
    menhash = hashlib.new("sha3_512", mensagem_decifrada.encode())
    menhash = menhash.hexdigest()
    assinatura_sem_base64= base64_decifra(assinatura)
    assinatura_hash = hex(pow(int(assinatura_sem_base64,16), e, n))
    assinatura_hash = menos2(assinatura_hash)

    if assinatura_hash == menhash:
        print('Assinatura confirmada!!!')
    else:
        print('Assinatura não confirmada!!!')

def cifra():
    p = gerador()
    q = gerador()
    n = p*q
    phin = (p-1)*(q-1)
    e = random.randrange(2, phin-1)
    aux = (math.gcd(phin, e))
    r = random.getrandbits(512)

    while(aux != 1):
        e = random.randrange(1, phin)
        aux = (math.gcd(phin,e))
        
    d = pow(e, -1, phin)
    mensagem = str(input('Digite a mensagem a ser criptografada:\n'))
    mensagem_assinada = assinatura(mensagem, d, n)
    mensagem_Hex = mensagem.encode().hex()
    mensagem_cifrada = oaepCifra(mensagem_Hex, e, n, r)
    if mensagem_cifrada != False:
        mensagem_basecifra = base64_cifra(mensagem_cifrada)
        print('Dois arquivos txt foram criados no diretorio')
        print('Um contendo todos os dados gerados nessa funcao para sua verificacao visual em \'Cifra.txt\'')
        print('Pois o terminal ficou extremamente poluido ao mostrar os dados gerados, já que os números são muito grandes')
        print('E todos os dados que serao usados para decifracao em \'RSA.txt\'.')
        print('Caso queira decifrar a mensagem basta escolher decifracao na proxima execucao e ele fara verificacao da assinatura e decifracao')

#def decifra():

def main():
    op = int(input('Escolha uma opção:\n1: Cifrar uma mensagem\n2:Decifrar uma mensagem(por txt)'))

    if op == 1:
        cifra()    
    else:
        verifica(mensagem, mensagem_assinada, e, n)
    
    # print("Base64 cifrada = ", mensagem_basecifra)
    # mensagem_basedecifra = base64_decifra(mensagem_basecifra)
    # print("Base64 decifra = ", mensagem_basedecifra)
    # mensagemdecifrada = oaepDecifra(mensagem_basedecifra, mensagemHex, d, n, r)
    # print("Mensagem Cifrada = ", mensagemcifrada)
    # print("Mensagem Decifrada = ", mensagemdecifrada)
if __name__ == '__main__':
    main()
