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
    tamanho_chave = int(math.ceil(size(n)/8))
    tamanho_msg = int(math.floor(len(mensagem)/2))
    k0 = int(math.ceil(size(r)/8))
    k1 = tamanho_chave - 2 * k0 - tamanho_msg - 2
    XYfim = int(pow(int(cifrada, 16), d, n))
    X = (pow(2, 8 * (k0 + k1 + tamanho_msg + 1)) - 1) & XYfim
    Y = (pow(2, 8 * k0) - 1) & (XYfim >> 8 * (k0 + k1 + tamanho_msg + 1))
    volta_r = int(mascara(menos2(hex(X)), k0), 16) ^ Y

    if r != volta_r:
        return False

    mensagem_completas = int(mascara(menos2(hex(volta_r)), k0 + k1 + tamanho_msg + 1), 16) ^ X
    mensagem = (pow(2, 8 * tamanho_msg) - 1) & mensagem_completas
   
    return menos2(hex(mensagem))

def oaepCifra(mensagem, e, n, r):
    lista_zeros = []
    menhash = hashlib.new("sha3_512", mensagem.encode())
    menhash = menhash.hexdigest()
    tamanho_msg = len(mensagem)/2
    tamanho_chave = int(math.ceil(size(n)/8))
    k0 = int(math.ceil(size(r)/8))
    k1 = tamanho_chave - 2 * k0 - tamanho_msg - 2   

    if k1 < 0:
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
    print("X = ", X)
    print("Y = ", Y)
    MensagemCifrada = hex(pow(XYfim, e, n))

    return menos2(MensagemCifrada)

def main():
    p = gerador()
    q = gerador()
    n = p*q
    phin = (p-1)*(q-1)
    e = random.randrange(2, phin-1)
    aux = (math.gcd(phin, e))
    r = random.getrandbits(512)
    print(size(r))
    while( aux != 1):
        e = random.randrange(1, phin)
        aux = (math.gcd(phin,e))
    d = pow(e, -1, phin)
    mensagem = str(input('Digite a mensagem a ser criptografada:\n'))
    mensagemHex = mensagem.encode().hex()
    mensagemcifrada = oaepCifra(mensagemHex, e, n, r)
    mensagemdecifrada = oaepDecifra(mensagemcifrada, mensagemHex, d, n, r)
    print("Mensagem Cifrada = ", mensagemcifrada)
    print("Mensagem Decifrada = ", binascii.unhexlify(mensagemdecifrada).decode())

if __name__ == '__main__':
    main()