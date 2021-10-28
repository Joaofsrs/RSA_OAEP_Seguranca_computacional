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

'''
    Funcao cifra usada para cifrar um texto, primeiro gerando as variaveis usadas, 
    em seguida pegando a mensagem do terminal, e fazendo a assinatura. 
    Pegando a mensagem original e tranformando em hexadecimal, para poder cifrar a mensagem em oaep,
    em seguida formatando em base64, e publicando tudo em um arquivo de texto.
'''
def cifra():
    d1, n1, e1 = gera_var()
    d2, n2, e2 = gera_var()
    r = random.getrandbits(512)
    mensagem = str(input('Digite a mensagem a ser criptografada:\n'))
    mensagem_assinada = assinatura(mensagem, d1, n1)
    mensagem_Hex = mensagem.encode().hex()
    mensagem_cifrada = oaep_cifra(mensagem_Hex, e2, n2, r)
    tamanho_msg = int(math.floor(len(mensagem_Hex)/2))

    if mensagem_cifrada != False:
        mensagem_basecifra = base64_cifra(mensagem_cifrada)
        salva(str(e1), str(n1), str(d1), str(e2), str(n2), str(d2), str(r), mensagem_basecifra, mensagem_assinada, str(tamanho_msg))
        print('Um arquivo Cifra.txt foi criado no diretório para verificação visual dos dados e sera usado na decicfracao tambem')
        print('O arquivo contem todos os dados gerados nessa funcao para sua verificacao visual')
        print('Pois o terminal ficou extremamente poluido ao mostrar os dados gerados, ja que os números sao muito grandes')
        print('Caso queira decifrar esta mensagem basta escolher decifracao na proxima execucao e ele fara verificacao da assinatura e decifracao')
        
'''
    A funcao gera_var, gera todas as variaveis usadas para fazer o RSA, onde temos P e Q, como numero primos
    gerados aleatoriamente pela funcao gerador, em seguida eh feito todos os calculos para achar N, E e o D,
    N e E sendo as chaves publicas, e D uma chave privada
'''
def gera_var():
    p = gerador()
    q = gerador()
    n = p*q
    phin = (p-1)*(q-1)
    e = random.randrange(2, phin-1)
    aux = (math.gcd(phin, e))
    while(aux != 1):
        e = random.randrange(1, phin)
        aux = (math.gcd(phin,e))
        
    d = pow(e, -1, phin)

    return d, n, e     

'''
    A funcao gerador eh usada para gerar numeros aleatorios de 1024 bits, esse numero so eh retornado caso 
    seja um numero impar de acordo com a funcao de miller_rabin
'''
def gerador():
    num = random.getrandbits(1024)
    while(miller_rabin(num) != True):
        num = random.getrandbits(1024)

    return num

'''
    A funcao de miller_rabin eh usada para verificar se um numero eh primo ou nao,
    a funcao faz uma serie de teste, e usado um calculo probabilistico, caso o numero nao passe no teste
    ele eh um numero nao primo, mas caso ele passe, ele tem uma probabilidade bem auto de ser um numero primo 
'''
def miller_rabin(n):
    s = 0
    d = n-1

    # Caso n seja igual a 2, n eh um numero primo
    if n == 2:  
        return True

    # Caso n seja um numero divisivel por 2 ou seja menor que 2, n eh um numero nao primo
    if n%2 == 0 or n < 2:
        return False

    # Caso n passe pelo primeiro teste, ele segue para o calculo de d, onde se tenta achar um d,
    # onde temos d = (n-1)/2^s
    while d % 2 == 0:
        s += 1
        d //= 2
    
    #sao feitos um total de 40 teste em n para ter a certeza que n eh um numero primo
    for i in range(40):
        band = 0
        auxs = s
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)                # x = a^d mod(n)

        # Caso x seja 1, entao temos que a nao tem divisor comum com n
        if x == 1:
            band = 1
            continue
        # Caso nao passe no teste, eh feito um segundo teste, x = a^((2^r)*d) mod(n), procurando um r entre 0 e s-1 
        while auxs != 0:
            if x == n - 1:
                band = 1
                break

            x = pow(x, 2, n)
            auxs -= 1
        # Caso nao passe em nenhum dos teste, n eh considera um numero nao primo
        if band == 0: 
            return False
    
    # Caso passe pelo teste, n eh considera um numero primo
    return True

'''
    A funcao assinatura eh usada para gerar a assinatura de uma mensagem, para poder ser verificado ao final da decifracao,
    a funcao recebe a mensagem original, D(chave privada) e N.
    A funcao comeca aplicando hash na mensagem, em seguida aplicando a cifra RSA usando a chave privada e N, e ao final eh 
    aplicado o formato base64 na mensagem, e assim eh feita a assinatura, em seguida retorna essa assinatura
'''
def assinatura(mensagem, d, n):
    menhash = hashlib.new("sha3_512", mensagem.encode())
    menhash = menhash.hexdigest()
    mensagem_cifrada = hex(pow(int(menhash,16), d, n))
    mensagem_base64 = base64_cifra(mensagem_cifrada)
    print('Assinatura feita com sucesso!!!\n')
    
    return mensagem_base64

'''
    A funcao de base 64 serve para formatacao da mensagem criptografada antes de ser enviada
    A funcao recebe a mensagem criptografada e juntando os bits de 3 em 3 caracteres de 8 bits cada, tranforma eles em, 
    4 numeros de 6 bits e depois adiciona padding compsto por 0, 1 ou 2 '=' para garantir que a string retornada seja divisivel por 3
'''
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

'''
    A funcao de oaep eh a funcao responsavel por cifrar a nossa mensagem, sao enviadas para ela a mensagem original,
    o numero aleatorio r e as chaves publicas do receptor da mensagem.
    Eh feito um padding na mensagem composto pela mensagem 'hasheada' com sha3 512 bits, k1 zeros, um '01' e por fim a propria mensagem
    Apos isso sao feitas duas mascaras que tambem usarao numeros aleatorios e essas mascaras farao xor primeiramente com a mensagem
    com o padding, depois com o r, esses dois xor's sao entao somados e a mensagem eh cifrada usando o algoritmo RSA
'''
def oaep_cifra(mensagem, e, n, r):
    lista_zeros = []
    menhash = hashlib.new("sha3_512", mensagem.encode())
    menhash = menhash.hexdigest()
    tamanho_msg = int(math.floor(len(mensagem)/2))
    tamanho_chave = int(math.ceil(size(n)/8))
    k0 = int(math.ceil(size(r)/8))
    k1 = tamanho_chave - 2 * k0 - tamanho_msg - 2
 
    if k1 < 0:
        print('Tamanho da mensagem muito grande')
        return False

    while len(lista_zeros) < 2 * k1:
        lista_zeros.append('0')

    lista_zeros = "".join(lista_zeros)
    completas = int(menhash + lista_zeros + '01' + mensagem, 16)
    tamanho_mascara = k0 + k1 + tamanho_msg + 1
    G = mascara(menos2(hex(r)), tamanho_mascara)
    X = int(G, 16) ^ completas
    Xhex= menos2(hex(X))
    H = mascara(Xhex, k0)
    Y = int(H, 16) ^ r
    Yhex = menos2(hex(Y))
    XY = '00' + Yhex + Xhex
    XYfim = int(XY, 16)
    MensagemCifrada = hex(pow(XYfim, e, n))

    return menos2(MensagemCifrada)

'''
    A funcao de mascara recebe um texto e o tamanho que queremos que ele saia, a saida sera o texto mais um contador que sera feito hash
    ate que a saida saia do tamanho especificado
'''
def mascara(texto , tamanho):
    contador = 0
    saida = ""
    
    while len(saida) < tamanho:
        C = i2osp(contador)
        teste = texto+str(C)
        hash = hashlib.new("sha3_512", teste.encode())
        saida += hash.hexdigest()
        contador += 1
        
    return saida 

'''
    Funcao responsavel pela conversao do numero do contador para uma string de tamanho definido
'''
def i2osp(num):
    return "".join([chr((num >> (8 * i)) & 0xFF) for i in reversed(range(4))])

'''
    A funcao menos2 eh uma funcao usada para tirar os dois primeiros caracteres de strings geralmente em hexadecimal,
    strings que contem 0x no inicio 
'''
def menos2(num):
    return num[2:len(num)]

'''
    A funcao salva_hash pega a chave ou o nonce e cria o txt correspondente e salva os 16 bytes que foram usados
    os bytes sao guardados em int separados por espaco 
'''
def salva(e1, n1, d1, e2, n2, d2, r, mensagem_basecifra, mensagem_assinada, tamanho_msg):
    arq = open('Cifra.txt','w+')

    arq.write('Sua mensagem cifrada = ' + mensagem_basecifra + '\n')
    arq.write('Tamanho da mensagem em bytes = ' + tamanho_msg + '\n')
    arq.write('Sua chave privada(d):[' + d1 +']\n')
    arq.write('Sua chave publica(e):[' + e1 + ']\n')
    arq.write('Sua chave publica(n):[' + n1 + ']\n')
    arq.write('Chave privada do receptor(d):[' + d2 +']\n')
    arq.write('Chave publica do receptor(e):[' + e2 + ']\n')
    arq.write('Chave publica do receptor(n):[' + n2 + ']\n')
    arq.write('Seu R gerado:[' + r + ']\n')
    arq.write('Sua mensagem assinada = ' + mensagem_assinada + '\n')  

    arq.close()

'''
    Funcao usada para fazer a decifracao da mensagem, primeiro pegando essa mensagem cifrada e as variaveis, tirando ela de base64 e 
    em seguida enviar essa mensagem para a funcao oaep, e depois para a verificacao da assinatura
'''
def decifra():
    print('Essa funcao pegara automaticamente os dados em \'Cifra.txt\' criado no seu diretorio caso algo ja tenha sido criptografado')
    print('Caso queira testar com dados proprios veja primeiro o readme.txt que fala como devem ser escritos os dados em \'Cifra.txt\'')
    op = int(input('Caso o esteja tudo certo digite 1 para continuar, ou 0 para parar o programa\n'))
    if op == 1:
        mensagem_basecifra, tamanho_msg, d, e, n1 , n2, tamanho_r, mensagem_assinada = le_arq()
        mensagem_basedecifra = base64_decifra(mensagem_basecifra)
        mensagem_decifrada = oaep_decifra(mensagem_basedecifra, tamanho_msg, d, n2, tamanho_r)
        verifica(mensagem_decifrada, mensagem_assinada, e, n1)
        print("Mensagem Decifrada:",mensagem_decifrada)
    else:
        return

'''
    Funcao usada para ler o arquivo de texto contendo as chaves publicas e privadas, e mensagem cifrar junto da
    assinatura, para a funcao de decifracao 
'''
def le_arq():
    arq = open('Cifra.txt','r')

    lista = arq.read().splitlines()

    arq.close()
    mensagem_basecifra = lista[0][23:len(lista[0])]
    tamanho_msg = int(lista[1][31:len(lista[1])])
    e = int(lista[3][22:len(lista[3])-1])
    n1 = int(lista[4][22:len(lista[4])-1])
    d = int(lista[5][30:len(lista[5])-1])
    n2 = int(lista[7][30:len(lista[7])-1])
    r = int(lista[8][14:len(lista[8])-1])
    r = int(math.ceil(size(r)/8))
    mensagem_assinada = lista[9][24:len(lista[9])]
    return mensagem_basecifra, tamanho_msg, d, e, n1, n2, r, mensagem_assinada

'''
    A funcao de base 64 decifra serve para tirar o base 64 da mensagem criptografada enviada
    A funcao recebe a mensagem criptografada em base 64 os paddings de '=' sao substituidos por A's, e fazendo o inverso da outra funcao
    essa pega a string de 4 em 4 caracteres de 6 bits cada e tranforma eles em 3 caracteres de 8 bits novamente
'''
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

'''
    A funcao de oaep eh a funcao responsavel por decifrar a nossa mensagem, sao enviadas para ela a mensagem cifrada,
    o numero aleatorio r e a chave privada do receptor da mensagem.
    Primeiro eh desfeita a criptografia RSA, depois disso voltamos as variaveis X e Y usando And's com a variavel XY
    E logo apos a mascara de X faz um or com Y para voltar o nosso numero r aleatorio, depois eh feita a mascara do r
    e um xor dela com o X fazendo assim nossa mensagem com o padding voltar e depois basta fazer o and com o tamanho original
    da mensagem para descartar o padding e retornar nossa mensagem
'''
def oaep_decifra(cifrada, tamanho_msg, d, n, k0):
    tamanho_chave = int(math.ceil(size(n)/8))
    k1 = tamanho_chave - 2 * k0 - tamanho_msg - 2
    XYfim = pow(int(cifrada, 16), d, n)
    
    X = (pow(2, 8 * (k0 + k1 + tamanho_msg + 1)) - 1) & XYfim
    Y = (pow(2, 8 * k0) - 1) & (XYfim >> 8 * (k0 + k1 + tamanho_msg + 1))
    volta_r = int(mascara(menos2(hex(X)), k0), 16) ^ Y

    mensagem_completas = int(mascara(menos2(hex(volta_r)), k0 + k1 + tamanho_msg + 1), 16) ^ X
    mensagem = (pow(2, 8 * tamanho_msg) - 1) & mensagem_completas
    
    return binascii.unhexlify(menos2(hex(mensagem))).decode()


'''
    A funcao verfica recebe a mensagem_dicifrada, assinatura, E(chave publica) e N.
    A funcao eh responsavel por verificar se a mensagem decifrada eh uma mensagem real/esperada,
    onde pegamos essa mensagem decifrada e fazemos o hash nela, em seguida pegamos assinatura, e voltamos ela,
    tirando a assinatura da base64 e Decifrando o RSA dela, em seguida verificamos, se a assinatura(em hash)
    eh igual a mensagem decifrada(em hash), caso seja, eh mostrada a mensagem (Assinarua da mensagem confirmada),
    caso contrario eh mostrada a mensagem(Assinatura da mensagem nao confirmada)
'''
def verifica(mensagem_decifrada, assinatura, e, n):
    menhash = hashlib.new("sha3_512", mensagem_decifrada.encode())
    menhash = menhash.hexdigest()
    assinatura_sem_base64= base64_decifra(assinatura)
    assinatura_hash = hex(pow(int(assinatura_sem_base64,16), e, n))
    assinatura_hash = menos2(assinatura_hash)
    print()
    if assinatura_hash == menhash:
        print('Assinatura da mensagem confirmada!!!')
    else:
        print('Assinatura da mensagem não confirmada!!!')

'''
    A funcao main contem o menu usado para direcionar a pessoa paras as funcoes de cifra e decifra
'''
def main():
    op = int(input('Escolha uma opção:\n1: Cifrar uma mensagem\n2:Decifrar uma mensagem(por txt)\n'))

    if op == 1:
        cifra()     
    else:
        decifra()  
    
if __name__ == '__main__':
    main()
