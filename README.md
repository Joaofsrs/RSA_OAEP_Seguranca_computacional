Universidade de Brasilia<br /> 
Instituto de Ciencias Exatas<br /> 
Departamento de Ciencia da Computação<br /> 
Segurança Computacional<br /> 
Aluno: João Fracisco Gomes Targino - 180102991<br /> 
Aluno: João Gabriel Ferreira Sariava - 180103016<br /> 
Versão do python: 3.9.7<br /> 
Sistema utilizado: Windows 10<br /> 

Requerimentos:<br /> 
pyCryptodome para usar a função de size() para retornar o número de bits de um número instalado pelo comando abaixo:
pip install pycryptodomepip

Sobre o Cifra.txt:<br /> 

Toda vez que a função de cifra for escolhida o programa salvará um arquivo txt com todas as informações importantes para visualização,
então caso queiram checar algo, lá salvamos as coisas geradas.<br /> 
Após a função cifra ser executada o programa demora um pouco a pedir entrada da mensagem pois está gerando as chaves privadas e publicas
que são muito grandes.<br /> 
Quando a opção de decifrar for escolhida o programa automaticamente tentará ler o txt, então caso queira colocar dados gerados por você
pode-se ou cifrar qualquer mensagem para ter o template e só modificar ou usar o template abaixo nomeando um txt de Cifra.txt<br /> 

Sua mensagem cifrada = mensagem(sempre com espaço após o =)<br /> 
Tamanho da mensagem em bytes = int(sempre com espaço após o =)<br /> 
Sua chave privada(d):[int]<br /> 
Sua chave publica(e):[int]<br /> 
Sua chave publica(n):[int]<br /> 
Chave privada do receptor(d):[int]<br /> 
Chave publica do receptor(e):[int]<br /> 
Chave publica do receptor(n):[int]<br /> 
Seu R gerado:[int]<br /> 
Sua mensagem assinada = mensagem após passar pela função de assinatura(sempre com espaço após o =)<br /> 
