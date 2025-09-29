# Project-2-SIO-equipa_16

### Autores
        - Nuno Cunha, 98124
        - Filipe Silveira, 97981
        - Nuno Matos, 97915
        - Ana Rosa, 98678
        
### Dependencies (tested on python 3.8.10)
pip install Flask
pip install cryptography


### Descrição do Projeto

UAP funcionalidades:

- Permite ter vários utilizadores, cada um deles com os seus pares de chaves (dns-username-password).
- Permite que um novo utilizador se registe.
- Um utilizador pode adicionar, remover e editar os seus pares de chaves.
- Permite de forma assincrona fazer a autenticação numa webapp, sendo que existe um socket para ouvir as ligações na porta 6000. Neste sentido, basta ter a UAP ligada com a sessão iniciada, pelo que não é necessária nenhuma interação por parte do utilizador para além do clicar no butão "UAP" da webapp.
- Tem vários shortcuts como clicar no "enter" para submeter os dados / editar pares de chaves, "delete" para eliminar pares de chaves e "double left click" para conseguir visualizar a password.
- A UAP foi compilada para exe, porque se não seria trivial para um atacante ter acesso às contas dos utilizadores.
- A UAP a cada dez minutos encerra a sessão do utilizador.

Encriptação na UAP:

- O ficheiro data.json está encriptado com cifra simétrica usando AES modo CBC, onde a KEY e o IV estão guardados no código da UAP. É de notar que como a UAP está compilada em exe fica mais difícil para um atacante descobrir a KEY e o IV.
- As palavras passes e nomes de utilizador dos utilizadores da UAP estão também encriptados, sendo que sobre o username é feito um hash(sha-256) e na password é realizado um hash(sha-256) com um salt(sufixo). O salt é obtido através de um hash(sha-256) sobre o id do utilizador. 
- A password dos pares de chaves de um utilizador são encriptadas com AES modo CBC, que é uma cifra simétrica, onde a KEY e o IV são diferentes para cada user da app. Os últimos 4 caracteres da KEY são os primeiros 4 do utilizador atual e os primeiros 4 caracteres do IV são os primeiros 4 do utilizador atual.
- Todas as passwords dos pares de chaves têm um salt diferente que é obtido atraves de um hash(sha-256) sobre o id do par de chave, que é depois adicionado à password(sufixo). Por fim a password é encriptada com AES modo CBC onde a KEY e o IV são únicos desse utilizador.

Webapp:

- Ao clicar no botão UAP a webapp envia um pedido para o utilizador que será apanhado pela UAP.
- Enquanto o e-chap é realizado a webapp espera mostrando uma loading page, e quando estiver concluído o utilizador é redirecionado para a sua conta.

### Observações 

No sentido de uma melhor visuzalização no ecrã, o trabalho realizado, Project-2-SIO-equipa_16, assim como o anterior, project-1-vulnerabilities, devem ser colocados com uma dimensão 1920x1080 e com uma escala a 100%.
