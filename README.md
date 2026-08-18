# Sistema de Controle de Acesso RBAC com Autenticação Segura e Registro de Logs de Auditoria

Perguntei para o meu Gemini se ele tem alguma ideia boa para um projeto pessoal para eu poder testar as minhas habilidades de programação, e ele me sugeriu essa ideia. Eu acho interessante os conceitos de Cybersegurança e Análise de Dados, então quando ele me deu essa ideia de fazer esse projeto, eu sinceramente eu gostei dela. 

## Aplicação e Objetivo do Projeto

Na rotina corporativa, garantir que apenas pessoas autorizadas acessem informações sensíveis e que **todas as ações sejam rastreáveis** é a base da **Cibersegurança** e da **Governança de Dados**.

O objetivo deste projeto foi construir uma aplicação real de back-end em **Python** integrada a um banco de dados relacional **SQLite**, capaz de simular a gestão de identidades e auditoria de segurança de uma organização de forma resiliente.

### Principais Casos de Uso:
1. **Garantir a Privacidade:** Proteger senhas de usuários usando algoritmos modernos de hashing contra vazamentos.
2. **Mitigar Vulnerabilidades de Injeção:** Impedir interceptações e injeções de código malicioso (*SQL Injection*).
3. **Gerenciar Privilégios (RBAC):** Restringir funcionalidades do sistema com base no perfil do usuário (`ADMIN`, `ANALISTA_SEGURANCA`, `USUARIO`).
4. **Análise de Incidentes:** Registrar e consultar dados de acesso em tempo real para auditorias e detecção de comportamentos anômalos.

---

##  Como o Projeto Foi Desenvolvido (Passo a Passo)

O desenvolvimento foi estruturado em **5 etapas de engenharia**, evoluindo desde a base de dados até a camada de interface:

###  Passo 1: Modelagem do Banco de Dados Relacional (`dados.sql`)
A primeira etapa consistiu no desenho arquitetural do banco. Criei três tabelas estruturadas no SQLite conectadas por chaves estrangeiras (`FOREIGN KEY`) para garantir consistência dos dados:
* **`perfis`**: Mapeia os níveis de acesso disponíveis.
* **`usuarios`**: Armazena cadastros e credenciais protegidas vinculadas a um perfil.
* **`logs_auditoria`**: Registra o histórico de eventos de segurança.

> ** Aprendizado de Análise de Dados:** Durante o desenvolvimento, ajustei a coluna `usuario_id` na tabela de logs para aceitar valores nulos (`NULL`). Isso permitiu o registro crítico de tentativas de login vindas de e-mails inexistentes (comportamento típico de ataques de força bruta) sem gerar quebras de restrição de integridade no banco.

###  Passo 2: Hashing de Senhas com `bcrypt`
Para assegurar a confidencialidade, apliquei o princípio de que **senhas nunca devem habitar um banco de dados em texto puro**.
* Utilizei a biblioteca `bcrypt` em Python para injetar um *salt* aleatório e único a cada registro.
* A senha é transformada em uma string criptográfica irreversível antes da inserção. 
* No login, o método `bcrypt.checkpw()` realiza a verificação matemática segura.

### Passo 3: Autenticação Segura e Prevenção de *SQL Injection*
Na integração do Python com o banco de dados via `sqlite3`, foquei na mitigação de riscos de injeção de código.
* **Abordagem Segura Utilizada:** `cursor.execute("SELECT * FROM usuarios WHERE email = ?", (email,))`
* Ao utilizar **parâmetros curinga (`?`)**, o banco trata qualquer string fornecida estritamente como um dado de busca, anulando tentativas de burlar rotas de login através de comandos concatenados.

### Passo 4: Controle de Acesso Baseado em Funções (RBAC) e Auditoria
Desenvolvi a inteligência de autorização do sistema mapeando restrições de negócio:
* A função `visualizar_logs_auditoria()` executa uma consulta avançada utilizando `LEFT JOIN` entre os logs e os usuários.
* Adicionei um verificador que barra a exibição se o perfil logado for um **`USUARIO` (ID 3)**, emitindo um alerta de acesso negado.
* Usuários com cargo **`ADMIN` (ID 1)** ou **`ANALISTA_SEGURANCA` (ID 2)** recebem a projeção da tabela formatada de acessos recentes.

### Passo 5: Interface Interativa via CLI (`backend.py`)
Por fim, consolidei as funções criando um menu interativo de Linha de Comando (CLI) orientado por loops `while`. A interface gerencia o estado da sessão atual do usuário, permitindo fluxos dinâmicos de cadastro, login, testes de violação de privilégios e encerramento seguro de conexões.

---

## Tecnologias Utilizadas

* **Linguagem:** Python 3.13+
* **Banco de Dados:** SQLite3 (Embutido)
* **Criptografia:** Biblioteca `bcrypt`
* **Versionamento:** Git e GitHub

---

## Como Executar o Projeto

### 1. Clonar o Repositório
```bash
git clone [https://github.com/HenriqueNC-3/Sistema-de-Controle-de-Acesso-RBAC-com-Autentica-o-Segura-e-Registro-de-Logs-de-Auditoria-main.git](https://github.com/HenriqueNC-3/Sistema-de-Controle-de-Acesso-RBAC-com-Autentica-o-Segura-e-Registro-de-Logs-de-Auditoria-main.git)
cd Sistema-de-Controle-de-Acesso-RBAC-com-Autentica-o-Segura-e-Registro-de-Logs-de-Auditoria-main
