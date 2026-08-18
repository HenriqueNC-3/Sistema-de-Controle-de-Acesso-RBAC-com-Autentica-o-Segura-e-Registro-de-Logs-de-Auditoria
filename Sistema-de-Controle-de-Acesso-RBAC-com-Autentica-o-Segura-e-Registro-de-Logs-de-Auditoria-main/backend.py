import sqlite3
import bcrypt
import os

# 0. Função para inicializar o Banco de Dados com o arquivo dados.sql
def inicializar_banco():
    nome_banco = 'sistema_seguranca.db'
    
    # Descobre a pasta exata onde o arquivo backend.py está salvo
    pasta_atual = os.path.dirname(os.path.abspath(__file__))
    caminho_sql = os.path.join(pasta_atual, 'dados.sql')
    caminho_banco = os.path.join(pasta_atual, nome_banco)
    
    conexao = sqlite3.connect(caminho_banco)
    cursor = conexao.cursor()
    
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='usuarios';")
    tabela_existe = cursor.fetchone()
    
    if not tabela_existe:
        print("Criando tabelas no banco de dados a partir do dados.sql...")
        if os.path.exists(caminho_sql):
            with open(caminho_sql, 'r', encoding='utf-8') as f:
                script_sql = f.read()
            cursor.executescript(script_sql)
            conexao.commit()
            print("Tabelas criadas com sucesso!\n")
        else:
            print(f"Erro: Arquivo 'dados.sql' não foi encontrado em: {caminho_sql}")
            
    conexao.close()


# 1. Função para gerar o hash seguro da senha
def gerar_hash_senha(senha_texto_puro: str) -> str:
    senha_bytes = senha_texto_puro.encode('utf-8')
    salt = bcrypt.gensalt()
    hash_senha = bcrypt.hashpw(senha_bytes, salt)
    return hash_senha.decode('utf-8')


# 2. Função para cadastrar o usuário no banco de dados
def cadastrar_usuario(nome, email, senha_texto_puro, perfil_id):
    senha_criptografada = gerar_hash_senha(senha_texto_puro)
    
    try:
        conexao = sqlite3.connect('sistema_seguranca.db')
        cursor = conexao.cursor()
        
        sql = """
            INSERT INTO usuarios (nome, email, senha_hash, perfil_id)
            VALUES (?, ?, ?, ?)
        """
        
        cursor.execute(sql, (nome, email, senha_criptografada, perfil_id))
        conexao.commit()
        
        print(f"Usuário '{nome}' cadastrado com sucesso!")
        print(f"Hash salvo no banco: {senha_criptografada}\n")
        
    except sqlite3.IntegrityError:
        print("Erro: O e-mail informado já está cadastrado.")
    except Exception as e:
        print(f"Erro ao cadastrar usuário: {e}")
    finally:
        conexao.close()

# 3. Função para registrar eventos de auditoria no banco 
def registrar_log(usuario_id, acao, ip_origem, detalhes):
    try:
        conexao = sqlite3.connect('sistema_seguranca.db')
        cursor = conexao.cursor()
        
        sql = """
            INSERT INTO logs_auditoria (usuario_id, acao, ip_origem, detalhes)
            VALUES (?, ?, ?, ?)
        """
        
        cursor.execute(sql, (usuario_id, acao, ip_origem, detalhes))
        conexao.commit()
        
        print(f"Log de auditoria registrado: Usuário {usuario_id}, Ação: {acao}")
        
    except Exception as e:
        print(f"Erro ao registrar log de auditoria: {e}")
    finally:
        conexao.close()


# 4. Função de Login / Autenticação
def autenticar_usuario(email, senha_texto_puro, ip_origem="127.0.0.1"):
    try:
        conexao = sqlite3.connect('sistema_seguranca.db')
        cursor = conexao.cursor()
        
        # Busca o usuário pelo e-mail de forma segura
        sql = "SELECT id, nome, senha_hash, perfil_id FROM usuarios WHERE email = ?"
        cursor.execute(sql, (email,))
        usuario = cursor.fetchone()
        conexao.close()
        
        # Caso 1: E-mail não encontrado
        if not usuario:
            print(" Falha no login: Usuário não encontrado.")
            registrar_log(None, 'LOGIN_FALHA', ip_origem, f'Tentativa de login com e-mail inexistente: {email}')
            return False
        
        usuario_id, nome, senha_hash_banco, perfil_id = usuario
        
        # Valida a senha usando o bcrypt
        senha_correta = bcrypt.checkpw(
            senha_texto_puro.encode('utf-8'), 
            senha_hash_banco.encode('utf-8')
        )
        
        # Caso 2: Senha incorreta
        if not senha_correta:
            print(f" Falha no login para {email}: Senha incorreta.")
            registrar_log(usuario_id, 'LOGIN_FALHA', ip_origem, 'Senha incorreta informada.')
            return False
        
        # Caso 3: Login efetuado com sucesso!
        print(f" Login bem-sucedido! Bem-vindo(a), {nome}.")
        registrar_log(usuario_id, 'LOGIN_SUCESSO', ip_origem, 'Autenticação realizada com sucesso.')
        return True

    except Exception as e:
        print(f"Erro durante o login: {e}")
        return False

#5. Função de Verificação de Permissões (RBAC)
def verificar_permissao(perfil_id, perfis_permitidos):
    """
    Mapeamento de Perfis do Banco:
    1 - ADMIN
    2 - ANALISTA_SEGURANCA
    3 - USUARIO
    """
    return perfil_id in perfis_permitidos

#6. Função para exibir logs de auditoria(Acesso Restrito)

def visualizar_logs_auditoria(perfil_usuario_logado):
    perfis_permitidos = [1, 2]  # ADMIN e ANALISTA_SEGURANCA
    if not verificar_permissao(perfil_usuario_logado, perfis_permitidos):
        print("Acesso negado: Você não tem permissão para visualizar os logs de auditoria.")
        return
    try:
        conexao = sqlite3.connect('sistema_seguranca.db')
        cursor = conexao.cursor()

        sql = """ SELECT 
                l.id, 
                COALESCE(u.email, 'Usuário não encontrado') AS usuario,
                l.acao,
                l.ip_origem,
                l.detalhes,
                l.data_hora
                FROM logs_auditoria l
                LEFT JOIN usuarios u ON l.usuario_id = u.id
                ORDER BY l.data_hora DESC
                LIMIT 10
        """
        cursor.execute(sql)
        logs = cursor.fetchall()
        conexao.close()
        print("\n=== 📜 RELATÓRIO DE AUDITORIA DE SEGURANÇA (ÚLTIMOS EVENTOS) ===")
        print(f"{'ID':<4} | {'Usuário':<25} | {'Ação':<15} | {'IP':<15} | {'Data/Hora'}")
        print("-" * 80)
        for log in logs:
            log_id, usuario, acao, ip, detalhes, data_hora = log
            print(f"{log_id:<4} | {usuario:<25} | {acao:<15} | {ip:<15} | {data_hora}")
        print("-" * 80 + "\n")

    except Exception as e:
        print(f" Erro ao consultar logs: {e}")

def menu_principal():
    inicializar_banco()

    usuario_logado = None

    while True:
        print("SISTEMA DE SEGURANÇA - MENU PRINCIPAL")

        if usuario_logado:
            print(f"Usuário logado: {usuario_logado['nome']} (Perfil ID: {usuario_logado['perfil_id']})")
            print("1. Visualizar Logs de Auditoria")
            print("2. Logout")
            print("3. Sair do Sistema")
        else:
            print("1. Login")
            print("2. Cadastrar Usuário")
            print("3. Sair do Sistema")

        opcao = input("Escolha uma opção: ").strip()

        if not usuario_logado:
            if opcao == '1':
                print("\n=== LOGIN ===")
                email = input("E-mail: ").strip()
                senha = input("Senha: ").strip()

                conexao = sqlite3.connect('sistema_seguranca.db')
                cursor = conexao.cursor()
                cursor.execute("SELECT id, nome, senha_hash, perfil_id FROM usuarios WHERE email = ?", (email,))
                usuario = cursor.fetchone()
                conexao.close()

                if usuario and autenticar_usuario(email, senha):
                    usuario_logado = {
                        'id': usuario[0],
                        'nome': usuario[1],
                        'perfil_id': usuario[3]
                    }
            elif opcao == '2':
                print("\n=== CADASTRO DE USUÁRIO ===")
                nome = input("Nome Completo: ")
                email = input("E-mail: ")
                senha = input("Senha: ")
                print("Perfis disponíveis: 1 - ADMIN, 2 - ANALISTA_SEGURANCA, 3 - USUARIO")

                try:
                    perfil_id = int(input("Escolha o Perfil (1, 2 ou 3): "))
                    cadastrar_usuario(nome, email, senha, perfil_id)
                except ValueError:
                    print("Perfil inválido. Por favor, insira um número inteiro (1, 2 ou 3).")
            elif opcao == '3':
                print("Saindo do sistema...")
                break
        else:
            if opcao == '1':
                visualizar_logs_auditoria(perfil_usuario_logado = usuario_logado['perfil_id'])
            elif opcao == '2':
                print(f"Usuário {usuario_logado['nome']} deslogado com sucesso.")
                usuario_logado = None
            elif opcao == '3':
                print("Saindo do sistema...")
                break
            else:
                print("Opção inválida. Tente novamente.")

                
if __name__ == "__main__":
    menu_principal()