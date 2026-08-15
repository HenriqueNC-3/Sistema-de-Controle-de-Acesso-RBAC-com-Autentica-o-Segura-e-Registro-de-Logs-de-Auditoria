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
        
        cursor.execute(sql, (nome, email, senha_texto_puro, perfil_id)) # atencao aqui
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

# 4. Função para autenticar o usuário


# --- EXECUÇÃO ---
if __name__ == "__main__":
    # Garante que o banco e as tabelas existam antes de cadastrar
    inicializar_banco()
    
    # Cadastra o usuário
    cadastrar_usuario(
        nome="Henrique Cerqueira",
        email="henrique@email.com",
        senha_texto_puro="MinhaSenhaSuperSegura123",
        perfil_id=1
    )