CREATE TABLE IF NOT EXISTS perfis(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    nome VARCHAR(100) NOT NULL UNIQUE,
    descricao TEXT
);

CREATE TABLE IF NOT EXISTS usuarios(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    nome VARCHAR(100) NOT NULL,
    email VARCHAR(100) NOT NULL UNIQUE,
    senha_hash VARCHAR(255) NOT NULL,
    perfil_id INTEGER NOT NULL,
    criado_em DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (perfil_id) REFERENCES perfis(id)
);

CREATE TABLE IF NOT EXISTS logs_auditoria(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    usuario_id INTEGER NULL,
    acao VARCHAR(255) NOT NULL,
    ip_origem VARCHAR(45) NOT NULL,
    detalhes TEXT,
    data_hora DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (usuario_id) REFERENCES usuarios(id)
);

INSERT OR IGNORE INTO perfis (id,nome,descricao) VALUES
(1,'Administrador','Perfil com acesso total ao sistema'),
(2,'Analista de Segurança', 'Pode visualizar logs de auditoria e relatórios de anomalias'),
(3,'Usuario','Perfil com acesso limitado ao sistema');