CREATE TABLE perfis(
    id INT PRIMARY KEY AUTOINCREMENT,
    nome VARCHAR(100) NOT NULL UNIQUE,
    descricao TEXT
);

CREATE TABLE usuarios(
    id INT PRIMARY KEY AUTOINCREMENT,
    nome VARCHAR(100) NOT NULL,
    email VARCHAR(100) NOT NULL UNIQUE,
    senha_hash VARCHAR(255) NOT NULL,
    perfil_id INT NOT NULL,
    criado_em DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (perfil_id) REFERENCES perfis(id)
);

CREATE TABLE logs_auditoria(
    id INT PRIMARY KEY AUTOINCREMENT,
    usuario_id INT NOT NULL,
    acao VARCHAR(255) NOT NULL,
    ip_origem VARCHAR(45) NOT NULL,
    detalhes TEXT,
    data_hora DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (usuario_id) REFERENCES usuarios(id)
);

INSERT INTO perfis (nome,descricao) VALUES
('Administrador','Perfil com acesso total ao sistema'),
('Analista de Segurança', 'Pode visualizar logs de auditoria e relatórios de anomalias'),
('Usuario','Perfil com acesso limitado ao sistema');