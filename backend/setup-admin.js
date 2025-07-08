const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');

const dbConfig = {
  host: '104.251.209.68',
  port: 35689,
  user: 'admin',
  password: 'Adr1an@',
  database: 'db_SamCast',
  charset: 'utf8mb4',
  timezone: '+00:00'
};

async function setupAdmin() {
  let connection;
  
  try {
    console.log('🔧 Conectando ao banco de dados...');
    connection = await mysql.createConnection(dbConfig);
    
    // Criar tabela administradores se não existir
    console.log('📋 Criando tabela administradores...');
    await connection.execute(`
      CREATE TABLE IF NOT EXISTS administradores (
        codigo INT AUTO_INCREMENT PRIMARY KEY,
        nome VARCHAR(255) NOT NULL,
        email VARCHAR(255) UNIQUE NOT NULL,
        senha VARCHAR(255) NOT NULL,
        nivel_acesso ENUM('suporte', 'admin', 'super_admin') DEFAULT 'admin',
        ativo TINYINT(1) DEFAULT 1,
        data_criacao TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        ultimo_acesso TIMESTAMP NULL,
        criado_por INT NULL,
        INDEX idx_email (email),
        INDEX idx_ativo (ativo)
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    `);

    // Criar tabela admin_sessions se não existir
    console.log('📋 Criando tabela admin_sessions...');
    await connection.execute(`
      CREATE TABLE IF NOT EXISTS admin_sessions (
        id INT AUTO_INCREMENT PRIMARY KEY,
        admin_id INT NOT NULL,
        token VARCHAR(255) NOT NULL,
        ip_address VARCHAR(45),
        user_agent TEXT,
        expires_at TIMESTAMP NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_activity TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        FOREIGN KEY (admin_id) REFERENCES administradores(codigo) ON DELETE CASCADE,
        INDEX idx_token (token),
        INDEX idx_admin_id (admin_id),
        INDEX idx_expires (expires_at)
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    `);

    // Criar tabela admin_logs se não existir
    console.log('📋 Criando tabela admin_logs...');
    await connection.execute(`
      CREATE TABLE IF NOT EXISTS admin_logs (
        id INT AUTO_INCREMENT PRIMARY KEY,
        admin_id INT NOT NULL,
        acao VARCHAR(255) NOT NULL,
        tabela_afetada VARCHAR(100),
        registro_id INT,
        dados_anteriores JSON,
        dados_novos JSON,
        ip_address VARCHAR(45),
        user_agent TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (admin_id) REFERENCES administradores(codigo) ON DELETE CASCADE,
        INDEX idx_admin_id (admin_id),
        INDEX idx_acao (acao),
        INDEX idx_created_at (created_at)
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    `);

    // Verificar se já existe um admin
    console.log('🔍 Verificando administrador existente...');
    const [existingAdmins] = await connection.execute(
      'SELECT codigo, email FROM administradores WHERE email = ?',
      ['admin@sistema.com']
    );

    if (existingAdmins.length > 0) {
      console.log('⚠️  Admin já existe, atualizando senha...');
      
      // Atualizar senha do admin existente
      const senhaHash = await bcrypt.hash('admin123', 10);
      await connection.execute(
        'UPDATE administradores SET senha = ?, ativo = 1 WHERE email = ?',
        [senhaHash, 'admin@sistema.com']
      );
      
      console.log('✅ Senha do admin atualizada com sucesso!');
    } else {
      console.log('👤 Criando novo administrador...');
      
      // Criar hash da senha
      const senhaHash = await bcrypt.hash('admin123', 10);
      
      // Inserir admin padrão
      await connection.execute(`
        INSERT INTO administradores (nome, email, senha, nivel_acesso, ativo)
        VALUES (?, ?, ?, ?, ?)
      `, ['Administrador', 'admin@sistema.com', senhaHash, 'super_admin', 1]);
      
      console.log('✅ Administrador criado com sucesso!');
    }

    // Verificar se o admin foi criado/atualizado corretamente
    const [verifyAdmin] = await connection.execute(
      'SELECT codigo, nome, email, nivel_acesso, ativo, LENGTH(senha) as senha_length FROM administradores WHERE email = ?',
      ['admin@sistema.com']
    );

    if (verifyAdmin.length > 0) {
      const admin = verifyAdmin[0];
      console.log('✅ Verificação do admin:');
      console.log(`   ID: ${admin.codigo}`);
      console.log(`   Nome: ${admin.nome}`);
      console.log(`   Email: ${admin.email}`);
      console.log(`   Nível: ${admin.nivel_acesso}`);
      console.log(`   Ativo: ${admin.ativo ? 'Sim' : 'Não'}`);
      console.log(`   Senha Hash Length: ${admin.senha_length} caracteres`);
    }

    console.log('\n🎉 Setup do admin concluído!');
    console.log('📧 Email: admin@sistema.com');
    console.log('🔑 Senha: admin123');
    console.log('🌐 Acesse: /admin/login');

  } catch (error) {
    console.error('❌ Erro no setup do admin:', error);
    process.exit(1);
  } finally {
    if (connection) {
      await connection.end();
    }
  }
}

// Executar setup
setupAdmin();