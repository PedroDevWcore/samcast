const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { query } = require('../../config/database');
const { adminAuth, logAdminAction, JWT_SECRET } = require('../../middlewares/adminAuth');

const router = express.Router();

// Login administrativo
router.post('/login', async (req, res) => {
  try {
    const { email, senha } = req.body;

    if (!email || !senha) {
      return res.status(400).json({
        success: false,
        error: 'Email e senha são obrigatórios'
      });
    }

    // Buscar administrador
    const admins = await query(
      'SELECT * FROM administradores WHERE email = ? AND ativo = 1',
      [email]
    );

    if (admins.length === 0) {
      return res.status(401).json({
        success: false,
        error: 'Credenciais inválidas'
      });
    }

    const admin = admins[0];

    // Verificar senha
    const senhaValida = admin.senha ? await bcrypt.compare(senha, admin.senha) : false;
    if (!senhaValida || !admin.senha) {
      return res.status(401).json({
        success: false,
        error: 'Credenciais inválidas'
      });
    }

    // Gerar token de sessão
    const sessionToken = crypto.randomBytes(64).toString('hex');
    const expiresAt = new Date(Date.now() + 8 * 60 * 60 * 1000); // 8 horas

    // Criar sessão
    await query(`
      INSERT INTO admin_sessions (admin_id, token, ip_address, user_agent, expires_at)
      VALUES (?, ?, ?, ?, ?)
    `, [
      admin.codigo,
      sessionToken,
      req.ip || req.connection.remoteAddress || 'unknown',
      req.get('User-Agent') || 'unknown',
      expiresAt
    ]);

    // Atualizar último acesso
    await query(
      'UPDATE administradores SET ultimo_acesso = NOW() WHERE codigo = ?',
      [admin.codigo]
    );

    // Log da ação
    await logAdminAction(admin.codigo, 'login', null, null, null, { ip: req.ip }, req);

    res.json({
      success: true,
      token: sessionToken,
      admin: {
        id: admin.codigo,
        nome: admin.nome,
        email: admin.email,
        nivel_acesso: admin.nivel_acesso
      }
    });

  } catch (error) {
    console.error('Admin login error:', error);
    res.status(500).json({
      success: false,
      error: 'Erro interno do servidor'
    });
  }
});

// Logout administrativo
router.post('/logout', adminAuth, async (req, res) => {
  try {
    const token = req.header('Authorization')?.replace('Bearer ', '');
    
    // Remover sessão
    await query('DELETE FROM admin_sessions WHERE token = ?', [token]);

    // Log da ação
    await logAdminAction(req.admin.id, 'logout', null, null, null, null, req);

    res.json({
      success: true,
      message: 'Logout realizado com sucesso'
    });

  } catch (error) {
    console.error('Admin logout error:', error);
    res.status(500).json({
      success: false,
      error: 'Erro interno do servidor'
    });
  }
});

// Verificar sessão atual
router.get('/me', adminAuth, async (req, res) => {
  try {
    res.json({
      success: true,
      admin: req.admin
    });
  } catch (error) {
    console.error('Admin me error:', error);
    res.status(500).json({
      success: false,
      error: 'Erro interno do servidor'
    });
  }
});

// Alterar senha
router.post('/change-password', adminAuth, async (req, res) => {
  try {
    const { senhaAtual, novaSenha } = req.body;

    if (!senhaAtual || !novaSenha) {
      return res.status(400).json({
        success: false,
        error: 'Senha atual e nova senha são obrigatórias'
      });
    }

    if (novaSenha.length < 6) {
      return res.status(400).json({
        success: false,
        error: 'Nova senha deve ter pelo menos 6 caracteres'
      });
    }

    // Buscar admin atual
    const admins = await query(
      'SELECT senha FROM administradores WHERE codigo = ?',
      [req.admin.id]
    );

    if (admins.length === 0) {
      return res.status(404).json({
        success: false,
        error: 'Administrador não encontrado'
      });
    }

    const admin = admins[0];
    if (!admin.senha) {
      return res.status(400).json({
        success: false,
        error: 'Senha não configurada para este administrador'
      });
    }

    // Verificar senha atual
    const senhaValida = await bcrypt.compare(senhaAtual, admin.senha);
    if (!senhaValida) {
      return res.status(401).json({
        success: false,
        error: 'Senha atual incorreta'
      });
    }

    // Criptografar nova senha
    const novaSenhaCriptografada = await bcrypt.hash(novaSenha, 10);

    // Atualizar senha
    await query(
      'UPDATE administradores SET senha = ? WHERE codigo = ?',
      [novaSenhaCriptografada, req.admin.id]
    );

    // Log da ação
    await logAdminAction(req.admin.id, 'change_password', 'administradores', req.admin.id, null, null, req);

    res.json({
      success: true,
      message: 'Senha alterada com sucesso'
    });

  } catch (error) {
    console.error('Admin change password error:', error);
    res.status(500).json({
      success: false,
      error: 'Erro interno do servidor'
    });
  }
});

module.exports = router;