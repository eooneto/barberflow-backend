/*
  =============================================================================
  PROJETO: BARBERFLOW API (COM AUTENTICAÇÃO E SERVIÇOS)
  AUTOR: Neto Souza
  =============================================================================
*/
require('dotenv').config();
const express = require('express');
const { Pool } = require('pg');
const cors = require('cors');
const helmet = require('helmet');
const bcrypt = require('bcryptjs'); // Criptografia
const jwt = require('jsonwebtoken'); // Token de Acesso

const app = express();
const port = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'SegredoSuperSecretoDoNeto';

// --- CONFIGURAÇÕES GLOBAIS ---
app.use(helmet());
app.use(cors());
app.use(express.json());

// --- CONEXÃO COM BANCO DE DADOS ---
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
});

// --- MIDDLEWARE DE PROTEÇÃO (O Cão de Guarda) ---
// Essa função verifica se o token é válido antes de deixar acessar as rotas
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  // O header vem como "Bearer TOKEN_AQUI", pegamos só a segunda parte
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Acesso negado: Token não fornecido' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Acesso negado: Token inválido ou expirado' });
    }
    // Se o token for válido, salvamos os dados do usuário na requisição
    req.user = user;
    next(); // Pode passar para a rota
  });
}

// =============================================================================
// ROTAS PÚBLICAS (Qualquer um acessa)
// =============================================================================

// --- ROTA DE LOGIN ---
app.post('/auth/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    // 1. Buscar usuário pelo email
    const userResult = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    
    if (userResult.rows.length === 0) {
      return res.status(401).json({ error: 'Email ou senha inválidos' });
    }

    const user = userResult.rows[0];

    // 2. Verificar a senha
    // MODO TESTE: Aceita senha '123456' OU a senha real criptografada
    const validPassword = (password === '123456') || (await bcrypt.compare(password, user.password_hash));

    if (!validPassword) {
      return res.status(401).json({ error: 'Senha incorreta' });
    }

    // 3. VERIFICAR SE A EMPRESA ESTÁ ATIVA
    const orgResult = await pool.query('SELECT * FROM organizations WHERE id = $1', [user.organization_id]);
    const organization = orgResult.rows[0];

    if (organization.status !== 'active') {
      return res.status(403).json({ error: 'Sua conta está suspensa. Contate o suporte.' });
    }

    // 4. Gerar o Token de Acesso
    const token = jwt.sign(
      { 
        userId: user.id, 
        organization_id: user.organization_id, // Padronizado para bater com o banco
        role: user.role 
      },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    // 5. Retornar Dados
    res.json({
      token,
      user: {
        id: user.id,
        name: user.full_name,
        email: user.email,
        role: user.role
      },
      organization: {
        name: organization.name,
        slug: organization.slug
      }
    });

  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Erro interno no servidor' });
  }
});

// --- ROTA DE CADASTRO (Placeholder) ---
app.post('/auth/register', async (req, res) => {
    res.json({ msg: "Em breve: Cadastro automático" });
});

// =============================================================================
// ROTAS PRIVADAS (Só com Token)
// =============================================================================

// --- LISTAR SERVIÇOS ---
app.get('/services', authenticateToken, async (req, res) => {
    try {
        const { rows } = await pool.query(
            'SELECT * FROM services WHERE organization_id = $1 AND active = true ORDER BY name',
            [req.user.organization_id] // O organization_id vem do token
        );
        res.json(rows);
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Erro ao buscar serviços' });
    }
});

// --- CRIAR NOVO SERVIÇO ---
app.post('/services', authenticateToken, async (req, res) => {
    const { name, price, duration, category } = req.body;
    try {
        const { rows } = await pool.query(
            'INSERT INTO services (organization_id, name, price, duration, category) VALUES ($1, $2, $3, $4, $5) RETURNING *',
            [req.user.organization_id, name, price, duration, category]
        );
        res.status(201).json(rows[0]);
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Erro ao criar serviço' });
    }
});

// --- EDITAR SERVIÇO ---
app.put('/services/:id', authenticateToken, async (req, res) => {
    const { id } = req.params;
    const { name, price, duration, category } = req.body;
    try {
        const { rows } = await pool.query(
            'UPDATE services SET name = $1, price = $2, duration = $3, category = $4 WHERE id = $5 AND organization_id = $6 RETURNING *',
            [name, price, duration, category, id, req.user.organization_id]
        );
        if (rows.length === 0) return res.status(404).json({ error: 'Serviço não encontrado' });
        res.json(rows[0]);
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Erro ao atualizar serviço' });
    }
});

// --- DELETAR SERVIÇO (Soft Delete) ---
app.delete('/services/:id', authenticateToken, async (req, res) => {
    const { id } = req.params;
    try {
        await pool.query(
            'UPDATE services SET active = false WHERE id = $1 AND organization_id = $2',
            [id, req.user.organization_id]
        );
        res.json({ message: 'Serviço removido' });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Erro ao excluir serviço' });
    }
});

// =============================================================================
// INICIALIZAÇÃO DO SERVIDOR (Sempre a última parte)
// =============================================================================
app.listen(port, () => {
  console.log(`🔥 API Barberflow rodando na porta ${port}`);
});