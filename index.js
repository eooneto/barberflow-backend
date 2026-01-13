/*
  =============================================================================
  PROJETO: BARBERFLOW API (COM AUTENTICAÇÃO)
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

app.use(helmet());
app.use(cors());
app.use(express.json());

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
});

// --- ROTA DE LOGIN (O GUARDIÃO) ---
app.post('/auth/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    // 1. Buscar usuário pelo email
    const userResult = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    
    if (userResult.rows.length === 0) {
      return res.status(401).json({ error: 'Email ou senha inválidos' });
    }

    const user = userResult.rows[0];

    // 2. Verificar a senha (se bate com a criptografia)
    // OBS: Como criamos o user manualmente no banco com senha '123456' ou hash falso,
    // vamos fazer um "bypass" temporário só pra você testar hoje. 
    // No futuro, usaremos apenas: const validPassword = await bcrypt.compare(password, user.password_hash);
    
    // TEMPORÁRIO PARA TESTE (Se a senha for igual a do banco OU se o hash bater)
    const validPassword = (password === '123456') || (await bcrypt.compare(password, user.password_hash));

    if (!validPassword) {
      return res.status(401).json({ error: 'Senha incorreta' });
    }

    // 3. VERIFICAR SE A EMPRESA PAGOU (STATUS ATIVO)
    const orgResult = await pool.query('SELECT * FROM organizations WHERE id = $1', [user.organization_id]);
    const organization = orgResult.rows[0];

    if (organization.status !== 'active') {
      return res.status(403).json({ error: 'Sua conta está suspensa. Contate o suporte.' });
    }

    // 4. Gerar o Token de Acesso (O Crachá VIP)
    const token = jwt.sign(
      { userId: user.id, orgId: user.organization_id, role: user.role },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    // 5. Sucesso!
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

// --- ROTA DE CADASTRO (TESTE GRÁTIS) ---
app.post('/auth/register', async (req, res) => {
    // Aqui a gente cria depois: Cria a Organization e o User Admin ao mesmo tempo
    res.json({ msg: "Em breve: Cadastro automático" });
});

// Iniciar
app.listen(port, () => {
  console.log(`🔥 API Barberflow rodando na porta ${port}`);
});