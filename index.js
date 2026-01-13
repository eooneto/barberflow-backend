/*
  =============================================================================
  PROJETO: BARBERFLOW API
  DESCRIÇÃO: O Cérebro do SaaS. Conecta Painel e Bot ao Banco.
  AUTOR: Neto Souza
  =============================================================================
*/

require('dotenv').config();
const express = require('express');
const { Pool } = require('pg');
const cors = require('cors');
const helmet = require('helmet');

const app = express();
const port = process.env.PORT || 3000;

// 1. Segurança e Configurações Básicas
app.use(helmet()); // Protege contra vulnerabilidades conhecidas
app.use(cors());   // Permite que o Painel acesse a API
app.use(express.json()); // Permite receber JSON no Body

// 2. Conexão com o Banco de Dados (PostgreSQL)
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
});

// Teste de conexão ao iniciar
pool.connect()
  .then(() => console.log('✅ Banco de Dados Conectado com Sucesso!'))
  .catch(err => console.error('❌ Erro ao conectar no Banco:', err));

// =============================================================================
// ROTAS DO SISTEMA (ENDPOINTS)
// =============================================================================

// Rota de Saúde (Para ver se a API tá de pé)
app.get('/', (req, res) => {
  res.json({ status: 'online', message: '🚀 Barberflow API rodando a milhão!' });
});

// [BOT & PAINEL] Buscar Serviços de uma Barbearia
// Exemplo de uso: GET /services/barberflow-model
app.get('/services/:slug', async (req, res) => {
  const { slug } = req.params;

  try {
    // 1. Primeiro descobre qual é a barbearia pelo Slug
    const orgResult = await pool.query('SELECT id FROM organizations WHERE slug = $1', [slug]);
    
    if (orgResult.rows.length === 0) {
      return res.status(404).json({ error: 'Barbearia não encontrada' });
    }

    const orgId = orgResult.rows[0].id;

    // 2. Busca os serviços dessa barbearia
    const services = await pool.query(
      'SELECT id, name, price, duration_minutes FROM services WHERE organization_id = $1 AND is_active = true', 
      [orgId]
    );

    res.json(services.rows);

  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Erro interno do servidor' });
  }
});

// [BOT & PAINEL] Buscar Profissionais (Barbeiros)
app.get('/barbers/:slug', async (req, res) => {
    const { slug } = req.params;
  
    try {
      const orgResult = await pool.query('SELECT id FROM organizations WHERE slug = $1', [slug]);
      if (orgResult.rows.length === 0) return res.status(404).json({ error: 'Barbearia 404' });
      const orgId = orgResult.rows[0].id;
  
      const barbers = await pool.query(
        "SELECT id, full_name, avatar_url FROM users WHERE organization_id = $1 AND role IN ('barber', 'owner', 'manager')", 
        [orgId]
      );
  
      res.json(barbers.rows);
  
    } catch (error) {
      res.status(500).json({ error: 'Erro interno' });
    }
  });

// 3. Iniciar o Servidor
app.listen(port, () => {
  console.log(`🔥 Servidor rodando na porta ${port}`);
});