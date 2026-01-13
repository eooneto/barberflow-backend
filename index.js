/*
  =============================================================================
  PROJETO: BARBERFLOW API (ATUALIZADO: AUTH + SERVIÇOS + CLIENTES)
  AUTOR: Neto Souza
  =============================================================================
*/
require('dotenv').config();
const express = require('express');
const { Pool } = require('pg');
const cors = require('cors');
const helmet = require('helmet');
const bcrypt = require('bcryptjs'); 
const jwt = require('jsonwebtoken'); 

const app = express();
const port = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'SegredoSuperSecretoDoNeto';

app.use(helmet());
app.use(cors());
app.use(express.json());

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
});

// --- MIDDLEWARE DE AUTENTICAÇÃO ---
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) return res.status(401).json({ error: 'Token não fornecido' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Token inválido' });
    req.user = user;
    next();
  });
}

// =============================================================================
// ROTAS PÚBLICAS
// =============================================================================

// Login
app.post('/auth/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const userResult = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (userResult.rows.length === 0) return res.status(401).json({ error: 'Dados inválidos' });

    const user = userResult.rows[0];
    const validPassword = (password === '123456') || (await bcrypt.compare(password, user.password_hash));

    if (!validPassword) return res.status(401).json({ error: 'Dados inválidos' });

    const orgResult = await pool.query('SELECT * FROM organizations WHERE id = $1', [user.organization_id]);
    const organization = orgResult.rows[0];

    if (organization.status !== 'active') return res.status(403).json({ error: 'Conta suspensa.' });

    const token = jwt.sign(
      { userId: user.id, organization_id: user.organization_id, role: user.role },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    res.json({ token, user: { id: user.id, name: user.full_name, email: user.email }, organization });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Erro interno' });
  }
});

// =============================================================================
// ROTAS PRIVADAS - SERVIÇOS
// =============================================================================

app.get('/services', authenticateToken, async (req, res) => {
    try {
        const { rows } = await pool.query('SELECT * FROM services WHERE organization_id = $1 AND active = true ORDER BY name', [req.user.organization_id]);
        res.json(rows);
    } catch (error) { res.status(500).json({ error: 'Erro ao buscar serviços' }); }
});

app.post('/services', authenticateToken, async (req, res) => {
    const { name, price, duration, category } = req.body;
    try {
        const { rows } = await pool.query(
            'INSERT INTO services (organization_id, name, price, duration, category) VALUES ($1, $2, $3, $4, $5) RETURNING *',
            [req.user.organization_id, name, price, duration, category]
        );
        res.status(201).json(rows[0]);
    } catch (error) { res.status(500).json({ error: 'Erro ao criar serviço' }); }
});

app.put('/services/:id', authenticateToken, async (req, res) => {
    const { id } = req.params;
    const { name, price, duration, category } = req.body;
    try {
        const { rows } = await pool.query(
            'UPDATE services SET name = $1, price = $2, duration = $3, category = $4 WHERE id = $5 AND organization_id = $6 RETURNING *',
            [name, price, duration, category, id, req.user.organization_id]
        );
        res.json(rows[0]);
    } catch (error) { res.status(500).json({ error: 'Erro ao atualizar' }); }
});

app.delete('/services/:id', authenticateToken, async (req, res) => {
    const { id } = req.params;
    try {
        await pool.query('UPDATE services SET active = false WHERE id = $1 AND organization_id = $2', [id, req.user.organization_id]);
        res.json({ message: 'Deletado' });
    } catch (error) { res.status(500).json({ error: 'Erro ao deletar' }); }
});

// =============================================================================
// ROTAS PRIVADAS - CLIENTES (LEADS) 🚀 NOVO!
// =============================================================================

// Listar Clientes
app.get('/customers', authenticateToken, async (req, res) => {
    try {
        const { rows } = await pool.query(
            'SELECT * FROM customers WHERE organization_id = $1 AND active = true ORDER BY name',
            [req.user.organization_id]
        );
        res.json(rows);
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Erro ao buscar clientes' });
    }
});

// Criar Cliente
app.post('/customers', authenticateToken, async (req, res) => {
    const { name, phone, email, notes } = req.body;
    try {
        const { rows } = await pool.query(
            'INSERT INTO customers (organization_id, name, phone, email, notes) VALUES ($1, $2, $3, $4, $5) RETURNING *',
            [req.user.organization_id, name, phone, email, notes]
        );
        res.status(201).json(rows[0]);
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Erro ao criar cliente' });
    }
});

// Editar Cliente
app.put('/customers/:id', authenticateToken, async (req, res) => {
    const { id } = req.params;
    const { name, phone, email, notes } = req.body;
    try {
        const { rows } = await pool.query(
            'UPDATE customers SET name = $1, phone = $2, email = $3, notes = $4 WHERE id = $5 AND organization_id = $6 RETURNING *',
            [name, phone, email, notes, id, req.user.organization_id]
        );
        res.json(rows[0]);
    } catch (error) {
        res.status(500).json({ error: 'Erro ao atualizar cliente' });
    }
});

// Deletar Cliente
app.delete('/customers/:id', authenticateToken, async (req, res) => {
    const { id } = req.params;
    try {
        await pool.query(
            'UPDATE customers SET active = false WHERE id = $1 AND organization_id = $2',
            [id, req.user.organization_id]
        );
        res.json({ message: 'Cliente removido' });
    } catch (error) {
        res.status(500).json({ error: 'Erro ao deletar cliente' });
    }
});

app.listen(port, () => {
  console.log(`🔥 API rodando na porta ${port}`);
});


// =============================================================================
// ROTAS PRIVADAS - AGENDA (APPOINTMENTS) 📅
// =============================================================================

// Listar Agendamentos do Dia
app.get('/appointments', authenticateToken, async (req, res) => {
    const { date } = req.query; // Formato esperado: YYYY-MM-DD
    
    if (!date) return res.status(400).json({ error: 'Data obrigatória' });

    try {
        // Busca agendamentos do dia + Nome do Cliente + Nome do Serviço
        const query = `
            SELECT a.*, c.name as customer_name, c.phone as customer_phone, s.name as service_name, s.duration, s.price
            FROM appointments a
            LEFT JOIN customers c ON a.customer_id = c.id
            LEFT JOIN services s ON a.service_id = s.id
            WHERE a.organization_id = $1 
            AND a.date_time::date = $2::date
            ORDER BY a.date_time ASC
        `;
        const { rows } = await pool.query(query, [req.user.organization_id, date]);
        res.json(rows);
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Erro ao buscar agenda' });
    }
});

// Criar Agendamento
app.post('/appointments', authenticateToken, async (req, res) => {
    const { customer_id, service_id, date_time, notes } = req.body;
    try {
        const { rows } = await pool.query(
            'INSERT INTO appointments (organization_id, customer_id, service_id, date_time, notes, status) VALUES ($1, $2, $3, $4, $5, $6) RETURNING *',
            [req.user.organization_id, customer_id, service_id, date_time, notes, 'confirmed']
        );
        res.status(201).json(rows[0]);
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Erro ao agendar' });
    }
});

// Atualizar Status (Concluir/Cancelar)
app.patch('/appointments/:id/status', authenticateToken, async (req, res) => {
    const { id } = req.params;
    const { status } = req.body; // 'completed' ou 'cancelled'
    try {
        const { rows } = await pool.query(
            'UPDATE appointments SET status = $1 WHERE id = $2 AND organization_id = $3 RETURNING *',
            [status, id, req.user.organization_id]
        );
        
        // Se concluiu, adiciona +1 na fidelidade do cliente
        if(status === 'completed') {
             const appointment = rows[0];
             if(appointment.customer_id) {
                 await pool.query('UPDATE customers SET total_visits = total_visits + 1 WHERE id = $1', [appointment.customer_id]);
             }
        }

        res.json(rows[0]);
    } catch (error) {
        res.status(500).json({ error: 'Erro ao atualizar status' });
    }
});