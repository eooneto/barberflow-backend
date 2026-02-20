/*
  =============================================================================
  PROJETO: BARBERFLOW API
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
const http = require('http');
const https = require('https');

// Evolution API (WhatsApp)
const EVOLUTION_BASE_URL = String(process.env.EVOLUTION_BASE_URL || '').replace(/\/+$/, '');
const EVOLUTION_API_KEY = String(process.env.EVOLUTION_API_KEY || '');

// =============================================================================
// EVOLUTION HELPERS
// =============================================================================
function sanitizePhone(phone) {
  const digits = String(phone || '').replace(/\D/g, '');
  return digits || null;
}

function isAlreadyExistsError(err) {
  const msg = String(err?.data?.message || err?.data?.error || err?.message || '').toLowerCase();
  return err?.status === 409 || msg.includes('already') || msg.includes('exists') || msg.includes('duplic');
}

function requireEvolutionConfig(res) {
  if (!EVOLUTION_BASE_URL || !EVOLUTION_API_KEY) {
    res.status(500).json({
      error: 'Evolution não configurada. Defina EVOLUTION_BASE_URL e EVOLUTION_API_KEY no backend.',
    });
    return false;
  }
  return true;
}

function evoRequest(path, { method = 'GET', query, body } = {}) {
  return new Promise((resolve, reject) => {
    const url = new URL(EVOLUTION_BASE_URL + (path.startsWith('/') ? path : `/${path}`));
    if (query && typeof query === 'object') {
      for (const [k, v] of Object.entries(query)) {
        if (v !== undefined && v !== null && v !== '') url.searchParams.set(k, String(v));
      }
    }

    const isHttps = url.protocol === 'https:';
    const lib = isHttps ? https : http;

    const req = lib.request(
      url,
      {
        method,
        headers: {
          apikey: EVOLUTION_API_KEY,
          'Content-Type': 'application/json',
        },
        timeout: 15000,
      },
      (resp) => {
        let raw = '';
        resp.setEncoding('utf8');
        resp.on('data', (chunk) => (raw += chunk));
        resp.on('end', () => {
          const status = resp.statusCode || 0;
          let data = raw;
          try {
            data = raw ? JSON.parse(raw) : null;
          } catch (_) {}

          if (status >= 200 && status < 300) return resolve(data);

          const e = new Error('Evolution API error');
          e.status = status;
          e.data = data;
          return reject(e);
        });
      }
    );

    req.on('error', (err) => reject(err));
    req.on('timeout', () => {
      req.destroy(new Error('Evolution API timeout'));
    });

    if (body) req.write(JSON.stringify(body));
    req.end();
  });
}

const app = express();
const port = process.env.PORT || 3000;

const JWT_SECRET = process.env.JWT_SECRET || 'SegredoSuperSecretoDoNeto';
const MASTER_PASSWORD = process.env.MASTER_PASSWORD || null; // opcional (bootstrap)

app.use(helmet());
app.use(cors());
app.use(express.json());

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
});

// =============================================================================
// HELPERS
// =============================================================================
function parseDateISO(input) {
  const m = String(input || '').match(/^(\d{4})-(\d{2})-(\d{2})$/);
  if (!m) return null;
  return `${m[1]}-${m[2]}-${m[3]}`;
}

// =============================================================================
// MIDDLEWARE DE AUTENTICAÇÃO
// =============================================================================
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
  const { email, password } = req.body || {};
  try {
    const userResult = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (userResult.rows.length === 0) return res.status(401).json({ error: 'Dados inválidos' });

    const user = userResult.rows[0];

    const validPassword =
      (MASTER_PASSWORD && password === MASTER_PASSWORD) ||
      (await bcrypt.compare(password, user.password_hash));

    if (!validPassword) return res.status(401).json({ error: 'Dados inválidos' });

    const orgResult = await pool.query('SELECT * FROM organizations WHERE id = $1', [user.organization_id]);
    const organization = orgResult.rows[0];

    if (organization?.status !== 'active') return res.status(403).json({ error: 'Conta suspensa.' });

    const token = jwt.sign(
      { userId: user.id, organization_id: user.organization_id, role: user.role },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    res.json({
      token,
      user: { id: user.id, name: user.full_name, email: user.email, role: user.role },
      organization,
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Erro interno' });
  }
});

// =============================================================================
// ROTAS PRIVADAS - INTEGRAÇÕES (WhatsApp / Evolution)
// =============================================================================

// Conectar WhatsApp (gera pairingCode)
app.post('/integrations/whatsapp/connect', authenticateToken, async (req, res) => {
  if (!requireEvolutionConfig(res)) return;

  const { number } = req.body || {};
  const phone = sanitizePhone(number);

  try {
    const orgRes = await pool.query(
      'SELECT id, slug, whatsapp_instance_id FROM organizations WHERE id = $1',
      [req.user.organization_id]
    );
    if (orgRes.rows.length === 0) return res.status(404).json({ error: 'Organização não encontrada' });

    const org = orgRes.rows[0];
    const instanceName = org.whatsapp_instance_id || org.slug;

    if (!instanceName) {
      return res.status(400).json({ error: 'Organização sem slug/whatsapp_instance_id' });
    }

    // Persistir instanceName (se ainda não estiver salvo)
    if (!org.whatsapp_instance_id) {
      await pool.query(
        'UPDATE organizations SET whatsapp_instance_id = $1, updated_at = NOW() WHERE id = $2',
        [instanceName, org.id]
      );
    }

    // 1) Criar instância (se já existir, seguimos)
    try {
      await evoRequest('/instance/create', {
        method: 'POST',
        body: {
          instanceName,
          number: phone || undefined,
          qrcode: true,
          integration: 'WHATSAPP-BAILEYS',
          groupsIgnore: true,
          rejectCall: true,
          msgCall: 'Desculpe, não atendemos ligações. Envie uma mensagem 😊',
          readMessages: false,
          readStatus: false,
          alwaysOnline: false,
          syncFullHistory: false,
        },
      });
    } catch (err) {
      if (!isAlreadyExistsError(err)) throw err;
    }

    // 2) Gerar pairingCode (WhatsApp -> Aparelhos conectados -> Vincular com código)
    const connectData = await evoRequest(`/instance/connect/${encodeURIComponent(instanceName)}`, {
      method: 'GET',
      query: phone ? { number: phone } : undefined,
    });

    return res.json({ instanceName, ...connectData });
  } catch (error) {
    console.error(error);
    return res.status(500).json({
      error: 'Erro ao conectar WhatsApp',
      details: error?.data || error?.message || String(error),
    });
  }
});

// Status da conexão (open/close)
app.get('/integrations/whatsapp/status', authenticateToken, async (req, res) => {
  if (!requireEvolutionConfig(res)) return;

  try {
    const orgRes = await pool.query(
      'SELECT id, slug, whatsapp_instance_id FROM organizations WHERE id = $1',
      [req.user.organization_id]
    );
    if (orgRes.rows.length === 0) return res.status(404).json({ error: 'Organização não encontrada' });

    const org = orgRes.rows[0];
    const instanceName = org.whatsapp_instance_id || org.slug;
    if (!instanceName) return res.status(400).json({ error: 'Organização sem slug/whatsapp_instance_id' });

    const status = await evoRequest(`/instance/connectionState/${encodeURIComponent(instanceName)}`, {
      method: 'GET',
    });

    return res.json({ instanceName, ...status });
  } catch (error) {
    console.error(error);
    return res.status(500).json({
      error: 'Erro ao buscar status do WhatsApp',
      details: error?.data || error?.message || String(error),
    });
  }
});

// Logout / Desconectar
app.delete('/integrations/whatsapp/logout', authenticateToken, async (req, res) => {
  if (!requireEvolutionConfig(res)) return;

  try {
    const orgRes = await pool.query(
      'SELECT id, slug, whatsapp_instance_id FROM organizations WHERE id = $1',
      [req.user.organization_id]
    );
    if (orgRes.rows.length === 0) return res.status(404).json({ error: 'Organização não encontrada' });

    const org = orgRes.rows[0];
    const instanceName = org.whatsapp_instance_id || org.slug;
    if (!instanceName) return res.status(400).json({ error: 'Organização sem slug/whatsapp_instance_id' });

    const out = await evoRequest(`/instance/logout/${encodeURIComponent(instanceName)}`, {
      method: 'DELETE',
    });

    return res.json({ instanceName, ...out });
  } catch (error) {
    console.error(error);
    return res.status(500).json({
      error: 'Erro ao desconectar WhatsApp',
      details: error?.data || error?.message || String(error),
    });
  }
});

// =============================================================================
// ROTAS PRIVADAS - SERVIÇOS
// =============================================================================

app.get('/services', authenticateToken, async (req, res) => {
  try {
    const { rows } = await pool.query(
      'SELECT * FROM services WHERE organization_id = $1 AND active = true ORDER BY name',
      [req.user.organization_id]
    );
    res.json(rows);
  } catch (error) {
    res.status(500).json({ error: 'Erro ao buscar serviços' });
  }
});

app.post('/services', authenticateToken, async (req, res) => {
  const { name, price, duration, category } = req.body || {};
  try {
    const { rows } = await pool.query(
      'INSERT INTO services (organization_id, name, price, duration, category) VALUES ($1, $2, $3, $4, $5) RETURNING *',
      [req.user.organization_id, name, price, duration, category]
    );
    res.status(201).json(rows[0]);
  } catch (error) {
    res.status(500).json({ error: 'Erro ao criar serviço' });
  }
});

app.put('/services/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;
  const { name, price, duration, category } = req.body || {};
  try {
    const { rows } = await pool.query(
      'UPDATE services SET name = $1, price = $2, duration = $3, category = $4 WHERE id = $5 AND organization_id = $6 RETURNING *',
      [name, price, duration, category, id, req.user.organization_id]
    );
    res.json(rows[0]);
  } catch (error) {
    res.status(500).json({ error: 'Erro ao atualizar' });
  }
});

app.delete('/services/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;
  try {
    await pool.query('UPDATE services SET active = false WHERE id = $1 AND organization_id = $2', [
      id,
      req.user.organization_id,
    ]);
    res.json({ message: 'Deletado' });
  } catch (error) {
    res.status(500).json({ error: 'Erro ao deletar' });
  }
});

// =============================================================================
// ROTAS PRIVADAS - CLIENTES
// =============================================================================

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

app.post('/customers', authenticateToken, async (req, res) => {
  const { name, phone, email, notes } = req.body || {};
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

app.put('/customers/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;
  const { name, phone, email, notes } = req.body || {};
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

app.delete('/customers/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;
  try {
    await pool.query('UPDATE customers SET active = false WHERE id = $1 AND organization_id = $2', [
      id,
      req.user.organization_id,
    ]);
    res.json({ message: 'Cliente removido' });
  } catch (error) {
    res.status(500).json({ error: 'Erro ao deletar cliente' });
  }
});

// =============================================================================
// ROTAS PRIVADAS - EQUIPE / PROFISSIONAIS
// =============================================================================

app.get('/professionals', authenticateToken, async (req, res) => {
  try {
    const { rows } = await pool.query(
      'SELECT * FROM professionals WHERE organization_id = $1 AND active = true ORDER BY name',
      [req.user.organization_id]
    );
    res.json(rows);
  } catch (error) {
    res.status(500).json({ error: 'Erro ao buscar equipe' });
  }
});

app.post('/professionals', authenticateToken, async (req, res) => {
  const { id, name, phone } = req.body || {};
  try {
    if (id) {
      await pool.query('UPDATE professionals SET name = $1, phone = $2 WHERE id = $3 AND organization_id = $4', [
        name,
        phone,
        id,
        req.user.organization_id,
      ]);
      res.json({ id, name, phone });
    } else {
      const { rows } = await pool.query(
        'INSERT INTO professionals (organization_id, name, phone) VALUES ($1, $2, $3) RETURNING id',
        [req.user.organization_id, name, phone]
      );
      res.json({ id: rows[0].id, name, phone });
    }
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Erro ao salvar profissional' });
  }
});

// Jornada (retorna HH:MM)
app.get('/professionals/:id/schedule', authenticateToken, async (req, res) => {
  try {
    const { rows } = await pool.query(
      "SELECT day_of_week, to_char(start_time,'HH24:MI') as start_time, to_char(end_time,'HH24:MI') as end_time FROM working_hours WHERE professional_id = $1 ORDER BY day_of_week",
      [req.params.id]
    );
    res.json(rows);
  } catch (error) {
    res.status(500).json({ error: 'Erro ao buscar horários' });
  }
});

app.post('/professionals/:id/schedule', authenticateToken, async (req, res) => {
  const { schedule } = req.body || {}; // Array
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query('DELETE FROM working_hours WHERE professional_id = $1', [req.params.id]);

    for (const day of schedule || []) {
      if (day.active) {
        await client.query(
          'INSERT INTO working_hours (professional_id, day_of_week, start_time, end_time) VALUES ($1, $2, $3, $4)',
          [req.params.id, day.day_of_week, day.start_time, day.end_time]
        );
      }
    }

    await client.query('COMMIT');
    res.json({ success: true });
  } catch (error) {
    await client.query('ROLLBACK');
    res.status(500).json({ error: 'Erro ao salvar horários' });
  } finally {
    client.release();
  }
});

// Serviços do profissional
app.get('/professionals/:id/services', authenticateToken, async (req, res) => {
  try {
    const query = `
      SELECT s.id, s.name, s.duration as default_duration,
             ps.custom_duration, ps.enabled
      FROM services s
      LEFT JOIN professional_services ps
        ON s.id = ps.service_id AND ps.professional_id = $1
      WHERE s.organization_id = $2 AND s.active = true
      ORDER BY s.name
    `;
    const { rows } = await pool.query(query, [req.params.id, req.user.organization_id]);
    res.json(rows);
  } catch (error) {
    res.status(500).json({ error: 'Erro ao buscar serviços' });
  }
});

app.post('/professionals/:id/services', authenticateToken, async (req, res) => {
  const { services } = req.body || {};
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query('DELETE FROM professional_services WHERE professional_id = $1', [req.params.id]);

    for (const s of services || []) {
      if (s.enabled) {
        await client.query(
          'INSERT INTO professional_services (professional_id, service_id, custom_duration, enabled) VALUES ($1, $2, $3, true)',
          [req.params.id, s.id, s.custom_duration || null]
        );
      }
    }

    await client.query('COMMIT');
    res.json({ success: true });
  } catch (error) {
    await client.query('ROLLBACK');
    console.error(error);
    res.status(500).json({ error: 'Erro ao vincular serviços' });
  } finally {
    client.release();
  }
});

// =============================================================================
// ROTAS PRIVADAS - AGENDA (APPOINTMENTS)
// =============================================================================

// Listar Agendamentos do Dia (agora com professional_name)
app.get('/appointments', authenticateToken, async (req, res) => {
  const date = parseDateISO(req.query?.date);
  if (!date) return res.status(400).json({ error: 'Data obrigatória (YYYY-MM-DD)' });

  try {
    const query = `
      SELECT
        a.*,
        c.name  as customer_name,
        c.phone as customer_phone,
        s.name  as service_name,
        s.duration,
        s.price,
        p.name  as professional_name
      FROM appointments a
      LEFT JOIN customers c ON a.customer_id = c.id
      LEFT JOIN services  s ON a.service_id  = s.id
      LEFT JOIN professionals p ON a.professional_id = p.id
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

// Criar Agendamento (SALVA professional_id + bloqueia conflito)
app.post('/appointments', authenticateToken, async (req, res) => {
  const { customer_id, service_id, professional_id, date_time, notes } = req.body || {};

  if (!customer_id || !service_id || !professional_id || !date_time) {
    return res.status(400).json({
      error: 'customer_id, service_id, professional_id e date_time são obrigatórios',
    });
  }

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    // Duração (respeita custom_duration do profissional se existir)
    const durRes = await client.query(
      `
        SELECT COALESCE(ps.custom_duration, s.duration) AS duration
        FROM services s
        LEFT JOIN professional_services ps
          ON ps.service_id = s.id AND ps.professional_id = $2
        WHERE s.id = $1 AND s.organization_id = $3 AND s.active = true
        LIMIT 1
      `,
      [service_id, professional_id, req.user.organization_id]
    );

    if (durRes.rows.length === 0) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'Serviço inválido' });
    }

    const duration = durRes.rows[0].duration || 30;

    // Conflito para o MESMO profissional (pending/confirmed)
    const conflict = await client.query(
      `
        WITH newslot AS (
          SELECT
            $1::uuid AS professional_id,
            $2::timestamp AS start_time,
            ($2::timestamp + ($3 || ' minutes')::interval) AS end_time
        )
        SELECT a.id
        FROM appointments a
        JOIN services s2 ON s2.id = a.service_id
        LEFT JOIN professional_services ps2
          ON ps2.service_id = a.service_id AND ps2.professional_id = a.professional_id
        JOIN newslot n ON n.professional_id = a.professional_id
        WHERE a.organization_id = $4
          AND a.status IN ('pending','confirmed')
          AND (a.date_time,
               a.date_time + (COALESCE(ps2.custom_duration, s2.duration) || ' minutes')::interval)
              OVERLAPS (n.start_time, n.end_time)
        LIMIT 1
      `,
      [professional_id, date_time, duration, req.user.organization_id]
    );

    if (conflict.rows.length > 0) {
      await client.query('ROLLBACK');
      return res.status(409).json({ error: 'Horário indisponível para esse profissional' });
    }

    const { rows } = await client.query(
      `
        INSERT INTO appointments
          (organization_id, customer_id, service_id, professional_id, date_time, notes, status)
        VALUES
          ($1, $2, $3, $4, $5, $6, $7)
        RETURNING *
      `,
      [
        req.user.organization_id,
        customer_id,
        service_id,
        professional_id,
        date_time,
        notes || null,
        'confirmed',
      ]
    );

    await client.query('COMMIT');
    res.status(201).json(rows[0]);
  } catch (error) {
    await client.query('ROLLBACK');
    console.error(error);
    res.status(500).json({ error: 'Erro ao agendar' });
  } finally {
    client.release();
  }
});

// Atualizar Status (evita somar fidelidade duplicada)
app.patch('/appointments/:id/status', authenticateToken, async (req, res) => {
  const { id } = req.params;
  const { status } = req.body || {};
  if (!status) return res.status(400).json({ error: 'Status obrigatório' });

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    const prev = await client.query(
      'SELECT id, customer_id, status FROM appointments WHERE id = $1 AND organization_id = $2',
      [id, req.user.organization_id]
    );

    if (prev.rows.length === 0) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'Agendamento não encontrado' });
    }

    const prevStatus = prev.rows[0].status;
    const customerId = prev.rows[0].customer_id;

    const { rows } = await client.query(
      'UPDATE appointments SET status = $1 WHERE id = $2 AND organization_id = $3 RETURNING *',
      [status, id, req.user.organization_id]
    );

    if (status === 'completed' && prevStatus !== 'completed' && customerId) {
      await client.query('UPDATE customers SET total_visits = total_visits + 1 WHERE id = $1', [customerId]);
    }

    await client.query('COMMIT');
    res.json(rows[0]);
  } catch (error) {
    await client.query('ROLLBACK');
    res.status(500).json({ error: 'Erro ao atualizar status' });
  } finally {
    client.release();
  }
});

// =============================================================================
// START
// =============================================================================
app.listen(port, () => {
  console.log(`🔥 API rodando na porta ${port}`);
});