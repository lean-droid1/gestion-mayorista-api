const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'mayorista-secret-key-change-me';
const FRONTEND_URL = process.env.FRONTEND_URL || 'https://lean-droidmayorista.netlify.app';

// ── DB ──
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
});

// ── Migrations (safe to run multiple times) ──
(async () => {
  try {
    await pool.query("ALTER TABLE pedidos ADD COLUMN IF NOT EXISTS metodo_pago VARCHAR(50) NOT NULL DEFAULT ''");
    await pool.query("ALTER TABLE listas_precio ADD COLUMN IF NOT EXISTS color VARCHAR(20) NOT NULL DEFAULT '#2563eb'");
    await pool.query("ALTER TABLE listas_precio ADD COLUMN IF NOT EXISTS promo_msg TEXT NOT NULL DEFAULT ''");
    console.log('[DB] Migrations OK');
  } catch (e) { console.log('[DB] Migration note:', e.message); }
})();

// ── Middleware ──
app.use(cors({ origin: [FRONTEND_URL, 'http://localhost:5173', 'http://localhost:4173'], credentials: true }));
app.use(express.json({ limit: '10mb' }));

// ── Auth middleware (requiere login + aprobado) ──
function auth(requiredRole) {
  return async (req, res, next) => {
    const token = req.headers.authorization?.replace('Bearer ', '');
    if (!token) return res.status(401).json({ error: 'Token requerido' });
    try {
      const decoded = jwt.verify(token, JWT_SECRET);
      const { rows } = await pool.query('SELECT id, usuario, nombre, telefono, rol, lista_precio_id, activo, aprobado FROM usuarios WHERE id = $1', [decoded.id]);
      if (!rows[0] || !rows[0].activo) return res.status(401).json({ error: 'Usuario no válido' });
      if (requiredRole === 'admin' && rows[0].rol !== 'admin') return res.status(403).json({ error: 'Acceso denegado' });
      // Admin siempre pasa; clientes necesitan estar aprobados
      if (rows[0].rol !== 'admin' && !rows[0].aprobado) return res.status(403).json({ error: 'Cuenta pendiente de aprobación', pendiente: true });
      req.user = rows[0];
      next();
    } catch { return res.status(401).json({ error: 'Token inválido' }); }
  };
}

// ── Auth opcional (para vitrina: no falla si no hay token) ──
async function optionalAuth(req, res, next) {
  const token = req.headers.authorization?.replace('Bearer ', '');
  if (!token) { req.user = null; return next(); }
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const { rows } = await pool.query('SELECT id, usuario, nombre, telefono, rol, lista_precio_id, activo, aprobado FROM usuarios WHERE id = $1', [decoded.id]);
    req.user = (rows[0] && rows[0].activo && rows[0].aprobado) ? rows[0] : null;
    // Admin siempre tiene acceso
    if (rows[0] && rows[0].rol === 'admin') req.user = rows[0];
  } catch { req.user = null; }
  next();
}

// ══════════════════════════════════════
// HEALTH
// ══════════════════════════════════════
app.get('/api/health', (req, res) => res.json({ ok: true, ts: new Date().toISOString() }));

// ══════════════════════════════════════
// MODO MANTENIMIENTO (público)
// ══════════════════════════════════════
app.get('/api/maintenance-status', async (req, res) => {
  try {
    const { rows } = await pool.query(
      "SELECT clave, valor FROM configuracion WHERE clave IN ('mantenimiento_activo', 'mantenimiento_mensaje', 'mantenimiento_countdown')"
    );
    const config = {};
    rows.forEach(r => config[r.clave] = r.valor);
    res.json({
      activo: config.mantenimiento_activo === 'true',
      mensaje: config.mantenimiento_mensaje || 'Estamos en mantenimiento',
      countdown: config.mantenimiento_countdown || null,
    });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ══════════════════════════════════════
// AUTH
// ══════════════════════════════════════
app.post('/api/auth/login', async (req, res) => {
  try {
    const { usuario, password } = req.body;
    const { rows } = await pool.query('SELECT * FROM usuarios WHERE usuario = $1 AND activo = true', [usuario]);
    if (!rows[0]) return res.status(401).json({ error: 'Usuario o contraseña incorrectos' });
    const valid = await bcrypt.compare(password, rows[0].password_hash);
    if (!valid) return res.status(401).json({ error: 'Usuario o contraseña incorrectos' });

    // Admin siempre puede entrar; clientes necesitan aprobación
    if (rows[0].rol !== 'admin' && !rows[0].aprobado) {
      return res.status(403).json({
        error: 'Tu cuenta está pendiente de aprobación por el administrador',
        pendiente: true,
      });
    }

    const token = jwt.sign({ id: rows[0].id, rol: rows[0].rol }, JWT_SECRET, { expiresIn: '30d' });
    const { password_hash, ...user } = rows[0];
    res.json({ token, user });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/auth/register', async (req, res) => {
  try {
    const { usuario, password, nombre, telefono, email, direccion } = req.body;
    if (!usuario || !password) return res.status(400).json({ error: 'Usuario y contraseña requeridos' });
    if (!nombre) return res.status(400).json({ error: 'Nombre requerido' });
    if (!telefono) return res.status(400).json({ error: 'Teléfono/WhatsApp requerido' });

    const exists = await pool.query('SELECT id FROM usuarios WHERE usuario = $1', [usuario]);
    if (exists.rows[0]) return res.status(409).json({ error: 'El usuario ya existe' });

    const hash = await bcrypt.hash(password, 10);
    const { rows } = await pool.query(
      'INSERT INTO usuarios (usuario, password_hash, nombre, telefono, email, direccion, rol, lista_precio_id, aprobado) VALUES ($1,$2,$3,$4,$5,$6,$7,4,$8) RETURNING *',
      [usuario, hash, nombre, telefono || '', email || '', direccion || '', 'cliente', false]
    );
    const { password_hash, ...user } = rows[0];

    // Devolver datos del usuario para que el frontend arme el WhatsApp al admin
    res.status(201).json({
      pendiente: true,
      mensaje: 'Registro exitoso. Tu cuenta será revisada por el administrador.',
      user: { nombre: user.nombre, usuario: user.usuario, telefono: user.telefono, email: user.email },
    });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/auth/me', auth(), async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT id, usuario, nombre, telefono, email, direccion, rol, lista_precio_id, aprobado, created_at FROM usuarios WHERE id = $1', [req.user.id]);
    res.json(rows[0]);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.put('/api/auth/me', auth(), async (req, res) => {
  try {
    const { nombre, telefono, email, direccion, password } = req.body;
    if (password) {
      const hash = await bcrypt.hash(password, 10);
      await pool.query('UPDATE usuarios SET nombre=$1, telefono=$2, email=$3, direccion=$4, password_hash=$5, updated_at=NOW() WHERE id=$6',
        [nombre, telefono, email, direccion, hash, req.user.id]);
    } else {
      await pool.query('UPDATE usuarios SET nombre=$1, telefono=$2, email=$3, direccion=$4, updated_at=NOW() WHERE id=$5',
        [nombre, telefono, email, direccion, req.user.id]);
    }
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ══════════════════════════════════════
// CONFIGURACIÓN
// ══════════════════════════════════════
app.get('/api/config', async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT clave, valor FROM configuracion');
    const config = {};
    rows.forEach(r => config[r.clave] = r.valor);
    res.json(config);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.put('/api/config', auth('admin'), async (req, res) => {
  try {
    const entries = Object.entries(req.body);
    for (const [clave, valor] of entries) {
      await pool.query('INSERT INTO configuracion (clave, valor) VALUES ($1, $2) ON CONFLICT (clave) DO UPDATE SET valor = $2', [clave, String(valor)]);
    }
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ══════════════════════════════════════
// LISTAS DE PRECIO
// ══════════════════════════════════════
app.get('/api/listas', async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT id, nombre, porcentaje, compra_minima, orden, color, promo_msg FROM listas_precio ORDER BY orden');
    res.json(rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.put('/api/listas', auth('admin'), async (req, res) => {
  try {
    const listas = req.body; // [{id, nombre, porcentaje?, multiplicador?, compra_minima, color, promo_msg}]
    for (const l of listas) {
      // Accept either porcentaje directly or compute from multiplicador
      const porcentaje = l.porcentaje !== undefined ? l.porcentaje : ((Number(l.multiplicador) || 1) - 1) * 100;
      await pool.query(
        'UPDATE listas_precio SET nombre=$1, porcentaje=$2, compra_minima=$3, color=$4, promo_msg=$5 WHERE id=$6',
        [l.nombre, porcentaje, l.compra_minima || 0, l.color || '#2563eb', l.promo_msg || '', l.id]
      );
    }
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ══════════════════════════════════════
// PRODUCTOS (vitrina pública sin precios)
// ══════════════════════════════════════
app.get('/api/productos', optionalAuth, async (req, res) => {
  try {
    const { q, categoria, page = 1, limit = 50 } = req.query;
    let where = 'WHERE activo = true';
    const params = [];
    let i = 1;

    if (categoria) { where += ` AND categoria = $${i++}`; params.push(categoria); }
    if (q) {
      where += ` AND (nombre ILIKE $${i} OR modelo ILIKE $${i} OR categoria ILIKE $${i})`;
      params.push(`%${q}%`);
      i++;
    }

    const countRes = await pool.query(`SELECT COUNT(*) FROM productos ${where}`, params);
    const total = parseInt(countRes.rows[0].count);
    const offset = (parseInt(page) - 1) * parseInt(limit);

    const { rows } = await pool.query(
      `SELECT * FROM productos ${where} ORDER BY categoria, nombre LIMIT $${i++} OFFSET $${i++}`,
      [...params, parseInt(limit), offset]
    );

    // Si NO está logueado/aprobado → quitar precios (vitrina)
    const showPrices = req.user !== null;
    const productos = showPrices ? rows : rows.map(({ precio_base, ...rest }) => rest);

    res.json({ productos, total, page: parseInt(page), pages: Math.ceil(total / parseInt(limit)), vitrina: !showPrices });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/productos/categorias', async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT DISTINCT categoria FROM productos WHERE activo = true ORDER BY categoria');
    res.json(rows.map(r => r.categoria));
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/productos', auth('admin'), async (req, res) => {
  try {
    const { nombre, modelo, categoria, precio_base } = req.body;
    const { rows } = await pool.query(
      'INSERT INTO productos (nombre, modelo, categoria, precio_base) VALUES ($1,$2,$3,$4) RETURNING *',
      [nombre, modelo || '', categoria || '', precio_base || 0]
    );
    res.status(201).json(rows[0]);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.put('/api/productos/:id', auth('admin'), async (req, res) => {
  try {
    const { nombre, modelo, categoria, precio_base } = req.body;
    await pool.query('UPDATE productos SET nombre=$1, modelo=$2, categoria=$3, precio_base=$4 WHERE id=$5',
      [nombre, modelo, categoria, precio_base, req.params.id]);
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/productos/:id', auth('admin'), async (req, res) => {
  try {
    await pool.query('UPDATE productos SET activo = false WHERE id = $1', [req.params.id]);
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Carga masiva desde Excel (array de {nombre, modelo, categoria, precio_base})
app.post('/api/productos/bulk', auth('admin'), async (req, res) => {
  try {
    const { productos, reemplazar } = req.body;
    if (reemplazar) await pool.query('UPDATE productos SET activo = false');

    let insertados = 0;
    for (const p of productos) {
      await pool.query(
        'INSERT INTO productos (nombre, modelo, categoria, precio_base) VALUES ($1,$2,$3,$4)',
        [p.nombre || p.PRODUCTO || '', p.modelo || p.MODELO || '', p.categoria || p.CATEGORIA || '', parseFloat(p.precio_base || p.PRECIO || 0)]
      );
      insertados++;
    }
    res.json({ ok: true, insertados });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Borrar por categoría
app.delete('/api/productos/categoria/:cat', auth('admin'), async (req, res) => {
  try {
    const result = await pool.query('UPDATE productos SET activo = false WHERE categoria = $1', [req.params.cat]);
    res.json({ ok: true, borrados: result.rowCount });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Borrar todos
app.delete('/api/productos/all/clear', auth('admin'), async (req, res) => {
  try {
    const result = await pool.query('UPDATE productos SET activo = false');
    res.json({ ok: true, borrados: result.rowCount });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Resetear precios a originales
app.post('/api/productos/reset-precios', auth('admin'), async (req, res) => {
  try {
    await pool.query('DELETE FROM precios_fijos');
    res.json({ ok: true, mensaje: 'Precios fijos eliminados, se usan los porcentajes base' });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Ajustar precios por porcentaje
app.post('/api/productos/ajustar-precios', auth('admin'), async (req, res) => {
  try {
    const { porcentaje, categoria, lista_id } = req.body;
    let query = 'UPDATE productos SET precio_base = precio_base * (1 + $1 / 100.0) WHERE activo = true';
    const params = [porcentaje];
    if (categoria) { query += ' AND categoria = $2'; params.push(categoria); }
    const result = await pool.query(query, params);
    res.json({ ok: true, actualizados: result.rowCount });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ══════════════════════════════════════
// PRECIOS FIJOS (override por producto/lista)
// ══════════════════════════════════════
app.get('/api/precios-fijos', async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM precios_fijos');
    res.json(rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.put('/api/precios-fijos', auth('admin'), async (req, res) => {
  try {
    const { producto_id, lista_precio_id, precio_fijo } = req.body;
    if (precio_fijo === null || precio_fijo === undefined) {
      await pool.query('DELETE FROM precios_fijos WHERE producto_id=$1 AND lista_precio_id=$2', [producto_id, lista_precio_id]);
    } else {
      await pool.query(
        'INSERT INTO precios_fijos (producto_id, lista_precio_id, precio_fijo) VALUES ($1,$2,$3) ON CONFLICT (producto_id, lista_precio_id) DO UPDATE SET precio_fijo=$3',
        [producto_id, lista_precio_id, precio_fijo]
      );
    }
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ══════════════════════════════════════
// USUARIOS (admin)
// ══════════════════════════════════════
app.get('/api/usuarios', auth('admin'), async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT id, usuario, nombre, telefono, email, direccion, rol, lista_precio_id, activo, aprobado, created_at,
       CASE WHEN aprobado = false AND activo = true AND rol = 'cliente' THEN 'pendiente'
            WHEN activo = false THEN 'suspendido'
            ELSE 'activo' END as estado
       FROM usuarios ORDER BY aprobado ASC, created_at DESC`
    );
    res.json(rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Contador de pendientes (para badge en el menú admin)
app.get('/api/usuarios/pendientes/count', auth('admin'), async (req, res) => {
  try {
    const { rows } = await pool.query("SELECT COUNT(*) FROM usuarios WHERE aprobado = false AND activo = true AND rol = 'cliente'");
    res.json({ count: parseInt(rows[0].count) });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.put('/api/usuarios/:id', auth('admin'), async (req, res) => {
  try {
    const { nombre, telefono, email, direccion, rol, lista_precio_id, activo, aprobado, password } = req.body;
    if (password) {
      const hash = await bcrypt.hash(password, 10);
      await pool.query(
        'UPDATE usuarios SET nombre=$1, telefono=$2, email=$3, direccion=$4, rol=$5, lista_precio_id=$6, activo=$7, aprobado=$8, password_hash=$9, updated_at=NOW() WHERE id=$10',
        [nombre, telefono, email, direccion, rol, lista_precio_id, activo, aprobado, hash, req.params.id]
      );
    } else {
      await pool.query(
        'UPDATE usuarios SET nombre=$1, telefono=$2, email=$3, direccion=$4, rol=$5, lista_precio_id=$6, activo=$7, aprobado=$8, updated_at=NOW() WHERE id=$9',
        [nombre, telefono, email, direccion, rol, lista_precio_id, activo, aprobado, req.params.id]
      );
    }
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Aprobación rápida (un solo click desde el panel)
app.post('/api/usuarios/:id/aprobar', auth('admin'), async (req, res) => {
  try {
    const { lista_precio_id } = req.body;
    await pool.query(
      'UPDATE usuarios SET aprobado = true, lista_precio_id = $1, updated_at = NOW() WHERE id = $2',
      [lista_precio_id || 4, req.params.id]
    );
    const { rows } = await pool.query('SELECT id, usuario, nombre, telefono, email, aprobado, lista_precio_id FROM usuarios WHERE id = $1', [req.params.id]);
    res.json({ ok: true, user: rows[0] });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Rechazar usuario (desactivar)
app.post('/api/usuarios/:id/rechazar', auth('admin'), async (req, res) => {
  try {
    await pool.query('UPDATE usuarios SET activo = false, updated_at = NOW() WHERE id = $1', [req.params.id]);
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/usuarios/:id', auth('admin'), async (req, res) => {
  try {
    if (parseInt(req.params.id) === req.user.id) return res.status(400).json({ error: 'No podés eliminarte a vos mismo' });
    await pool.query('UPDATE usuarios SET activo = false WHERE id = $1', [req.params.id]);
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ══════════════════════════════════════
// PEDIDOS
// ══════════════════════════════════════
app.get('/api/pedidos', auth(), async (req, res) => {
  try {
    let query, params;
    if (req.user.rol === 'admin') {
      query = `SELECT p.*, u.nombre as usuario_nombre, u.telefono as usuario_telefono, COALESCE(ic.item_count, 0) as item_count
               FROM pedidos p
               LEFT JOIN usuarios u ON u.id = p.usuario_id
               LEFT JOIN (SELECT pedido_id, COUNT(*) as item_count FROM pedido_items GROUP BY pedido_id) ic ON ic.pedido_id = p.id
               ORDER BY p.created_at DESC`;
      params = [];
    } else {
      query = `SELECT p.*, u.nombre as usuario_nombre, u.telefono as usuario_telefono, COALESCE(ic.item_count, 0) as item_count
               FROM pedidos p
               LEFT JOIN usuarios u ON u.id = p.usuario_id
               LEFT JOIN (SELECT pedido_id, COUNT(*) as item_count FROM pedido_items GROUP BY pedido_id) ic ON ic.pedido_id = p.id
               WHERE p.usuario_id = $1 ORDER BY p.created_at DESC`;
      params = [req.user.id];
    }
    const { rows } = await pool.query(query, params);
    res.json(rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/pedidos/:id', auth(), async (req, res) => {
  try {
    const { rows: [pedido] } = await pool.query(
      `SELECT p.*, u.nombre as usuario_nombre, u.telefono as usuario_telefono
       FROM pedidos p LEFT JOIN usuarios u ON u.id = p.usuario_id WHERE p.id = $1`, [req.params.id]);
    if (!pedido) return res.status(404).json({ error: 'Pedido no encontrado' });
    if (req.user.rol !== 'admin' && pedido.usuario_id !== req.user.id) return res.status(403).json({ error: 'Acceso denegado' });
    const { rows: items } = await pool.query('SELECT * FROM pedido_items WHERE pedido_id = $1', [req.params.id]);
    res.json({ ...pedido, items });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/pedidos', auth(), async (req, res) => {
  try {
    const { tipo_entrega, direccion_envio, notas, items, lista_precio_nombre, metodo_pago } = req.body;
    const total = items.reduce((sum, it) => sum + (it.precio_unitario * it.cantidad), 0);
    const { rows: [pedido] } = await pool.query(
      `INSERT INTO pedidos (usuario_id, cliente_nombre, cliente_telefono, tipo_entrega, direccion_envio, notas, total, lista_precio_nombre, metodo_pago)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING *`,
      [req.user.id, req.user.nombre, req.user.telefono || '', tipo_entrega || 'retiro', direccion_envio || '', notas || '', total, lista_precio_nombre || '', metodo_pago || '']
    );
    for (const it of items) {
      await pool.query(
        'INSERT INTO pedido_items (pedido_id, producto_id, nombre_producto, cantidad, precio_unitario, subtotal) VALUES ($1,$2,$3,$4,$5,$6)',
        [pedido.id, it.producto_id, it.nombre_producto, it.cantidad, it.precio_unitario, it.precio_unitario * it.cantidad]
      );
    }
    res.status(201).json(pedido);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.put('/api/pedidos/:id', auth('admin'), async (req, res) => {
  try {
    const { estado, estado_pago, notas, items, metodo_pago } = req.body;
    // Merge with existing values to avoid null constraint violations
    const { rows: [existing] } = await pool.query('SELECT estado, estado_pago, notas, metodo_pago FROM pedidos WHERE id = $1', [req.params.id]);
    if (!existing) return res.status(404).json({ error: 'Pedido no encontrado' });
    const newEstado = estado !== undefined ? estado : existing.estado;
    const newEstadoPago = estado_pago !== undefined ? estado_pago : existing.estado_pago;
    const newNotas = notas !== undefined ? notas : existing.notas;
    const newMetodoPago = metodo_pago !== undefined ? metodo_pago : (existing.metodo_pago || '');
    await pool.query('UPDATE pedidos SET estado=$1, estado_pago=$2, notas=$3, metodo_pago=$4, updated_at=NOW() WHERE id=$5',
      [newEstado, newEstadoPago, newNotas, newMetodoPago, req.params.id]);

    if (items) {
      await pool.query('DELETE FROM pedido_items WHERE pedido_id = $1', [req.params.id]);
      let total = 0;
      for (const it of items) {
        const sub = it.precio_unitario * it.cantidad;
        total += sub;
        await pool.query(
          'INSERT INTO pedido_items (pedido_id, producto_id, nombre_producto, cantidad, precio_unitario, subtotal) VALUES ($1,$2,$3,$4,$5,$6)',
          [req.params.id, it.producto_id, it.nombre_producto, it.cantidad, it.precio_unitario, sub]
        );
      }
      await pool.query('UPDATE pedidos SET total=$1 WHERE id=$2', [total, req.params.id]);
    }
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/pedidos/:id', auth('admin'), async (req, res) => {
  try {
    await pool.query('DELETE FROM pedidos WHERE id = $1', [req.params.id]);
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ══════════════════════════════════════
// ESTADÍSTICAS (admin)
// ══════════════════════════════════════
app.get('/api/stats', auth('admin'), async (req, res) => {
  try {
    const totalProductos = (await pool.query('SELECT COUNT(*) FROM productos WHERE activo = true')).rows[0].count;
    const totalUsuarios = (await pool.query('SELECT COUNT(*) FROM usuarios WHERE activo = true')).rows[0].count;
    const totalPedidos = (await pool.query('SELECT COUNT(*) FROM pedidos')).rows[0].count;
    const pendientesAprobacion = (await pool.query("SELECT COUNT(*) FROM usuarios WHERE aprobado = false AND activo = true AND rol = 'cliente'")).rows[0].count;
    const ventasHoy = (await pool.query("SELECT COALESCE(SUM(total),0) as total FROM pedidos WHERE created_at >= CURRENT_DATE AND estado_pago = 'pagado'")).rows[0].total;
    const ventasSemana = (await pool.query("SELECT COALESCE(SUM(total),0) as total FROM pedidos WHERE created_at >= CURRENT_DATE - INTERVAL '7 days' AND estado_pago = 'pagado'")).rows[0].total;
    const ventasMes = (await pool.query("SELECT COALESCE(SUM(total),0) as total FROM pedidos WHERE created_at >= CURRENT_DATE - INTERVAL '30 days' AND estado_pago = 'pagado'")).rows[0].total;

    // Top clientes
    const { rows: topClientes } = await pool.query(`
      SELECT u.nombre, u.usuario, COUNT(p.id) as pedidos, COALESCE(SUM(p.total),0) as total
      FROM pedidos p JOIN usuarios u ON p.usuario_id = u.id
      WHERE p.estado_pago = 'pagado'
      GROUP BY u.id, u.nombre, u.usuario ORDER BY total DESC LIMIT 10
    `);

    res.json({ totalProductos, totalUsuarios, totalPedidos, pendientesAprobacion, ventasHoy, ventasSemana, ventasMes, topClientes });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ══════════════════════════════════════
// START
// ══════════════════════════════════════
app.listen(PORT, () => console.log(`[API] Servidor corriendo en puerto ${PORT}`));
