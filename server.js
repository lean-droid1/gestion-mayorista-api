const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'mayorista-secret-key-change-me';
const FRONTEND_URL = process.env.FRONTEND_URL || 'https://mayorista.lean-droidgremio.com';

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
});

// ── Migrations ──
(async () => {
  try {
    const migs = [
      "ALTER TABLE pedidos ADD COLUMN IF NOT EXISTS metodo_pago VARCHAR(50) NOT NULL DEFAULT ''",
      "ALTER TABLE pedidos ADD COLUMN IF NOT EXISTS tipo VARCHAR(20) NOT NULL DEFAULT 'pedido'",
      "ALTER TABLE pedidos ADD COLUMN IF NOT EXISTS archivado BOOLEAN NOT NULL DEFAULT false",
      "ALTER TABLE pedidos ADD COLUMN IF NOT EXISTS asignado_usuario_id INT REFERENCES usuarios(id)",
      "ALTER TABLE listas_precio ADD COLUMN IF NOT EXISTS color VARCHAR(20) NOT NULL DEFAULT '#2563eb'",
      "ALTER TABLE listas_precio ADD COLUMN IF NOT EXISTS promo_msg TEXT NOT NULL DEFAULT ''",
      "ALTER TABLE productos ADD COLUMN IF NOT EXISTS compatibilidad TEXT NOT NULL DEFAULT ''",
      "ALTER TABLE productos ADD COLUMN IF NOT EXISTS stock INT NOT NULL DEFAULT 0",
      "ALTER TABLE productos ADD COLUMN IF NOT EXISTS stock_minimo INT NOT NULL DEFAULT 0",
      "ALTER TABLE productos ADD COLUMN IF NOT EXISTS imagen TEXT NOT NULL DEFAULT ''",
      "ALTER TABLE productos ADD COLUMN IF NOT EXISTS notas TEXT NOT NULL DEFAULT ''",
      "ALTER TABLE usuarios ADD COLUMN IF NOT EXISTS notas_admin TEXT NOT NULL DEFAULT ''",
      "ALTER TABLE usuarios ADD COLUMN IF NOT EXISTS permisos TEXT NOT NULL DEFAULT ''",
      "ALTER TABLE usuarios ADD COLUMN IF NOT EXISTS nombre_fantasia TEXT NOT NULL DEFAULT ''",
      "INSERT INTO configuracion (clave, valor) VALUES ('metodos_pago', '') ON CONFLICT (clave) DO NOTHING",
      "INSERT INTO configuracion (clave, valor) VALUES ('alertas_stock', 'false') ON CONFLICT (clave) DO NOTHING",
      `CREATE TABLE IF NOT EXISTS historial_precios (
        id SERIAL PRIMARY KEY,
        producto_id INT REFERENCES productos(id) ON DELETE CASCADE,
        precio_anterior NUMERIC(12,2),
        precio_nuevo NUMERIC(12,2),
        usuario_id INT REFERENCES usuarios(id),
        usuario_nombre VARCHAR(200) NOT NULL DEFAULT '',
        tipo VARCHAR(30) NOT NULL DEFAULT 'manual',
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )`,
    ];
    for (const m of migs) await pool.query(m).catch(() => {});
    console.log('[DB] Migrations OK');
  } catch (e) { console.log('[DB] Migration note:', e.message); }
})();

app.use(cors({ origin: [FRONTEND_URL, 'https://mayorista.lean-droidgremio.com', /\.vercel\.app$/, 'http://localhost:5173', 'http://localhost:4173'], credentials: true }));
app.use(express.json({ limit: '10mb' }));

// ── Auth ──
function auth(requiredRole) {
  return async (req, res, next) => {
    const token = req.headers.authorization?.replace('Bearer ', '');
    if (!token) return res.status(401).json({ error: 'Token requerido' });
    try {
      const decoded = jwt.verify(token, JWT_SECRET);
      const { rows } = await pool.query('SELECT id, usuario, nombre, telefono, rol, lista_precio_id, activo, aprobado, permisos FROM usuarios WHERE id = $1', [decoded.id]);
      if (!rows[0] || !rows[0].activo) return res.status(401).json({ error: 'Usuario no válido' });
      const isAdminLike = rows[0].rol === 'admin' || rows[0].rol === 'subadmin';
      if (requiredRole === 'admin' && !isAdminLike) return res.status(403).json({ error: 'Acceso denegado' });
      if (!isAdminLike && !rows[0].aprobado) return res.status(403).json({ error: 'Cuenta pendiente de aprobación', pendiente: true });
      req.user = rows[0];
      next();
    } catch { return res.status(401).json({ error: 'Token inválido' }); }
  };
}

async function optionalAuth(req, res, next) {
  const token = req.headers.authorization?.replace('Bearer ', '');
  if (!token) { req.user = null; return next(); }
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const { rows } = await pool.query('SELECT id, usuario, nombre, telefono, rol, lista_precio_id, activo, aprobado, permisos FROM usuarios WHERE id = $1', [decoded.id]);
    req.user = (rows[0] && rows[0].activo && rows[0].aprobado) ? rows[0] : null;
    if (rows[0] && (rows[0].rol === 'admin' || rows[0].rol === 'subadmin')) req.user = rows[0];
  } catch { req.user = null; }
  next();
}

// ══ HEALTH ══
app.get('/api/health', (req, res) => res.json({ ok: true, ts: new Date().toISOString() }));

// ══ MANTENIMIENTO ══
app.get('/api/maintenance-status', async (req, res) => {
  try {
    const { rows } = await pool.query("SELECT clave, valor FROM configuracion WHERE clave IN ('mantenimiento_activo', 'mantenimiento_mensaje', 'mantenimiento_countdown')");
    const c = {}; rows.forEach(r => c[r.clave] = r.valor);
    res.json({ activo: c.mantenimiento_activo === 'true', mensaje: c.mantenimiento_mensaje || 'En mantenimiento', countdown: c.mantenimiento_countdown || null });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ══ AUTH ══
app.post('/api/auth/login', async (req, res) => {
  try {
    const { usuario, password } = req.body;
    const { rows } = await pool.query('SELECT * FROM usuarios WHERE LOWER(usuario) = LOWER($1) AND activo = true', [usuario]);
    if (!rows[0]) return res.status(401).json({ error: 'Usuario o contraseña incorrectos' });
    const valid = await bcrypt.compare(password, rows[0].password_hash);
    if (!valid) return res.status(401).json({ error: 'Usuario o contraseña incorrectos' });
    if (rows[0].rol === 'cliente' && !rows[0].aprobado) return res.status(403).json({ error: 'Cuenta pendiente de aprobación', pendiente: true });
    const token = jwt.sign({ id: rows[0].id, rol: rows[0].rol }, JWT_SECRET, { expiresIn: '30d' });
    const { password_hash, ...user } = rows[0];
    res.json({ token, user });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/auth/register', async (req, res) => {
  try {
    const { usuario, password, nombre, telefono, email, direccion, nombre_fantasia } = req.body;
    if (!usuario || !password) return res.status(400).json({ error: 'Usuario y contraseña requeridos' });
    if (!nombre) return res.status(400).json({ error: 'Nombre requerido' });
    if (!telefono) return res.status(400).json({ error: 'Teléfono requerido' });
    const exists = await pool.query('SELECT id FROM usuarios WHERE LOWER(usuario) = LOWER($1)', [usuario]);
    if (exists.rows[0]) return res.status(409).json({ error: 'El usuario ya existe' });
    const hash = await bcrypt.hash(password, 10);
    const { rows } = await pool.query(
      'INSERT INTO usuarios (usuario, password_hash, nombre, telefono, email, direccion, nombre_fantasia, rol, lista_precio_id, aprobado) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,4,$9) RETURNING *',
      [usuario, hash, nombre, telefono || '', email || '', direccion || '', nombre_fantasia || '', 'cliente', false]);
    const { password_hash, ...user } = rows[0];
    res.status(201).json({ pendiente: true, mensaje: 'Registro exitoso. Tu cuenta será revisada.', user: { nombre: user.nombre, usuario: user.usuario, telefono: user.telefono, email: user.email } });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/auth/me', auth(), async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT id, usuario, nombre, telefono, email, direccion, rol, lista_precio_id, aprobado, permisos, nombre_fantasia, created_at FROM usuarios WHERE id = $1', [req.user.id]);
    res.json(rows[0]);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.put('/api/auth/me', auth(), async (req, res) => {
  try {
    const { nombre, usuario, telefono, email, direccion, password, nombre_fantasia } = req.body;
    if (usuario) {
      const { rows: dup } = await pool.query('SELECT id FROM usuarios WHERE usuario = $1 AND id != $2', [usuario, req.user.id]);
      if (dup.length) return res.status(400).json({ error: 'Ese nombre de usuario ya existe' });
    }
    if (password) {
      const hash = await bcrypt.hash(password, 10);
      await pool.query('UPDATE usuarios SET nombre=$1, usuario=$2, telefono=$3, email=$4, direccion=$5, password_hash=$6, nombre_fantasia=$7, updated_at=NOW() WHERE id=$8', [nombre, usuario, telefono, email, direccion, hash, nombre_fantasia || '', req.user.id]);
    } else {
      await pool.query('UPDATE usuarios SET nombre=$1, usuario=$2, telefono=$3, email=$4, direccion=$5, nombre_fantasia=$6, updated_at=NOW() WHERE id=$7', [nombre, usuario, telefono, email, direccion, nombre_fantasia || '', req.user.id]);
    }
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ══ CONFIG ══
app.get('/api/config', async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT clave, valor FROM configuracion');
    const config = {}; rows.forEach(r => config[r.clave] = r.valor);
    res.json(config);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.put('/api/config', auth('admin'), async (req, res) => {
  try {
    for (const [clave, valor] of Object.entries(req.body)) {
      await pool.query('INSERT INTO configuracion (clave, valor) VALUES ($1, $2) ON CONFLICT (clave) DO UPDATE SET valor = $2', [clave, String(valor)]);
    }
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ══ LISTAS ══
app.get('/api/listas', async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT id, nombre, porcentaje, compra_minima, orden, color, promo_msg FROM listas_precio ORDER BY orden');
    res.json(rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.put('/api/listas', auth('admin'), async (req, res) => {
  try {
    for (const l of req.body) {
      const pct = l.porcentaje !== undefined ? l.porcentaje : ((Number(l.multiplicador) || 1) - 1) * 100;
      await pool.query('UPDATE listas_precio SET nombre=$1, porcentaje=$2, compra_minima=$3, color=$4, promo_msg=$5 WHERE id=$6',
        [l.nombre, pct, l.compra_minima || 0, l.color || '#2563eb', l.promo_msg || '', l.id]);
    }
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ══ PRODUCTOS ══
app.get('/api/productos', optionalAuth, async (req, res) => {
  try {
    const { q, categoria, page = 1, limit = 50 } = req.query;
    let where = 'WHERE activo = true'; const params = []; let i = 1;
    if (categoria) { where += ` AND categoria = $${i++}`; params.push(categoria); }
    if (q) { where += ` AND (nombre ILIKE $${i} OR modelo ILIKE $${i} OR categoria ILIKE $${i} OR compatibilidad ILIKE $${i})`; params.push(`%${q}%`); i++; }
    const total = parseInt((await pool.query(`SELECT COUNT(*) FROM productos ${where}`, params)).rows[0].count);
    const offset = (parseInt(page) - 1) * parseInt(limit);
    const { rows } = await pool.query(`SELECT * FROM productos ${where} ORDER BY categoria, nombre LIMIT $${i++} OFFSET $${i++}`, [...params, parseInt(limit), offset]);
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
    const { nombre, modelo, categoria, precio_base, compatibilidad } = req.body;
    const { rows } = await pool.query('INSERT INTO productos (nombre, modelo, categoria, precio_base, compatibilidad) VALUES ($1,$2,$3,$4,$5) RETURNING *',
      [nombre, modelo || '', categoria || '', precio_base || 0, compatibilidad || '']);
    res.status(201).json(rows[0]);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// FIX: merge with existing values to avoid null constraint
app.put('/api/productos/:id', auth('admin'), async (req, res) => {
  try {
    const { rows: [ex] } = await pool.query('SELECT * FROM productos WHERE id = $1', [req.params.id]);
    if (!ex) return res.status(404).json({ error: 'Producto no encontrado' });
    const nombre = req.body.nombre !== undefined ? req.body.nombre : ex.nombre;
    const modelo = req.body.modelo !== undefined ? req.body.modelo : ex.modelo;
    const categoria = req.body.categoria !== undefined ? req.body.categoria : ex.categoria;
    const precio_base = req.body.precio_base !== undefined ? req.body.precio_base : ex.precio_base;
    const compatibilidad = req.body.compatibilidad !== undefined ? req.body.compatibilidad : (ex.compatibilidad || '');
    const stock = req.body.stock !== undefined ? req.body.stock : (ex.stock || 0);
    const stock_minimo = req.body.stock_minimo !== undefined ? req.body.stock_minimo : (ex.stock_minimo || 0);
    const imagen = req.body.imagen !== undefined ? req.body.imagen : (ex.imagen || '');
    const notas = req.body.notas !== undefined ? req.body.notas : (ex.notas || '');
    // Log price change
    if (Number(precio_base) !== Number(ex.precio_base)) {
      await pool.query('INSERT INTO historial_precios (producto_id, precio_anterior, precio_nuevo, usuario_id, usuario_nombre, tipo) VALUES ($1,$2,$3,$4,$5,$6)',
        [req.params.id, ex.precio_base, precio_base, req.user.id, req.user.nombre, 'manual']);
    }
    await pool.query('UPDATE productos SET nombre=$1, modelo=$2, categoria=$3, precio_base=$4, compatibilidad=$5, stock=$6, stock_minimo=$7, imagen=$8, notas=$9 WHERE id=$10',
      [nombre, modelo, categoria, precio_base, compatibilidad, stock, stock_minimo, imagen, notas, req.params.id]);
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/productos/:id', auth('admin'), async (req, res) => {
  try { await pool.query('UPDATE productos SET activo = false WHERE id = $1', [req.params.id]); res.json({ ok: true }); }
  catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/productos/bulk', auth('admin'), async (req, res) => {
  try {
    const { productos, reemplazar } = req.body;
    if (reemplazar) await pool.query('UPDATE productos SET activo = false');
    let insertados = 0;
    for (const p of productos) {
      await pool.query('INSERT INTO productos (nombre, modelo, categoria, precio_base) VALUES ($1,$2,$3,$4)',
        [p.nombre || p.PRODUCTO || '', p.modelo || p.MODELO || '', p.categoria || p.CATEGORIA || '', parseFloat(p.precio_base || p.PRECIO || 0)]);
      insertados++;
    }
    res.json({ ok: true, insertados });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/productos/categoria/:cat', auth('admin'), async (req, res) => {
  try { const r = await pool.query('UPDATE productos SET activo = false WHERE categoria = $1', [req.params.cat]); res.json({ ok: true, borrados: r.rowCount }); }
  catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/productos/all/clear', auth('admin'), async (req, res) => {
  try { const r = await pool.query('UPDATE productos SET activo = false'); res.json({ ok: true, borrados: r.rowCount }); }
  catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/productos/reset-precios', auth('admin'), async (req, res) => {
  try { await pool.query('DELETE FROM precios_fijos'); res.json({ ok: true }); }
  catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/productos/ajustar-precios', auth('admin'), async (req, res) => {
  try {
    const { porcentaje, categoria } = req.body;
    // Log all changes
    let q = 'SELECT id, precio_base FROM productos WHERE activo = true';
    const p = [];
    if (categoria) { q += ' AND categoria = $1'; p.push(categoria); }
    const { rows: prods } = await pool.query(q, p);
    for (const pr of prods) {
      const nuevo = Number(pr.precio_base) * (1 + porcentaje / 100);
      await pool.query('INSERT INTO historial_precios (producto_id, precio_anterior, precio_nuevo, usuario_id, usuario_nombre, tipo) VALUES ($1,$2,$3,$4,$5,$6)',
        [pr.id, pr.precio_base, nuevo, req.user.id, req.user.nombre, `ajuste_${porcentaje}%`]);
    }
    let uq = 'UPDATE productos SET precio_base = precio_base * (1 + $1 / 100.0) WHERE activo = true';
    const up = [porcentaje];
    if (categoria) { uq += ' AND categoria = $2'; up.push(categoria); }
    const result = await pool.query(uq, up);
    res.json({ ok: true, actualizados: result.rowCount });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ══ HISTORIAL PRECIOS ══
app.get('/api/historial-precios', auth('admin'), async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT h.*, p.modelo, p.categoria FROM historial_precios h
      LEFT JOIN productos p ON p.id = h.producto_id
      ORDER BY h.created_at DESC LIMIT 200`);
    res.json(rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ══ PRECIOS FIJOS ══
app.get('/api/precios-fijos', async (req, res) => {
  try { const { rows } = await pool.query('SELECT * FROM precios_fijos'); res.json(rows); }
  catch (err) { res.status(500).json({ error: err.message }); }
});

app.put('/api/precios-fijos', auth('admin'), async (req, res) => {
  try {
    const { producto_id, lista_precio_id, precio_fijo } = req.body;
    if (precio_fijo === null || precio_fijo === undefined) {
      await pool.query('DELETE FROM precios_fijos WHERE producto_id=$1 AND lista_precio_id=$2', [producto_id, lista_precio_id]);
    } else {
      await pool.query('INSERT INTO precios_fijos (producto_id, lista_precio_id, precio_fijo) VALUES ($1,$2,$3) ON CONFLICT (producto_id, lista_precio_id) DO UPDATE SET precio_fijo=$3', [producto_id, lista_precio_id, precio_fijo]);
    }
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ══ USUARIOS ══
app.get('/api/usuarios', auth('admin'), async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT id, usuario, nombre, telefono, email, direccion, rol, lista_precio_id, activo, aprobado, permisos, notas_admin, nombre_fantasia, created_at,
       CASE WHEN aprobado = false AND activo = true AND rol = 'cliente' THEN 'pendiente'
            WHEN activo = false THEN 'suspendido'
            ELSE 'activo' END as estado
       FROM usuarios ORDER BY aprobado ASC, created_at DESC`);
    res.json(rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/usuarios/pendientes/count', auth('admin'), async (req, res) => {
  try {
    const { rows } = await pool.query("SELECT COUNT(*) FROM usuarios WHERE aprobado = false AND activo = true AND rol = 'cliente'");
    res.json({ count: parseInt(rows[0].count) });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.put('/api/usuarios/:id', auth('admin'), async (req, res) => {
  try {
    const { nombre, usuario, telefono, email, direccion, rol, lista_precio_id, activo, aprobado, password, permisos, notas_admin, nombre_fantasia } = req.body;
    // Verificar usuario único si se cambió
    if (usuario) {
      const { rows: dup } = await pool.query('SELECT id FROM usuarios WHERE usuario = $1 AND id != $2', [usuario, req.params.id]);
      if (dup.length) return res.status(400).json({ error: 'Ese nombre de usuario ya existe' });
    }
    if (password) {
      const hash = await bcrypt.hash(password, 10);
      await pool.query('UPDATE usuarios SET nombre=$1, usuario=$2, telefono=$3, email=$4, direccion=$5, rol=$6, lista_precio_id=$7, activo=$8, aprobado=$9, password_hash=$10, permisos=$11, notas_admin=$12, nombre_fantasia=$13, updated_at=NOW() WHERE id=$14',
        [nombre, usuario, telefono, email, direccion, rol, lista_precio_id, activo, aprobado, hash, permisos || '', notas_admin || '', nombre_fantasia || '', req.params.id]);
    } else {
      await pool.query('UPDATE usuarios SET nombre=$1, usuario=$2, telefono=$3, email=$4, direccion=$5, rol=$6, lista_precio_id=$7, activo=$8, aprobado=$9, permisos=$10, notas_admin=$11, nombre_fantasia=$12, updated_at=NOW() WHERE id=$13',
        [nombre, usuario, telefono, email, direccion, rol, lista_precio_id, activo, aprobado, permisos || '', notas_admin || '', nombre_fantasia || '', req.params.id]);
    }
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/usuarios/:id/aprobar', auth('admin'), async (req, res) => {
  try {
    const { lista_precio_id } = req.body;
    await pool.query('UPDATE usuarios SET aprobado = true, lista_precio_id = $1, updated_at = NOW() WHERE id = $2', [lista_precio_id || 4, req.params.id]);
    const { rows } = await pool.query('SELECT id, usuario, nombre, telefono, email, aprobado, lista_precio_id FROM usuarios WHERE id = $1', [req.params.id]);
    res.json({ ok: true, user: rows[0] });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/usuarios/:id/rechazar', auth('admin'), async (req, res) => {
  try { await pool.query('UPDATE usuarios SET activo = false, updated_at = NOW() WHERE id = $1', [req.params.id]); res.json({ ok: true }); }
  catch (err) { res.status(500).json({ error: err.message }); }
});

// Reset password a "1234"
app.post('/api/usuarios/:id/reset-password', auth('admin'), async (req, res) => {
  try {
    const hash = await bcrypt.hash('1234', 10);
    await pool.query('UPDATE usuarios SET password_hash = $1, updated_at = NOW() WHERE id = $2', [hash, req.params.id]);
    const { rows: [u] } = await pool.query('SELECT id, nombre, usuario, telefono FROM usuarios WHERE id = $1', [req.params.id]);
    res.json({ ok: true, user: u });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Suspender usuario (soft)
app.put('/api/usuarios/:id/suspender', auth('admin'), async (req, res) => {
  try {
    if (parseInt(req.params.id) === req.user.id) return res.status(400).json({ error: 'No podés suspenderte' });
    const { activo } = req.body;
    await pool.query('UPDATE usuarios SET activo = $1, updated_at = NOW() WHERE id = $2', [activo ?? false, req.params.id]);
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Eliminar usuario (real delete, preserva pedidos para estadísticas)
app.delete('/api/usuarios/:id', auth('admin'), async (req, res) => {
  try {
    if (parseInt(req.params.id) === req.user.id) return res.status(400).json({ error: 'No podés eliminarte' });
    // Guardar nombre en pedidos antes de borrar
    await pool.query(`UPDATE pedidos SET cliente_nombre = COALESCE(cliente_nombre, (SELECT nombre FROM usuarios WHERE id = $1)),
      cliente_telefono = COALESCE(cliente_telefono, (SELECT telefono FROM usuarios WHERE id = $1))
      WHERE usuario_id = $1`, [req.params.id]);
    await pool.query('UPDATE pedidos SET usuario_id = NULL WHERE usuario_id = $1', [req.params.id]);
    await pool.query('DELETE FROM usuarios WHERE id = $1', [req.params.id]);
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ══ PEDIDOS ══
app.get('/api/pedidos', auth(), async (req, res) => {
  try {
    const { tipo, archivado, cancelados, all } = req.query;
    let whereExtra = '';
    if (archivado === 'true') whereExtra += ' AND p.archivado = true';
    else whereExtra += ' AND p.archivado = false';
    if (tipo) whereExtra += ` AND p.tipo = '${tipo === 'presupuesto' ? 'presupuesto' : 'pedido'}'`;
    if (cancelados === 'true') whereExtra += " AND p.estado = 'cancelado'";
    else if (all !== 'true' && (!archivado || archivado !== 'true')) whereExtra += " AND p.estado != 'cancelado'";
    const isAdmin = req.user.rol === 'admin' || req.user.rol === 'subadmin';
    const base = `SELECT p.*, u.nombre as usuario_nombre, u.telefono as usuario_telefono, COALESCE(ic.item_count, 0) as item_count
      FROM pedidos p LEFT JOIN usuarios u ON u.id = p.usuario_id
      LEFT JOIN (SELECT pedido_id, COUNT(*) as item_count FROM pedido_items GROUP BY pedido_id) ic ON ic.pedido_id = p.id`;
    let query, params;
    if (isAdmin) { query = `${base} WHERE 1=1 ${whereExtra} ORDER BY p.created_at DESC`; params = []; }
    else { query = `${base} WHERE p.usuario_id = $1 ${whereExtra} ORDER BY p.created_at DESC`; params = [req.user.id]; }
    const { rows } = await pool.query(query, params);
    res.json(rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/pedidos/:id', auth(), async (req, res) => {
  try {
    const { rows: [pedido] } = await pool.query(
      `SELECT p.*, u.nombre as usuario_nombre, u.telefono as usuario_telefono,
       au.nombre as asignado_nombre, au.telefono as asignado_telefono
       FROM pedidos p LEFT JOIN usuarios u ON u.id = p.usuario_id
       LEFT JOIN usuarios au ON au.id = p.asignado_usuario_id WHERE p.id = $1`, [req.params.id]);
    if (!pedido) return res.status(404).json({ error: 'No encontrado' });
    const isAdmin = req.user.rol === 'admin' || req.user.rol === 'subadmin';
    if (!isAdmin && pedido.usuario_id !== req.user.id) return res.status(403).json({ error: 'Acceso denegado' });
    const { rows: items } = await pool.query('SELECT * FROM pedido_items WHERE pedido_id = $1', [req.params.id]);
    res.json({ ...pedido, items });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/pedidos', auth(), async (req, res) => {
  try {
    const { tipo_entrega, direccion_envio, notas, items, lista_precio_nombre, metodo_pago, tipo, asignado_usuario_id } = req.body;
    const total = items.reduce((sum, it) => sum + (it.precio_unitario * it.cantidad), 0);
    const { rows: [pedido] } = await pool.query(
      `INSERT INTO pedidos (usuario_id, cliente_nombre, cliente_telefono, tipo_entrega, direccion_envio, notas, total, lista_precio_nombre, metodo_pago, tipo, asignado_usuario_id)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) RETURNING *`,
      [req.user.id, req.user.nombre, req.user.telefono || '', tipo_entrega || 'retiro', direccion_envio || '', notas || '', total, lista_precio_nombre || '', metodo_pago || '', tipo || 'pedido', asignado_usuario_id || null]);
    for (const it of items) {
      await pool.query('INSERT INTO pedido_items (pedido_id, producto_id, nombre_producto, cantidad, precio_unitario, subtotal) VALUES ($1,$2,$3,$4,$5,$6)',
        [pedido.id, it.producto_id, it.nombre_producto, it.cantidad, it.precio_unitario, it.precio_unitario * it.cantidad]);
    }
    res.status(201).json(pedido);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.put('/api/pedidos/:id', auth('admin'), async (req, res) => {
  try {
    const { estado, estado_pago, notas, items, metodo_pago, tipo, asignado_usuario_id } = req.body;
    const { rows: [ex] } = await pool.query('SELECT * FROM pedidos WHERE id = $1', [req.params.id]);
    if (!ex) return res.status(404).json({ error: 'No encontrado' });
    const ne = estado !== undefined ? estado : ex.estado;
    const np = estado_pago !== undefined ? estado_pago : ex.estado_pago;
    const nn = notas !== undefined ? notas : ex.notas;
    const nm = metodo_pago !== undefined ? metodo_pago : (ex.metodo_pago || '');
    const nt = tipo !== undefined ? tipo : (ex.tipo || 'pedido');
    await pool.query('UPDATE pedidos SET estado=$1, estado_pago=$2, notas=$3, metodo_pago=$4, tipo=$5, updated_at=NOW() WHERE id=$6', [ne, np, nn, nm, nt, req.params.id]);
    if (asignado_usuario_id !== undefined) {
      await pool.query('UPDATE pedidos SET asignado_usuario_id=$1 WHERE id=$2', [asignado_usuario_id || null, req.params.id]);
      if (asignado_usuario_id) {
        const { rows: [au] } = await pool.query('SELECT nombre, telefono FROM usuarios WHERE id = $1', [asignado_usuario_id]);
        if (au) await pool.query('UPDATE pedidos SET cliente_nombre=$1, cliente_telefono=$2 WHERE id=$3', [au.nombre, au.telefono || '', req.params.id]);
      }
    }
    if (items) {
      await pool.query('DELETE FROM pedido_items WHERE pedido_id = $1', [req.params.id]);
      let total = 0;
      for (const it of items) { const sub = it.precio_unitario * it.cantidad; total += sub;
        await pool.query('INSERT INTO pedido_items (pedido_id, producto_id, nombre_producto, cantidad, precio_unitario, subtotal) VALUES ($1,$2,$3,$4,$5,$6)',
          [req.params.id, it.producto_id, it.nombre_producto, it.cantidad, it.precio_unitario, sub]); }
      await pool.query('UPDATE pedidos SET total=$1 WHERE id=$2', [total, req.params.id]);
    }
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/pedidos/:id/archivar', auth('admin'), async (req, res) => {
  try { await pool.query('UPDATE pedidos SET archivado = true, updated_at = NOW() WHERE id = $1', [req.params.id]); res.json({ ok: true }); }
  catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/pedidos/:id/desarchivar', auth('admin'), async (req, res) => {
  try { await pool.query('UPDATE pedidos SET archivado = false, updated_at = NOW() WHERE id = $1', [req.params.id]); res.json({ ok: true }); }
  catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/pedidos/:id', auth('admin'), async (req, res) => {
  try { await pool.query('DELETE FROM pedidos WHERE id = $1', [req.params.id]); res.json({ ok: true }); }
  catch (err) { res.status(500).json({ error: err.message }); }
});

// ══ STATS ══
app.get('/api/stats', auth('admin'), async (req, res) => {
  try {
    const tp = (await pool.query('SELECT COUNT(*) FROM productos WHERE activo = true')).rows[0].count;
    const tu = (await pool.query('SELECT COUNT(*) FROM usuarios WHERE activo = true')).rows[0].count;
    const tpe = (await pool.query("SELECT COUNT(*) FROM pedidos WHERE archivado = false AND tipo = 'pedido' AND estado != 'cancelado'")).rows[0].count;
    const pa = (await pool.query("SELECT COUNT(*) FROM usuarios WHERE aprobado = false AND activo = true AND rol = 'cliente'")).rows[0].count;
    const vh = (await pool.query("SELECT COALESCE(SUM(total),0) as t FROM pedidos WHERE created_at >= CURRENT_DATE AND estado_pago = 'pagado' AND archivado = false AND tipo = 'pedido'")).rows[0].t;
    const vs = (await pool.query("SELECT COALESCE(SUM(total),0) as t FROM pedidos WHERE created_at >= CURRENT_DATE - INTERVAL '7 days' AND estado_pago = 'pagado' AND archivado = false AND tipo = 'pedido'")).rows[0].t;
    const vm = (await pool.query("SELECT COALESCE(SUM(total),0) as t FROM pedidos WHERE created_at >= CURRENT_DATE - INTERVAL '30 days' AND estado_pago = 'pagado' AND archivado = false AND tipo = 'pedido'")).rows[0].t;
    const { rows: topClientes } = await pool.query(`SELECT u.nombre, u.usuario, COUNT(p.id) as pedidos, COALESCE(SUM(p.total),0) as total
      FROM pedidos p JOIN usuarios u ON p.usuario_id = u.id WHERE p.estado_pago = 'pagado' AND p.archivado = false
      GROUP BY u.id, u.nombre, u.usuario ORDER BY total DESC LIMIT 10`);
    // Stats por categoría
    const { rows: porCategoria } = await pool.query(`SELECT pi2.cat as categoria, COUNT(DISTINCT p.id) as pedidos, COALESCE(SUM(pi2.subtotal),0) as total
      FROM pedidos p JOIN (SELECT pedido_id, SPLIT_PART(nombre_producto, ' - ', 1) as cat, subtotal FROM pedido_items) pi2 ON pi2.pedido_id = p.id
      WHERE p.estado_pago = 'pagado' AND p.archivado = false AND p.tipo = 'pedido'
      GROUP BY pi2.cat ORDER BY total DESC LIMIT 20`);
    // Alertas stock
    const { rows: stockBajo } = await pool.query('SELECT id, modelo, categoria, stock, stock_minimo FROM productos WHERE activo = true AND stock_minimo > 0 AND stock <= stock_minimo ORDER BY stock ASC LIMIT 20');
    res.json({ totalProductos: tp, totalUsuarios: tu, totalPedidos: tpe, pendientesAprobacion: pa, ventasHoy: vh, ventasSemana: vs, ventasMes: vm, topClientes, porCategoria, stockBajo });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.listen(PORT, () => console.log(`[API] Puerto ${PORT}`));
