const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const fs = require('fs');
const path = require('path');

async function initDB() {
  const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false });
  const client = await pool.connect();
  try {
    const schema = fs.readFileSync(path.join(__dirname, 'schema.sql'), 'utf8');
    await client.query(schema);
    console.log('[init-db] Schema aplicado');

    // Crear admin si no existe
    const existing = await client.query("SELECT id FROM usuarios WHERE usuario = 'admin'");
    if (existing.rows.length === 0) {
      const hash = await bcrypt.hash('admin', 10);
      await client.query(
        "INSERT INTO usuarios (usuario, password_hash, nombre, rol, lista_precio_id) VALUES ('admin', $1, 'Administrador', 'admin', 1)",
        [hash]
      );
      console.log('[init-db] Usuario admin creado (admin/admin)');
    } else {
      console.log('[init-db] Usuario admin ya existe');
    }

    console.log('[init-db] Inicialización completa');
  } catch (err) {
    console.error('[init-db] Error:', err.message);
    process.exit(1);
  } finally {
    client.release();
    await pool.end();
  }
}

initDB();
