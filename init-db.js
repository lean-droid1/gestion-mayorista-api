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

    // ── Migraciones (safe para correr múltiples veces) ──

    // Agregar columna aprobado si no existe
    await client.query(`
      DO $$ BEGIN
        ALTER TABLE usuarios ADD COLUMN aprobado BOOLEAN NOT NULL DEFAULT false;
      EXCEPTION WHEN duplicate_column THEN NULL;
      END $$;
    `);

    // Nuevas config keys de mantenimiento y vitrina
    await client.query(`
      INSERT INTO configuracion (clave, valor) VALUES
        ('mantenimiento_activo', 'false'),
        ('mantenimiento_mensaje', 'Estamos en mantenimiento, volvemos pronto'),
        ('mantenimiento_countdown', ''),
        ('vitrina_texto', 'Ingresá o registrate para ver precios')
      ON CONFLICT (clave) DO NOTHING;
    `);

    console.log('[init-db] Migraciones aplicadas');

    // Crear admin si no existe
    const existing = await client.query("SELECT id FROM usuarios WHERE usuario = 'admin'");
    if (existing.rows.length === 0) {
      const hash = await bcrypt.hash('admin', 10);
      await client.query(
        "INSERT INTO usuarios (usuario, password_hash, nombre, rol, lista_precio_id, aprobado) VALUES ('admin', $1, 'Administrador', 'admin', 1, true)",
        [hash]
      );
      console.log('[init-db] Usuario admin creado (admin/admin)');
    } else {
      // Asegurar que admin siempre esté aprobado
      await client.query("UPDATE usuarios SET aprobado = true WHERE usuario = 'admin'");
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
