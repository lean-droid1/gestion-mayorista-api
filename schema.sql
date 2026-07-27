-- ========================================
-- SISTEMA DE GESTIÓN - SCHEMA PostgreSQL
-- ========================================

-- Configuración general del sistema
CREATE TABLE IF NOT EXISTS configuracion (
  clave VARCHAR(100) PRIMARY KEY,
  valor TEXT NOT NULL DEFAULT ''
);

-- Valores iniciales
INSERT INTO configuracion (clave, valor) VALUES
  ('whatsapp', '5491122525568'),
  ('nombre_negocio', 'Mayorista'),
  ('logo_url', ''),
  ('banner_url', ''),
  ('info_pagos', ''),
  ('info_envios', ''),
  ('modo_oscuro', 'false'),
  ('compra_minima_activa', 'false'),
  ('compra_minima_monto', '0'),
  ('compra_minima_promo', ''),
  ('dolar_manual', '0')
ON CONFLICT (clave) DO NOTHING;

-- Listas de precio (porcentajes de aumento sobre base)
CREATE TABLE IF NOT EXISTS listas_precio (
  id SERIAL PRIMARY KEY,
  nombre VARCHAR(50) NOT NULL UNIQUE,
  porcentaje NUMERIC(6,2) NOT NULL DEFAULT 0,
  compra_minima NUMERIC(12,2) NOT NULL DEFAULT 0,
  orden INT NOT NULL DEFAULT 0
);

INSERT INTO listas_precio (nombre, porcentaje, compra_minima, orden) VALUES
  ('Mayorista AAA', 0, 0, 1),
  ('Mayorista AA', 15, 0, 2),
  ('Mayorista A', 35, 0, 3),
  ('Minorista', 70, 0, 4),
  ('Dropshipping', 120, 0, 5)
ON CONFLICT (nombre) DO NOTHING;

-- Usuarios
CREATE TABLE IF NOT EXISTS usuarios (
  id SERIAL PRIMARY KEY,
  usuario VARCHAR(100) NOT NULL UNIQUE,
  password_hash VARCHAR(255) NOT NULL,
  nombre VARCHAR(200) NOT NULL DEFAULT '',
  telefono VARCHAR(50) NOT NULL DEFAULT '',
  email VARCHAR(200) NOT NULL DEFAULT '',
  direccion TEXT NOT NULL DEFAULT '',
  rol VARCHAR(20) NOT NULL DEFAULT 'cliente',  -- admin | cliente
  lista_precio_id INT REFERENCES listas_precio(id) DEFAULT 4,
  activo BOOLEAN NOT NULL DEFAULT true,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Productos
CREATE TABLE IF NOT EXISTS productos (
  id SERIAL PRIMARY KEY,
  nombre VARCHAR(300) NOT NULL,
  modelo VARCHAR(300) NOT NULL DEFAULT '',
  categoria VARCHAR(200) NOT NULL DEFAULT '',
  precio_base NUMERIC(12,2) NOT NULL DEFAULT 0,
  activo BOOLEAN NOT NULL DEFAULT true,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Precios fijos por producto por lista (override del %)
CREATE TABLE IF NOT EXISTS precios_fijos (
  id SERIAL PRIMARY KEY,
  producto_id INT NOT NULL REFERENCES productos(id) ON DELETE CASCADE,
  lista_precio_id INT NOT NULL REFERENCES listas_precio(id) ON DELETE CASCADE,
  precio_fijo NUMERIC(12,2) NOT NULL,
  UNIQUE(producto_id, lista_precio_id)
);

-- Pedidos
CREATE TABLE IF NOT EXISTS pedidos (
  id SERIAL PRIMARY KEY,
  usuario_id INT REFERENCES usuarios(id),
  cliente_nombre VARCHAR(200) NOT NULL DEFAULT '',
  cliente_telefono VARCHAR(50) NOT NULL DEFAULT '',
  tipo_entrega VARCHAR(20) NOT NULL DEFAULT 'retiro',  -- retiro | envio
  direccion_envio TEXT NOT NULL DEFAULT '',
  estado VARCHAR(30) NOT NULL DEFAULT 'pendiente',
  estado_pago VARCHAR(30) NOT NULL DEFAULT 'pendiente',
  notas TEXT NOT NULL DEFAULT '',
  total NUMERIC(12,2) NOT NULL DEFAULT 0,
  lista_precio_nombre VARCHAR(50) NOT NULL DEFAULT '',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Items de pedido
CREATE TABLE IF NOT EXISTS pedido_items (
  id SERIAL PRIMARY KEY,
  pedido_id INT NOT NULL REFERENCES pedidos(id) ON DELETE CASCADE,
  producto_id INT REFERENCES productos(id),
  nombre_producto VARCHAR(300) NOT NULL,
  cantidad INT NOT NULL DEFAULT 1,
  precio_unitario NUMERIC(12,2) NOT NULL DEFAULT 0,
  subtotal NUMERIC(12,2) NOT NULL DEFAULT 0
);

-- Índices para búsquedas
CREATE INDEX IF NOT EXISTS idx_productos_categoria ON productos(categoria);
CREATE INDEX IF NOT EXISTS idx_productos_busqueda ON productos USING gin(to_tsvector('spanish', nombre || ' ' || modelo));
CREATE INDEX IF NOT EXISTS idx_pedidos_usuario ON pedidos(usuario_id);
CREATE INDEX IF NOT EXISTS idx_pedidos_estado ON pedidos(estado);
