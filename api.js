// ═══════════════════════════════════════════════════
// api.js — Capa de comunicación frontend ↔ backend
// Reemplaza localStorage por fetch a la API de Railway
// ═══════════════════════════════════════════════════

const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:3000';

// ── Token management ──
let token = localStorage.getItem('auth_token');

export function setToken(t) {
  token = t;
  if (t) localStorage.setItem('auth_token', t);
  else localStorage.removeItem('auth_token');
}

export function getToken() { return token; }

// ── Base fetch wrapper ──
async function api(path, options = {}) {
  const headers = { 'Content-Type': 'application/json', ...options.headers };
  if (token) headers['Authorization'] = `Bearer ${token}`;

  const res = await fetch(`${API_URL}${path}`, { ...options, headers });

  if (res.status === 401) {
    setToken(null);
    window.location.reload();
    throw new Error('Sesión expirada');
  }

  const data = await res.json();
  if (!res.ok) throw new Error(data.error || `Error ${res.status}`);
  return data;
}

// Fetch público (sin forzar logout en 401)
async function apiPublic(path) {
  const headers = { 'Content-Type': 'application/json' };
  if (token) headers['Authorization'] = `Bearer ${token}`;
  const res = await fetch(`${API_URL}${path}`, { headers });
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || `Error ${res.status}`);
  return data;
}

// ══════════════════════════════════════
// MODO MANTENIMIENTO (público)
// ══════════════════════════════════════
export async function getMaintenanceStatus() {
  const res = await fetch(`${API_URL}/api/maintenance-status`);
  return res.json();
}

export async function setMaintenanceMode(activo, mensaje, countdown) {
  return api('/api/config', {
    method: 'PUT',
    body: JSON.stringify({
      mantenimiento_activo: activo ? 'true' : 'false',
      mantenimiento_mensaje: mensaje || 'Estamos en mantenimiento, volvemos pronto',
      mantenimiento_countdown: countdown || '',
    }),
  });
}

// ══════════════════════════════════════
// AUTH
// ══════════════════════════════════════
export async function login(usuario, password) {
  const headers = { 'Content-Type': 'application/json' };
  const res = await fetch(`${API_URL}/api/auth/login`, {
    method: 'POST',
    headers,
    body: JSON.stringify({ usuario, password }),
  });
  const data = await res.json();

  // Usuario pendiente de aprobación
  if (res.status === 403 && data.pendiente) {
    throw { pendiente: true, message: data.error };
  }

  if (!res.ok) throw new Error(data.error || 'Error de login');

  setToken(data.token);
  return data.user;
}

export async function register(datos) {
  const headers = { 'Content-Type': 'application/json' };
  const res = await fetch(`${API_URL}/api/auth/register`, {
    method: 'POST',
    headers,
    body: JSON.stringify(datos),
  });
  const data = await res.json();

  if (!res.ok) throw new Error(data.error || 'Error de registro');

  // El registro NO da token — queda pendiente de aprobación
  return { pendiente: true, mensaje: data.mensaje, user: data.user };
}

export async function getMe() {
  return api('/api/auth/me');
}

export async function updateMe(datos) {
  return api('/api/auth/me', { method: 'PUT', body: JSON.stringify(datos) });
}

export function logout() {
  setToken(null);
}

export function isLoggedIn() {
  return !!token;
}

// ══════════════════════════════════════
// CONFIGURACIÓN
// ══════════════════════════════════════
export async function getConfig() {
  return api('/api/config');
}

export async function updateConfig(config) {
  return api('/api/config', { method: 'PUT', body: JSON.stringify(config) });
}

// ══════════════════════════════════════
// LISTAS DE PRECIO
// ══════════════════════════════════════
export async function getListas() {
  return api('/api/listas');
}

export async function updateListas(listas) {
  return api('/api/listas', { method: 'PUT', body: JSON.stringify(listas) });
}

// ══════════════════════════════════════
// PRODUCTOS (vitrina pública)
// ══════════════════════════════════════
export async function getProductos({ q, categoria, page = 1, limit = 50 } = {}) {
  const params = new URLSearchParams();
  if (q) params.set('q', q);
  if (categoria) params.set('categoria', categoria);
  params.set('page', page);
  params.set('limit', limit);
  // Usa apiPublic: no fuerza logout si no hay token
  return apiPublic(`/api/productos?${params}`);
}

export async function getCategorias() {
  return apiPublic('/api/productos/categorias');
}

export async function createProducto(producto) {
  return api('/api/productos', { method: 'POST', body: JSON.stringify(producto) });
}

export async function updateProducto(id, producto) {
  return api(`/api/productos/${id}`, { method: 'PUT', body: JSON.stringify(producto) });
}

export async function deleteProducto(id) {
  return api(`/api/productos/${id}`, { method: 'DELETE' });
}

export async function bulkProductos(productos, reemplazar = false) {
  return api('/api/productos/bulk', {
    method: 'POST',
    body: JSON.stringify({ productos, reemplazar }),
  });
}

export async function deleteCategoria(categoria) {
  return api(`/api/productos/categoria/${encodeURIComponent(categoria)}`, { method: 'DELETE' });
}

export async function deleteAllProductos() {
  return api('/api/productos/all/clear', { method: 'DELETE' });
}

export async function ajustarPrecios(porcentaje, categoria = null) {
  return api('/api/productos/ajustar-precios', {
    method: 'POST',
    body: JSON.stringify({ porcentaje, categoria }),
  });
}

export async function resetPrecios() {
  return api('/api/productos/reset-precios', { method: 'POST' });
}

// ══════════════════════════════════════
// PRECIOS FIJOS
// ══════════════════════════════════════
export async function getPreciosFijos() {
  return api('/api/precios-fijos');
}

export async function setPrecioFijo(producto_id, lista_precio_id, precio_fijo) {
  return api('/api/precios-fijos', {
    method: 'PUT',
    body: JSON.stringify({ producto_id, lista_precio_id, precio_fijo }),
  });
}

// ══════════════════════════════════════
// USUARIOS (admin)
// ══════════════════════════════════════
export async function getUsuarios() {
  return api('/api/usuarios');
}

export async function getUsuariosPendientesCount() {
  return api('/api/usuarios/pendientes/count');
}

export async function updateUsuario(id, datos) {
  return api(`/api/usuarios/${id}`, { method: 'PUT', body: JSON.stringify(datos) });
}

export async function aprobarUsuario(id, lista_precio_id) {
  return api(`/api/usuarios/${id}/aprobar`, {
    method: 'POST',
    body: JSON.stringify({ lista_precio_id }),
  });
}

export async function rechazarUsuario(id) {
  return api(`/api/usuarios/${id}/rechazar`, { method: 'POST' });
}

export async function deleteUsuario(id) {
  return api(`/api/usuarios/${id}`, { method: 'DELETE' });
}

// ══════════════════════════════════════
// PEDIDOS
// ══════════════════════════════════════
export async function getPedidos() {
  return api('/api/pedidos');
}

export async function getPedido(id) {
  return api(`/api/pedidos/${id}`);
}

export async function createPedido(pedido) {
  return api('/api/pedidos', { method: 'POST', body: JSON.stringify(pedido) });
}

export async function updatePedido(id, datos) {
  return api(`/api/pedidos/${id}`, { method: 'PUT', body: JSON.stringify(datos) });
}

export async function deletePedido(id) {
  return api(`/api/pedidos/${id}`, { method: 'DELETE' });
}

// ══════════════════════════════════════
// STATS (admin)
// ══════════════════════════════════════
export async function getStats() {
  return api('/api/stats');
}
