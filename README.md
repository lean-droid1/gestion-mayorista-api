# Sistema de Gestión Mayorista - Backend API

API Express + PostgreSQL para el sistema de ventas mayorista/minorista.

## Deploy en Railway

1. **Crear repo en GitHub** → subir estos archivos
2. **Railway** → New Project → Deploy from GitHub repo
3. **Agregar PostgreSQL** → New Service → Database → PostgreSQL
4. **Variables de entorno** en el servicio web:
   - `JWT_SECRET` = (un string largo y seguro)
   - `FRONTEND_URL` = `https://lean-droidmayorista.netlify.app`
   - `DATABASE_URL` → Railway la conecta automáticamente si vinculas la DB
5. **Deploy** → Railway ejecuta `node init-db.js && node server.js`

## Endpoints

### Auth
- `POST /api/auth/login` → `{usuario, password}` → `{token, user}`
- `POST /api/auth/register` → `{usuario, password, nombre, ...}` → `{token, user}`
- `GET /api/auth/me` → perfil del usuario logueado
- `PUT /api/auth/me` → actualizar perfil

### Config
- `GET /api/config` → configuración pública
- `PUT /api/config` → (admin) actualizar config

### Listas de precio
- `GET /api/listas` → las 5 listas con sus porcentajes
- `PUT /api/listas` → (admin) actualizar porcentajes y mínimos

### Productos
- `GET /api/productos?q=&categoria=&page=1&limit=50`
- `GET /api/productos/categorias`
- `POST /api/productos` → (admin) crear uno
- `POST /api/productos/bulk` → (admin) carga masiva `{productos[], reemplazar?}`
- `PUT /api/productos/:id` → (admin) editar
- `DELETE /api/productos/:id` → (admin) desactivar
- `DELETE /api/productos/categoria/:cat` → (admin) borrar categoría
- `DELETE /api/productos/all/clear` → (admin) borrar todos
- `POST /api/productos/ajustar-precios` → (admin) `{porcentaje, categoria?}`
- `POST /api/productos/reset-precios` → (admin) eliminar precios fijos

### Precios fijos
- `GET /api/precios-fijos`
- `PUT /api/precios-fijos` → (admin) `{producto_id, lista_precio_id, precio_fijo}`

### Usuarios
- `GET /api/usuarios` → (admin) listar todos
- `PUT /api/usuarios/:id` → (admin) editar
- `DELETE /api/usuarios/:id` → (admin) desactivar

### Pedidos
- `GET /api/pedidos` → admin ve todos, cliente ve los suyos
- `GET /api/pedidos/:id` → detalle con items
- `POST /api/pedidos` → crear pedido `{tipo_entrega, items[], ...}`
- `PUT /api/pedidos/:id` → (admin) actualizar estado/items
- `DELETE /api/pedidos/:id` → (admin) eliminar

### Stats
- `GET /api/stats` → (admin) dashboard con totales y top clientes

### Health
- `GET /api/health` → `{ok: true}`
