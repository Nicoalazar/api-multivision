const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const fetch = require('node-fetch');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT;

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Servir archivos estáticos
app.use(express.static('public'));

// Conectar a MongoDB
mongoose.connect(process.env.MONGODB_URI)
  .then(() => console.log('✅ Conectado a MongoDB'))
  .catch(err => console.error('❌ Error conectando a MongoDB:', err));

// Esquema de Usuario
const usuarioSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true, lowercase: true, trim: true },
  password: { type: String, required: true },
  plan: { type: String, default: '1', enum: ['0', '1'] }, // 0: fulbo, 1: premium
  activo: { type: Boolean, default: true },
  fechaCreacion: { type: Date, default: Date.now },
  ultimoAcceso: { type: Date, default: Date.now }
});

const Usuario = mongoose.model('Usuario', usuarioSchema);

// Esquema de Sesión
const sesionSchema = new mongoose.Schema({
  email: { type: String, required: true },
  deviceId: { type: String, required: true },
  deviceModel: { type: String, default: 'Desconocido' },
  lastActive: { type: Date, default: Date.now }
});

// Índice para mejorar búsquedas
sesionSchema.index({ email: 1, deviceId: 1 });

const Sesion = mongoose.model('Sesion', sesionSchema);

// Configuración
const LIMITE_DISPOSITIVOS = parseInt(process.env.LIMITE_DISPOSITIVOS);
const ADMIN_SECRET = process.env.ADMIN_SECRET;

// Middleware de autenticación para endpoints admin
const requireAdminAuth = (req, res, next) => {
  const auth = req.headers.authorization;
  if (auth === `Bearer ${ADMIN_SECRET}`) {
    next();
  } else {
    res.status(401).json({ error: 'No autorizado' });
  }
};

// ==================== ENDPOINTS PÚBLICOS ====================

// Endpoint de login
app.post('/login', async (req, res) => {
  try {
    const { usuario, password, id, modelo } = req.body;

    if (!usuario || !password) {
      return res.json({
        response: {
          msg: 'error',
          message: 'Usuario y contraseña son requeridos'
        }
      });
    }

    // Buscar usuario activo
    const user = await Usuario.findOne({ 
      email: usuario.toLowerCase().trim(),
      activo: true 
    });

    if (!user) {
      return res.json({
        response: {
          msg: 'error',
          message: 'Credenciales incorrectas o usuario inactivo'
        }
      });
    }

    // Verificar contraseña con bcrypt
    const passwordValida = await bcrypt.compare(password, user.password);

    if (!passwordValida) {
      return res.json({
        response: {
          msg: 'error',
          message: 'Credenciales incorrectas'
        }
      });
    }

    // Actualizar último acceso
    user.ultimoAcceso = new Date();
    await user.save();

    // Verificar sesiones activas
    const deviceId = id || 'unknown';
    const sesionesActivas = await Sesion.find({ email: usuario });
    
    // Verificar si este dispositivo ya tiene sesión
    const sesionExistente = sesionesActivas.find(s => s.deviceId === deviceId);

    if (sesionExistente) {
      sesionExistente.lastActive = new Date();
      await sesionExistente.save();

      return res.json({
        response: {
          msg: 'dispositivo_activo',
          idv: user._id.toString(),
          cuentaCreada: user.fechaCreacion.toISOString().split('T')[0],
          plan: user.plan
        }
      });
    }

    // Si excede el límite
    if (sesionesActivas.length >= LIMITE_DISPOSITIVOS) {
      return res.json({
        response: {
          msg: 'dispositivos_superados',
          idv: user._id.toString(),
          cuentaCreada: user.fechaCreacion.toISOString().split('T')[0],
          plan: user.plan
        }
      });
    }

    // Crear nueva sesión
    await Sesion.create({
      email: usuario,
      deviceId: deviceId,
      deviceModel: modelo || 'Desconocido',
      lastActive: new Date()
    });

    return res.json({
      response: {
        msg: 'success_login',
        idv: user._id.toString(),
        cuentaCreada: user.fechaCreacion.toISOString().split('T')[0],
        plan: user.plan
      }
    });

  } catch (error) {
    console.error('Error en login:', error);
    return res.json({
      response: {
        msg: 'error',
        message: 'Error del servidor'
      }
    });
  }
});

// Endpoint de logout (cerrar sesión)
app.post('/logout', async (req, res) => {
  try {
    const { email, deviceId } = req.body;

    if (!email || !deviceId) {
      return res.json({
        success: false,
        message: 'Email y deviceId son requeridos'
      });
    }

    // Eliminar la sesión específica de este dispositivo
    const resultado = await Sesion.deleteOne({ 
      email: email.toLowerCase().trim(), 
      deviceId: deviceId 
    });

    if (resultado.deletedCount > 0) {
      return res.json({
        success: true,
        message: 'Sesión cerrada exitosamente'
      });
    } else {
      return res.json({
        success: false,
        message: 'Sesión no encontrada'
      });
    }

  } catch (error) {
    console.error('Error en logout:', error);
    return res.json({
      success: false,
      message: 'Error del servidor'
    });
  }
});

// Endpoint para obtener sesiones activas (compatible con la app)
app.get('/sesiones_activas_api.php', async (req, res) => {
  try {
    const { correo } = req.query;
    
    if (!correo) {
      return res.json([]);
    }

    const sesiones = await Sesion.find({ email: correo });
    
    return res.json(
      sesiones.map(s => ({
        id: s._id.toString(),
        device_id: s.deviceId,
        modelo: s.deviceModel,
        last_active: s.lastActive
      }))
    );

  } catch (error) {
    console.error('Error obteniendo sesiones:', error);
    return res.json([]);
  }
});

// Endpoint para eliminar dispositivo (compatible con la app)
app.post('/eliminar_device.php', async (req, res) => {
  try {
    const { id } = req.body;
    
    if (!id) {
      return res.json({ success: false, message: 'ID requerido' });
    }

    await Sesion.findByIdAndDelete(id);
    
    return res.json({ success: true, message: 'Dispositivo eliminado' });

  } catch (error) {
    console.error('Error eliminando sesión:', error);
    return res.json({ success: false, message: 'Error del servidor' });
  }
});

// ==================== ENDPOINTS ADMIN (PROTEGIDOS) ====================

// Crear usuario
app.post('/admin/usuarios', requireAdminAuth, async (req, res) => {
  try {
    const { email, password, plan } = req.body;

    if (!email || !password) {
      return res.status(400).json({ 
        error: 'Email y contraseña son requeridos' 
      });
    }

    if (plan && !['0', '1'].includes(plan)) {
      return res.status(400).json({ 
        error: 'Plan debe ser "0" (básico) o "1" (premium)' 
      });
    }

    const existente = await Usuario.findOne({ email: email.toLowerCase().trim() });
    if (existente) {
      return res.status(400).json({ 
        error: 'El usuario ya existe' 
      });
    }

    // Encriptar contraseña
    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    const nuevoUsuario = await Usuario.create({
      email: email.toLowerCase().trim(),
      password: hashedPassword,
      plan: plan || '1'
    });

    return res.status(201).json({
      success: true,
      usuario: {
        id: nuevoUsuario._id,
        email: nuevoUsuario.email,
        plan: nuevoUsuario.plan,
        activo: nuevoUsuario.activo,
        fechaCreacion: nuevoUsuario.fechaCreacion
      }
    });

  } catch (error) {
    console.error('Error creando usuario:', error);
    return res.status(500).json({ error: 'Error del servidor' });
  }
});

// Listar todos los usuarios
app.get('/admin/usuarios', requireAdminAuth, async (req, res) => {
  try {
    const usuarios = await Usuario.find()
      .select('-password') // No enviar contraseñas
      .sort({ fechaCreacion: -1 });

    return res.json({
      total: usuarios.length,
      usuarios: usuarios
    });

  } catch (error) {
    console.error('Error listando usuarios:', error);
    return res.status(500).json({ error: 'Error del servidor' });
  }
});

// Actualizar usuario
app.put('/admin/usuarios/:id', requireAdminAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const { email, password, plan, activo } = req.body;

    const updateData = {};
    if (email) updateData.email = email.toLowerCase().trim();
    
    // Si se actualiza password, encriptarlo
    if (password) {
      const saltRounds = 10;
      updateData.password = await bcrypt.hash(password, saltRounds);
    }
    
    if (plan !== undefined) updateData.plan = plan;
    if (activo !== undefined) updateData.activo = activo;

    const usuario = await Usuario.findByIdAndUpdate(
      id,
      updateData,
      { returnDocument: 'after', runValidators: true }
    ).select('-password');

    if (!usuario) {
      return res.status(404).json({ error: 'Usuario no encontrado' });
    }

    return res.json({
      success: true,
      usuario
    });

  } catch (error) {
    console.error('Error actualizando usuario:', error);
    return res.status(500).json({ error: 'Error del servidor' });
  }
});

// Eliminar usuario
app.delete('/admin/usuarios/:id', requireAdminAuth, async (req, res) => {
  try {
    const { id } = req.params;

    const usuario = await Usuario.findByIdAndDelete(id);

    if (!usuario) {
      return res.status(404).json({ error: 'Usuario no encontrado' });
    }

    // También eliminar todas sus sesiones
    await Sesion.deleteMany({ email: usuario.email });

    return res.json({
      success: true,
      message: 'Usuario y sesiones eliminados'
    });

  } catch (error) {
    console.error('Error eliminando usuario:', error);
    return res.status(500).json({ error: 'Error del servidor' });
  }
});

// Listar todas las sesiones activas
app.get('/admin/sesiones', requireAdminAuth, async (req, res) => {
  try {
    const sesiones = await Sesion.find().sort({ lastActive: -1 });

    return res.json({
      total: sesiones.length,
      sesiones
    });

  } catch (error) {
    console.error('Error listando sesiones:', error);
    return res.status(500).json({ error: 'Error del servidor' });
  }
});

// Limpiar sesiones inactivas (más de 7 días)
app.post('/admin/limpiar-sesiones', requireAdminAuth, async (req, res) => {
  try {
    const diasInactividad = req.body.dias || 7;
    const fechaLimite = new Date();
    fechaLimite.setDate(fechaLimite.getDate() - diasInactividad);

    const resultado = await Sesion.deleteMany({
      lastActive: { $lt: fechaLimite }
    });

    return res.json({
      success: true,
      sesionesEliminadas: resultado.deletedCount
    });

  } catch (error) {
    console.error('Error limpiando sesiones:', error);
    return res.status(500).json({ error: 'Error del servidor' });
  }
});

// Estadísticas
app.get('/admin/stats', requireAdminAuth, async (req, res) => {
  try {
    const totalUsuarios = await Usuario.countDocuments();
    const usuariosActivos = await Usuario.countDocuments({ activo: true });
    const usuariosPremium = await Usuario.countDocuments({ plan: '1' });
    const totalSesiones = await Sesion.countDocuments();

    return res.json({
      usuarios: {
        total: totalUsuarios,
        activos: usuariosActivos,
        inactivos: totalUsuarios - usuariosActivos,
        premium: usuariosPremium,
        basicos: totalUsuarios - usuariosPremium
      },
      sesiones: {
        total: totalSesiones
      }
    });

  } catch (error) {
    console.error('Error obteniendo estadísticas:', error);
    return res.status(500).json({ error: 'Error del servidor' });
  }
});

// ==================== ENDPOINT DE CONTENIDO UNIFICADO ====================

// Caché para optimizar performance
let cachedPremiumData = null;
let lastFetch = 0;
const CACHE_DURATION = 5 * 60 * 1000; // 5 minutos
const API_MASTER_URL = process.env.API_MASTER_URL;

// Configuración de filtrado
const CATEGORIAS_BASICAS = process.env.CATEGORIAS_BASICAS 
  ? process.env.CATEGORIAS_BASICAS.split(',').map(c => c.trim().toLowerCase()) 
  : ['deportivos'];
const CANALES_BLOQUEADOS_PREMIUM = process.env.CANALES_BLOQUEADOS_PREMIUM 
  ? process.env.CANALES_BLOQUEADOS_PREMIUM.split(',').map(c => c.trim()) 
  : [];

console.log('⚙️ Configuración de filtrado:');
console.log('   Categorías plan básico:', CATEGORIAS_BASICAS);
console.log('   Canales bloqueados en premium:', CANALES_BLOQUEADOS_PREMIUM);


app.get('/content', async (req, res) => {
  try {
    const { plan } = req.query;
    const now = Date.now();

    console.log(`📥 Request recibido - plan: "${plan}" (tipo: ${typeof plan})`);

    // Usar caché si está disponible y no expiró
    if (cachedPremiumData && (now - lastFetch < CACHE_DURATION)) {
      console.log('✅ Usando caché de contenido');
      
      if (plan === '0') {
        console.log('🔍 Plan básico - Filtrando solo DEPORTIVOS...');
        const data = filterBasicContent(cachedPremiumData);
        return res.json(data);
      } else {
        console.log('💎 Plan premium - Bloqueando canales específicos...');
        const data = filterPremiumContent(cachedPremiumData);
        return res.json(data);
      }
    }

    // Fetch nuevo contenido premium
    console.log('🔄 Fetching contenido premium...');
    const response = await fetch(API_MASTER_URL);
    
    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }
    
    const data = await response.json();
    
    // Actualizar caché
    cachedPremiumData = data;
    lastFetch = now;

    // Filtrar según plan
    let finalData;
    if (plan === '0') {
      console.log('🔍 Plan básico - Filtrando solo DEPORTIVOS...');
      finalData = filterBasicContent(data);
    } else {
      console.log('💎 Plan premium - Bloqueando canales específicos...');
      finalData = filterPremiumContent(data);
    }
    
    console.log(`📦 Sirviendo contenido para plan ${plan}`);
    return res.json(finalData);

  } catch (error) {
    console.error('❌ Error obteniendo contenido:', error);
    
    // Si hay caché disponible, usarlo como fallback
    if (cachedPremiumData) {
      console.log('⚠️ Usando caché como fallback');
      const data = req.query.plan === '0' 
        ? filterBasicContent(cachedPremiumData) 
        : filterPremiumContent(cachedPremiumData);
      return res.json(data);
    }
    
    return res.status(500).json({ 
      error: 'Error obteniendo contenido',
      message: error.message 
    });
  }
});

// Filtrado para plan básico: solo categorías específicas
function filterBasicContent(premiumData) {
  if (!Array.isArray(premiumData)) {
    return premiumData;
  }

  console.log('🔍 Filtrando contenido básico...');

  // Filtrar solo categorías permitidas
  const categoriasFiltradas = premiumData.filter(categoria => {
    const nombreCategoria = (categoria.name || categoria.nombre || '').toLowerCase();
    const esBasica = CATEGORIAS_BASICAS.some(cat => nombreCategoria.includes(cat));
    if (esBasica) {
      console.log(`  ✅ Categoría incluida: ${categoria.name}`);
    }
    return esBasica;
  });

  return categoriasFiltradas;
}

// Filtrado para plan premium: todas las categorías pero bloqueando canales específicos
function filterPremiumContent(premiumData) {
  if (!Array.isArray(premiumData)) {
    return premiumData;
  }

  console.log('🔍 Filtrando contenido premium...');

  // Recorrer todas las categorías y bloquear canales específicos
  return premiumData.map(categoria => {
    if (!Array.isArray(categoria.lista)) {
      return categoria;
    }

    const listaOriginal = categoria.lista.length;
    const listaFiltrada = categoria.lista.filter(canal => {
      const nombreCanal = canal.name || '';
      const bloqueado = CANALES_BLOQUEADOS_PREMIUM.includes(nombreCanal);
      if (bloqueado) {
        console.log(`  ❌ Bloqueando canal en ${categoria.name}: ${nombreCanal}`);
      }
      return !bloqueado;
    });

    if (listaOriginal !== listaFiltrada.length) {
      console.log(`  📺 ${categoria.name}: ${listaOriginal} → ${listaFiltrada.length} canales`);
    }

    return {
      ...categoria,
      lista: listaFiltrada
    };
  });
}

// Endpoint para limpiar caché manualmente (admin)
app.post('/admin/clear-cache', requireAdminAuth, (req, res) => {
  cachedPremiumData = null;
  lastFetch = 0;
  console.log('🗑️ Caché limpiado');
  return res.json({ 
    success: true, 
    message: 'Caché limpiado exitosamente' 
  });
});

// =================== ENDPOINT AUTH MAGMA ===================

app.post('/auth', async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ error: 'Usuario y contraseña son requeridos' });
    }

    const user = await Usuario.findOne({
      email: username.toLowerCase().trim(),
      activo: true
    });

    if (!user) {
      return res.status(401).json({ error: 'Credenciales incorrectas o usuario inactivo' });
    }

    const passwordValida = await bcrypt.compare(password, user.password);
    if (!passwordValida) {
      return res.status(401).json({ error: 'Credenciales incorrectas' });
    }

    return res.json({
      token: user._id.toString(),
      smarters: [
        {
          url: process.env.MAGMA_URL1,
          username: process.env.MAGMA_USER1,
          password: process.env.MAGMA_PASS1
        },
        {
          url: process.env.MAGMA_URL2,
          username: process.env.MAGMA_USER2,
          password: process.env.MAGMA_PASS2
        }
      ]
    });

  } catch (error) {
    console.error('Error en /magma:', error);
    return res.status(500).json({ error: 'Error del servidor' });
  }
});


// ==================== ENDPOINT DE PRUEBA ====================

app.get('/', (req, res) => {
  res.json({ 
    message: 'API Multivision con MongoDB funcionando correctamente',
    version: '2.0',
    endpoints: {
      admin: [
        'POST /admin/usuarios (crear)',
        'GET /admin/usuarios (listar)',
        'PUT /admin/usuarios/:id (actualizar)',
        'DELETE /admin/usuarios/:id (eliminar)',
        'GET /admin/sesiones (listar sesiones)',
        'POST /admin/limpiar-sesiones (limpiar)',
        'GET /admin/stats (estadísticas)'
      ]
    }
  });
});

app.listen(PORT, () => {
  console.log(`🚀 Servidor corriendo en puerto ${PORT}`);
  console.log(`📊 Límite de dispositivos: ${LIMITE_DISPOSITIVOS}`);
});