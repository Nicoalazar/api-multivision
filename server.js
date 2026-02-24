const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Conectar a MongoDB
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/multivision')
  .then(() => console.log('✅ Conectado a MongoDB'))
  .catch(err => console.error('❌ Error conectando a MongoDB:', err));

// Esquema de Usuario
const usuarioSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true, lowercase: true, trim: true },
  password: { type: String, required: true },
  plan: { type: String, default: '1', enum: ['0', '1'] }, // 0: básico, 1: premium
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
const LIMITE_DISPOSITIVOS = parseInt(process.env.LIMITE_DISPOSITIVOS) || 2;
const ADMIN_SECRET = process.env.ADMIN_SECRET || 'cambiar_este_secreto_en_produccion';

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