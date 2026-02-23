const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
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
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  plan: { type: String, default: '1' }
});

const Usuario = mongoose.model('Usuario', usuarioSchema);

// Esquema de Sesión (para control de dispositivos)
const sesionSchema = new mongoose.Schema({
  email: { type: String, required: true },
  deviceId: { type: String, required: true },
  deviceModel: { type: String, default: 'Desconocido' },
  lastActive: { type: Date, default: Date.now }
});

const Sesion = mongoose.model('Sesion', sesionSchema);

// Inicializar usuarios de prueba
async function inicializarUsuarios() {
  const count = await Usuario.countDocuments();
  if (count === 0) {
    await Usuario.insertMany([
      { email: 'usuario1@test.com', password: '123456', plan: '0' },
      { email: 'usuario2@test.com', password: '123456', plan: '0' },
      { email: 'admin@test.com', password: 'admin123', plan: '0' }
    ]);
    console.log('✅ Usuarios de prueba creados');
  }
}

inicializarUsuarios();

// Endpoint de login
app.post('/login', async (req, res) => {
  try {
    const { usuario, password, id, modelo } = req.body;

    console.log('Login attempt:', { usuario, password, id, modelo });

    if (!usuario || !password) {
      return res.json({
        response: {
          msg: 'error',
          message: 'Usuario y contraseña son requeridos'
        }
      });
    }

    // Buscar usuario
    const user = await Usuario.findOne({ email: usuario, password: password });

    if (!user) {
      return res.json({
        response: {
          msg: 'error',
          message: 'Credenciales incorrectas'
        }
      });
    }

    // Verificar sesiones activas
    const deviceId = id || 'unknown';
    const sesionesActivas = await Sesion.find({ email: usuario });
    
    // Límite de dispositivos: 2
    const LIMITE_DISPOSITIVOS = 2;

    // Verificar si este dispositivo ya tiene sesión
    const sesionExistente = sesionesActivas.find(s => s.deviceId === deviceId);

    if (sesionExistente) {
      // Actualizar última actividad
      sesionExistente.lastActive = new Date();
      await sesionExistente.save();

      return res.json({
        response: {
          msg: 'dispositivo_activo',
          idv: '12345',
          cuentaCreada: '2024-01-01',
          plan: user.plan
        }
      });
    }

    // Si excede el límite
    if (sesionesActivas.length >= LIMITE_DISPOSITIVOS) {
      return res.json({
        response: {
          msg: 'dispositivos_superados',
          idv: '12345',
          cuentaCreada: '2024-01-01',
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
        idv: '12345',
        cuentaCreada: '2024-01-01',
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

// Endpoint para obtener sesiones activas
app.get('/sesiones', async (req, res) => {
  try {
    const { correo } = req.query;
    
    if (!correo) {
      return res.json({ error: 'Email requerido' });
    }

    const sesiones = await Sesion.find({ email: correo });
    
    return res.json({
      sesiones: sesiones.map(s => ({
        id: s._id,
        deviceId: s.deviceId,
        deviceModel: s.deviceModel,
        lastActive: s.lastActive
      }))
    });

  } catch (error) {
    console.error('Error obteniendo sesiones:', error);
    return res.json({ error: 'Error del servidor' });
  }
});

// Endpoint para eliminar una sesión
app.post('/eliminar-sesion', async (req, res) => {
  try {
    const { id } = req.body;
    
    if (!id) {
      return res.json({ error: 'ID requerido' });
    }

    await Sesion.findByIdAndDelete(id);
    
    return res.json({ success: true });

  } catch (error) {
    console.error('Error eliminando sesión:', error);
    return res.json({ error: 'Error del servidor' });
  }
});

// Endpoint de prueba
app.get('/', (req, res) => {
  res.json({ message: 'API Multivision con MongoDB funcionando correctamente' });
});

app.listen(PORT, () => {
  console.log(`🚀 Servidor corriendo en puerto ${PORT}`);
});