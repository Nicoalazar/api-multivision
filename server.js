const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const fetch = require('node-fetch');
const https = require('https');
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const axios = require('axios');
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

// ══════════════════════════════════════════════════════════════════
//  MODELOS (MongoDB)
// ══════════════════════════════════════════════════════════════════

const usuarioSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true, lowercase: true, trim: true },
  password: { type: String, required: true },
  plan: { type: String, default: '1', enum: ['0', '1'] },
  activo: { type: Boolean, default: true },
  fechaCreacion: { type: Date, default: Date.now },
  ultimoAcceso: { type: Date, default: Date.now }
});

const Usuario = mongoose.model('Usuario', usuarioSchema);

const sesionSchema = new mongoose.Schema({
  email: { type: String, required: true },
  deviceId: { type: String, required: true },
  deviceModel: { type: String, default: 'Desconocido' },
  lastActive: { type: Date, default: Date.now }
});

sesionSchema.index({ email: 1, deviceId: 1 });

const Sesion = mongoose.model('Sesion', sesionSchema);

// ══════════════════════════════════════════════════════════════════
//  CONFIGURACIÓN
// ══════════════════════════════════════════════════════════════════

const LIMITE_DISPOSITIVOS = parseInt(process.env.LIMITE_DISPOSITIVOS);
const ADMIN_SECRET = process.env.ADMIN_SECRET;
const API_MASTER_URL = process.env.API_MASTER_URL;

const CATEGORIAS_BASICAS = process.env.CATEGORIAS_BASICAS
  ? process.env.CATEGORIAS_BASICAS.split(',').map(c => c.trim().toLowerCase())
  : ['deportivos'];
const CANALES_BLOQUEADOS_PREMIUM = process.env.CANALES_BLOQUEADOS_PREMIUM
  ? process.env.CANALES_BLOQUEADOS_PREMIUM.split(',').map(c => c.trim())
  : [];

console.log('⚙️ Configuración de filtrado:');
console.log('   Categorías plan básico:', CATEGORIAS_BASICAS);
console.log('   Canales bloqueados en premium:', CANALES_BLOQUEADOS_PREMIUM);

// ── Configuración mTLS y criptografía ──
const VERIFY_HOST = '179.43.126.108';
const VERIFY_PORT = 7443;
const VERIFY_PATH = '/verify';
const CIPHERTEXT_PAYLOAD = '{"ciphertext":"nrm7CAwtrvcktCJs8bUP8uhSX5uZJpjyPH+dfkYzeWM="}';
const P12_PASSWORD = 'PlayDigitalSas290114';

// Estado global de llaves de encriptación
let cryptoKeys = {
  PASS_IV: null,
  PASS_KEY: null,
  CIPHER_ALGO: null,
  ready: false,
  error: null,
  lastFetch: null,
};

// Cargar certificados mTLS
const certsDir = path.join(__dirname, 'certs');
let pfx, ca;

try {
  pfx = fs.readFileSync(path.join(certsDir, 'client.p12'));
  ca = fs.readFileSync(path.join(certsDir, 'ca.crt'));
  console.log('✅ Certificados mTLS cargados correctamente');
  console.log(`   - client.p12: ${pfx.length} bytes`);
  console.log(`   - ca.crt: ${ca.length} bytes`);
} catch (err) {
  console.warn('⚠️ Certificados mTLS no encontrados:', err.message);
  console.warn('   Los endpoints /api/* de la web no funcionarán sin certificados.');
  console.warn('   Colocá client.p12 y ca.crt en la carpeta "certs/"');
}

// Caché de contenido APK
let cachedPremiumData = null;
let lastContentFetch = 0;
const CACHE_DURATION = 5 * 60 * 1000;

// ══════════════════════════════════════════════════════════════════
//  FUNCIONES CRIPTOGRÁFICAS (réplica de BbhQzYp.java)
// ══════════════════════════════════════════════════════════════════

function fetchCryptoKeys() {
  return new Promise((resolve, reject) => {
    if (!pfx || !ca) return reject(new Error('Certificados mTLS no disponibles'));

    const options = {
      hostname: VERIFY_HOST,
      port: VERIFY_PORT,
      path: VERIFY_PATH,
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(CIPHERTEXT_PAYLOAD),
      },
      pfx: pfx,
      passphrase: P12_PASSWORD,
      ca: ca,
      rejectUnauthorized: false,
    };

    console.log(`\n🔐 Conectando a https://${VERIFY_HOST}:${VERIFY_PORT}${VERIFY_PATH}...`);

    const req = https.request(options, (res) => {
      let data = '';
      console.log(`   Status: ${res.statusCode}`);

      res.on('data', (chunk) => { data += chunk; });
      res.on('end', () => {
        if (res.statusCode !== 200) {
          return reject(new Error(`HTTP ${res.statusCode}: ${data}`));
        }
        try {
          const PASS_IV = extractJsonValue(data, 'PASS_IV');
          const PASS_KEY = extractJsonValue(data, 'PASS_KEY');
          const CIPHER_ALGO = extractJsonValue(data, 'CIPHER_ALGO');

          if (!PASS_IV || !PASS_KEY || !CIPHER_ALGO) {
            return reject(new Error('Respuesta incompleta del servidor de llaves'));
          }

          console.log('✅ Llaves obtenidas:');
          console.log(`   PASS_IV: ${PASS_IV.substring(0, 8)}...`);
          console.log(`   PASS_KEY: ${PASS_KEY.substring(0, 8)}...`);
          console.log(`   CIPHER_ALGO: ${CIPHER_ALGO}`);

          resolve({ PASS_IV, PASS_KEY, CIPHER_ALGO });
        } catch (e) {
          reject(new Error(`Error parseando respuesta: ${e.message}`));
        }
      });
    });

    req.on('error', (err) => {
      console.error(`   ❌ Error de conexión: ${err.message}`);
      reject(err);
    });

    req.setTimeout(15000, () => {
      req.destroy();
      reject(new Error('Timeout de conexión (15s)'));
    });

    req.write(CIPHERTEXT_PAYLOAD);
    req.end();
  });
}

function extractJsonValue(str, key) {
  const search = `"${key}":"`;
  const startIdx = str.indexOf(search);
  if (startIdx === -1) return null;
  const valueStart = startIdx + search.length;
  const valueEnd = str.indexOf('"', valueStart);
  if (valueEnd === -1) return null;
  return str.substring(valueStart, valueEnd);
}

function deriveIV(passIV) {
  return crypto.createHash('md5').update(passIV, 'utf8').digest();
}

function deriveKey(passKey) {
  return crypto.createHash('sha256').update(passKey, 'utf8').digest();
}

function mapCipherAlgo(javaAlgo) {
  const mapping = {
    'AES/CBC/PKCS5Padding': 'aes-256-cbc',
    'AES/CBC/PKCS7Padding': 'aes-256-cbc',
    'AES/ECB/PKCS5Padding': 'aes-256-ecb',
  };
  return mapping[javaAlgo] || 'aes-256-cbc';
}

function decrypt(encryptedBase64) {
  if (!cryptoKeys.ready) throw new Error('Llaves no disponibles');
  const iv = deriveIV(cryptoKeys.PASS_IV);
  const key = deriveKey(cryptoKeys.PASS_KEY);
  const algo = mapCipherAlgo(cryptoKeys.CIPHER_ALGO);
  const encryptedBuffer = Buffer.from(encryptedBase64, 'base64');
  const decipher = crypto.createDecipheriv(algo, key, iv);
  let decrypted = decipher.update(encryptedBuffer, null, 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
}

function encrypt(plainText) {
  if (!cryptoKeys.ready) throw new Error('Llaves no disponibles');
  const iv = deriveIV(cryptoKeys.PASS_IV);
  const key = deriveKey(cryptoKeys.PASS_KEY);
  const algo = mapCipherAlgo(cryptoKeys.CIPHER_ALGO);
  const cipher = crypto.createCipheriv(algo, key, iv);
  let encrypted = cipher.update(plainText, 'utf8');
  encrypted = Buffer.concat([encrypted, cipher.final()]);
  return encrypted.toString('base64');
}

async function initCryptoKeys() {
  try {
    const result = await fetchCryptoKeys();
    cryptoKeys.PASS_IV = result.PASS_IV;
    cryptoKeys.PASS_KEY = result.PASS_KEY;
    cryptoKeys.CIPHER_ALGO = result.CIPHER_ALGO;
    cryptoKeys.ready = true;
    cryptoKeys.error = null;
    cryptoKeys.lastFetch = new Date().toISOString();
    console.log('\n🎉 Llaves de encriptación listas!\n');
  } catch (err) {
    cryptoKeys.error = err.message;
    cryptoKeys.ready = false;
    console.error('\n⚠️ No se pudieron obtener las llaves:', err.message);
    console.log('   Reintentá con GET /api/keys/refresh\n');
  }
}

// ══════════════════════════════════════════════════════════════════
//  FUNCIONES DE FILTRADO DE CONTENIDO (para APK)
// ══════════════════════════════════════════════════════════════════

function filterBasicContent(premiumData) {
  if (!Array.isArray(premiumData)) return premiumData;
  return premiumData.filter(categoria => {
    const nombreCategoria = (categoria.name || categoria.nombre || '').toLowerCase();
    return CATEGORIAS_BASICAS.some(cat => nombreCategoria.includes(cat));
  });
}

function filterPremiumContent(premiumData) {
  if (!Array.isArray(premiumData)) return premiumData;
  return premiumData.map(categoria => {
    if (!Array.isArray(categoria.lista)) return categoria;
    const listaFiltrada = categoria.lista.filter(canal => {
      const nombreCanal = canal.name || '';
      return !CANALES_BLOQUEADOS_PREMIUM.includes(nombreCanal);
    });
    return { ...categoria, lista: listaFiltrada };
  });
}

// ══════════════════════════════════════════════════════════════════
//  MIDDLEWARE
// ══════════════════════════════════════════════════════════════════

const requireAdminAuth = (req, res, next) => {
  const auth = req.headers.authorization;
  if (auth === `Bearer ${ADMIN_SECRET}`) {
    next();
  } else {
    res.status(401).json({ error: 'No autorizado' });
  }
};

// ══════════════════════════════════════════════════════════════════
//  ENDPOINTS PÚBLICOS (APK + WEB)
// ══════════════════════════════════════════════════════════════════

// ── Login (APK + Web) ───────────────────────────────────────────
app.post('/login', async (req, res) => {
  try {
    const { usuario, password, id, modelo } = req.body;

    if (!usuario || !password) {
      return res.json({
        response: { msg: 'error', message: 'Usuario y contraseña son requeridos' }
      });
    }

    const user = await Usuario.findOne({
      email: usuario.toLowerCase().trim(),
      activo: true
    });

    if (!user) {
      return res.json({
        response: { msg: 'error', message: 'Credenciales incorrectas o usuario inactivo' }
      });
    }

    const passwordValida = await bcrypt.compare(password, user.password);

    if (!passwordValida) {
      return res.json({
        response: { msg: 'error', message: 'Credenciales incorrectas' }
      });
    }

    user.ultimoAcceso = new Date();
    await user.save();

    const deviceId = id || 'unknown';
    const sesionesActivas = await Sesion.find({ email: usuario });
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
      response: { msg: 'error', message: 'Error del servidor' }
    });
  }
});

// ── Logout ──────────────────────────────────────────────────────
app.post('/logout', async (req, res) => {
  try {
    const { email, deviceId } = req.body;
    if (!email || !deviceId) {
      return res.json({ success: false, message: 'Email y deviceId son requeridos' });
    }
    const resultado = await Sesion.deleteOne({
      email: email.toLowerCase().trim(),
      deviceId: deviceId
    });
    return res.json({
      success: resultado.deletedCount > 0,
      message: resultado.deletedCount > 0 ? 'Sesión cerrada exitosamente' : 'Sesión no encontrada'
    });
  } catch (error) {
    console.error('Error en logout:', error);
    return res.json({ success: false, message: 'Error del servidor' });
  }
});

// ── Sesiones activas (compatible con APK) ───────────────────────
app.get('/sesiones_activas_api.php', async (req, res) => {
  try {
    const { correo } = req.query;
    if (!correo) return res.json([]);
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

// ── Eliminar dispositivo (compatible con APK) ───────────────────
app.post('/eliminar_device.php', async (req, res) => {
  try {
    const { id } = req.body;
    if (!id) return res.json({ success: false, message: 'ID requerido' });
    await Sesion.findByIdAndDelete(id);
    return res.json({ success: true, message: 'Dispositivo eliminado' });
  } catch (error) {
    console.error('Error eliminando sesión:', error);
    return res.json({ success: false, message: 'Error del servidor' });
  }
});

// ══════════════════════════════════════════════════════════════════
//  ENDPOINTS ADMIN (PROTEGIDOS)
// ══════════════════════════════════════════════════════════════════

app.post('/admin/usuarios', requireAdminAuth, async (req, res) => {
  try {
    const { email, password, plan } = req.body;
    if (!email || !password) {
      return res.status(400).json({ error: 'Email y contraseña son requeridos' });
    }
    if (plan && !['0', '1'].includes(plan)) {
      return res.status(400).json({ error: 'Plan debe ser "0" (básico) o "1" (premium)' });
    }
    const existente = await Usuario.findOne({ email: email.toLowerCase().trim() });
    if (existente) {
      return res.status(400).json({ error: 'El usuario ya existe' });
    }
    const hashedPassword = await bcrypt.hash(password, 10);
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

app.get('/admin/usuarios', requireAdminAuth, async (req, res) => {
  try {
    const usuarios = await Usuario.find().select('-password').sort({ fechaCreacion: -1 });
    return res.json({ total: usuarios.length, usuarios });
  } catch (error) {
    console.error('Error listando usuarios:', error);
    return res.status(500).json({ error: 'Error del servidor' });
  }
});

app.put('/admin/usuarios/:id', requireAdminAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const { email, password, plan, activo } = req.body;
    const updateData = {};
    if (email) updateData.email = email.toLowerCase().trim();
    if (password) updateData.password = await bcrypt.hash(password, 10);
    if (plan !== undefined) updateData.plan = plan;
    if (activo !== undefined) updateData.activo = activo;

    const usuario = await Usuario.findByIdAndUpdate(id, updateData, {
      returnDocument: 'after', runValidators: true
    }).select('-password');

    if (!usuario) return res.status(404).json({ error: 'Usuario no encontrado' });
    return res.json({ success: true, usuario });
  } catch (error) {
    console.error('Error actualizando usuario:', error);
    return res.status(500).json({ error: 'Error del servidor' });
  }
});

app.delete('/admin/usuarios/:id', requireAdminAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const usuario = await Usuario.findByIdAndDelete(id);
    if (!usuario) return res.status(404).json({ error: 'Usuario no encontrado' });
    await Sesion.deleteMany({ email: usuario.email });
    return res.json({ success: true, message: 'Usuario y sesiones eliminados' });
  } catch (error) {
    console.error('Error eliminando usuario:', error);
    return res.status(500).json({ error: 'Error del servidor' });
  }
});

app.get('/admin/sesiones', requireAdminAuth, async (req, res) => {
  try {
    const sesiones = await Sesion.find().sort({ lastActive: -1 });
    return res.json({ total: sesiones.length, sesiones });
  } catch (error) {
    console.error('Error listando sesiones:', error);
    return res.status(500).json({ error: 'Error del servidor' });
  }
});

app.post('/admin/limpiar-sesiones', requireAdminAuth, async (req, res) => {
  try {
    const diasInactividad = req.body.dias || 7;
    const fechaLimite = new Date();
    fechaLimite.setDate(fechaLimite.getDate() - diasInactividad);
    const resultado = await Sesion.deleteMany({ lastActive: { $lt: fechaLimite } });
    return res.json({ success: true, sesionesEliminadas: resultado.deletedCount });
  } catch (error) {
    console.error('Error limpiando sesiones:', error);
    return res.status(500).json({ error: 'Error del servidor' });
  }
});

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
      sesiones: { total: totalSesiones }
    });
  } catch (error) {
    console.error('Error obteniendo estadísticas:', error);
    return res.status(500).json({ error: 'Error del servidor' });
  }
});

app.post('/admin/clear-cache', requireAdminAuth, (req, res) => {
  cachedPremiumData = null;
  lastContentFetch = 0;
  console.log('🗑️ Caché limpiado');
  return res.json({ success: true, message: 'Caché limpiado exitosamente' });
});

// ══════════════════════════════════════════════════════════════════
//  CONTENIDO APK (endpoint /content)
// ══════════════════════════════════════════════════════════════════

app.get('/content', async (req, res) => {
  try {
    const { plan } = req.query;
    const now = Date.now();

    if (cachedPremiumData && (now - lastContentFetch < CACHE_DURATION)) {
      const data = plan === '0' ? filterBasicContent(cachedPremiumData) : filterPremiumContent(cachedPremiumData);
      return res.json(data);
    }

    const response = await fetch(API_MASTER_URL);
    if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);

    const data = await response.json();
    cachedPremiumData = data;
    lastContentFetch = now;

    const finalData = plan === '0' ? filterBasicContent(data) : filterPremiumContent(data);
    return res.json(finalData);

  } catch (error) {
    console.error('❌ Error obteniendo contenido:', error);
    if (cachedPremiumData) {
      const data = req.query.plan === '0'
        ? filterBasicContent(cachedPremiumData)
        : filterPremiumContent(cachedPremiumData);
      return res.json(data);
    }
    return res.status(500).json({ error: 'Error obteniendo contenido', message: error.message });
  }
});

// ══════════════════════════════════════════════════════════════════
//  ENDPOINTS WEB STREAMING (/api/*)
// ══════════════════════════════════════════════════════════════════

// ── Estado de llaves de encriptación ────────────────────────────
app.get('/api/keys/status', (req, res) => {
  res.json({
    ready: cryptoKeys.ready,
    error: cryptoKeys.error,
    lastFetch: cryptoKeys.lastFetch,
    cipherAlgo: cryptoKeys.CIPHER_ALGO,
  });
});

// ── Refrescar llaves manualmente ────────────────────────────────
app.get('/api/keys/refresh', async (req, res) => {
  try {
    const result = await fetchCryptoKeys();
    cryptoKeys.PASS_IV = result.PASS_IV;
    cryptoKeys.PASS_KEY = result.PASS_KEY;
    cryptoKeys.CIPHER_ALGO = result.CIPHER_ALGO;
    cryptoKeys.ready = true;
    cryptoKeys.error = null;
    cryptoKeys.lastFetch = new Date().toISOString();
    res.json({ success: true, message: 'Llaves actualizadas' });
  } catch (err) {
    cryptoKeys.error = err.message;
    res.status(500).json({ success: false, error: err.message });
  }
});

// ── Desencriptar un string ──────────────────────────────────────
app.post('/api/decrypt', (req, res) => {
  try {
    if (!cryptoKeys.ready) return res.status(503).json({ error: 'Llaves no disponibles' });
    const { data } = req.body;
    if (!data) return res.status(400).json({ error: 'Falta el campo "data"' });
    res.json({ decrypted: decrypt(data) });
  } catch (err) {
    res.status(500).json({ error: `Error al desencriptar: ${err.message}` });
  }
});

// ── Encriptar un string ─────────────────────────────────────────
app.post('/api/encrypt', (req, res) => {
  try {
    if (!cryptoKeys.ready) return res.status(503).json({ error: 'Llaves no disponibles' });
    const { data } = req.body;
    if (!data) return res.status(400).json({ error: 'Falta el campo "data"' });
    res.json({ encrypted: encrypt(data) });
  } catch (err) {
    res.status(500).json({ error: `Error al encriptar: ${err.message}` });
  }
});

// ── Desencriptar en batch ───────────────────────────────────────
app.post('/api/decrypt-batch', (req, res) => {
  try {
    if (!cryptoKeys.ready) return res.status(503).json({ error: 'Llaves no disponibles' });
    const { fields } = req.body;
    if (!fields || typeof fields !== 'object') {
      return res.status(400).json({ error: 'Falta el campo "fields" (objeto)' });
    }
    const result = {};
    for (const [key, value] of Object.entries(fields)) {
      if (value && typeof value === 'string' && value.length > 0) {
        try { result[key] = decrypt(value); }
        catch { result[key] = null; }
      } else {
        result[key] = value;
      }
    }
    res.json({ decrypted: result });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── ClearKey License (desencripta kid/k server-side) ────────────
app.post('/api/clearkey', async (req, res) => {
  try {
    const { licenseUrl, deviceId, email } = req.body;
    if (!licenseUrl) return res.status(400).json({ error: 'Falta licenseUrl' });
    if (!cryptoKeys.ready) return res.status(503).json({ error: 'Llaves no disponibles' });

    const encDeviceId = deviceId ? encrypt(deviceId) : '';
    const encEmail = email ? encrypt(email) : '';
    const userAgent = encDeviceId + '|' + encEmail;

    const httpModule = licenseUrl.startsWith('https') ? https : http;
    const url = new URL(licenseUrl);

    const rawJson = await new Promise((resolve, reject) => {
      const options = {
        hostname: url.hostname,
        port: url.port || (url.protocol === 'https:' ? 443 : 80),
        path: url.pathname + url.search,
        method: 'POST',
        headers: {
          'User-Agent': userAgent,
          'Content-Type': 'application/octet-stream',
          'Content-Length': 0,
        },
        rejectUnauthorized: false,
      };

      const req = httpModule.request(options, (response) => {
        let data = '';
        response.on('data', chunk => { data += chunk; });
        response.on('end', () => {
          if (response.statusCode !== 200) return reject(new Error(`HTTP ${response.statusCode}: ${data}`));
          resolve(data);
        });
      });
      req.on('error', reject);
      req.setTimeout(10000, () => { req.destroy(); reject(new Error('Timeout')); });
      req.end();
    });

    const licData = JSON.parse(rawJson);
    if (!licData.keys || !licData.keys[0]) {
      return res.status(404).json({ error: 'No keys in license response' });
    }

    let decKid, decK;
    try {
      decKid = decrypt(licData.keys[0].kid);
      decK = decrypt(licData.keys[0].k);
    } catch {
      decKid = licData.keys[0].kid;
      decK = licData.keys[0].k;
    }

    res.json({
      keys: [{ kid: decKid, k: decK }],
      clearKeyJson: { keys: [{ kty: 'oct', kid: decKid, k: decK }] },
    });
  } catch (err) {
    res.status(500).json({ error: `ClearKey error: ${err.message}` });
  }
});

// ── Flow CDN Token ──────────────────────────────────────────────
app.post('/api/flow-token', async (req, res) => {
  try {
    const { streamUrl } = req.body;
    if (!streamUrl) return res.status(400).json({ error: 'Falta streamUrl' });

    // Step 1: Get JWT from mtd.llc
    const jwtData = await new Promise((resolve, reject) => {
      http.get('http://mtd.llc/jwt_cache/jwt_999900002785712.json', (response) => {
        let data = '';
        if (response.statusCode >= 300 && response.statusCode < 400 && response.headers.location) {
          const httpMod = response.headers.location.startsWith('https') ? https : http;
          httpMod.get(response.headers.location, { rejectUnauthorized: false }, (r2) => {
            let d2 = '';
            r2.on('data', c => { d2 += c; });
            r2.on('end', () => { try { resolve(JSON.parse(d2)); } catch { reject(new Error('JWT parse error')); } });
          }).on('error', reject);
          return;
        }
        response.on('data', chunk => { data += chunk; });
        response.on('end', () => { try { resolve(JSON.parse(data)); } catch { reject(new Error('JWT parse error')); } });
      }).on('error', reject);
    });

    const jwt = jwtData?.jwt;
    if (!jwt) return res.status(500).json({ error: 'No JWT available' });

    // Step 2: Request CDN token (GET)
    const tokenUrl = `https://cdn-token.app.flow.com.ar/cdntoken/v1/generator?path=${encodeURIComponent(streamUrl)}`;
    const tUrl = new URL(tokenUrl);

    const tokenData = await new Promise((resolve, reject) => {
      https.get({
        hostname: tUrl.hostname,
        port: 443,
        path: tUrl.pathname + tUrl.search,
        headers: {
          'Authorization': `Bearer ${jwt}`,
          'Origin': 'https://portal.app.flow.com.ar',
          'Referer': 'https://portal.app.flow.com.ar/',
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36',
        },
        rejectUnauthorized: false,
      }, (response) => {
        let data = '';
        response.on('data', chunk => { data += chunk; });
        response.on('end', () => { try { resolve(JSON.parse(data)); } catch { resolve({ raw: data }); } });
      }).on('error', reject);
    });

    const token = tokenData?.token;
    if (!token) return res.json({ error: 'No token in response', details: tokenData });

    const sep = streamUrl.includes('?') ? '&' : '?';
    res.json({ tokenizedUrl: streamUrl + sep + 'cdntoken=' + token, token });
  } catch (err) {
    res.status(500).json({ error: `Flow token error: ${err.message}` });
  }
});

// ── Proxy para listas de canales (desencriptadas) ───────────────
const LIST_URLS = {
  premium: 'https://mtd.llc/listamplaynew.json',
  basico: 'https://mtd.llc/listamplay_basico.json',
};

function fetchUrl(targetUrl) {
  return new Promise((resolve, reject) => {
    const httpMod = targetUrl.startsWith('https') ? https : http;
    httpMod.get(targetUrl, { rejectUnauthorized: false }, (response) => {
      if (response.statusCode >= 300 && response.statusCode < 400 && response.headers.location) {
        return fetchUrl(response.headers.location).then(resolve).catch(reject);
      }
      let data = '';
      response.on('data', chunk => { data += chunk; });
      response.on('end', () => resolve(data));
    }).on('error', reject);
  });
}

app.get('/api/channels/:plan', async (req, res) => {
  const plan = req.params.plan;
  const url = LIST_URLS[plan];
  if (!url) return res.status(400).json({ error: 'Plan inválido. Usar "premium" o "basico"' });
  try {
    const data = await fetchUrl(url);
    res.setHeader('Content-Type', 'application/json');
    res.send(data);
  } catch (err) {
    res.status(500).json({ error: `Error al obtener lista: ${err.message}` });
  }
});

app.get('/api/channels/:plan/decrypted', async (req, res) => {
  if (!cryptoKeys.ready) {
    return res.status(503).json({ error: 'Llaves no disponibles. Ejecutar GET /api/keys/refresh primero.' });
  }
  const plan = req.params.plan;
  const url = LIST_URLS[plan];
  if (!url) return res.status(400).json({ error: 'Plan inválido' });

  try {
    const rawData = await fetchUrl(url);
    const categorias = JSON.parse(rawData);

    const decryptedCategorias = categorias.map(cat => ({
      name: cat.name,
      lista: cat.lista.map(canal => {
        const decrypted = { ...canal };
        const encryptedFields = ['uri', 'headers', 'drm_license_url', 'transmission_html', 'regex_pattern', 'cookie_url'];
        for (const field of encryptedFields) {
          if (canal[field] && typeof canal[field] === 'string' && canal[field].length > 0) {
            try { decrypted[field] = decrypt(canal[field]); }
            catch { decrypted[field] = canal[field]; }
          }
        }
        return decrypted;
      }),
    }));

    res.json(decryptedCategorias);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── Proxy genérico (CORS bypass para el frontend web) ───────────
app.all('/api/proxy', async (req, res) => {
  try {
    const targetUrl = req.query.url || req.body?.url;
    if (!targetUrl) return res.status(400).json({ error: 'Falta parámetro "url"' });

    const httpModule = targetUrl.startsWith('https') ? https : http;
    const url = new URL(targetUrl);
    const customHeaders = req.body?.headers || {};
    const method = req.method === 'OPTIONS' ? 'GET' : (req.body?.method || req.method);

    const options = {
      hostname: url.hostname,
      port: url.port || (url.protocol === 'https:' ? 443 : 80),
      path: url.pathname + url.search,
      method: method,
      headers: {
        'User-Agent': customHeaders['User-Agent'] || req.headers['user-agent'] || 'MultivisionPlay/8.0.7',
        ...customHeaders,
      },
      rejectUnauthorized: false,
    };
    delete options.headers['host'];
    delete options.headers['Host'];

    const proxyReq = httpModule.request(options, (proxyRes) => {
      let chunks = [];
      proxyRes.on('data', (chunk) => { chunks.push(chunk); });
      proxyRes.on('end', () => {
        const data = Buffer.concat(chunks).toString('utf-8');
        res.status(proxyRes.statusCode);
        try { res.json(JSON.parse(data)); }
        catch { res.send(data); }
      });
    });

    proxyReq.on('error', (err) => { res.status(502).json({ error: `Proxy error: ${err.message}` }); });
    proxyReq.setTimeout(15000, () => { proxyReq.destroy(); res.status(504).json({ error: 'Proxy timeout' }); });

    const payload = req.body?.payload;
    if (payload !== undefined && payload !== null) {
      const payloadStr = typeof payload === 'string' ? payload : JSON.stringify(payload);
      if (payloadStr.length > 0) proxyReq.write(payloadStr);
    } else if (method === 'POST') {
      proxyReq.write('');
    }

    proxyReq.end();
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Proxy para imágenes de canales
app.get('/api/image-proxy', async (req, res) => {
  const { url } = req.query;
  
  if (!url) {
    return res.status(400).json({ error: 'URL requerida' });
  }

  try {
    const response = await axios.get(url, {
      responseType: 'arraybuffer',
      headers: {
        'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 11; sdk_gphone_x86_64 Build/RSR1.210722.013.A6)',
        'Accept': 'image/webp,image/png,image/jpeg,*/*',
      },
      timeout: 8000,
    });

    const contentType = response.headers['content-type'] || 'image/png';
    res.set('Content-Type', contentType);
    res.set('Cache-Control', 'public, max-age=86400'); // cache 24hs
    res.send(response.data);
  } catch (error) {
    // Si falla el proxy, devolvemos 404 limpio
    res.status(404).send();
  }
});

// ── Health check ────────────────────────────────────────────────
app.get('/api/health', (req, res) => {
  res.json({
    status: 'ok',
    keysReady: cryptoKeys.ready,
    mongoConnected: mongoose.connection.readyState === 1,
    uptime: process.uptime(),
  });
});

// ── Image proxy (for blocked icon domains like static.tvar.io) ──
const imgCache = new Map();
const IMG_CACHE_TTL = 30 * 60 * 1000; // 30 min
const IMG_FAIL_TTL = 5 * 60 * 1000; // 5 min for failures

// 1x1 transparent PNG as fallback
const PLACEHOLDER_PNG = Buffer.from(
  'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAAC0lEQVQI12NgAAIABQABNjN9GQAAAABJRElEQkSuQmCC',
  'base64'
);

app.get('/api/img', async (req, res) => {
  const url = req.query.url;
  if (!url || (!url.startsWith('http://') && !url.startsWith('https://'))) {
    res.set('Content-Type', 'image/png');
    res.set('Cache-Control', 'public, max-age=60');
    return res.send(PLACEHOLDER_PNG);
  }

  // Check cache (hits AND failures)
  const cached = imgCache.get(url);
  if (cached) {
    const ttl = cached.failed ? IMG_FAIL_TTL : IMG_CACHE_TTL;
    if (Date.now() - cached.time < ttl) {
      res.set('Content-Type', cached.contentType || 'image/png');
      res.set('Cache-Control', cached.failed ? 'public, max-age=300' : 'public, max-age=1800');
      return res.send(cached.data);
    }
    imgCache.delete(url);
  }

  try {
    const imgData = await new Promise((resolve, reject) => {
      const doGet = (targetUrl, redirects = 0) => {
        if (redirects > 3) return reject(new Error('Too many redirects'));
        const mod = targetUrl.startsWith('https') ? https : http;
        const req = mod.get(targetUrl, {
          headers: { 'User-Agent': 'MultivisionPlay/8.0.7', 'Accept': 'image/*,*/*' },
          rejectUnauthorized: false,
          timeout: 8000,
        }, (response) => {
          if (response.statusCode >= 300 && response.statusCode < 400 && response.headers.location) {
            return doGet(response.headers.location, redirects + 1);
          }
          if (response.statusCode !== 200) {
            return reject(new Error(`HTTP ${response.statusCode}`));
          }
          const chunks = [];
          response.on('data', c => chunks.push(c));
          response.on('end', () => resolve({
            data: Buffer.concat(chunks),
            contentType: response.headers['content-type'] || 'image/png',
          }));
        });
        req.on('error', reject);
        req.on('timeout', () => { req.destroy(); reject(new Error('Timeout')); });
      };
      doGet(url);
    });

    // Cache success
    imgCache.set(url, { ...imgData, time: Date.now(), failed: false });
    res.set('Content-Type', imgData.contentType);
    res.set('Cache-Control', 'public, max-age=1800');
    res.send(imgData.data);
  } catch {
    // Cache failure with placeholder
    imgCache.set(url, { data: PLACEHOLDER_PNG, contentType: 'image/png', time: Date.now(), failed: true });
    res.set('Content-Type', 'image/png');
    res.set('Cache-Control', 'public, max-age=300');
    res.send(PLACEHOLDER_PNG);
  }

  // Evict old entries
  if (imgCache.size > 600) {
    const now = Date.now();
    for (const [k, v] of imgCache) {
      const ttl = v.failed ? IMG_FAIL_TTL : IMG_CACHE_TTL;
      if (now - v.time > ttl) imgCache.delete(k);
    }
  }
});

// ══════════════════════════════════════════════════════════════════
//  ENDPOINT RAÍZ
// ══════════════════════════════════════════════════════════════════

app.get('/', (req, res) => {
  res.json({
    message: 'API Multivision Unificada (APK + Web)',
    version: '3.0',
    cryptoKeysReady: cryptoKeys.ready,
    endpoints: {
      publicos: [
        'POST /login',
        'POST /logout',
        'GET  /content?plan=0|1',
        'GET  /sesiones_activas_api.php?correo=...',
        'POST /eliminar_device.php',
      ],
      web_streaming: [
        'GET  /api/keys/status',
        'GET  /api/keys/refresh',
        'POST /api/decrypt',
        'POST /api/encrypt',
        'POST /api/clearkey',
        'POST /api/flow-token',
        'GET  /api/channels/:plan/decrypted',
        'ALL  /api/proxy?url=...',
        'GET  /api/health',
      ],
      admin: [
        'POST   /admin/usuarios',
        'GET    /admin/usuarios',
        'PUT    /admin/usuarios/:id',
        'DELETE /admin/usuarios/:id',
        'GET    /admin/sesiones',
        'POST   /admin/limpiar-sesiones',
        'GET    /admin/stats',
        'POST   /admin/clear-cache',
      ]
    }
  });
});

// ══════════════════════════════════════════════════════════════════
//  ARRANQUE
// ══════════════════════════════════════════════════════════════════

app.listen(PORT, async () => {
  console.log(`\n🚀 Servidor Multivision Unificado corriendo en puerto ${PORT}`);
  console.log(`📊 Límite de dispositivos: ${LIMITE_DISPOSITIVOS}`);
  console.log('─'.repeat(55));

  // Intentar obtener llaves de encriptación al arrancar
  if (pfx && ca) {
    await initCryptoKeys();
  }
});