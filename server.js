const express = require('express');
const cors = require('cors');
const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true })); // Para recibir form data

// Base de datos simulada de usuarios
const usuarios = [
  { email: 'usuario1@test.com', password: '123456' },
  { email: 'usuario2@test.com', password: '123456' },
  { email: 'admin@test.com', password: 'admin123' }
];

// Endpoint de login (igual que la API original)
app.post('/login', (req, res) => {
  const { usuario, password } = req.body;

  console.log('Login attempt:', { usuario, password });

  // Validar que vengan los datos
  if (!usuario || !password) {
    return res.json({
      response: {
        msg: 'error',
        message: 'Usuario y contraseña son requeridos'
      }
    });
  }

  // Buscar usuario
  const user = usuarios.find(u => u.email === usuario && u.password === password);

  if (user) {
    // Login exitoso - responder en el formato que espera la app
    return res.json({
      response: {
        msg: 'success_login',
        idv: '12345',
        cuentaCreada: '2024-01-01',
        plan: '1' // Plan premium
      }
    });
  } else {
    // Credenciales incorrectas
    return res.json({
      response: {
        msg: 'error',
        message: 'Credenciales incorrectas'
      }
    });
  }
});

// Endpoint de prueba
app.get('/', (req, res) => {
  res.json({ message: 'API Multivision funcionando correctamente' });
});

app.listen(PORT, () => {
  console.log(`Servidor corriendo en puerto ${PORT}`);
});