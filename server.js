const express = require('express');
const cors = require('cors');
const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());

// Base de datos simulada de usuarios
const usuarios = [
  { email: 'usuario1@test.com', password: '123456' },
  { email: 'usuario2@test.com', password: '123456' },
  { email: 'admin@test.com', password: 'admin123' }
];

// Endpoint de login
app.post('/login', (req, res) => {
  const { email, password } = req.body;

  // Validar que vengan los datos
  if (!email || !password) {
    return res.status(400).json({ 
      success: false, 
      message: 'Email y contraseña son requeridos' 
    });
  }

  // Buscar usuario
  const usuario = usuarios.find(u => u.email === email && u.password === password);

  if (usuario) {
    return res.json({ 
      success: true, 
      message: 'Login exitoso',
      user: { email: usuario.email }
    });
  } else {
    return res.status(401).json({ 
      success: false, 
      message: 'Credenciales incorrectas' 
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