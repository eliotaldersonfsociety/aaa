const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const dotenv = require('dotenv');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { createClient } = require('@libsql/client');  // Usamos createClient para Turso

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3001;

// Verificar que las variables de entorno están cargadas correctamente
console.log("TURSO_CONNECTION_URL: ", process.env.TURSO_CONNECTION_URL);
console.log("TURSO_AUTH_TOKEN: ", process.env.TURSO_AUTH_TOKEN);

// Conexión a la base de datos de Turso utilizando createClient
const db = createClient({
  url: process.env.TURSO_CONNECTION_URL,  // Asegúrate de que la URL es correcta
  authToken: process.env.TURSO_AUTH_TOKEN,  // Token de autenticación
});

// Conectar a la base de datos
async function connectDatabase() {
  try {
    // Test para verificar la conexión (esto no es necesario, pero útil para depuración)
    await db.execute('SELECT 1');
    console.log('Conexión exitosa a la base de datos');
  } catch (err) {
    console.error('Error en la conexión a la base de datos:', err);
  }
}

// Configurar CORS
app.use(cors({
  origin: "*",  // Permitir solicitudes desde cualquier frontend
  credentials: true,
}));

// Configurar body parser para solicitudes JSON
app.use(bodyParser.json());

// Ruta para registrar un nuevo usuario
app.post('/api/v1/user/register', async (req, res) => {
  const { name, lastname, email, password, direction, postalcode } = req.body;

  if (!name || !lastname || !email || !password || !direction || !postalcode) {
    return res.status(400).json({ message: 'Faltan campos requeridos' });
  }

  try {
    // Verificar si el usuario ya existe
    const existingUser = await db.execute('SELECT * FROM users WHERE email = ?', [email]);
    if (existingUser.length > 0) {
      return res.status(400).json({ message: 'El correo electrónico ya está en uso' });
    }

    // Cifrar la contraseña
    const hashedPassword = await bcrypt.hash(password, 10);

    // Crear nuevo usuario
    await db.execute(
      'INSERT INTO users (name, lastname, email, password, direction, postalcode) VALUES (?, ?, ?, ?, ?, ?)',
      [name, lastname, email, hashedPassword, direction, postalcode]
    );
    res.status(201).json({ message: 'Usuario registrado con éxito' });
  } catch (error) {
    console.error('Error registrando usuario:', error);
    res.status(500).json({ message: 'Error en el servidor' });
  }
});

// Ruta para iniciar sesión
app.post('/api/v1/user/login', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ message: 'Faltan credenciales' });
  }

  try {
    // Buscar al usuario por correo electrónico
    const result = await db.execute('SELECT * FROM users WHERE email = ?', [email]);
    const user = result[0];
    if (!user) {
      return res.status(400).json({ message: 'Usuario no encontrado' });
    }

    // Verificar la contraseña
    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) {
      return res.status(400).json({ message: 'Contraseña incorrecta' });
    }

    // Generar JWT
    const token = jwt.sign({ userId: user.id, username: user.name }, process.env.JWT_SECRET, {
      expiresIn: '1h',  // El token expirará en 1 hora
    });

    res.json({ message: 'Login exitoso', token });
  } catch (error) {
    console.error('Error en el login:', error);
    res.status(500).json({ message: 'Error en el servidor' });
  }
});

// Ruta para obtener todos los usuarios
app.get('/api/v1/user/all', async (req, res) => {
  try {
    const result = await db.execute('SELECT * FROM users');
    res.json(result);
  } catch (error) {
    console.error('Error obteniendo usuarios:', error);
    res.status(500).json({ message: 'Error en el servidor' });
  }
});

// Ruta para actualizar un usuario
app.put('/api/v1/user/update', async (req, res) => {
  const { userId, newName, newLastname, newEmail, newPassword } = req.body;

  if (!newName || !newLastname || !newEmail || !newPassword) {
    return res.status(400).json({ message: 'Faltan campos para actualizar' });
  }

  try {
    // Cifrar la nueva contraseña
    const hashedPassword = await bcrypt.hash(newPassword, 10);

    const result = await db.execute(
      'UPDATE users SET name = ?, lastname = ?, email = ?, password = ? WHERE id = ?',
      [newName, newLastname, newEmail, hashedPassword, userId]
    );

    if (result.length === 0) {
      return res.status(404).json({ message: 'Usuario no encontrado' });
    }

    res.json({ message: 'Usuario actualizado', user: result[0] });
  } catch (error) {
    console.error('Error actualizando usuario:', error);
    res.status(500).json({ message: 'Error en el servidor' });
  }
});

// Ruta para eliminar un usuario
app.delete('/api/v1/user/delete', async (req, res) => {
  const { userId } = req.body;

  if (!userId) {
    return res.status(400).json({ message: 'Falta el ID de usuario' });
  }

  try {
    const result = await db.execute('DELETE FROM users WHERE id = ? RETURNING *', [userId]);
    if (result.length === 0) {
      return res.status(404).json({ message: 'Usuario no encontrado' });
    }

    res.json({ message: `Usuario con ID ${userId} eliminado` });
  } catch (error) {
    console.error('Error eliminando usuario:', error);
    res.status(500).json({ message: 'Error en el servidor' });
  }
});

// Ruta de prueba para verificar si la API está funcionando
app.get('/', (req, res) => {
  res.json({ message: 'API is working!' });
});

// Iniciar servidor y conectar a la base de datos
async function startServer() {
  await connectDatabase();  // Conectar a la base de datos
  app.listen(PORT, () => {
    console.log(`Servidor corriendo en el puerto ${PORT}`);
  });
}

startServer();
