const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const dotenv = require('dotenv');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Client } = require('pg');

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3001;

// Conexión a la base de datos de Turso
const client = new Client({
  connectionString: process.env.TURSO_CONNECTION_URL,
  ssl: true,  // Habilitar SSL para la conexión
  headers: {
    Authorization: `Bearer ${process.env.TURSO_AUTH_TOKEN}`,  // Token de autenticación
  },
});

client.connect()
  .then(() => console.log('Conexión exitosa a la base de datos'))
  .catch(err => console.error('Error en la conexión a la base de datos:', err));

// Configurar CORS
app.use(cors({
  origin: "*",  // Permitir solicitudes desde cualquier frontend
  credentials: true,
}));

// Configurar body parser para solicitudes JSON
app.use(bodyParser.json());

// Crear tablas de usuarios y compras
async function createUserTable() {
  try {
    await client.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username VARCHAR(50) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        email VARCHAR(100) UNIQUE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);
    console.log('Tabla de usuarios creada o ya existe');
  } catch (error) {
    console.error('Error creando la tabla de usuarios:', error);
  }
}

// Ruta para registrar un nuevo usuario
app.post('/api/v1/user/register', async (req, res) => {
  const { username, password, email } = req.body;

  if (!username || !password || !email) {
    return res.status(400).json({ message: 'Faltan campos requeridos' });
  }

  try {
    // Verificar si el usuario ya existe
    const existingUser = await client.query('SELECT * FROM users WHERE username = $1', [username]);
    if (existingUser.rows.length > 0) {
      return res.status(400).json({ message: 'El nombre de usuario ya está en uso' });
    }

    // Cifrar la contraseña
    const hashedPassword = await bcrypt.hash(password, 10);

    // Crear nuevo usuario
    const result = await client.query(
      'INSERT INTO users (username, password, email) VALUES ($1, $2, $3) RETURNING id, username, email, created_at',
      [username, hashedPassword, email]
    );
    res.status(201).json({ message: 'Usuario registrado con éxito', user: result.rows[0] });
  } catch (error) {
    console.error('Error registrando usuario:', error);
    res.status(500).json({ message: 'Error en el servidor' });
  }
});

// Ruta para iniciar sesión
app.post('/api/v1/user/login', async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ message: 'Faltan credenciales' });
  }

  try {
    // Buscar al usuario por nombre de usuario
    const result = await client.query('SELECT * FROM users WHERE username = $1', [username]);
    const user = result.rows[0];
    if (!user) {
      return res.status(400).json({ message: 'Usuario no encontrado' });
    }

    // Verificar la contraseña
    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) {
      return res.status(400).json({ message: 'Contraseña incorrecta' });
    }

    // Generar JWT
    const token = jwt.sign({ userId: user.id, username: user.username }, process.env.JWT_SECRET, {
      expiresIn: '1h',  // El token expirará en 1 hora
    });

    res.json({ message: 'Login exitoso', token });
  } catch (error) {
    console.error('Error en el login:', error);
    res.status(500).json({ message: 'Error en el servidor' });
  }
});

// Ruta para obtener todos los usuarios (solo para pruebas)
app.get('/api/v1/user/all', async (req, res) => {
  try {
    const result = await client.query('SELECT * FROM users');
    res.json(result.rows);
  } catch (error) {
    console.error('Error obteniendo usuarios:', error);
    res.status(500).json({ message: 'Error en el servidor' });
  }
});

// Ruta para actualizar un usuario
app.put('/api/v1/user/update', async (req, res) => {
  const { userId, newUsername, newPassword } = req.body;

  if (!newUsername || !newPassword) {
    return res.status(400).json({ message: 'Faltan campos para actualizar' });
  }

  try {
    // Cifrar la nueva contraseña
    const hashedPassword = await bcrypt.hash(newPassword, 10);

    const result = await client.query(
      'UPDATE users SET username = $1, password = $2 WHERE id = $3 RETURNING *',
      [newUsername, hashedPassword, userId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Usuario no encontrado' });
    }

    res.json({ message: 'Usuario actualizado', user: result.rows[0] });
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
    const result = await client.query('DELETE FROM users WHERE id = $1 RETURNING *', [userId]);
    if (result.rows.length === 0) {
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

// Iniciar servidor y crear tablas
async function startServer() {
  await createUserTable();  // Crear tabla de usuarios
  app.listen(PORT, () => {
    console.log(`Servidor corriendo en el puerto ${PORT}`);
  });
}

startServer();
