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

// Ruta para registrar un nuevo usuario
app.post('/api/v1/user/register', async (req, res) => {
  const { name, lastname, email, password, direction, postalcode } = req.body;

  if (!name || !lastname || !email || !password || !direction || !postalcode) {
    return res.status(400).json({ message: 'Faltan campos requeridos' });
  }

  try {
    // Verificar si el usuario ya existe
    const existingUser = await client.query('SELECT * FROM users WHERE email = $1', [email]);
    if (existingUser.rows.length > 0) {
      return res.status(400).json({ message: 'El correo electrónico ya está en uso' });
    }

    // Cifrar la contraseña
    const hashedPassword = await bcrypt.hash(password, 10);

    // Crear nuevo usuario
    const result = await client.query(
      'INSERT INTO users (name, lastname, email, password, direction, postalcode) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id, name, lastname, email, direction, postalcode, created_at',
      [name, lastname, email, hashedPassword, direction, postalcode]
    );
    res.status(201).json({ message: 'Usuario registrado con éxito', user: result.rows[0] });
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
    const result = await client.query('SELECT * FROM users WHERE email = $1', [email]);
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
    const token = jwt.sign({ userId: user.id, email: user.email }, process.env.JWT_SECRET, {
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
    const result = await client.query('SELECT id, name, lastname, email, direction, postalcode, created_at FROM users');
    res.json(result.rows);
  } catch (error) {
    console.error('Error obteniendo usuarios:', error);
    res.status(500).json({ message: 'Error en el servidor' });
  }
});

// Ruta para actualizar un usuario
app.put('/api/v1/user/update', async (req, res) => {
  const { userId, newName, newLastname, newEmail, newPassword, newDirection, newPostalcode } = req.body;

  if (!userId || !newName || !newLastname || !newEmail || !newPassword || !newDirection || !newPostalcode) {
    return res.status(400).json({ message: 'Faltan campos para actualizar' });
  }

  try {
    // Cifrar la nueva contraseña
    const hashedPassword = await bcrypt.hash(newPassword, 10);

    const result = await client.query(
      'UPDATE users SET name = $1, lastname = $2, email = $3, password = $4, direction = $5, postalcode = $6 WHERE id = $7 RETURNING *',
      [newName, newLastname, newEmail, hashedPassword, newDirection, newPostalcode, userId]
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

// Iniciar servidor
app.listen(PORT, () => {
  console.log(`Servidor corriendo en el puerto ${PORT}`);
});
