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
  url: process.env.TURSO_CONNECTION_URL,
  authToken: process.env.TURSO_AUTH_TOKEN,
});

// Middleware para verificar JWT
const authMiddleware = (req, res, next) => {
  const token = req.header('Authorization')?.replace('Bearer ', '');

  if (!token) {
    return res.status(401).json({ message: 'No token provided' });
  }

  try {
    const payload = jwt.verify(token, process.env.JWT_SECRET);
    req.user = payload; // Añadimos el payload al request para acceder a él
    next();
  } catch (error) {
    console.error('JWT Error:', error);
    return res.status(401).json({ message: 'Invalid or expired token' });
  }
};

// Configurar CORS
app.use(cors({
  origin: "*",
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
    const result = await db.execute('SELECT * FROM users WHERE email = ?', [email]);

    // Aquí verificamos si `result` tiene un campo que contiene los resultados
    if (result && result.length > 0) {
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

    console.log("Resultado de la consulta:", result);  // Depuración para ver cómo llega el resultado


    // Verificar que el resultado sea un array y tenga al menos un usuario
    if (!result.rows || result.rows.length === 0) {
      return res.status(400).json({ message: 'Usuario no encontrado o error al recuerar los datos' });
    }

    const user = result.rows[0]; // Asignar el primer usuario encontrado

    // Verificar la contraseña
    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) {
      return res.status(400).json({ message: 'Contraseña incorrecta' });
    }
    // Generar JWT
    const token = jwt.sign({ userId: user.id, username: user.name }, process.env.JWT_SECRET, {
      expiresIn: '1h',  // El token expirará en 1 hora
    });

    res.json({ message: 'Login exitoso', 
              token: token,
              user: {
                id: user.id,
                name: user.name,
                lastname: user.lastname,
                email: user.email,
            
              }
             });
  } catch (error) {
    console.error('Error en el login:', error);
    res.status(500).json({ message: 'Error en el servidor' });
  }
});

// Ruta para actualizar saldo
app.post('/api/v1/user/saldo', authMiddleware, async (req, res) => {
  const { amount } = req.body;
  if (typeof amount !== 'number') {
    return res.status(400).json({ message: "El valor de 'amount' debe ser un número" });
  }

  const userId = req.user.id;

  try {
    // Consultar el saldo actual del usuario en la base de datos
    const result = await db.execute('SELECT saldo FROM users WHERE id = ?', [userId]);
    if (result.length === 0) {
      return res.status(404).json({ message: 'Usuario no encontrado' });
    }

    const currentSaldo = result[0].saldo;

    // Calcular el nuevo saldo
    const newSaldo = currentSaldo + amount;

    // Validar que el saldo no sea negativo
    if (newSaldo < 0) {
      return res.status(400).json({ message: 'Saldo insuficiente' });
    }

    // Actualizar el saldo del usuario en la base de datos
    await db.execute('UPDATE users SET saldo = ? WHERE id = ?', [newSaldo, userId]);

    return res.json({ success: true, newSaldo });
  } catch (error) {
    console.error('Error actualizando saldo:', error);
    return res.status(500).json({ message: 'Error al actualizar saldo' });
  }
});

app.get('/api/v1/user/saldo', authMiddleware, async (req, res) => {
  const userId = req.user.userId;

  console.log("ID del usuario autenticado:", userId); // Ver el ID del usuario que está realizando la solicitud

  // Verificar si userId es del tipo adecuado
  if (typeof userId !== 'number') {
    console.error("El userId no es un número válido:", userId);
    return res.status(400).json({ message: 'ID de usuario no válido' });
  }

  try {
    // Obtener el saldo del usuario
    const saldoResult = await db.execute('SELECT saldo FROM users WHERE id = ?', [userId]);

    console.log("Resultado de la consulta a la base de datos:", saldoResult); // Ver los resultados de la consulta

    if (!saldoResult || saldoResult.length === 0) {
      console.error("No se encontró saldo para el usuario con ID:", userId);
      return res.status(500).json({ message: 'Error al obtener el saldo' });
    }

    const saldo = saldoResult[0].saldo;
    console.log("Saldo obtenido de la base de datos:", saldo); // Ver el saldo obtenido de la base de datos

    // Devolver el saldo actual sin modificaciones
    return res.json({ success: true, saldo: saldo });
  } catch (error) {
    console.error('Error obteniendo saldo:', error);
    return res.status(500).json({ message: 'Error al obtener saldo' });
  }
});


// Ruta para obtener compras (posts) del usuario
app.get("/api/v1/purchases", authMiddleware, async (req, res) => {
  const userId = req.user.id;
  console.log("User ID from JWT:", userId);
  try {
    const result = await db.execute('SELECT * FROM purchases WHERE userId = ?', [userId]);
       // Si no hay compras, devolver un mensaje adecuado
    if (!result || result.length === 0) {
      console.log("No purchases found for the user.");
      return res.status(404).json({ message: 'No purchases found' });
    }

    return res.json({ purchases: result });
  } catch (error) {
    console.error("Error fetching purchases:", error);
    return res.status(500).json({ error: "Error fetching purchases" });
  }
});

// Ruta de prueba para verificar si la API está funcionando
app.get('/', (req, res) => {
  res.json({ message: 'API is working!' });
});

// Iniciar servidor y conectar a la base de datos
async function startServer() {
  try {
    // Test para verificar la conexión (esto no es necesario, pero útil para depuración)
    await db.execute('SELECT 1');
    console.log('Conexión exitosa a la base de datos');

    app.listen(PORT, () => {
      console.log(`Servidor corriendo en el puerto ${PORT}`);
    });
  } catch (err) {
    console.error('Error en la conexión a la base de datos:', err);
  }
}

startServer();
