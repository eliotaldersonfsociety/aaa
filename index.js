const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const dotenv = require('dotenv');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { createClient } = require('@libsql/client');  // Usamos createClient para Turso
const cookieParser = require('cookie-parser'); // Requerimos cookie-parser

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

// Middleware para verificar JWT❤️❤️❤️❤️❤️❤️❤️
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

// Configurar CORS adecuadamente
const allowedOrigins = ["https://next-navy-seven.vercel.app"];
app.use(cors({
  origin: (origin, callback) => {
    if (!origin || allowedOrigins.includes(origin)) {
      return callback(null, origin || allowedOrigins[0]);
    }
    return callback(new Error('CORS policy does not allow this origin'), false);
  },
  credentials: true,
}));

// Configurar body parser para solicitudes JSON
app.use(bodyParser.json());

// Agregar cookie-parser (¡Muy importante para leer y escribir cookies!)
app.use(cookieParser());

console.log("NEXTAUTH_SECRET:", process.env.NEXTAUTH_SECRET);
// Ruta para registrar un nuevo usuario 📓📒
app.post('/api/v1/user/register', async (req, res) => {
  const { name, lastname, email, password, direction, postalcode } = req.body;

  if (!name || !lastname || !email || !password || !direction || !postalcode) {
    return res.status(400).json({ message: 'Faltan campos requeridos' });
  }

  try {
    // Verificar si el usuario ya existe
    const result = await db.execute('SELECT * FROM users WHERE email = ?', [email]);

    // Aquí verificamos si `result` tiene un campo que contiene los resultados
    if (result && result.rows.length > 0) {
      return res.status(400).json({ message: 'El correo electrónico ya está en uso' });
    }

    // Cifrar la contraseña
    const hashedPassword = await bcrypt.hash(password, 10);

    // Crear nuevo usuario
    await db.execute(
      'INSERT INTO users (name, lastname, email, password, direction, postalcode, saldo) VALUES (?, ?, ?, ?, ?, ?, ?)',
      [name, lastname, email, hashedPassword, direction, postalcode, 0]
    );

    // Recuperar el usuario recién creado para generar un token
    const newUserResult = await db.execute('SELECT * FROM users WHERE email = ?', [email]);
    const newUser = newUserResult.rows[0];

    const token = jwt.sign({ userId: newUser.id, username: newUser.name, isAdmin: newUser.isAdmin }, 
      process.env.NEXTAUTH_SECRET,
      { expiresIn: '1h' },
    );
    
    res.status(201).json({ 
      message: 'Usuario registrado con éxito',
      token: token,
        user: {
          id: newUser.id,
          name: newUser.name,
          lastname: newUser.lastname,
          email: newUser.email,
          isAdmin: newUser.isAdmin
        }
    });
  } catch (error) {
    console.error('Error registrando usuario:', error);
    res.status(500).json({ message: 'Error en el servidor' });
  }
});

// Ruta para iniciar sesión 🤷‍♂️
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
      return res.status(400).json({ message: 'Usuario no encontrado o error al recuperar los datos' });
    }

    const user = result.rows[0]; // Asignar el primer usuario encontrado

    // Verificar la contraseña
    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) {
      return res.status(400).json({ message: 'Contraseña incorrecta' });
    }

    // Generar JWT
    const token = jwt.sign({ userId: user.id, username: user.name, isAdmin: user.isAdmin }, process.env.JWT_SECRET, {
      expiresIn: '1h',  // El token expirará en 1 hora
    });

    res.json({ message: 'Login exitoso',
              token: token,
              user: {
                id: user.id,
                name: user.name,
                lastname: user.lastname,
                email: user.email,
                isAdmin: user.isAdmin
              }
             });
  } catch (error) {
    console.error('Error en el login:', error);
    res.status(500).json({ message: 'Error en el servidor' });
  }
});

// Ruta para actualizar saldo de la compra q hizo 💳
app.post('/api/v1/user/saldo', authMiddleware, async (req, res) => {
  const { amount } = req.body;
  if (typeof amount !== 'number') {
    return res.status(400).json({ message: "El valor de 'amount' debe ser un número" });
  }

  const userId = req.user.userId;

  try {
    // Consultar el saldo actual del usuario en la base de datos
    const saldoResult = await db.execute('SELECT saldo FROM users WHERE id = ?', [userId]);
    if (!saldoResult || saldoResult.rows.length === 0) {
      return res.status(404).json({ message: 'Usuario no encontrado' });
    }

    const currentSaldo = saldoResult.rows[0].saldo;

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

//Ruta para mostrar el saldo en dashboard 🤞
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

    if (saldoResult.rows.length === 0) {
      return res.status(404).json({ message: 'Usuario no encontrado' });
    }

    const saldo = saldoResult.rows[0].saldo;
    console.log("Saldo obtenido de la base de datos:", saldo); // Ver el saldo obtenido de la base de datos

    // Devolver el saldo actual sin modificaciones
    return res.json({ success: true, saldo: saldo });
  } catch (error) {
    console.error('Error obteniendo saldo:', error);
    return res.status(500).json({ message: 'Error al obtener saldo' });
  }
});

// Ruta para obtener compras ya hechas del usuario 🛍️
app.get("/api/v1/purchases", authMiddleware, async (req, res) => {
  const userId = req.user.userId;
  console.log("User ID from JWT:", userId);
  try {
    const result = await db.execute('SELECT * FROM purchases WHERE user_id = ?', [userId]);
       // Si no hay compras, devolver un mensaje adecuado
    if (!result || result.rows.length === 0) {
      console.log("No purchases found for the user.");
      return res.status(404).json({ message: 'No purchases found' });
    }

    return res.json({ purchases: result.rows });
  } catch (error) {
    console.error("Error fetching purchases:", error);
    return res.status(500).json({ error: "Error fetching purchases" });
  }
});

// Ruta para guardar compras 🔏
app.post('/api/v1/user/compras', authMiddleware, async (req, res) => {
  const { items, payment_method, total_amount } = req.body;

  if (!items || !payment_method || typeof total_amount !== 'number') {
    return res.status(400).json({ message: 'Faltan campos requeridos o datos inválidos' });
  }

  const userId = req.user.userId;

  try {
    await db.execute(
      'INSERT INTO purchases (items, payment_method, user_id, total_amount) VALUES (?, ?, ?, ?)',
      [JSON.stringify(items), payment_method, userId, total_amount]
    );
    
    return res.status(201).json({ message: 'Compra registrada con éxito' });
  } catch (error) {
    console.error('Error guardando compra:', error);
    return res.status(500).json({ message: 'Error al registrar la compra' });
  }
});

// Ruta para actualizar saldo tras una compra 🪙
app.post('/api/v1/user/actualizar', async (req, res) => {
  const { userId, total_amount } = req.body;

  try {
    // Validar que total_amount sea un número positivo
    if (typeof total_amount !== 'number' || total_amount <= 0) {
      return res.status(400).json({ message: 'El total de la compra es inválido' });
    }

    // Obtener el saldo actual del usuario
    const saldoResult = await db.execute('SELECT saldo FROM users WHERE id = ?', [userId]);

    if (!saldoResult || saldoResult.rows.length === 0) {
      return res.status(404).json({ message: 'Usuario no encontrado' });
    }

    const currentSaldo = saldoResult.rows[0].saldo;
    const newSaldo = currentSaldo - total_amount;

    if (newSaldo < 0) {
      return res.status(400).json({ message: 'Saldo insuficiente' });
    }

    // Actualizar saldo del usuario
    await db.execute('UPDATE users SET saldo = ? WHERE id = ?', [newSaldo, userId]);

    return res.status(200).json({ message: 'Saldo actualizado con éxito', newSaldo });
  } catch (error) {
    console.error('Error actualizando saldo:', error);
    return res.status(500).json({ message: 'Error al actualizar el saldo' });
  }
});

// Ruta para obtener el email y saldo de todos los usuarios (solo para administradores)
app.get('/api/v1/user/recargar', authMiddleware, async (req, res) => {
  const userId = req.user.userId; // ID del usuario autenticado
   console.log("ID del usuario autenticado:", userId); // Ver el ID del usuario que está realizando la solicitud

  // Verificar si userId es del tipo adecuado
  if (typeof userId !== 'number') {
    console.error("El userId no es un número válido:", userId);
    return res.status(400).json({ message: 'ID de usuario no válido' });
  }

  try {
    // Verificar si el usuario autenticado es administrador
    const adminCheck = await db.execute('SELECT isAdmin FROM users WHERE id = ?', [userId]);

    if (adminCheck.rows[0].isAdmin !== 1) {
      return res.status(403).json({ message: 'Acceso denegado. Solo administradores pueden ver esta información' });
    }

    // Obtener todos los usuarios con su email y saldo
    const users = await db.execute('SELECT email, saldo FROM users');

    return res.json({ success: true, users: users.rows });
  } catch (error) {
    console.error('Error obteniendo los usuarios:', error);
    return res.status(500).json({ message: 'Error al obtener los usuarios' });
  }
});

// Ruta para actualizar el saldo manualmente de un usuario (solo administradores)
app.put('/api/v1/user/updateSaldo', authMiddleware, async (req, res) => {
  const userId = req.user.userId; // Obtener el ID del usuario autenticado
  const { email, saldo } = req.body; // Recibir los datos del saldo a actualizar

  if (!email || typeof saldo !== 'number') {
    return res.status(400).json({ message: 'Faltan datos o el saldo no es un número válido' });
  }

  try {
    // Verificar si el usuario autenticado es un administrador
    const userCheck = await db.execute('SELECT isAdmin FROM users WHERE id = ?', [userId]);
    if (userCheck.rows.length === 0 || userCheck.rows[0].isAdmin !== 1) {
      return res.status(403).json({ message: 'Acceso denegado. Solo el administrador puede modificar el saldo.' });
    }

    // Obtener el saldo actual del usuario
    const currentSaldoResult = await db.execute('SELECT saldo FROM users WHERE email = ?', [email]);
    if (currentSaldoResult.rows.length === 0) {
      return res.status(404).json({ message: 'Usuario no encontrado' });
    }

    const currentSaldo = currentSaldoResult.rows[0].saldo;

    // Sumar el saldo actual con el nuevo saldo proporcionado
    const newSaldo = currentSaldo + saldo;

    // Actualizar el saldo del usuario
    await db.execute('UPDATE users SET saldo = ? WHERE email = ?', [newSaldo, email]);

    return res.json({ message: 'Saldo actualizado correctamente', newSaldo });
  } catch (error) {
    console.error('Error actualizando saldo:', error);
    return res.status(500).json({ message: 'Error al actualizar saldo' });
  }
});


// Ruta de prueba para verificar si la API está funcionando❤️😍💕
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
