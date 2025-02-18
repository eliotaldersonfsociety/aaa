const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const dotenv = require('dotenv');
const authRouter = require('./routes/auth');
const postRouter = require('./routes/post');
const userRouter = require('./routes/user');
const actualizarRouter = require('./routes/actualizar');
const { createUserTable } = require('./models/user');
const { createPurchasesTable } = require('./models/purchase');

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3001;

// Habilitar CORS
app.use(cors({
  origin: "*", // Permitir solicitudes desde el frontend
  credentials: true, // Permitir cookies y autenticación con credenciales
}));

app.use(bodyParser.json());

app.get('/', (req, res) => {
  res.json({ message: 'API is working!' });
});

app.get('/test-db', async (req, res) => {
  try {
    const users = await client.execute({
      sql: 'SELECT * FROM users',
      args: [],
    });
    res.json(users);
  } catch (error) {
    res.status(500).json({ error: 'Error connecting to the database' });
  }
});


app.use('/api/v1/auth', authRouter);
app.use('/api/v1/posts', postRouter);
app.use('/api/v1/user', userRouter);
app.use('/api/v1/actualizar', actualizarRouter);

async function startServer() {
  await createUserTable();
  console.log('User table created or already exists');
  await createPurchasesTable();
  console.log('Purchases table created or already exists');
  app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
  });
}

startServer();
