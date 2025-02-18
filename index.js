const express = require('express');

const app = express();
const port = process.env.PORT || 3000;

// Configurar Express
app.use(express.json());

app.get('/api/login', async (req, res) => {
  // Usamos una plantilla de literal (backticks) para el HTML
  const htmlResponse = `
  <html>
    <head>
      <title>Asi es mano</title>
    </head>
    <body>
      <h1>Claro que si papi</h1>
    </body>
  </html>
  `;
  res.send(htmlResponse);
});

app.listen(port, () => {
  console.log(`Puerto corriendo aqui: http://localhost:${port}`);
});
