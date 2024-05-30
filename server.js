require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const base64url = require('base64url');

const app = express();
const port = process.env.PORT || 3000;

app.use(bodyParser.json());

const secretKey = process.env.SECRET_KEY;

// Middleware de autenticación para el administrador
function authenticateAdmin(req, res, next) {
  const authHeader = req.headers['authorization'];
  if (authHeader) {
    const encodedCredentials = authHeader.split(' ')[1];
    const decodedCredentials = Buffer.from(encodedCredentials, 'base64').toString('ascii');
    const [username, password] = decodedCredentials.split(':');

    if (username === process.env.ADMIN_USERNAME && password === process.env.ADMIN_PASSWORD) {
      return next();
    }
  }
  res.status(403).json({ error: 'Acceso denegado: Solo el administrador puede generar la URL para el ambiente de producción.' });
}

// Middleware de autenticación para usuarios regulares
function authenticate(req, res, next) {
  const authHeader = req.headers['authorization'];
  if (authHeader) {
    const token = authHeader.split(' ')[1];
    jwt.verify(token, secretKey, (err, user) => {
      if (err) {
        return res.status(403).send('Forbidden');
      }
      req.user = user;
      next();
    });
  } else {
    res.status(403).json({ error: 'Acceso denegado: Se requiere un token.' });
  }
}

// Endpoints de los ambientes
const environments = {
  local: process.env.URL_LOCAL,
  qa: process.env.URL_QA,
  ams: process.env.URL_AMS,
  ppr: process.env.URL_PPR,
  prd: process.env.URL_PRD
};

const environmentNames = {
  local: 'LOCAL',
  qa: 'QA',
  ams: 'AMS',
  ppr: 'PPR',
  prd: 'PRD'
};

function createCustomJWT(payload, secret) {
  // Encabezado con orden personalizado
  const header = {
    "typ": "JWT",
    "alg": "HS256"
  };

  // Codificar el encabezado y el payload
  const encodedHeader = base64url.encode(JSON.stringify(header));
  const encodedPayload = base64url.encode(JSON.stringify(payload));

  // Crear la firma usando el módulo 'crypto' para asegurar que coincide con jwt.io
  const signature = base64url.encode(
    require('crypto')
      .createHmac('sha256', secret)
      .update(`${encodedHeader}.${encodedPayload}`)
      .digest()
  );

  // Crear el token final
  return `${encodedHeader}.${encodedPayload}.${signature}`;
}

// Endpoint para generar el token
app.post('/generate-token', (req, res) => {
  const { data, environment } = req.body;
  if (environment === 'prod') {
    authenticateAdmin(req, res, next);
  } else {
    authenticate(req, res, next);
  }
}, (req, res) => {
  const { data, environment } = req.body;

  if (!data || !environment) {
    return res.status(400).send('Faltan datos en el body de datos o ambiente.');
  }

  if (!environments[environment]) {
    return res.status(400).send('Ambiente no válido.');
  }
  // Generar el token sin el campo `iat`
  const token = createCustomJWT(data, secretKey);

  // Construir la URL
  const tokenUrl = `${environments[environment]}${token}`;
  const environmentName = environmentNames[environment];

  res.json({
    //"TOKEN GENERADO": token,
    [`URL Generada ${environmentName}:`]: tokenUrl
  });
});

app.listen(port, () => {
  console.log(`Servidor ejecutándose en http://localhost:${port}`);
});
