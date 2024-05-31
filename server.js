require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const base64url = require('base64url');
const axios = require('axios');
const winston = require('winston');
const { Loggly } = require('winston-loggly-bulk');

const app = express();
const port = process.env.PORT || 3000;

app.use(bodyParser.json());

const secretKey = process.env.SECRET_KEY;

// Configurar winston para enviar logs a Loggly
winston.add(new Loggly({
  token: process.env.LOGGLY_TOKEN,
  subdomain: process.env.LOGGLY_SUBDOMAIN,
  tags: ['Winston-NodeJS'],
  json: true
}));

// Middleware de autenticación para el administrador
function authenticateAdmin(req, res, next) {
  const authHeader = req.headers['authorization'];
  if (authHeader) {
    const encodedCredentials = authHeader.split(' ')[1];
    const decodedCredentials = Buffer.from(encodedCredentials, 'base64').toString('ascii');
    const [username, password] = decodedCredentials.split(':');

    if (username === process.env.ADMIN_USERNAME && password === process.env.ADMIN_PASSWORD) {
      req.user = { username }; // Almacena el usuario autenticado
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
    if (token === secretKey) {
      req.user = { username: 'regular_user' }; // Almacena el usuario regular
      next();
    } else {
      res.status(403).json({ error: 'Forbidden - Token inválido.' });
    }
  } else {
    res.status(403).json({ error: 'Acceso denegado: Se requiere un token.' });
  }
}

// Obtener la ubicación del usuario
async function getClientLocation(ip) {
  try {
    const response = await axios.get(`http://ip-api.com/json/${ip}`);
    return response.data;
  } catch (error) {
    winston.error(`Error al obtener la ubicación del cliente: ${error.message}`);
    return null;
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
  const header = {
    "typ": "JWT",
    "alg": "HS256"
  };

  const encodedHeader = base64url.encode(JSON.stringify(header));
  const encodedPayload = base64url.encode(JSON.stringify(payload));

  const signature = base64url.encode(
    require('crypto')
      .createHmac('sha256', secret)
      .update(`${encodedHeader}.${encodedPayload}`)
      .digest()
  );

  return `${encodedHeader}.${encodedPayload}.${signature}`;
}

// Middleware para verificar autenticación del administrador o usuario regular
function verifyAuthentication(req, res, next) {
  const { environment } = req.body;
  if (environment.toLowerCase() === 'prd') {
    authenticateAdmin(req, res, next);
  } else {
    const authHeader = req.headers['authorization'];
    if (authHeader) {
      const encodedCredentials = authHeader.split(' ')[1];
      const decodedCredentials = Buffer.from(encodedCredentials, 'base64').toString('ascii');
      const [username, password] = decodedCredentials.split(':');

      if (username === process.env.ADMIN_USERNAME && password === process.env.ADMIN_PASSWORD) {
        req.user = { username }; // Almacena el usuario autenticado
        return next();
      } else {
        authenticate(req, res, next);
      }
    } else {
      authenticate(req, res, next);
    }
  }
}

// Endpoint para generar el token
app.post('/generate-token', verifyAuthentication, async (req, res) => {
  const { data, environment } = req.body;

  if (!data || !environment) {
    return res.status(400).json({ error: 'Faltan datos en el body de datos o ambiente.' });
  }

  if (!environments[environment.toLowerCase()]) {
    return res.status(400).json({ error: 'Ambiente no válido.' });
  }

  const token = createCustomJWT(data, secretKey);
  const tokenUrl = `${environments[environment.toLowerCase()]}${token}`;
  const environmentName = environmentNames[environment.toLowerCase()];

  const clientIp = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
  const location = await getClientLocation(clientIp);

  // Log en formato JSON con múltiples mensajes
  winston.info({
    message: [
      `Token solicitado por el usuario: ${req.user ? req.user.username : 'Usuario no autenticado'}`,
      `Ubicación del cliente: ${location ? `${location.city}, ${location.regionName}, ${location.country}` : 'Ubicación no disponible'}`,
      `URL Generada para el ambiente ${environmentName}: ${tokenUrl}`
    ],
    level: 'info',
    timestamp: new Date().toISOString()
  });

  res.json({
    [`URL Generada ${environmentName}:`]: tokenUrl
  });
});

app.listen(port, () => {
  console.log(`Servidor ejecutándose en http://localhost:${port}`);
});
