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
    if (token === secretKey) {
      next();
    } else {
      res.status(403).json({ error: 'Forbidden - Token inválido.' });
    }
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
app.post('/generate-token', verifyAuthentication, (req, res) => {
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

  res.json({
    [`URL Generada ${environmentName}:`]: tokenUrl
  });
});

app.listen(port, () => {
  console.log(`Servidor ejecutándose en http://localhost:${port}`);
});
