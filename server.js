const express = require('express');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const base64url = require('base64url');

const app = express();
const port = process.env.PORT || 3000;

app.use(bodyParser.json());

const secretKey = 'kjsfg!)=)4diof25sfdg302dfg57438)!#$#70dfgf234asdnan';

// Endpoints de los ambientes
const environments = {
    local: 'http://localhost:3000/IngresoExterno/?token=',
    qa: 'https://ffvvmqa.somosbelcorp.com/portal/IngresoSistema/IngresoExterno/?token=',
    ams: 'https://ffvvmams.somosbelcorp.com/portal/IngresoSistema/IngresoExterno/?token=',
    prd: 'https://ffvv.somosbelcorp.com/portal/IngresoSistema/IngresoExterno/?token='
    
};

const environmentNames = {
    local: 'LOCAL',
    ams: 'AMS',
    qa: 'QA',
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
