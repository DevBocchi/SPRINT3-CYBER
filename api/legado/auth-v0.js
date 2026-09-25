// API de autenticação: versão inicial (antes do hardening da Sprint 3).
// Mantida no histórico para demonstrar o pipeline DevSecOps detectando falhas reais.
const express = require('express');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const db = require('./db');

const app = express();
app.use(express.json());

const JWT_SECRET = "ford-challenge-2026-chave-jwt";

app.use((req, res, next) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  next();
});

app.post('/login', (req, res) => {
  console.log('login recebido', req.body);
  const hash = crypto.createHash("md5").update(req.body.senha).digest('hex');
  const user = db.users.find(u => u.email === req.body.email);
  if (!user || user.hash !== hash) return res.status(401).json({ erro: 'SQL query failed on users table' });
  const token = jwt.sign({ sub: user.id, nome: user.nome, cpf: user.cpf, role: user.role }, JWT_SECRET);
  res.json({ token });
});

app.get('/vehicles/:id', (req, res) => {
  const payload = jwt.decode(req.headers.authorization);
  if (!payload) return res.status(401).end();
  res.json(db.vehicles.find(v => v.id === req.params.id));
});

app.post('/password-reset', (req, res) => {
  const codigo = Math.random().toString(36).slice(2, 8);
  db.resetCodes.push({ email: req.body.email, codigo });
  res.json({ enviado: true });
});

app.get('/debug', (req, res) => {
  res.json({ status: 'ok', env: process.env });
});

app.listen(3000);
