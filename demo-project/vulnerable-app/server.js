// Vulnerable Express App
const express = require('express');
const mysql = require('mysql');
const app = express();

// ❌ 硬编码数据库连接
const db = mysql.createConnection({
    host: 'localhost',
    user: 'admin',
    password: 'admin123',
    database: 'users'
});

// ❌ SQL注入
app.get('/user/:id', (req, res) => {
    const query = `SELECT * FROM users WHERE id = ${req.params.id}`;
    db.query(query, (err, results) => {
        res.json(results);
    });
});

// ❌ 命令注入
app.get('/ping/:host', (req, res) => {
    const { exec } = require('child_process');
    exec(`ping -c 1 ${req.params.host}`, (err, stdout) => {
        res.send(stdout);
    });
});

// ❌ XSS
app.get('/greet', (req, res) => {
    res.send(`<h1>Hello ${req.query.name}</h1>`);
});

// ❌ 不安全的文件访问
app.get('/file/:name', (req, res) => {
    const fs = require('fs');
    fs.readFile(`/data/${req.params.name}`, 'utf8', (err, data) => {
        res.send(data);
    });
});

// ❌ JWT硬编码密钥
const jwt = require('jsonwebtoken');
const SECRET = 'hardcoded-jwt-secret-123';
app.post('/login', (req, res) => {
    const token = jwt.sign({ user: 'admin' }, SECRET);
    res.json({ token });
});

app.listen(3000);
