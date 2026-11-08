const express = require('express');
const mysql = require('mysql2');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
require('dotenv').config();
const app = express();


app.use(cors());
app.use(express.json()); 


const db = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    port: process.env.DB_PORT,
    ssl: { rejectUnauthorized: false }
});


db.getConnection((err, connection) => {
    if (err) {
        console.error('Erro ao conectar ao banco de dados:', err);
    } else {
        console.log('✅ Conectado ao banco de dados MySQL com sucesso!');
        connection.release();
    }
});

const path = require('path');


app.use(express.static(__dirname)); 


app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// ==========================================
// 5. ROTA DE SERVIÇOS: Buscar catálogo
// ==========================================
app.get('/api/services', (req, res) => {
    
    const sql = 'SELECT id, name, price, duration_mins FROM services';
    
    
    db.query(sql, (err, results) => {
        if (err) {
            console.error('Erro ao buscar serviços:', err);
            
            return res.status(500).json({ erro: 'Erro interno ao buscar serviços' });
        }
        
        
        res.status(200).json(results);
    });
});

// ==========================================
// 6. ROTA DE AUTENTICAÇÃO: Cadastro de Cliente
// ==========================================
app.post('/api/auth/register', async (req, res) => {
    try {
        
        const { name, phone, password } = req.body;

        
        if (!name || !phone || !password) {
            return res.status(400).json({ erro: 'Nome, telefone e senha são obrigatórios.' });
        }

        
        const saltRounds = 10;
        const passwordHash = await bcrypt.hash(password, saltRounds);

        
        const sql = 'INSERT INTO users (name, phone, password_hash, role) VALUES (?, ?, ?, ?)';
        const values = [name, phone, passwordHash, 'client'];

        db.query(sql, values, (err, result) => {
            if (err) {
                
                if (err.code === 'ER_DUP_ENTRY') {
                    return res.status(409).json({ erro: 'Este telefone já está cadastrado.' });
                }
                console.error('Erro ao cadastrar usuário:', err);
                return res.status(500).json({ erro: 'Erro interno no banco de dados.' });
            }

            
            res.status(201).json({ 
                mensagem: 'Usuário cadastrado com sucesso!',
                userId: result.insertId 
            });
        });
    } catch (error) {
        console.error('Erro no servidor:', error);
        res.status(500).json({ erro: 'Erro ao processar o cadastro.' });
    }
});

// ==========================================
// 7. ROTA DE AUTENTICAÇÃO: Login de Cliente
// ==========================================
app.post('/api/auth/login', (req, res) => {
    const { phone, password } = req.body;

    
    const sql = 'SELECT * FROM users WHERE phone = ?';
    db.query(sql, [phone], async (err, results) => {
        if (err) return res.status(500).json({ erro: 'Erro no banco de dados.' });

        
        if (results.length === 0) {
            return res.status(401).json({ erro: 'Telefone ou senha inválidos.' });
        }

        const user = results[0];

        
        const senhaValida = await bcrypt.compare(password, user.password_hash);
        
        if (!senhaValida) {
            return res.status(401).json({ erro: 'Telefone ou senha inválidos.' });
        }

        
        const token = jwt.sign(
            { id: user.id, role: user.role },
            process.env.JWT_SECRET,
            { expiresIn: '7d' } 
        );

        
        res.status(200).json({
            mensagem: 'Login bem-sucedido!',
            token: token,
            user: { 
                id: user.id, 
                name: user.name, 
                role: user.role 
            }
        });
    });
});

// ==========================================
// MIDDLEWARE DE SEGURANÇA (Valida JWT)
// ==========================================
function verificarToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ erro: 'Acesso negado. Token não fornecido.' });
    }

    jwt.verify(token, process.env.JWT_SECRET, (err, userPayload) => {
        if (err) {
            return res.status(403).json({ erro: 'Token inválido ou expirado.' });
        }
        
        
        req.user = userPayload; 
        next(); 
    });
}

// ==========================================
// 8. ROTA DE AGENDAMENTOS (Protegida)
// ==========================================
app.post('/api/appointments', verificarToken, (req, res) => {
    const { service_id, start_time } = req.body;
    
    
    const client_id = req.user.id; 

    if (!service_id || !start_time) {
        return res.status(400).json({ erro: 'Serviço e horário são obrigatórios.' });
    }

    
    const sql = "INSERT INTO appointments (client_id, service_id, start_time, status) VALUES (?, ?, ?, 'scheduled')";
    
    db.query(sql, [client_id, service_id, start_time], (err, result) => {
        if (err) {
            console.error('Erro ao salvar agendamento:', err);
            return res.status(500).json({ erro: 'Erro interno ao salvar agendamento.' });
        }

        res.status(201).json({ 
            mensagem: 'Agendamento confirmado com sucesso!',
            appointmentId: result.insertId
        });
    });
});

// ==========================================
// ROTA: Meus Agendamentos (Visão do Cliente)
// ==========================================
app.get('/api/client/appointments', verificarToken, (req, res) => {
    
    const userId = req.userId; 

    
    const sql = `
        SELECT a.id, a.start_time, s.name as service_name, s.price 
        FROM appointments a
        JOIN services s ON a.service_id = s.id
        WHERE a.client_id = ? AND a.start_time >= CURDATE()
        ORDER BY a.start_time ASC
    `;

    
    db.query(sql, [userId], (err, results) => {
        if (err) return res.status(500).json({ erro: 'Erro ao buscar histórico.' });
        res.status(200).json(results);
    });
});

// ==========================================
// 9. ROTA DO BARBEIRO: Ver Agenda Completa
// ==========================================
app.get('/api/admin/appointments', verificarToken, (req, res) => {
    
    
    if (req.user.role !== 'admin') {
        return res.status(403).json({ erro: 'Acesso negado. Área restrita para barbeiros.' });
    }

    const sql = `
            SELECT 
                a.id, 
                a.service_id, 
                DATE_FORMAT(a.start_time, '%Y-%m-%d %H:%i:%s') AS start_time, 
                u.name AS client_name, 
                s.name AS service_name, 
                s.duration_mins 
            FROM appointments a
            JOIN users u ON a.client_id = u.id
            JOIN services s ON a.service_id = s.id
            ORDER BY a.start_time ASC
        `;

    db.query(sql, (err, results) => {
        if (err) {
            console.error('Erro ao buscar agenda:', err);
            return res.status(500).json({ erro: 'Erro interno ao buscar a agenda do barbeiro.' });
        }
        res.status(200).json(results);
    });
});

// ==========================================
// 10. ROTA DE DISPONIBILIDADE (Horários Livres)
// ==========================================

function gerarHorarios() {
    const horarios = [];
    let hora = 9;   
    let minuto = 0; 

    
    while (hora < 19) {
        let horaFormatada = String(hora).padStart(2, '0');
        let minutoFormatado = String(minuto).padStart(2, '0');
        
        horarios.push(`${horaFormatada}:${minutoFormatado}`);

        minuto += 30; 
        
        if (minuto === 60) {
            minuto = 0;
            hora += 1;
        }
    }
    
    return horarios;
}

// ==========================================
// 10. ROTA DE DISPONIBILIDADE (Horários Livres)
// ==========================================
app.get('/api/availability', verificarToken, (req, res) => {
    const { date } = req.query; 

    if (!date) return res.status(400).json({ erro: 'Data não fornecida.' });

    
    const todosHorarios = gerarHorarios();

    
    const sql = "SELECT start_time FROM appointments WHERE DATE(start_time) = ?";

    db.query(sql, [date], (err, results) => {
        if (err) return res.status(500).json({ erro: 'Erro ao buscar disponibilidade.' });

        
        const horariosOcupados = results.map(ag => {
            const dataObj = new Date(ag.start_time);
            return dataObj.toLocaleTimeString('pt-BR', { hour: '2-digit', minute: '2-digit', timeZone: 'UTC' });
        });

        
        const horariosLivres = todosHorarios.filter(hora => !horariosOcupados.includes(hora));

        res.status(200).json(horariosLivres);
    });
});

// ==========================================
// 11. ROTAS DE GESTÃO (EDITAR E EXCLUIR)
// ==========================================


app.put('/api/admin/appointments/:id', verificarToken, (req, res) => {
        if (req.user.role !== 'admin') return res.status(403).json({ erro: 'Acesso negado.' });
        
        const { service_id, start_time } = req.body;
        
        
        console.log("<-- O BACK-END RECEBEU ESTE START_TIME:", start_time);

        const sql = "UPDATE appointments SET service_id = ?, start_time = ? WHERE id = ?";
        
        db.query(sql, [service_id, start_time, req.params.id], (err, result) => {
            if (err) {
                console.log("<-- ERRO NO SQL:", err);
                return res.status(500).json({ erro: 'Erro ao atualizar agendamento.' });
            }
            console.log("<-- SQL EXECUTADO COM SUCESSO!");
            res.status(200).json({ mensagem: 'Agendamento atualizado com sucesso.' });
        });
    });


app.delete('/api/admin/appointments/:id', verificarToken, (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).json({ erro: 'Acesso negado.' });
    
    const sql = "DELETE FROM appointments WHERE id = ?";
    db.query(sql, [req.params.id], (err, result) => {
        if (err) return res.status(500).json({ erro: 'Erro ao excluir agendamento.' });
        res.status(200).json({ mensagem: 'Agendamento cancelado com sucesso.' });
    });
});


const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`🚀 Servidor rodando na porta ${PORT}`);
});