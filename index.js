const express = require('express');
const mysql = require('mysql2');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
require('dotenv').config();
const app = express();

// Configurações essenciais para uma API REST
app.use(cors());
app.use(express.json()); // Permite que a API entenda requisições no formato JSON

// 1. Configurando a conexão com o Banco de Dados
const db = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    port: process.env.DB_PORT,
    ssl: { rejectUnauthorized: false }
});

// 2. Testando se o banco conectou
db.getConnection((err, connection) => {
    if (err) {
        console.error('Erro ao conectar ao banco de dados:', err);
    } else {
        console.log('✅ Conectado ao banco de dados MySQL com sucesso!');
        connection.release();
    }
});

// 3. Rota de Teste (Endpoint base)
app.get('/', (req, res) => {
    res.status(200).json({ mensagem: 'API da Barbearia rodando perfeitamente!' });
});

// ==========================================
// 5. ROTA DE SERVIÇOS: Buscar catálogo
// ==========================================
app.get('/api/services', (req, res) => {
    // Comando SQL que será executado no banco
    const sql = 'SELECT id, name, price, duration_mins FROM services';
    
    // Executando a query
    db.query(sql, (err, results) => {
        if (err) {
            console.error('Erro ao buscar serviços:', err);
            // Retorna status 500 (Erro de Servidor) caso algo dê errado no banco
            return res.status(500).json({ erro: 'Erro interno ao buscar serviços' });
        }
        
        // Retorna status 200 (OK) e a lista de serviços em JSON
        res.status(200).json(results);
    });
});

// ==========================================
// 6. ROTA DE AUTENTICAÇÃO: Cadastro de Cliente
// ==========================================
app.post('/api/auth/register', async (req, res) => {
    try {
        // Extrai os dados que o front-end vai enviar no formato JSON
        const { name, phone, password } = req.body;

        // 1. Validação básica (não deixa cadastrar vazio)
        if (!name || !phone || !password) {
            return res.status(400).json({ erro: 'Nome, telefone e senha são obrigatórios.' });
        }

        // 2. Criar o Hash da senha com "Salt" de 10 rounds
        const saltRounds = 10;
        const passwordHash = await bcrypt.hash(password, saltRounds);

        // 3. Salvar no Banco de Dados (Os '?' evitam ataques de SQL Injection)
        const sql = 'INSERT INTO users (name, phone, password_hash, role) VALUES (?, ?, ?, ?)';
        const values = [name, phone, passwordHash, 'client'];

        db.query(sql, values, (err, result) => {
            if (err) {
                // Erro 1062 no MySQL: O UNIQUE do telefone foi acionado
                if (err.code === 'ER_DUP_ENTRY') {
                    return res.status(409).json({ erro: 'Este telefone já está cadastrado.' });
                }
                console.error('Erro ao cadastrar usuário:', err);
                return res.status(500).json({ erro: 'Erro interno no banco de dados.' });
            }

            // 201 Created: Código HTTP correto para quando criamos algo novo
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

    // 1. Busca o usuário no banco pelo telefone
    const sql = 'SELECT * FROM users WHERE phone = ?';
    db.query(sql, [phone], async (err, results) => {
        if (err) return res.status(500).json({ erro: 'Erro no banco de dados.' });

        // Se o array voltar vazio, o telefone não existe
        if (results.length === 0) {
            return res.status(401).json({ erro: 'Telefone ou senha inválidos.' });
        }

        const user = results[0];

        // 2. Compara a senha digitada com o Hash salvo no banco
        const senhaValida = await bcrypt.compare(password, user.password_hash);
        
        if (!senhaValida) {
            return res.status(401).json({ erro: 'Telefone ou senha inválidos.' });
        }

        // 3. Gera o Token JWT (O 'payload' carrega o id e a role do usuário)
        const token = jwt.sign(
            { id: user.id, role: user.role },
            process.env.JWT_SECRET,
            { expiresIn: '7d' } // O cliente fica logado por 7 dias
        );

        // 4. Devolve o token e os dados para o front-end
        res.status(200).json({
            mensagem: 'Login bem-sucedido!',
            token: token,
            user: { 
                id: user.id, 
                name: user.name, 
                role: user.role // <--- ADICIONE ESTA LINHA AQUI
            }
        });
    });
});

// ==========================================
// MIDDLEWARE DE SEGURANÇA (Valida JWT)
// ==========================================
function verificarToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    // O padrão HTTP envia o token como: "Bearer eyJhbGciOi..."
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ erro: 'Acesso negado. Token não fornecido.' });
    }

    jwt.verify(token, process.env.JWT_SECRET, (err, userPayload) => {
        if (err) {
            return res.status(403).json({ erro: 'Token inválido ou expirado.' });
        }
        // Se o token for válido, guardamos os dados do usuário na requisição
        // O userPayload contém o { id, role } que gravamos na hora do login
        req.user = userPayload; 
        next(); // Permite que a requisição continue para a rota final
    });
}

// ==========================================
// 8. ROTA DE AGENDAMENTOS (Protegida)
// ==========================================
app.post('/api/appointments', verificarToken, (req, res) => {
    const { service_id, start_time } = req.body;
    
    // Pegamos o ID do cliente diretamente do token validado (Super seguro!)
    const client_id = req.user.id; 

    if (!service_id || !start_time) {
        return res.status(400).json({ erro: 'Serviço e horário são obrigatórios.' });
    }

    // Insere no banco com status padrão 'scheduled'
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
// 9. ROTA DO BARBEIRO: Ver Agenda Completa
// ==========================================
app.get('/api/admin/appointments', verificarToken, (req, res) => {
    
    // A FECHADURA DE SEGURANÇA: Só passa se o perfil for 'admin'
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
app.get('/api/availability', verificarToken, (req, res) => {
    const { date } = req.query; // Pega a data que o Front-end enviou

    if (!date) return res.status(400).json({ erro: 'Data não fornecida.' });

    // Todos os horários que a barbearia atende num dia normal
    const todosHorarios = ['09:00', '09:45', '10:30', '11:15', '14:00', '14:45', '15:30', '16:15'];

    // O comando SQL DATE() ignora as horas e compara apenas o dia/mês/ano
    const sql = "SELECT start_time FROM appointments WHERE DATE(start_time) = ?";

    db.query(sql, [date], (err, results) => {
        if (err) return res.status(500).json({ erro: 'Erro ao buscar disponibilidade.' });

        // Extrai as horas que já estão gravadas no banco (ex: ['14:00', '09:45'])
        const horariosOcupados = results.map(ag => {
            const dataObj = new Date(ag.start_time);
            return dataObj.toLocaleTimeString('pt-BR', { hour: '2-digit', minute: '2-digit', timeZone: 'UTC' });
        });

        // A MÁGICA: Filtra os horários mantendo apenas aqueles que NÃO estão ocupados
        const horariosLivres = todosHorarios.filter(hora => !horariosOcupados.includes(hora));

        res.status(200).json(horariosLivres);
    });
});

// ==========================================
// 11. ROTAS DE GESTÃO (EDITAR E EXCLUIR)
// ==========================================

// Atualizar Agendamento (PUT)
app.put('/api/admin/appointments/:id', verificarToken, (req, res) => {
        if (req.user.role !== 'admin') return res.status(403).json({ erro: 'Acesso negado.' });
        
        const { service_id, start_time } = req.body;
        
        // O RASTREIO DO BACK-END
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

// Cancelar/Excluir Agendamento (DELETE)
app.delete('/api/admin/appointments/:id', verificarToken, (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).json({ erro: 'Acesso negado.' });
    
    const sql = "DELETE FROM appointments WHERE id = ?";
    db.query(sql, [req.params.id], (err, result) => {
        if (err) return res.status(500).json({ erro: 'Erro ao excluir agendamento.' });
        res.status(200).json({ mensagem: 'Agendamento cancelado com sucesso.' });
    });
});

// 4. Ligando o servidor
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`🚀 Servidor rodando na porta ${PORT}`);
});