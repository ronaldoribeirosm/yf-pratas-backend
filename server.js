const express = require('express');
const cors = require('cors');
const pool = require('./db');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const nodemailer = require('nodemailer');
const { MercadoPagoConfig, Preference } = require('mercadopago');
const { calcularPrecoPrazo } = require('correios-brasil');

// Carrega variáveis do .env
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;
const BACKEND_URL = process.env.BACKEND_URL || 'https://yf-pratas-backend.onrender.com';

// --- DEFINIÇÃO DA URL DO FRONTEND (PRODUÇÃO VS LOCAL) ---
// Em produção (Hospedagem), defina FRONTEND_URL no .env com o link do seu site (sem barra no final)
// Em teste local, ele assume localhost:5173
const FRONTEND_URL = process.env.FRONTEND_URL || "http://localhost:5173";

// --- SEGURANÇA E CONFIGURAÇÕES ---
const JWT_SECRET = process.env.JWT_SECRET || 'chave_mestra_yf_pratas_seguranca_total';

// Mercado Pago
const client = new MercadoPagoConfig({ accessToken: process.env.MP_ACCESS_TOKEN });

// Email (Nodemailer)
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});

app.use(cors());
app.use(express.json());

// --- UPLOAD ---
app.use('/uploads', express.static('uploads'));
if (!fs.existsSync('./uploads')) fs.mkdirSync('./uploads');

const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, 'uploads/'),
    filename: (req, file, cb) => cb(null, Date.now() + path.extname(file.originalname))
});
const upload = multer({ storage: storage });

// --- MIDDLEWARE DE AUTENTICAÇÃO ---
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.sendStatus(401);

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
}

// --- ROTA SAÚDE ---
app.get('/', async (req, res) => {
    try {
        const result = await pool.query('SELECT NOW()');
        res.json({ message: 'API YF Pratas: Online!', time: result.rows[0].now, env: process.env.NODE_ENV });
    } catch (err) { res.status(500).json({ error: 'Erro no banco de dados' }); }
});

// ==========================================
//              AUTENTICAÇÃO
// ==========================================

app.post('/auth/register', async (req, res) => {
    const { nome, email, password } = req.body;
    try {
        const userCheck = await pool.query('SELECT * FROM usuarios WHERE email = $1', [email]);
        if (userCheck.rows.length > 0) return res.status(400).json({ error: 'Email já cadastrado.' });

        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);
        const count = await pool.query('SELECT COUNT(*) FROM usuarios');
        const isAdmin = count.rows[0].count === '0';

        const newUser = await pool.query(
            'INSERT INTO usuarios (nome, email, senha, is_admin) VALUES ($1, $2, $3, $4) RETURNING id, nome, email, is_admin',
            [nome, email, hashedPassword, isAdmin]
        );
        res.json({ message: 'Criado com sucesso!', user: newUser.rows[0] });
    } catch (err) { res.status(500).json({ error: 'Erro no cadastro' }); }
});

app.post('/auth/login', async (req, res) => {
    const { email, password, code } = req.body; 
    try {
        const userResult = await pool.query('SELECT * FROM usuarios WHERE email = $1', [email]);
        const user = userResult.rows[0];
        if (!user) return res.status(400).json({ error: 'Usuário não encontrado.' });

        const validPassword = await bcrypt.compare(password, user.senha);
        if (!validPassword) return res.status(400).json({ error: 'Senha incorreta.' });

        // LÓGICA 2FA COMPLETA
        if (user.two_factor_enabled) {
            // Se não enviou código, gera e envia por e-mail
            if (!code) {
                const newCode = Math.floor(100000 + Math.random() * 900000).toString();
                // Expira em 10 minutos
                await pool.query(`UPDATE usuarios SET email_code = $1, email_code_expires = NOW() + INTERVAL '10 minutes' WHERE id = $2`, [newCode, user.id]);
                
                try {
                    await transporter.sendMail({
                        from: `YF Pratas <${process.env.EMAIL_USER}>`,
                        to: email,
                        subject: 'Seu Código de Acesso',
                        text: `Seu código de verificação é: ${newCode} (Válido por 10 min)`
                    });
                } catch (e) { console.error("Erro ao enviar email", e); }
                
                return res.json({ require2fa: true, message: 'Código enviado para seu e-mail.' }); 
            }

            // Verifica código
            if (user.email_code !== code) {
                return res.status(400).json({ error: 'Código inválido.' });
            }

            // Verifica expiração
            const agora = new Date();
            const validade = new Date(user.email_code_expires);
            if (agora > validade) {
                return res.status(400).json({ error: 'Código expirado. Faça login novamente.' });
            }

            // Limpa código após uso
            await pool.query(`UPDATE usuarios SET email_code = NULL WHERE id = $1`, [user.id]);
        }

        const token = jwt.sign({ id: user.id, is_admin: user.is_admin }, JWT_SECRET, { expiresIn: '1d' });
        res.json({ 
            message: 'Login OK', 
            token, 
            user: { id: user.id, nome: user.nome, email: user.email, is_admin: user.is_admin, two_factor_enabled: user.two_factor_enabled } 
        });
    } catch (err) { console.error(err); res.status(500).json({ error: 'Erro no login' }); }
});

app.post('/auth/2fa/enable', async (req, res) => {
    const { email } = req.body;
    try {
        await pool.query('UPDATE usuarios SET two_factor_enabled = TRUE WHERE email = $1', [email]);
        res.json({ message: 'Autenticação de dois fatores ativada!' });
    } catch (err) { res.status(500).json({ error: 'Erro ao ativar 2FA' }); }
});

// ==========================================
//              PRODUTOS
// ==========================================

aapp.get('/produtos', async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM produtos ORDER BY id ASC');
        res.json(result.rows);
    } catch (err) { res.status(500).json({ error: 'Erro ao buscar produtos' }); }
});

app.get('/produtos/categoria/:tipo', async (req, res) => {
    const { tipo } = req.params;
    try {
        const result = await pool.query('SELECT * FROM produtos WHERE categoria ILIKE $1', [`%${tipo}%`]);
        res.json(result.rows);
    } catch (err) { console.error(err); res.status(500).json({ error: 'Erro no servidor' }); }
});

app.get('/produtos/:id', async (req, res) => {
    const { id } = req.params;
    try {
        const result = await pool.query('SELECT * FROM produtos WHERE id = $1', [id]);
        if (result.rows.length === 0) return res.status(404).json({ error: 'Produto não encontrado' });
        res.json(result.rows[0]);
    } catch (err) { res.status(500).json({ error: 'Erro no servidor' }); }
});

app.post('/produtos', upload.single('imagem'), async (req, res) => {
    const { nome, descricao, preco, categoria, estoque } = req.body;
    
    // 🚀 CORREÇÃO: Agora salva com o link do Render e não mais localhost!
    let img = req.file ? `${BACKEND_URL}/uploads/${req.file.filename}` : 'https://via.placeholder.com/150';
    
    try {
        const newP = await pool.query('INSERT INTO produtos (nome, descricao, preco, categoria, imagem_url, estoque) VALUES ($1, $2, $3, $4, $5, $6) RETURNING *', [nome, descricao, parseFloat(preco), categoria, img, parseInt(estoque)]);
        res.json(newP.rows[0]);
    } catch (e) { res.status(500).json({ error: 'Erro ao criar produto' }); }
});

app.put('/produtos/:id', upload.single('imagem'), async (req, res) => {
    const { id } = req.params;
    const { nome, descricao, preco, categoria, estoque } = req.body;
    try {
        const old = await pool.query('SELECT * FROM produtos WHERE id = $1', [id]);
        if (old.rows.length === 0) return res.status(404).json({ error: 'Não encontrado' });
        
        let img = old.rows[0].imagem_url;
        
        // 🚀 CORREÇÃO: Atualiza com o link do Render se enviar imagem nova!
        if (req.file) img = `${BACKEND_URL}/uploads/${req.file.filename}`;

        const up = await pool.query('UPDATE produtos SET nome=$1, descricao=$2, preco=$3, categoria=$4, estoque=$5, imagem_url=$6 WHERE id=$7 RETURNING *', [nome, descricao, parseFloat(preco), categoria, parseInt(estoque), img, id]);
        res.json(up.rows[0]);
    } catch (e) { res.status(500).json({ error: 'Erro ao editar produto' }); }
});

app.delete('/produtos/:id', async (req, res) => {
    const { id } = req.params;
    try {
        const result = await pool.query('DELETE FROM produtos WHERE id = $1 RETURNING *', [id]);
        if (result.rowCount === 0) return res.status(404).json({ error: 'Produto não encontrado' });
        res.json({ message: 'Produto deletado com sucesso!', produto: result.rows[0] });
    } catch (e) { res.status(500).json({ error: 'Erro ao deletar' }); }
});
// ==========================================
//              CARRINHO
// ==========================================

app.post('/carrinho', authenticateToken, async (req, res) => {
    const { produto_id, quantidade } = req.body;
    try {
        const check = await pool.query('SELECT * FROM carrinho_itens WHERE usuario_id = $1 AND produto_id = $2', [req.user.id, produto_id]);
        if (check.rows.length > 0) {
            await pool.query('UPDATE carrinho_itens SET quantidade = quantidade + $1 WHERE id = $2', [quantidade, check.rows[0].id]);
        } else {
            await pool.query('INSERT INTO carrinho_itens (usuario_id, produto_id, quantidade) VALUES ($1, $2, $3)', [req.user.id, produto_id, quantidade]);
        }
        res.json({ message: 'Adicionado ao carrinho' });
    } catch (e) { res.status(500).json({ error: 'Erro no carrinho' }); }
});

app.get('/carrinho', authenticateToken, async (req, res) => {
    try {
        const r = await pool.query('SELECT c.id, c.quantidade, p.id as produto_id, p.nome, p.preco, p.imagem_url FROM carrinho_itens c JOIN produtos p ON c.produto_id = p.id WHERE c.usuario_id = $1 ORDER BY c.criado_em ASC', [req.user.id]);
        res.json(r.rows);
    } catch (e) { res.status(500).json({ error: 'Erro no carrinho' }); }
});

app.delete('/carrinho/:pid', authenticateToken, async (req, res) => {
    try {
        await pool.query('DELETE FROM carrinho_itens WHERE usuario_id = $1 AND produto_id = $2', [req.user.id, req.params.pid]);
        res.json({ message: 'Item removido' });
    } catch (e) { res.status(500).json({ error: 'Erro ao remover' }); }
});

// ==========================================
//           FRETE E PAGAMENTO
// ==========================================

// Rota antiga mantida por compatibilidade (se o frontend usar)
app.post('/create-preference', authenticateToken, async (req, res) => {
    return res.status(400).json({ message: "Utilize a rota /pedidos para gerar o pagamento" });
});

app.post('/calcular-frete', async (req, res) => {
    const { cepDestino, estadoDestino } = req.body;
    if (!cepDestino) return res.status(400).json({ error: 'CEP obrigatório' });

    // Configuração Correios
    const args = { sCepOrigem: '12460000', sCepDestino: cepDestino.replace(/\D/g, ''), nVlPeso: '0.3', nCdFormato: '1', nVlComprimento: '16', nVlAltura: '4', nVlLargura: '11', nCdServico: ['04014', '04510'], nVlDiametro: '0' };

    try {
        // Tenta Correios com Timeout de 4s
        const timeoutPromise = new Promise((_, reject) => setTimeout(() => reject(new Error('Timeout Correios')), 4000));
        const response = await Promise.race([calcularPrecoPrazo(args), timeoutPromise]);
        
        const opcoes = response.map(item => ({ 
            tipo: item.Codigo === '04014' ? 'SEDEX' : 'PAC', 
            valor: parseFloat(item.Valor.replace(',', '.')), 
            prazo: item.PrazoEntrega, 
            erro: item.Erro !== '0' 
        })).filter(i => !i.erro);
        
        if (opcoes.length === 0) throw new Error("Sem opções dos Correios");
        
        res.json(opcoes);

    } catch (error) {
        console.log("⚠️ Falha Correios/Timeout. Usando Tabela de Estado:", error.message);
        
        // --- LÓGICA MANUAL DE CONTINGÊNCIA (RESTAURADA) ---
        let valor = 35.00, prazo = '7-10';
        if (estadoDestino) {
            const uf = estadoDestino.toUpperCase();
            if (uf === 'SP') { valor = 22.00; prazo = '2-4'; }
            else if (['RJ', 'MG', 'ES'].includes(uf)) { valor = 28.00; prazo = '4-6'; }
            else if (['PR', 'SC', 'RS'].includes(uf)) { valor = 32.00; prazo = '5-8'; }
            else if (['DF', 'GO', 'MS', 'MT'].includes(uf)) { valor = 45.00; prazo = '6-9'; }
            else if (['BA', 'SE', 'AL', 'PE', 'PB', 'RN', 'CE', 'PI', 'MA'].includes(uf)) { valor = 58.00; prazo = '8-15'; }
            else { valor = 75.00; prazo = '10-20'; } // Norte
        }
        res.json([{ tipo: 'Envio Segurado (Transportadora)', valor, prazo }]);
    }
});

// ✅ ROTA PRINCIPAL DE PEDIDOS (REDIRECT + PIX + DÉBITO)
app.post('/pedidos', authenticateToken, async (req, res) => {
    const { dados_cliente, endereco, itens, frete, prazo } = req.body;
    try {
        console.log("--- 🏁 CRIANDO PREFERÊNCIA DE PAGAMENTO (REDIRECT) 🏁 ---");
        console.log("🔗 URL Base para Retorno:", FRONTEND_URL);

        // 1. Prepara Itens para o Mercado Pago
        const itemsMP = itens.map(i => ({ 
            title: i.nome, 
            quantity: Number(i.quantity), 
            currency_id: 'BRL', 
            unit_price: Number(i.preco) 
        }));
        
        if (frete > 0) {
            itemsMP.push({ title: "Frete / Envio", quantity: 1, currency_id: 'BRL', unit_price: Number(frete) });
        }

        const preference = new Preference(client);
        
        // Dados do Pagador (Importante para antifraude)
        const payerInfo = { 
            name: dados_cliente.nome, 
            email: dados_cliente.email,
            identification: { 
                type: "CPF", 
                number: dados_cliente.cpf ? dados_cliente.cpf.replace(/\D/g, '') : "00000000000"
            }
        };
        
        // --- CRIAÇÃO DA PREFERÊNCIA CHECKOUT PRO ---
        const bodyPreference = { 
            items: itemsMP, 
            payer: payerInfo,
            
            // Configurações de Retorno (Usando a variável FRONTEND_URL)
            back_urls: { 
                success: `${FRONTEND_URL}/sucesso`, 
                failure: `${FRONTEND_URL}/`, 
                pending: `${FRONTEND_URL}/` 
            }, 
            auto_return: "approved", 
            
            // Permite todos os métodos (PIX, Boleto, Cartão)
            payment_methods: {
                excluded_payment_types: [], 
                excluded_payment_methods: [],
                installments: 12
            },
            
            external_reference: String(req.user.id),
            statement_descriptor: "YF PRATAS"
        };

        const result = await preference.create({ body: bodyPreference });
        
        const prefId = result.id;
        const linkPagamento = result.init_point; // Link para redirecionar o usuário
        
        console.log("✅ Preferência criada com sucesso! ID:", prefId);

        // 2. Salva o Pedido no Banco de Dados
        const itensHist = itens.map(i => ({ nome: i.nome, quantity: i.quantity, preco: i.preco }));
        const detalhes = { valor: frete, prazo: prazo || 'A definir', transportadora: 'Correios' };
        const total = itemsMP.reduce((acc, i) => acc + (i.unit_price * i.quantity), 0);

        const newOrder = await pool.query(
            `INSERT INTO pedidos (usuario_id, total, dados_cliente, endereco_entrega, preference_id, status, itens, detalhes_envio) VALUES ($1, $2, $3, $4, $5, 'pendente', $6, $7) RETURNING id`,
            [req.user.id, total, JSON.stringify(dados_cliente), JSON.stringify(endereco), prefId, JSON.stringify(itensHist), JSON.stringify(detalhes)]
        );
        
        // Retorna o LINK para o frontend redirecionar
        res.json({ id: prefId, pedido_id: newOrder.rows[0].id, url: linkPagamento });

    } catch (e) { 
        console.error("❌ Erro ao criar pedido:", e); 
        res.status(500).json({ error: "Erro ao processar pedido no servidor." }); 
    }
});

// ==========================================
//          ÁREA DO CLIENTE & ADMIN
// ==========================================

app.get('/meus-pedidos', authenticateToken, async (req, res) => {
    try {
        const r = await pool.query('SELECT * FROM pedidos WHERE usuario_id = $1 ORDER BY criado_em DESC', [req.user.id]);
        res.json(r.rows);
    } catch (e) { res.status(500).json({ error: 'Erro ao buscar pedidos' }); }
});

app.get('/admin/pedidos', authenticateToken, async (req, res) => {
    try {
        const check = await pool.query('SELECT is_admin FROM usuarios WHERE id = $1', [req.user.id]);
        if (!check.rows.length || !check.rows[0].is_admin) return res.status(403).json({ error: 'Acesso negado' });
        
        const r = await pool.query('SELECT * FROM pedidos ORDER BY id DESC');
        res.json(r.rows);
    } catch (e) { res.status(500).json({ error: 'Erro ao buscar pedidos (admin)' }); }
});

// Admin: Atualizar status e código de rastreio
app.put('/admin/pedidos/:id/status', authenticateToken, async (req, res) => {
    const { id } = req.params;
    const { status, codigo_rastreio } = req.body;

    try {
        const check = await pool.query('SELECT is_admin FROM usuarios WHERE id = $1', [req.user.id]);
        if (!check.rows[0].is_admin) return res.sendStatus(403);

        if (codigo_rastreio) {
            await pool.query('UPDATE pedidos SET status = $1, codigo_rastreio = $2 WHERE id = $3', [status, codigo_rastreio, id]);
        } else {
            await pool.query('UPDATE pedidos SET status = $1 WHERE id = $2', [status, id]);
        }
        res.json({ message: 'Status atualizado!' });
    } catch (e) { res.status(500).json({ error: 'Erro ao atualizar pedido' }); }
});

// --- VERIFICAÇÃO DE PAGAMENTO (WEBHOOK) ---
app.post('/verificar-pagamento', async (req, res) => {
    const { payment_id, preference_id } = req.body;
    try {
        const payment = await fetch(`https://api.mercadopago.com/v1/payments/${payment_id}`, { headers: { 'Authorization': `Bearer ${process.env.MP_ACCESS_TOKEN}` } }).then(r => r.json());
        
        if (payment.status === 'approved') {
            await pool.query(`UPDATE pedidos SET status = 'pago' WHERE preference_id = $1`, [preference_id]);
            return res.json({ status: 'approved' });
        }
        res.json({ status: payment.status });
    } catch (e) { 
        console.error("Erro no webhook:", e);
        res.status(500).json({ error: "Erro ao verificar pagamento" }); 
    }
});

app.listen(PORT, () => console.log(`🚀 Servidor rodando na porta ${PORT} | Front: ${FRONTEND_URL}`));