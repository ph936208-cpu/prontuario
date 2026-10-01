require('dotenv').config();
const path=require('path'),express=require('express'),cors=require('cors'),mysql=require('mysql2/promise'),bcrypt=require('bcryptjs'),jwt=require('jsonwebtoken');
const pool=mysql.createPool(process.env.MYSQL_URL||{host:process.env.DB_HOST||'localhost',port:+(process.env.DB_PORT||3306),user:process.env.DB_USER,password:process.env.DB_PASS,database:process.env.DB_NAME||'proz_center'});
const SECRET=process.env.JWT_SECRET;if(!SECRET){console.error('Defina JWT_SECRET no .env');process.exit(1)}
const app=express();app.use(cors({origin:process.env.ORIGIN||false}));app.use(express.json({limit:'1mb'}));
app.use(express.static(path.join(__dirname,'public')));
const w=f=>(q,s,n)=>f(q,s,n).catch(e=>{console.error(e);s.status(500).json({erro:'erro interno'})});
const auth=(q,s,n)=>{try{q.user=jwt.verify((q.headers.authorization||'').slice(7),SECRET);n()}catch(e){s.status(401).json({erro:'não autorizado'})}};

app.post('/api/login',w(async(q,s)=>{
 const[r]=await pool.query('SELECT * FROM usuarios WHERE login=? AND ativo=1',[String(q.body.u||'').toLowerCase()]);const u=r[0];
 if(!u||!await bcrypt.compare(String(q.body.p||''),u.senha_hash))return s.status(401).json({erro:'inválido'});
 const user={id:u.id,nome:u.nome,reg:u.registro,role:u.perfil};
 s.json({token:jwt.sign(user,SECRET,{expiresIn:'8h'}),user})}));

app.get('/api/prontuarios',auth,w(async(q,s)=>{const[r]=await pool.query('SELECT dados FROM prontuarios ORDER BY criado_em');s.json(r.map(x=>x.dados))}));
app.put('/api/prontuarios/:id',auth,w(async(q,s)=>{
 await pool.query('INSERT INTO prontuarios (id,dados) VALUES (?,?) ON DUPLICATE KEY UPDATE dados=VALUES(dados)',[q.params.id,JSON.stringify({...q.body,id:q.params.id})]);s.json({ok:true})}));
app.get('/api/auditoria',auth,w(async(q,s)=>{const[r]=await pool.query('SELECT dados FROM auditoria ORDER BY id');s.json(r.map(x=>x.dados))}));
app.post('/api/auditoria',auth,w(async(q,s)=>{
 await pool.query('INSERT INTO auditoria (prontuario_id,dados) VALUES (?,?)',[String(q.body.pid||''),JSON.stringify(q.body)]);s.json({ok:true})}));

const SQL=[
`CREATE TABLE IF NOT EXISTS usuarios (id INT AUTO_INCREMENT PRIMARY KEY, login VARCHAR(50) NOT NULL UNIQUE, senha_hash VARCHAR(100) NOT NULL, nome VARCHAR(120) NOT NULL, registro VARCHAR(40) NOT NULL, perfil ENUM('Médico','Técnico') NOT NULL, ativo TINYINT(1) NOT NULL DEFAULT 1, criado_em TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP) CHARACTER SET utf8mb4`,
`CREATE TABLE IF NOT EXISTS prontuarios (id VARCHAR(30) PRIMARY KEY, dados JSON NOT NULL, criado_em TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP, atualizado_em TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP) CHARACTER SET utf8mb4`,
`CREATE TABLE IF NOT EXISTS auditoria (id BIGINT AUTO_INCREMENT PRIMARY KEY, prontuario_id VARCHAR(30) NOT NULL, dados JSON NOT NULL, criado_em TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP, INDEX (prontuario_id)) CHARACTER SET utf8mb4`];
async function init(){
 for(const q of SQL)await pool.query(q);
 const[[{n}]]=await pool.query('SELECT COUNT(*) AS n FROM usuarios');
 if(!n&&process.env.FIRST_USER_PASS){
  await pool.query('INSERT INTO usuarios (login,senha_hash,nome,registro,perfil) VALUES (?,?,?,?,?)',[(process.env.FIRST_USER_LOGIN||'admin').toLowerCase(),bcrypt.hashSync(process.env.FIRST_USER_PASS,10),process.env.FIRST_USER_NAME||'Administrador',process.env.FIRST_USER_REG||'CRM 00000',process.env.FIRST_USER_ROLE||'Médico']);
  console.log('Primeiro usuário criado.')}
}
init().then(()=>app.listen(process.env.PORT||3000,()=>console.log('API PROZ CENTER no ar na porta '+(process.env.PORT||3000)))).catch(e=>{console.error('Erro ao iniciar:',e.message);process.exit(1)});
