require('dotenv').config();
const express=require('express'),mysql=require('mysql2/promise'),bcrypt=require('bcryptjs'),jwt=require('jsonwebtoken'),crypto=require('crypto'),helmet=require('helmet'),rateLimit=require('express-rate-limit');
const {DB_HOST,DB_USER,DB_PASS,DB_NAME,JWT_SECRET,PAYMONGO_SECRET_KEY:SK,PAYMONGO_PUBLIC_KEY:PK,PAYMONGO_WEBHOOK_SECRET:WH}=process.env;
const MISSING=['DB_HOST','DB_USER','DB_PASS','DB_NAME'].filter(k=>!process.env[k]);if(!JWT_SECRET||JWT_SECRET.length<32)MISSING.push('JWT_SECRET (32+ chars)');
const db=mysql.createPool({host:DB_HOST,user:DB_USER,password:DB_PASS,database:DB_NAME,port:+process.env.DB_PORT||3306,ssl:process.env.DB_SSL==='false'?undefined:{minVersion:'TLSv1.2',rejectUnauthorized:true},connectionLimit:3,decimalNumbers:true,timezone:'Z'});
const app=express();app.set('trust proxy',1);
app.use(helmet({contentSecurityPolicy:{useDefaults:true,directives:{'script-src-attr':["'unsafe-inline'"],'img-src':["'self'",'data:','https:']}}}));

app.use('/api',(q,r,n)=>MISSING.length?r.status(503).json({error:'Server not configured. Missing: '+MISSING.join(', ')}):n());
const bad=(m,s=400)=>Object.assign(new Error(m),{status:s});
const A=f=>(q,r,n)=>f(q,r,n).catch(e=>{if(!e.status)console.error(e);r.status(e.status||500).json({error:e.status?e.message:'Server error'})});
const auth=(...roles)=>(q,r,n)=>{try{q.user=jwt.verify((q.headers.authorization||'').replace('Bearer ',''),JWT_SECRET)}catch{return r.status(401).json({error:'Please sign in'})}
  if(roles.length&&!roles.includes(q.user.role))return r.status(403).json({error:'Not allowed'});n()};
const optAuth=(q,_,n)=>{try{q.user=jwt.verify((q.headers.authorization||'').replace('Bearer ',''),JWT_SECRET)}catch{}n()};
const lim=(m,max)=>rateLimit({windowMs:m*60000,max,standardHeaders:true,legacyHeaders:false});
const STAFF=['cashier','kitchen','admin'];

/* ---------- PayMongo ---------- */
async function pm(path,attrs,key){
  const r=await fetch('https://api.paymongo.com/v1'+path,{method:attrs?'POST':'GET',headers:{'Content-Type':'application/json',Authorization:'Basic '+Buffer.from(key+':').toString('base64')},body:attrs?JSON.stringify({data:{attributes:attrs}}):undefined});
  const j=await r.json().catch(()=>({}));
  if(!r.ok)throw bad(j.errors?.[0]?.detail||'PayMongo request failed',502);
  return j.data;
}
function sigOk(raw,header){
  const p=Object.fromEntries((header||'').split(',').map(s=>s.split('=')));
  if(!p.t||Math.abs(Date.now()/1000-Number(p.t))>600)return false;
  const mac=crypto.createHmac('sha256',WH).update(`${p.t}.${raw}`).digest('hex');
  const got=(SK||'').startsWith('sk_live')?p.li:p.te;
  return !!got&&got.length===mac.length&&crypto.timingSafeEqual(Buffer.from(got),Buffer.from(mac));
}
/* Idempotent: row lock + paid check + unique pm_payment_id => a payment can never be applied twice */
async function markPaid(id,payId,centavos,method){
  const c=await db.getConnection();
  try{await c.beginTransaction();
    const [[o]]=await c.query('SELECT * FROM orders WHERE id=? FOR UPDATE',[id]);
    if(!o||o.payment_status==='paid'||o.status==='cancelled'){await c.rollback();return false}
    if(centavos!=null&&Math.round(o.total*100)!==centavos){await c.rollback();console.error('Amount mismatch on',o.order_no);return false}
    await c.query("UPDATE orders SET payment_status='paid',payment_method=?,pm_payment_id=?,paid_at=UTC_TIMESTAMP() WHERE id=?",[method,payId||null,id]);
    await c.query('UPDATE products p JOIN order_items i ON i.product_id=p.id SET p.stock=GREATEST(p.stock-i.qty,0) WHERE i.order_id=?',[id]);
    await c.commit();return true;
  }catch(e){await c.rollback();throw e}finally{c.release()}
}
/* Webhook needs the raw body, so it is registered before express.json() */
app.post('/api/webhooks/paymongo',express.raw({type:'*/*',limit:'1mb'}),A(async(q,r)=>{
  const buf=Buffer.isBuffer(q.body)?q.body:null;
  if(buf&&(!WH||!sigOk(buf.toString('utf8'),q.headers['paymongo-signature'])))return r.status(401).end();
  const ev=(buf?JSON.parse(buf.toString('utf8')):q.body)?.data?.attributes;
  if(ev?.type==='payment.paid'){
    const intent=ev.data?.attributes?.payment_intent_id;
    const [[o]]=await db.query('SELECT id FROM orders WHERE pm_intent_id=?',[intent]);
    if(o){/* never trust the payload alone: confirm the payment with PayMongo's API */
      const it=await pm('/payment_intents/'+intent,null,SK);
      if(it.attributes.status==='succeeded')await markPaid(o.id,it.attributes.payments?.[0]?.id||ev.data.id,it.attributes.amount,'qrph');
    }
  }
  r.json({ok:true});
}));
app.use(express.json({limit:'100kb'}));
app.use(express.static('public'));

/* ---------- Auth ---------- */
app.use('/api/auth',lim(15,30));
app.post('/api/auth/register',A(async(q,r)=>{
  const {name,email,password}=q.body;
  if(!name?.trim()||!/^\S+@\S+\.\S+$/.test(email||'')||(password||'').length<8)throw bad('Enter a name, valid email and a password of 8+ characters');
  try{await db.query("INSERT INTO users(name,email,password_hash,role) VALUES(?,?,?,'customer')",[name.trim().slice(0,100),email.toLowerCase(),await bcrypt.hash(password,12)])}
  catch(e){throw e.code==='ER_DUP_ENTRY'?bad('Email already registered'):e}
  r.json({ok:true});
}));
app.post('/api/auth/login',A(async(q,r)=>{
  const [[u]]=await db.query('SELECT * FROM users WHERE email=? AND active=1',[String(q.body.email||'').toLowerCase()]);
  if(!u||!(await bcrypt.compare(String(q.body.password||''),u.password_hash)))throw bad('Wrong email or password',401);
  const user={id:u.id,name:u.name,role:u.role};
  r.json({token:jwt.sign(user,JWT_SECRET,{expiresIn:'12h'}),user});
}));

/* ---------- Public menu & orders ---------- */
app.get('/api/menu',A(async(q,r)=>{
  const [categories]=await db.query('SELECT * FROM categories ORDER BY name');
  const [products]=await db.query('SELECT id,category_id,name,description,price,image_url,stock FROM products WHERE active=1 ORDER BY name');
  r.json({categories,products});
}));
const getOrder=no=>db.query('SELECT *,qr_expires_at>UTC_TIMESTAMP() AS qr_valid FROM orders WHERE order_no=?',[no]).then(([x])=>x[0]);
async function pub(o){
  const [items]=await db.query('SELECT name,price,qty FROM order_items WHERE order_id=?',[o.id]);
  const {order_no,customer_name,type,status,payment_status,payment_method,total,paid_at,created_at}=o;
  return {order_no,customer_name,type,status,payment_status,payment_method,total,paid_at,created_at,items};
}
app.post('/api/orders',lim(1,20),optAuth,A(async(q,r)=>{
  const {items,type,name}=q.body;
  if(!Array.isArray(items)||!items.length||items.length>50||!['dine-in','takeout'].includes(type))throw bad('Invalid order');
  const pos=q.body.source==='pos'&&['cashier','admin'].includes(q.user?.role);
  const qty={};for(const i of items){const n=parseInt(i.qty);if(!(n>=1&&n<=20))throw bad('Invalid quantity');qty[+i.id]=(qty[+i.id]||0)+n}
  const ids=Object.keys(qty).map(Number);
  const [ps]=await db.query('SELECT * FROM products WHERE active=1 AND id IN (?)',[ids]);
  if(ps.length!==ids.length)throw bad('An item is no longer available');
  let total=0;for(const p of ps){if(p.stock<qty[p.id])throw bad(`Only ${p.stock} left of ${p.name}`);total+=p.price*qty[p.id]}
  total=Math.round(total*100)/100;
  if(total<20)throw bad('Minimum online payment is ₱20.00');
  const orderNo='CM-'+crypto.randomBytes(4).toString('hex').toUpperCase();
  const cname=(name||q.user?.name||'Guest').toString().trim().slice(0,100)||'Guest';
  const c=await db.getConnection();
  try{await c.beginTransaction();
    const [res]=await c.query('INSERT INTO orders(order_no,user_id,customer_name,type,source,total) VALUES(?,?,?,?,?,?)',[orderNo,q.user?.id||null,cname,type,pos?'pos':'online',total]);
    await c.query('INSERT INTO order_items(order_id,product_id,name,price,qty) VALUES ?',[ps.map(p=>[res.insertId,p.id,p.name,p.price,qty[p.id]])]);
    await c.commit();r.json({id:res.insertId,orderNo,total});
  }catch(e){await c.rollback();throw e}finally{c.release()}
}));
/* Dynamic QR Ph: PaymentIntent (qrph) -> PaymentMethod (qrph) -> attach -> next_action.code.image_url */
app.post('/api/orders/:no/qr',lim(1,15),A(async(q,r)=>{
  const o=await getOrder(q.params.no);
  if(!o)throw bad('Order not found',404);
  if(o.payment_status==='paid'||o.status==='cancelled')throw bad('This order cannot be paid');
  if(o.qr_image&&o.qr_valid)return r.json({image:o.qr_image,total:o.total});
  const it=await pm('/payment_intents',{amount:Math.round(o.total*100),currency:'PHP',payment_method_allowed:['qrph'],description:'Cassey Manwa Coffee '+o.order_no,metadata:{order_no:o.order_no}},SK);
  const m=await pm('/payment_methods',{type:'qrph'},PK);
  const at=await pm(`/payment_intents/${it.id}/attach`,{payment_method:m.id,client_key:it.attributes.client_key},PK);
  const image=at.attributes.next_action?.code?.image_url;
  if(!image)throw bad('PayMongo did not return a QR code. Check that QR Ph is activated on your account.',502);
  await db.query('UPDATE orders SET pm_intent_id=?,qr_image=?,qr_expires_at=DATE_ADD(UTC_TIMESTAMP(),INTERVAL 29 MINUTE) WHERE id=?',[it.id,image,o.id]);
  r.json({image,total:o.total});
}));
/* Tracking. Also re-checks the PaymentIntent with PayMongo (real status) in case a webhook was missed. */
app.get('/api/orders/track/:no',lim(1,60),A(async(q,r)=>{
  let o=await getOrder(q.params.no);
  if(!o)throw bad('Order not found',404);
  if(o.payment_status==='unpaid'&&o.pm_intent_id&&o.status!=='cancelled'){
    try{const it=await pm('/payment_intents/'+o.pm_intent_id,null,SK);
      if(it.attributes.status==='succeeded'){const p=it.attributes.payments?.[0];if(await markPaid(o.id,p?.id,it.attributes.amount,'qrph'))o=await getOrder(q.params.no)}
    }catch(e){console.error('Intent check failed:',e.message)}
  }
  r.json(await pub(o));
}));
app.get('/api/my/orders',auth(),A(async(q,r)=>{
  const [o]=await db.query('SELECT order_no,total,status,payment_status,created_at FROM orders WHERE user_id=? ORDER BY id DESC LIMIT 30',[q.user.id]);
  r.json(o);
}));

/* ---------- Staff: POS / kitchen ---------- */
app.get('/api/staff/orders',auth(...STAFF),A(async(q,r)=>{
  const w={kitchen:"payment_status='paid' AND status IN ('pending','preparing','ready')",all:'1=1'}[q.query.view]||'1=1';
  const [os]=await db.query(`SELECT id,order_no,customer_name,type,source,status,payment_status,payment_method,total,created_at FROM orders WHERE ${w} ORDER BY id ${q.query.view==='kitchen'?'ASC':'DESC'} LIMIT 200`);
  if(os.length){const [its]=await db.query('SELECT order_id,name,qty FROM order_items WHERE order_id IN (?)',[os.map(o=>o.id)]);os.forEach(o=>o.items=its.filter(i=>i.order_id===o.id))}
  r.json(os);
}));
app.patch('/api/staff/orders/:id/status',auth(...STAFF),A(async(q,r)=>{
  const s=q.body.status;
  if(!['preparing','ready','completed','cancelled'].includes(s))throw bad('Invalid status');
  if(s==='cancelled'&&q.user.role==='kitchen')throw bad('Not allowed',403);
  const [[o]]=await db.query('SELECT * FROM orders WHERE id=?',[q.params.id]);
  if(!o)throw bad('Not found',404);
  if(s==='cancelled'&&o.payment_status==='paid')throw bad('Paid orders cannot be cancelled here. Refund through PayMongo first.');
  if(s!=='cancelled'&&o.payment_status!=='paid')throw bad('Order is not paid yet');
  await db.query('UPDATE orders SET status=? WHERE id=?',[s,o.id]);r.json({ok:true});
}));
app.post('/api/staff/orders/:id/cash',auth('cashier','admin'),A(async(q,r)=>{
  if(!(await markPaid(q.params.id,null,null,'cash')))throw bad('Order is already paid or cancelled');
  r.json({ok:true});
}));

/* ---------- Admin ---------- */
const adm=auth('admin');
app.post('/api/admin/categories',adm,A(async(q,r)=>{if(!q.body.name?.trim())throw bad('Name required');await db.query('INSERT IGNORE INTO categories(name) VALUES(?)',[q.body.name.trim().slice(0,60)]);r.json({ok:true})}));
app.delete('/api/admin/categories/:id',adm,A(async(q,r)=>{await db.query('DELETE FROM categories WHERE id=?',[q.params.id]);r.json({ok:true})}));
app.get('/api/admin/products',adm,A(async(q,r)=>r.json((await db.query('SELECT * FROM products ORDER BY name'))[0])));
const pv=b=>{const price=+b.price,stock=parseInt(b.stock),img=(b.image_url||'').trim();
  if(!b.name?.trim()||!(price>=0)||!(stock>=0))throw bad('Name, price and stock are required');
  if(img&&!/^https?:\/\//i.test(img))throw bad('Image must be an http(s) URL');
  return [b.category_id||null,b.name.trim().slice(0,100),(b.description||'').slice(0,300),price,img.slice(0,500),stock,b.active?1:0]};
app.post('/api/admin/products',adm,A(async(q,r)=>{await db.query('INSERT INTO products(category_id,name,description,price,image_url,stock,active) VALUES(?)',[pv(q.body)]);r.json({ok:true})}));
app.put('/api/admin/products/:id',adm,A(async(q,r)=>{await db.query('UPDATE products SET category_id=?,name=?,description=?,price=?,image_url=?,stock=?,active=? WHERE id=?',[...pv(q.body),q.params.id]);r.json({ok:true})}));
app.patch('/api/admin/products/:id/stock',adm,A(async(q,r)=>{const s=parseInt(q.body.stock);if(!(s>=0))throw bad('Invalid stock');await db.query('UPDATE products SET stock=? WHERE id=?',[s,q.params.id]);r.json({ok:true})}));
app.get('/api/admin/users',adm,A(async(q,r)=>r.json((await db.query('SELECT id,name,email,role,active,created_at FROM users ORDER BY role,name'))[0])));
app.post('/api/admin/users',adm,A(async(q,r)=>{
  const {name,email,password,role}=q.body;
  if(!name?.trim()||!/^\S+@\S+\.\S+$/.test(email||'')||(password||'').length<8||!['admin','cashier','kitchen'].includes(role))throw bad('Name, valid email, role and 8+ char password required');
  try{await db.query('INSERT INTO users(name,email,password_hash,role) VALUES(?,?,?,?)',[name.trim(),email.toLowerCase(),await bcrypt.hash(password,12),role])}
  catch(e){throw e.code==='ER_DUP_ENTRY'?bad('Email already exists'):e}
  r.json({ok:true});
}));
app.patch('/api/admin/users/:id',adm,A(async(q,r)=>{if(+q.params.id===q.user.id)throw bad('You cannot deactivate yourself');await db.query('UPDATE users SET active=? WHERE id=?',[q.body.active?1:0,q.params.id]);r.json({ok:true})}));
app.get('/api/admin/reports',adm,A(async(q,r)=>{
  const [g,iv]={day:['DATE(paid_at)','30 DAY'],week:["YEARWEEK(paid_at,1)",'84 DAY'],month:["DATE_FORMAT(paid_at,'%Y-%m')",'365 DAY']}[q.query.period]||['DATE(paid_at)','30 DAY'];
  const W=`o.payment_status='paid' AND o.status<>'cancelled' AND o.paid_at>=UTC_TIMESTAMP()-INTERVAL ${iv}`;
  const [rows]=await db.query(`SELECT ${g} label,COUNT(*) orders,SUM(total) sales FROM orders o WHERE ${W} GROUP BY label ORDER BY label DESC`);
  const [top]=await db.query(`SELECT i.name,SUM(i.qty) qty,SUM(i.qty*i.price) sales FROM order_items i JOIN orders o ON o.id=i.order_id WHERE ${W} GROUP BY i.name ORDER BY qty DESC LIMIT 10`);
  const [pay]=await db.query(`SELECT payment_method method,COUNT(*) orders,SUM(total) sales FROM orders o WHERE ${W} GROUP BY payment_method`);
  r.json({rows,top,pay});
}));

if(!process.env.VERCEL)app.listen(process.env.PORT||3000,()=>console.log('Cassey Manwa Coffee running'));
module.exports=app;
