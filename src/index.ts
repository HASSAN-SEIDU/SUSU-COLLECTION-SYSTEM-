import express, { Request, Response, NextFunction } from 'express';
import { Pool } from 'pg';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import helmet from 'helmet';
import cors from 'cors';
import crypto from 'crypto';
import dotenv from 'dotenv';
dotenv.config();

const PORT = process.env.PORT || 4000;
const API = '/api/v1';
const SYSTEM_NAME = 'SUSU COLLECTION SYSTEM';
const JWT_SECRET = process.env.JWT_SECRET || 'CHANGE_THIS_32_CHARS_SECRET_12345678';
const N8N_WEBHOOK = process.env.N8N_WEBHOOK_URL || '';
const pool = new Pool({ connectionString: process.env.DATABASE_URL || 'postgresql://postgres:postgres@localhost:5432/susu_collection_db' });

const app = express();
app.use(helmet());
app.use(cors());
app.use(express.json({ limit: '2mb' }));

async function initDB() {
  const c = await pool.connect();
  try {
    await c.query('BEGIN');
    await c.query(`
      CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
      DO $$ BEGIN CREATE TYPE system_role AS ENUM ('CUSTOMER','COLLECTOR','SUPERVISOR','BRANCH_MANAGER','ACCOUNTANT','COMPLIANCE_OFFICER','ADMINISTRATOR','AUDITOR'); EXCEPTION WHEN duplicate_object THEN null; END $$;
      DO $$ BEGIN CREATE TYPE account_category AS ENUM ('ASSET','LIABILITY','EQUITY','REVENUE','EXPENSE'); EXCEPTION WHEN duplicate_object THEN null; END $$;
      DO $$ BEGIN CREATE TYPE tx_status AS ENUM ('PENDING','APPROVED','REJECTED','POSTED','FAILED','REVERSED'); EXCEPTION WHEN duplicate_object THEN null; END $$;
      DO $$ BEGIN CREATE TYPE account_status AS ENUM ('PENDING','ACTIVE','DORMANT','SUSPENDED','CLOSED'); EXCEPTION WHEN duplicate_object THEN null; END $$;
      CREATE TABLE IF NOT EXISTS branches (id UUID PRIMARY KEY DEFAULT uuid_generate_v4(), code VARCHAR(20) UNIQUE NOT NULL, name VARCHAR(100) NOT NULL, location VARCHAR(100) NOT NULL, created_at TIMESTAMPTZ DEFAULT NOW());
      CREATE TABLE IF NOT EXISTS users (id UUID PRIMARY KEY DEFAULT uuid_generate_v4(), branch_id UUID REFERENCES branches(id), username VARCHAR(50) UNIQUE NOT NULL, email VARCHAR(100) UNIQUE, phone VARCHAR(20) UNIQUE NOT NULL, password_hash VARCHAR(255) NOT NULL, pin_hash VARCHAR(255), role system_role NOT NULL, first_name VARCHAR(50) NOT NULL, last_name VARCHAR(50) NOT NULL, is_active BOOLEAN DEFAULT TRUE, device_id VARCHAR(100), failed_attempts INT DEFAULT 0, locked_until TIMESTAMPTZ, created_at TIMESTAMPTZ DEFAULT NOW());
      CREATE TABLE IF NOT EXISTS customers (id UUID PRIMARY KEY DEFAULT uuid_generate_v4(), branch_id UUID REFERENCES branches(id), collector_id UUID REFERENCES users(id), account_number VARCHAR(30) UNIQUE NOT NULL, first_name VARCHAR(50) NOT NULL, last_name VARCHAR(50) NOT NULL, phone VARCHAR(20) UNIQUE NOT NULL, ghana_card_no VARCHAR(30) UNIQUE, ghana_card_encrypted TEXT, address TEXT NOT NULL, market_location VARCHAR(100) NOT NULL, occupation VARCHAR(100), next_of_kin_name VARCHAR(100), next_of_kin_phone VARCHAR(20), status account_status DEFAULT 'PENDING', kyc_level INT DEFAULT 0, kyc_verified BOOLEAN DEFAULT FALSE, consent BOOLEAN DEFAULT FALSE, sms_opt_out BOOLEAN DEFAULT FALSE, created_at TIMESTAMPTZ DEFAULT NOW());
      CREATE TABLE IF NOT EXISTS susu_accounts (id UUID PRIMARY KEY DEFAULT uuid_generate_v4(), customer_id UUID REFERENCES customers(id), branch_id UUID REFERENCES branches(id), account_number VARCHAR(30) UNIQUE NOT NULL, account_type VARCHAR(30) NOT NULL, status account_status DEFAULT 'ACTIVE', daily_target_pesewas BIGINT DEFAULT 0, commission_type VARCHAR(30) DEFAULT 'ONE_DAY_PER_CYCLE', cycle_days INT DEFAULT 31, created_at TIMESTAMPTZ DEFAULT NOW());
      CREATE TABLE IF NOT EXISTS chart_of_accounts (id UUID PRIMARY KEY DEFAULT uuid_generate_v4(), account_code VARCHAR(10) UNIQUE NOT NULL, account_name VARCHAR(100) NOT NULL, category account_category NOT NULL);
      CREATE TABLE IF NOT EXISTS financial_transactions (id UUID PRIMARY KEY DEFAULT uuid_generate_v4(), client_uuid VARCHAR(100) UNIQUE NOT NULL, transaction_ref VARCHAR(50) UNIQUE NOT NULL, transaction_type VARCHAR(50) NOT NULL, status tx_status DEFAULT 'POSTED', amount_pesewas BIGINT NOT NULL, fee_pesewas BIGINT DEFAULT 0, narration TEXT NOT NULL, idempotency_key VARCHAR(100) UNIQUE NOT NULL, branch_id UUID, actor_id UUID, posted_at TIMESTAMPTZ DEFAULT NOW());
      CREATE TABLE IF NOT EXISTS ledger_entries (id UUID PRIMARY KEY DEFAULT uuid_generate_v4(), transaction_id UUID REFERENCES financial_transactions(id), account_id UUID REFERENCES chart_of_accounts(id), branch_id UUID, susu_account_id UUID REFERENCES susu_accounts(id), debit_pesewas BIGINT DEFAULT 0, credit_pesewas BIGINT DEFAULT 0, created_at TIMESTAMPTZ DEFAULT NOW());
      CREATE TABLE IF NOT EXISTS collections (id UUID PRIMARY KEY DEFAULT uuid_generate_v4(), transaction_id UUID REFERENCES financial_transactions(id) UNIQUE, collector_id UUID REFERENCES users(id), susu_account_id UUID REFERENCES susu_accounts(id), amount_pesewas BIGINT NOT NULL, gps_lat DOUBLE PRECISION, gps_lng DOUBLE PRECISION, device_id VARCHAR(100), client_uuid VARCHAR(100) UNIQUE NOT NULL, status VARCHAR(20) DEFAULT 'SYNCED', collected_at TIMESTAMPTZ DEFAULT NOW());
      CREATE TABLE IF NOT EXISTS withdrawals (id UUID PRIMARY KEY DEFAULT uuid_generate_v4(), susu_account_id UUID REFERENCES susu_accounts(id), amount_pesewas BIGINT NOT NULL, fee_pesewas BIGINT DEFAULT 0, status tx_status DEFAULT 'PENDING', requested_by UUID, approved_by UUID, rejection_reason TEXT, otp_verified BOOLEAN DEFAULT FALSE, payout_method VARCHAR(20) DEFAULT 'CASH', momo_number VARCHAR(20), transaction_id UUID REFERENCES financial_transactions(id), created_at TIMESTAMPTZ DEFAULT NOW());
      CREATE TABLE IF NOT EXISTS reversals (id UUID PRIMARY KEY DEFAULT uuid_generate_v4(), original_tx_id UUID REFERENCES financial_transactions(id) UNIQUE, reversal_tx_id UUID REFERENCES financial_transactions(id) UNIQUE, reason TEXT NOT NULL, requested_by UUID, approved_by UUID, status tx_status DEFAULT 'PENDING', created_at TIMESTAMPTZ DEFAULT NOW());
      CREATE TABLE IF NOT EXISTS cash_ups (id UUID PRIMARY KEY DEFAULT uuid_generate_v4(), collector_id UUID REFERENCES users(id), branch_id UUID, business_date DATE NOT NULL, expected_pesewas BIGINT NOT NULL, counted_pesewas BIGINT NOT NULL, variance_pesewas BIGINT NOT NULL, status VARCHAR(30) DEFAULT 'PENDING_REVIEW', supervisor_reviewed_by UUID, banking_ref VARCHAR(100), created_at TIMESTAMPTZ DEFAULT NOW());
      CREATE TABLE IF NOT EXISTS approval_requests (id UUID PRIMARY KEY DEFAULT uuid_generate_v4(), entity_type VARCHAR(50) NOT NULL, entity_id UUID NOT NULL, requested_by UUID NOT NULL, approved_by UUID, status VARCHAR(20) DEFAULT 'PENDING', reason TEXT, previous_state JSONB, new_state JSONB, created_at TIMESTAMPTZ DEFAULT NOW(), decided_at TIMESTAMPTZ);
      CREATE TABLE IF NOT EXISTS fee_schedules (id UUID PRIMARY KEY DEFAULT uuid_generate_v4(), fee_type VARCHAR(50) NOT NULL, amount_pesewas BIGINT NOT NULL, effective_from TIMESTAMPTZ DEFAULT NOW(), created_by UUID, approved_by UUID, created_at TIMESTAMPTZ DEFAULT NOW());
      CREATE TABLE IF NOT EXISTS sms_logs (id UUID PRIMARY KEY DEFAULT uuid_generate_v4(), phone VARCHAR(20) NOT NULL, message TEXT NOT NULL, type VARCHAR(30), status VARCHAR(20) DEFAULT 'QUEUED', provider_response TEXT, retry_count INT DEFAULT 0, created_at TIMESTAMPTZ DEFAULT NOW());
      CREATE TABLE IF NOT EXISTS momo_transactions (id UUID PRIMARY KEY DEFAULT uuid_generate_v4(), provider VARCHAR(20) NOT NULL, provider_ref VARCHAR(100) UNIQUE, type VARCHAR(20) NOT NULL, amount_pesewas BIGINT NOT NULL, phone VARCHAR(20) NOT NULL, status VARCHAR(20) DEFAULT 'PENDING', webhook_payload JSONB, idempotency_key VARCHAR(100) UNIQUE NOT NULL, created_at TIMESTAMPTZ DEFAULT NOW());
      CREATE TABLE IF NOT EXISTS audit_logs (id UUID PRIMARY KEY DEFAULT uuid_generate_v4(), user_id UUID, role VARCHAR(30), action VARCHAR(100) NOT NULL, entity VARCHAR(100) NOT NULL, entity_id VARCHAR(100), ip VARCHAR(50), device_id VARCHAR(100), branch_id UUID, previous_value JSONB, new_value JSONB, reason TEXT, created_at TIMESTAMPTZ DEFAULT NOW());
      CREATE TABLE IF NOT EXISTS fraud_alerts (id UUID PRIMARY KEY DEFAULT uuid_generate_v4(), type VARCHAR(100) NOT NULL, severity VARCHAR(10) NOT NULL, description TEXT NOT NULL, entity_type VARCHAR(50), entity_id UUID, collector_id UUID, status VARCHAR(20) DEFAULT 'OPEN', created_at TIMESTAMPTZ DEFAULT NOW());
      CREATE TABLE IF NOT EXISTS sync_batches (id UUID PRIMARY KEY DEFAULT uuid_generate_v4(), collector_id UUID, device_id VARCHAR(100), count INT, status VARCHAR(20) DEFAULT 'PROCESSED', created_at TIMESTAMPTZ DEFAULT NOW());
    `);
    await c.query('COMMIT');
    console.log(`[DB] ${SYSTEM_NAME} Schema ready`);
  } catch (e) { await c.query('ROLLBACK'); throw e; } finally { c.release(); }
}

async function seed() {
  const c = await pool.connect();
  try {
    await c.query('BEGIN');
    const b = await c.query(`INSERT INTO branches (code,name,location) VALUES ('ACC-001','Tamale Central','Tamale') ON CONFLICT (code) DO UPDATE SET name=EXCLUDED.name RETURNING id`);
    const branchId = b.rows[0].id;
    const coa = [['1010','Vault Cash','ASSET'],['1020','Collector Float Cash','ASSET'],['2010','Customer Susu Savings Liability','LIABILITY'],['4010','Susu Commission Revenue','REVENUE'],['5010','Commission Expense','EXPENSE'],['1025','MoMo Settlement','ASSET']];
    for (const [code,name,cat] of coa) { await c.query(`INSERT INTO chart_of_accounts (account_code,account_name,category) VALUES ($1,$2,$3) ON CONFLICT DO NOTHING`, [code,name,cat]); }
    const adminHash = await bcrypt.hash('Admin@123', 12);
    const pinHash = await bcrypt.hash('1234', 10);
    await c.query(`INSERT INTO users (branch_id,username,email,phone,password_hash,role,first_name,last_name) VALUES ($1,'admin','admin@susu-collection.com','+233241111111',$2,'ADMINISTRATOR','System','Admin') ON CONFLICT (username) DO NOTHING`, [branchId, adminHash]);
    await c.query(`INSERT INTO users (branch_id,username,email,phone,password_hash,pin_hash,role,first_name,last_name) VALUES ($1,'collector1','collector1@susu-collection.com','+233242222222',$2,$3,'COLLECTOR','Ibrahim','Inusah') ON CONFLICT (username) DO NOTHING`, [branchId, adminHash, pinHash]);
    await c.query(`INSERT INTO users (branch_id,username,email,phone,password_hash,role,first_name,last_name) VALUES ($1,'supervisor1','sup@susu-collection.com','+233243333333',$2,'SUPERVISOR','Supervisor','One') ON CONFLICT (username) DO NOTHING`, [branchId, adminHash]);
    await c.query(`INSERT INTO fee_schedules (fee_type,amount_pesewas) VALUES ('WITHDRAWAL_FEE',100) ON CONFLICT DO NOTHING`);
    await c.query('COMMIT');
    console.log(`[SEED] ${SYSTEM_NAME} - admin/Admin@123 | collector1 PIN 1234`);
  } catch (e) { await c.query('ROLLBACK'); console.error(e); } finally { c.release(); }
}

type Posting = { accountCode:string; debit:bigint; credit:bigint; branchId?:string; susuAccountId?:string; };
class Ledger {
  static check(p: Posting[]) { let d=0n,c=0n; for(const x of p){ if(x.debit<0n||x.credit<0n) throw new Error('NEGATIVE_FORBIDDEN'); if(x.debit>0n&&x.credit>0n) throw new Error('BOTH_DEBIT_CREDIT'); d+=x.debit; c+=x.credit; } if(d!==c) throw new Error(`LEDGER_UNBALANCED ${d}!=${c}`); if(d===0n) throw new Error('ZERO_AMOUNT'); }
  static async post(db:any, params:{clientUuid:string; idempotencyKey:string; type:string; amount:bigint; fee:bigint; narration:string; postings:Posting[]; actorId?:string; branchId?:string;}) {
    this.check(params.postings);
    const ex = await db.query(`SELECT * FROM financial_transactions WHERE idempotency_key=$1`, [params.idempotencyKey]);
    if(ex.rows.length>0) return {dup:true, tx:ex.rows[0]};
    const ref = `TX-${Date.now()}-${crypto.randomInt(100000,999999)}`;
    const ft = await db.query(`INSERT INTO financial_transactions (client_uuid,transaction_ref,transaction_type,status,amount_pesewas,fee_pesewas,narration,idempotency_key,actor_id,branch_id) VALUES ($1,$2,$3,'POSTED',$4,$5,$6,$7,$8,$9) RETURNING *`, [params.clientUuid, ref, params.type, params.amount.toString(), params.fee.toString(), params.narration, params.idempotencyKey, params.actorId, params.branchId]);
    const transaction = ft.rows[0];
    for(const p of params.postings){
      const coa = await db.query(`SELECT id FROM chart_of_accounts WHERE account_code=$1`, [p.accountCode]);
      if(!coa.rows[0]) throw new Error(`COA_MISSING ${p.accountCode}`);
      await db.query(`INSERT INTO ledger_entries (transaction_id,account_id,branch_id,susu_account_id,debit_pesewas,credit_pesewas) VALUES ($1,$2,$3,$4,$5,$6)`, [transaction.id, coa.rows[0].id, p.branchId||null, p.susuAccountId||null, p.debit.toString(), p.credit.toString()]);
    }
    return {dup:false, tx:transaction};
  }
}

const signToken = (p:any, exp='8h') => jwt.sign(p, JWT_SECRET, {expiresIn: exp} as any);
const auth = (req:any,res:Response,next:NextFunction)=>{ const h=req.headers.authorization; if(!h?.startsWith('Bearer ')) return res.status(401).json({success:false,error:{code:'UNAUTHORIZED'}}); try{ req.user=jwt.verify(h.split(' ')[1], JWT_SECRET) as any; next(); }catch{ return res.status(401).json({success:false,error:{code:'TOKEN_EXPIRED'}}); } };
const allow = (...roles:string[])=> (req:any,res:Response,next:NextFunction)=>{ if(!roles.includes(req.user.role)) return res.status(403).json({success:false,error:{code:'FORBIDDEN'}}); next(); };
async function auditLog(userId:string, role:string, action:string, entity:string, entityId:string, prev:any, nextVal:any, req:Request){ await pool.query(`INSERT INTO audit_logs (user_id,role,action,entity,entity_id,ip,branch_id,previous_value,new_value) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`, [userId,role,action,entity,entityId,(req as any).ip||'0.0.0.0',(req as any).user?.branchId||null, prev?JSON.stringify(prev):null, nextVal?JSON.stringify(nextVal):null]); }
async function queueSms(phone:string, message:string, type:string){ await pool.query(`INSERT INTO sms_logs (phone,message,type,status) VALUES ($1,$2,$3,'QUEUED')`, [phone,message,type]); console.log(`[SMS] ${phone}: ${message}`); }

app.get(`${API}/health`, async (req,res)=>{ try{ await pool.query('SELECT 1'); res.json({success:true, status:'HEALTHY', system: SYSTEM_NAME, ledger:'DOUBLE_ENTRY_ENFORCED'}); }catch(e:any){ res.status(500).json({success:false}); } });

app.post(`${API}/auth/login`, async (req,res)=>{
  const {username,password,deviceId} = req.body;
  const u = await pool.query(`SELECT * FROM users WHERE username=$1 AND is_active=TRUE`, [username]);
  if(!u.rows[0]) return res.status(401).json({success:false,error:{code:'INVALID_CREDENTIALS'}});
  const user=u.rows[0];
  if(!(await bcrypt.compare(password, user.password_hash))) return res.status(401).json({success:false,error:{code:'INVALID_CREDENTIALS'}});
  const token=signToken({userId:user.id, role:user.role, branchId:user.branch_id});
  await auditLog(user.id,user.role,'LOGIN','USER',user.id,null,{deviceId},req);
  res.json({success:true, data:{token, user:{id:user.id, username:user.username, role:user.role, branchId:user.branch_id}, system: SYSTEM_NAME}});
});

app.post(`${API}/auth/pin-login`, async (req,res)=>{
  const {phone,pin} = req.body;
  const u = await pool.query(`SELECT * FROM users WHERE phone=$1 AND role='COLLECTOR' AND is_active=TRUE`, [phone]);
  if(!u.rows[0]||!u.rows[0].pin_hash) return res.status(401).json({success:false});
  if(!(await bcrypt.compare(pin, u.rows[0].pin_hash))) return res.status(401).json({success:false,error:{code:'INVALID_PIN'}});
  const token=signToken({userId:u.rows[0].id, role:u.rows[0].role, branchId:u.rows[0].branch_id}, '12h');
  res.json({success:true, data:{token}});
});

app.post(`${API}/customers`, auth, allow('ADMINISTRATOR','BRANCH_MANAGER','SUPERVISOR','COLLECTOR'), async (req:any,res)=>{
  const {firstName,lastName,phone,address,marketLocation,ghanaCardNo,nextOfKinName,nextOfKinPhone,collectorId} = req.body;
  if(!firstName||!phone||!address) return res.status(400).json({success:false,error:{code:'MISSING_FIELDS'}});
  try{
    const accNo = `SCS-${Date.now().toString().slice(-6)}`;
    const cust = await pool.query(`INSERT INTO customers (branch_id,collector_id,account_number,first_name,last_name,phone,ghana_card_no,address,market_location,next_of_kin_name,next_of_kin_phone,status) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,'ACTIVE') RETURNING *`, [req.user.branchId, collectorId||req.user.userId, accNo, firstName, lastName||'', phone, ghanaCardNo||null, address, marketLocation||'Unknown', nextOfKinName||null, nextOfKinPhone||null]);
    const c=cust.rows[0];
    const saNo=`SA-${Date.now().toString().slice(-6)}`;
    const sa=await pool.query(`INSERT INTO susu_accounts (customer_id,branch_id,account_number,account_type,daily_target_pesewas) VALUES ($1,$2,$3,'INDIVIDUAL_SUSU',2000) RETURNING *`, [c.id, req.user.branchId, saNo]);
    await auditLog(req.user.userId, req.user.role, 'CREATE_CUSTOMER','CUSTOMER',c.id,null,c,req);
    res.json({success:true, data:{customer:c, susuAccount:sa.rows[0]}});
  }catch(e:any){ if(e.code==='23505') return res.status(409).json({success:false,error:{code:'DUPLICATE_PHONE_OR_GHANA_CARD'}}); res.status(500).json({success:false,error:{code:'SERVER_ERROR',message:e.message}}); }
});

app.get(`${API}/customers`, auth, async (req:any,res)=>{
  const {search} = req.query;
  let q=`SELECT c.*, sa.id as susu_account_id, sa.account_number as susu_account_no FROM customers c LEFT JOIN susu_accounts sa ON sa.customer_id=c.id WHERE c.branch_id=$1`;
  const params:any[]=[req.user.branchId];
  if(search){ q+=` AND (c.phone ILIKE $2 OR c.first_name ILIKE $2 OR c.account_number ILIKE $2)`; params.push(`%${search}%`); }
  const r=await pool.query(q, params);
  res.json({success:true, data:r.rows});
});

app.post(`${API}/collections`, auth, allow('COLLECTOR','SUPERVISOR','BRANCH_MANAGER'), async (req:any,res)=>{
  const db = await pool.connect();
  try{
    const {susuAccountId, amountPesewas, clientUuid, idempotencyKey, gpsLat, gpsLng, deviceId} = req.body;
    if(!susuAccountId||!amountPesewas||!clientUuid||!idempotencyKey) return res.status(400).json({success:false,error:{code:'MISSING_FIELDS'}});
    await db.query('BEGIN');
    const saRes = await db.query(`SELECT sa.*, c.first_name, c.last_name, c.phone FROM susu_accounts sa JOIN customers c ON sa.customer_id=c.id WHERE sa.id=$1`, [susuAccountId]);
    if(!saRes.rows[0]){ await db.query('ROLLBACK'); return res.status(404).json({success:false}); }
    const sa=saRes.rows[0];
    const amount=BigInt(amountPesewas);
    const result = await Ledger.post(db, {
      clientUuid, idempotencyKey, type:'COLLECTION', amount, fee:0n,
      narration:`${SYSTEM_NAME} Collection from ${sa.first_name} ${sa.last_name}`,
      postings:[
        {accountCode:'1020', debit:amount, credit:0n, branchId:req.user.branchId, susuAccountId:sa.id},
        {accountCode:'2010', debit:0n, credit:amount, branchId:req.user.branchId, susuAccountId:sa.id}
      ],
      actorId:req.user.userId, branchId:req.user.branchId
    });
    if(!result.dup){
      await db.query(`INSERT INTO collections (transaction_id,collector_id,susu_account_id,amount_pesewas,gps_lat,gps_lng,device_id,client_uuid) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`, [result.tx.id, req.user.userId, sa.id, amount.toString(), gpsLat||null, gpsLng||null, deviceId||null, clientUuid]);
    }
    await db.query('COMMIT');
    const bal = await pool.query(`SELECT COALESCE(SUM(credit_pesewas-debit_pesewas),0) as net FROM ledger_entries WHERE susu_account_id=$1`, [sa.id]);
    const net = BigInt(bal.rows[0].net);
    if(!result.dup){
      queueSms(sa.phone, `${SYSTEM_NAME}: GHS ${(Number(amount)/100).toFixed(2)} received. Bal GHS ${(Number(net)/100).toFixed(2)} Ref ${result.tx.transaction_ref}`, 'RECEIPT');
      if(N8N_WEBHOOK) fetch(N8N_WEBHOOK,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({system: SYSTEM_NAME, event:'collection.created', phone:sa.phone, amountGHS:(Number(amount)/100).toFixed(2), ref:result.tx.transaction_ref})}).catch(()=>{});
    }
    res.json({success:true, data:{system: SYSTEM_NAME, transactionRef:result.tx.transaction_ref, duplicate:result.dup, balancePesewas:net.toString(), balanceFormatted:`GHS ${(Number(net)/100).toFixed(2)}`}});
  }catch(e:any){ await db.query('ROLLBACK'); res.status(500).json({success:false,error:{code:'SERVER_ERROR',message:e.message}}); } finally {db.release();}
});

app.get(`${API}/accounts/:id/balance`, auth, async (req,res)=>{
  const r=await pool.query(`SELECT COALESCE(SUM(credit_pesewas-debit_pesewas),0) as net FROM ledger_entries WHERE susu_account_id=$1`, [req.params.id]);
  const net=BigInt(r.rows[0].net);
  res.json({success:true, data:{system: SYSTEM_NAME, susuAccountId:req.params.id, balancePesewas:net.toString(), balanceFormatted:`GHS ${(Number(net)/100).toFixed(2)}`}});
});

app.post(`${API}/withdrawals`, auth, async (req:any,res)=>{
  const {susuAccountId, amountPesewas, payoutMethod, momoNumber} = req.body;
  const amount=BigInt(amountPesewas);
  const balRes=await pool.query(`SELECT COALESCE(SUM(credit_pesewas-debit_pesewas),0) as net FROM ledger_entries WHERE susu_account_id=$1`, [susuAccountId]);
  if(BigInt(balRes.rows[0].net) < amount) return res.status(400).json({success:false,error:{code:'INSUFFICIENT_BALANCE'}});
  const feeRes=await pool.query(`SELECT amount_pesewas FROM fee_schedules WHERE fee_type='WITHDRAWAL_FEE' ORDER BY effective_from DESC LIMIT 1`);
  const fee=BigInt(feeRes.rows[0]?.amount_pesewas||100);
  const w=await pool.query(`INSERT INTO withdrawals (susu_account_id,amount_pesewas,fee_pesewas,status,requested_by,payout_method,momo_number) VALUES ($1,$2,$3,'PENDING',$4,$5,$6) RETURNING *`, [susuAccountId, amount.toString(), fee.toString(), req.user.userId, payoutMethod||'CASH', momoNumber||null]);
  await pool.query(`INSERT INTO approval_requests (entity_type,entity_id,requested_by,new_state) VALUES ('WITHDRAWAL',$1,$2,$3)`, [w.rows[0].id, req.user.userId, JSON.stringify(w.rows[0])]);
  res.json({success:true, data:w.rows[0]});
});

app.post(`${API}/withdrawals/:id/approve`, auth, allow('SUPERVISOR','BRANCH_MANAGER','ACCOUNTANT','ADMINISTRATOR'), async (req:any,res)=>{
  const db=await pool.connect();
  try{
    await db.query('BEGIN');
    const wRes=await db.query(`SELECT * FROM withdrawals WHERE id=$1`, [req.params.id]);
    if(!wRes.rows[0]){ await db.query('ROLLBACK'); return res.status(404).json({success:false}); }
    const w=wRes.rows[0];
    if(w.requested_by===req.user.userId){ await db.query('ROLLBACK'); return res.status(403).json({success:false,error:{code:'SELF_APPROVAL_FORBIDDEN'}}); }
    const amount=BigInt(w.amount_pesewas); const fee=BigInt(w.fee_pesewas); const total=amount+fee;
    const ledgerRes=await Ledger.post(db, {
      clientUuid:crypto.randomUUID(), idempotencyKey:`WD-${w.id}`, type:'WITHDRAWAL', amount:total, fee, narration:`${SYSTEM_NAME} Withdrawal ${w.id}`,
      postings:[
        {accountCode:'2010', debit:total, credit:0n, branchId:req.user.branchId, susuAccountId:w.susu_account_id},
        {accountCode:'1020', debit:0n, credit:amount, branchId:req.user.branchId, susuAccountId:w.susu_account_id},
        {accountCode:'4010', debit:0n, credit:fee, branchId:req.user.branchId, susuAccountId:w.susu_account_id}
      ],
      actorId:req.user.userId, branchId:req.user.branchId
    });
    await db.query(`UPDATE withdrawals SET status='APPROVED', approved_by=$1, transaction_id=$2 WHERE id=$3`, [req.user.userId, ledgerRes.tx.id, w.id]);
    await db.query('COMMIT');
    res.json({success:true, data:{system: SYSTEM_NAME, transactionRef:ledgerRes.tx.transaction_ref}});
  }catch(e:any){ await db.query('ROLLBACK'); res.status(500).json({success:false,error:{code:'SERVER_ERROR',message:e.message}}); } finally {db.release();}
});

app.post(`${API}/cashups`, auth, allow('COLLECTOR'), async (req:any,res)=>{
  const {businessDate, countedPesewas} = req.body;
  const counted=BigInt(countedPesewas);
  const coll=await pool.query(`SELECT COALESCE(SUM(amount_pesewas),0) as total FROM collections WHERE collector_id=$1 AND DATE(collected_at)=$2`, [req.user.userId, businessDate]);
  const expected=BigInt(coll.rows[0].total);
  const variance=counted-expected;
  const status = variance< -50000n || variance> 50000n? 'FLAGGED_VARIANCE' : 'PENDING_REVIEW';
  const cu=await pool.query(`INSERT INTO cash_ups (collector_id,branch_id,business_date,expected_pesewas,counted_pesewas,variance_pesewas,status) VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING *`, [req.user.userId, req.user.branchId, businessDate, expected.toString(), counted.toString(), variance.toString(), status]);
  res.json({success:true, data:cu.rows[0]});
});

app.get(`${API}/reports/daily`, auth, async (req:any,res)=>{
  const {date} = req.query; const d = date|| new Date().toISOString().split('T')[0];
  const totalColl=await pool.query(`SELECT COALESCE(SUM(amount_pesewas),0) as total, COUNT(*) as cnt FROM collections WHERE DATE(collected_at)=$1`, [d]);
  const liabilities=await pool.query(`SELECT COALESCE(SUM(credit_pesewas-debit_pesewas),0) as total FROM ledger_entries le JOIN chart_of_accounts coa ON le.account_id=coa.id WHERE coa.account_code='2010'`);
  const trial=await pool.query(`SELECT coa.account_code, coa.account_name, SUM(le.debit_pesewas) as debit, SUM(le.credit_pesewas) as credit FROM ledger_entries le JOIN chart_of_accounts coa ON le.account_id=coa.id GROUP BY coa.account_code, coa.account_name`);
  res.json({success:true, data:{system: SYSTEM_NAME, date:d, totalCollections:totalColl.rows[0].total, collectionCount:totalColl.rows[0].cnt, customerLiabilities:liabilities.rows[0].total, trialBalance:trial.rows}});
});

app.post(`${API}/sync`, auth, allow('COLLECTOR'), async (req:any,res)=>{
  const {transactions, deviceId} = req.body;
  const results=[];
  for(const t of transactions){
    const db=await pool.connect();
    try{
      await db.query('BEGIN');
      const amount=BigInt(t.amountPesewas);
      const r=await Ledger.post(db, {clientUuid:t.clientUuid, idempotencyKey:t.idempotencyKey, type:'COLLECTION', amount, fee:0n, narration:`${SYSTEM_NAME} Offline sync`, postings:[{accountCode:'1020', debit:amount, credit:0n, branchId:req.user.branchId, susuAccountId:t.susuAccountId},{accountCode:'2010', debit:0n, credit:amount, branchId:req.user.branchId, susuAccountId:t.susuAccountId}], actorId:req.user.userId, branchId:req.user.branchId});
      if(!r.dup){ await db.query(`INSERT INTO collections (transaction_id,collector_id,susu_account_id,amount_pesewas,device_id,client_uuid) VALUES ($1,$2,$3,$4,$5,$6)`, [r.tx.id, req.user.userId, t.susuAccountId, amount.toString(), deviceId||null, t.clientUuid]); }
      await db.query('COMMIT');
      results.push({clientUuid:t.clientUuid, success:true, duplicate:r.dup, ref:r.tx.transaction_ref});
    }catch(e:any){ await db.query('ROLLBACK'); results.push({clientUuid:t.clientUuid, success:false, error:e.message}); } finally {db.release();}
  }
  res.json({success:true, data:results});
});

async function start(){ await initDB(); await seed(); app.listen(PORT, ()=> console.log(`${SYSTEM_NAME} READY http://localhost:${PORT}${API}`)); }
start();
