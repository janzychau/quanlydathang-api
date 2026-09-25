require("dotenv").config();

const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { createClient } = require("@supabase/supabase-js");

const app = express();
app.use(express.json({limit:"5mb"}));

const ORIGINS=(process.env.FRONTEND_ORIGINS||"*").split(",").map(x=>x.trim()).filter(Boolean);
app.use(cors({
  origin:(origin,cb)=>{
    if(!origin || ORIGINS.includes("*") || ORIGINS.includes(origin)) return cb(null,true);
    cb(new Error("Origin not allowed"));
  }
}));

const PORT=Number(process.env.PORT||10000);
const SUPABASE_URL=process.env.SUPABASE_URL;
const SUPABASE_SECRET_KEY=process.env.SUPABASE_SECRET_KEY;
const JWT_SECRET=process.env.JWT_SECRET;

if(!SUPABASE_URL||!SUPABASE_SECRET_KEY||!JWT_SECRET){
  console.error("Missing SUPABASE_URL, SUPABASE_SECRET_KEY or JWT_SECRET");
  process.exit(1);
}

const supabase=createClient(SUPABASE_URL,SUPABASE_SECRET_KEY,{
  auth:{persistSession:false,autoRefreshToken:false}
});

const OWNER="Chủ Sở Hữu", ADMIN="Quản Trị", MEMBER="Thành Viên", VIEWER="Người Xem";
const TICKET_TABLES=["phieu_de_xuat","phieu_duyet_de_xuat","phieu_dat_hang","phieu_nhan_hang","phieu_tra_hang","phieu_huy_hang"];
const TABLES=new Set(["nhan_vien","san_pham","danh_muc",...TICKET_TABLES]);

function role(v){
  const s=String(v||"").trim().toLowerCase();
  if(s===OWNER.toLowerCase()) return OWNER;
  if(s===ADMIN.toLowerCase()) return ADMIN;
  if(s===MEMBER.toLowerCase()) return MEMBER;
  return VIEWER;
}
function publicUser(u){
  return {id:u.id,ma:u.ma,ten:u.ten,chuc_vu:u.chuc_vu,phong_ban:u.phong_ban,
    tai_khoan:u.tai_khoan,phan_quyen:role(u.phan_quyen),hieu_luc:u.hieu_luc,ghi_chu:u.ghi_chu};
}
async function getUser(id){
  const {data,error}=await supabase.from("nhan_vien").select("*").eq("id",id).maybeSingle();
  if(error) throw error;
  return data;
}
async function auth(req,res,next){
  try{
    const h=req.headers.authorization||"";
    const token=h.startsWith("Bearer ")?h.slice(7):"";
    if(!token) return res.status(401).json({error:"Chưa đăng nhập."});
    const p=jwt.verify(token,JWT_SECRET);
    const u=await getUser(p.sub);
    if(!u||!u.hieu_luc) return res.status(401).json({error:"Tài khoản không tồn tại hoặc đã bị khóa."});
    req.user=u; next();
  }catch(e){res.status(401).json({error:"Phiên đăng nhập không hợp lệ hoặc đã hết hạn."});}
}
function ownerAdmin(req,res,next){
  if(![OWNER,ADMIN].includes(role(req.user.phan_quyen)))
    return res.status(403).json({error:"Bạn không có quyền thực hiện thao tác này."});
  next();
}
function canManageTarget(actor,target){
  const a=role(actor.phan_quyen), t=role(target.phan_quyen);
  return a===OWNER || (a===ADMIN && [MEMBER,VIEWER].includes(t));
}

app.get("/",(req,res)=>res.json({ok:true,service:"quanlydathang-api"}));

app.get("/api/health",async(req,res)=>{
  try{
    const {error}=await supabase.from("danh_muc").select("id").limit(1);
    if(error) throw error;
    res.json({ok:true,database:"connected"});
  }catch(e){res.status(500).json({ok:false,database:"error"});}
});

app.post("/api/auth/login",async(req,res)=>{
  try{
    const username=String(req.body.username||"").trim();
    const password=String(req.body.password||"");
    const {data:u,error}=await supabase.from("nhan_vien").select("*").eq("tai_khoan",username).maybeSingle();
    if(error) throw error;
    if(!u||!u.hieu_luc||!u.mat_khau_hash) return res.status(401).json({error:"Tài khoản hoặc mật khẩu không đúng."});
    if(!(await bcrypt.compare(password,u.mat_khau_hash))) return res.status(401).json({error:"Tài khoản hoặc mật khẩu không đúng."});
    const token=jwt.sign({sub:u.id,tai_khoan:u.tai_khoan,phan_quyen:role(u.phan_quyen)},JWT_SECRET,{expiresIn:"12h"});
    res.json({ok:true,token,user:publicUser(u)});
  }catch(e){res.status(500).json({error:"Lỗi máy chủ khi đăng nhập.",detail:e.message});}
});

app.get("/api/auth/me",auth,(req,res)=>res.json({ok:true,user:publicUser(req.user)}));

app.post("/api/auth/change-password",auth,async(req,res)=>{
  try{
    const oldPass=String(req.body.currentPassword||"");
    const newPass=String(req.body.newPassword||"");
    if(newPass.length<6) return res.status(400).json({error:"Mật khẩu mới phải có ít nhất 6 ký tự."});
    if(!(await bcrypt.compare(oldPass,req.user.mat_khau_hash||"")))
      return res.status(400).json({error:"Mật khẩu hiện tại không đúng."});
    const hash=await bcrypt.hash(newPass,12);
    const {error}=await supabase.from("nhan_vien").update({mat_khau_hash:hash,updated_at:new Date().toISOString()}).eq("id",req.user.id);
    if(error) throw error;
    res.json({ok:true});
  }catch(e){res.status(500).json({error:"Không thể đổi mật khẩu.",detail:e.message});}
});

app.get("/api/employees",auth,async(req,res)=>{
  const {data,error}=await supabase.from("nhan_vien")
    .select("id,ma,ten,chuc_vu,phong_ban,tai_khoan,phan_quyen,hieu_luc,ghi_chu,created_at,updated_at")
    .order("created_at",{ascending:true});
  if(error) return res.status(500).json({error:error.message});
  res.json({data:data||[]});
});

app.post("/api/employees",auth,ownerAdmin,async(req,res)=>{
  try{
    const r=role(req.body.phan_quyen);
    if(role(req.user.phan_quyen)===ADMIN && ![MEMBER,VIEWER].includes(r))
      return res.status(403).json({error:"Admin chỉ được tạo Thành Viên hoặc Người Xem."});
    const pass=String(req.body.mat_khau||"");
    if(pass.length<6) return res.status(400).json({error:"Mật khẩu phải có ít nhất 6 ký tự."});
    const p={ma:req.body.ma,ten:req.body.ten,chuc_vu:req.body.chuc_vu,phong_ban:req.body.phong_ban,
      tai_khoan:req.body.tai_khoan,phan_quyen:r,hieu_luc:req.body.hieu_luc!==false,ghi_chu:req.body.ghi_chu,
      mat_khau_hash:await bcrypt.hash(pass,12)};
    const {data,error}=await supabase.from("nhan_vien").insert(p).select("*").single();
    if(error) throw error;
    res.status(201).json({data:publicUser(data)});
  }catch(e){res.status(500).json({error:"Không thể tạo nhân viên.",detail:e.message});}
});

app.patch("/api/employees/:id",auth,ownerAdmin,async(req,res)=>{
  try{
    const target=await getUser(req.params.id);
    if(!target) return res.status(404).json({error:"Không tìm thấy nhân viên."});
    if(!canManageTarget(req.user,target)) return res.status(403).json({error:"Bạn không được sửa tài khoản này."});
    const p={};
    ["ma","ten","chuc_vu","phong_ban","tai_khoan","hieu_luc","ghi_chu"].forEach(k=>{
      if(Object.prototype.hasOwnProperty.call(req.body,k)) p[k]=req.body[k];
    });
    if(req.body.phan_quyen!==undefined){
      const r=role(req.body.phan_quyen);
      if(role(req.user.phan_quyen)===ADMIN&&!([MEMBER,VIEWER].includes(r)))
        return res.status(403).json({error:"Admin không được đổi quyền thành Owner/Admin."});
      p.phan_quyen=r;
    }
    if(req.body.mat_khau) p.mat_khau_hash=await bcrypt.hash(String(req.body.mat_khau),12);
    p.updated_at=new Date().toISOString();
    const {data,error}=await supabase.from("nhan_vien").update(p).eq("id",req.params.id).select("*").single();
    if(error) throw error;
    res.json({data:publicUser(data)});
  }catch(e){res.status(500).json({error:"Không thể cập nhật nhân viên.",detail:e.message});}
});

app.delete("/api/employees/:id",auth,ownerAdmin,async(req,res)=>{
  try{
    if(req.params.id===req.user.id) return res.status(400).json({error:"Không thể tự xóa tài khoản đang đăng nhập."});
    const target=await getUser(req.params.id);
    if(!target) return res.status(404).json({error:"Không tìm thấy nhân viên."});
    if(!canManageTarget(req.user,target)) return res.status(403).json({error:"Bạn không được xóa tài khoản này."});
    const {error}=await supabase.from("nhan_vien").delete().eq("id",req.params.id);
    if(error) throw error;
    res.json({ok:true});
  }catch(e){res.status(500).json({error:"Không thể xóa nhân viên.",detail:e.message});}
});

app.get("/api/data/:table",auth,async(req,res)=>{
  try{
    const table=req.params.table;
    if(!TABLES.has(table)) return res.status(404).json({error:"Bảng không hợp lệ."});
    const {data,error}=await supabase.from(table).select("*").order("created_at",{ascending:true});
    if(error) throw error;
    res.json({data:data||[]});
  }catch(e){res.status(500).json({error:"Không thể tải dữ liệu.",detail:e.message});}
});

app.post("/api/data/:table",auth,async(req,res)=>{
  try{
    const table=req.params.table, r=role(req.user.phan_quyen);
    if(table==="nhan_vien") return res.status(403).json({error:"Dùng /api/employees."});
    if(table==="danh_muc"&&! [OWNER,ADMIN].includes(r)) return res.status(403).json({error:"Không có quyền quản lý danh mục."});
    if(TICKET_TABLES.includes(table)&&![OWNER,ADMIN,MEMBER].includes(r)) return res.status(403).json({error:"Không có quyền tạo phiếu."});
    if(table==="san_pham"&&![OWNER,ADMIN,MEMBER].includes(r)) return res.status(403).json({error:"Không có quyền thêm sản phẩm."});
    if(!TABLES.has(table)) return res.status(404).json({error:"Bảng không hợp lệ."});
    const {data,error}=await supabase.from(table).insert(req.body).select("*").single();
    if(error) throw error;
    res.status(201).json({data});
  }catch(e){res.status(500).json({error:"Không thể tạo dữ liệu.",detail:e.message});}
});

app.patch("/api/data/:table/:id",auth,async(req,res)=>{
  try{
    const table=req.params.table, r=role(req.user);
    if(!TABLES.has(table)||table==="nhan_vien") return res.status(404).json({error:"Bảng không hợp lệ."});
    if(table==="danh_muc"&&! [OWNER,ADMIN].includes(r)) return res.status(403).json({error:"Không có quyền sửa danh mục."});
    if(TICKET_TABLES.includes(table)&&![OWNER,ADMIN,MEMBER].includes(r)) return res.status(403).json({error:"Không có quyền sửa phiếu."});
    if(table==="san_pham"&&![OWNER,ADMIN,MEMBER].includes(r)) return res.status(403).json({error:"Không có quyền sửa sản phẩm."});
    const {data,error}=await supabase.from(table).update(req.body).eq("id",req.params.id).select("*").single();
    if(error) throw error;
    res.json({data});
  }catch(e){res.status(500).json({error:"Không thể cập nhật dữ liệu.",detail:e.message});}
});

app.delete("/api/data/:table/:id",auth,async(req,res)=>{
  try{
    const table=req.params.table, r=role(req.user);
    if(!TABLES.has(table)||table==="nhan_vien") return res.status(404).json({error:"Bảng không hợp lệ."});
    if(table==="danh_muc"&&! [OWNER,ADMIN].includes(r)) return res.status(403).json({error:"Không có quyền xóa danh mục."});
    if(TICKET_TABLES.includes(table)&&![OWNER,ADMIN].includes(r)) return res.status(403).json({error:"Chỉ Owner/Admin được xóa phiếu."});
    if(table==="san_pham"&&![OWNER,ADMIN].includes(r)) return res.status(403).json({error:"Chỉ Owner/Admin được xóa sản phẩm."});
    const {error}=await supabase.from(table).delete().eq("id",req.params.id);
    if(error) throw error;
    res.json({ok:true});
  }catch(e){res.status(500).json({error:"Không thể xóa dữ liệu.",detail:e.message});}
});

app.listen(PORT,"0.0.0.0",()=>console.log("quanlydathang-api listening on "+PORT));
