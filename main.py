import os
import json
import csv
import bcrypt
import pyodbc
import requests
import traceback

from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import FastAPI, HTTPException, Depends, Security, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import RedirectResponse, FileResponse
from pydantic import BaseModel
from jose import jwt,JWTError, ExpiredSignatureError



# ======================================================
# AMBIENTE / VARIÁVEIS
# ======================================================

ENV = os.getenv("ENV", "production").lower()

# ⚠️ Só carrega .env se NÃO estiver no Azure
if ENV != "production":
    from dotenv import load_dotenv
    load_dotenv()

def get_env(name: str, required: bool = True, default=None):
    value = os.getenv(name, default)
    if required and not value:
        raise RuntimeError(f"Variável de ambiente obrigatória não configurada: {name}")
    return value

# ======================================================
# CONFIGURAÇÕES CRÍTICAS
# ======================================================

AZURE_SQL_CONN_STR = get_env("AZURE_SQL_CONN_STR")
JWT_SECRET = get_env("JWT_SECRET")
JWT_ALG = "HS256"
JWT_EXPIRES_MIN = int(get_env("JWT_EXPIRES_MIN", required=False, default="720"))

# ======================================================
# MERCADO LIVRE (opcional, mas inicializado com segurança)
# ======================================================

ML_CLIENT_ID = os.getenv("ML_CLIENT_ID", "")
ML_CLIENT_SECRET = os.getenv("ML_CLIENT_SECRET", "")
ML_REDIRECT_URI = os.getenv("ML_REDIRECT_URI", "")
ML_SELLER_ID = os.getenv("ML_SELLER_ID", "")
JOB_LOOKBACK_MIN = int(os.getenv("JOB_LOOKBACK_MIN", "120"))
ML_DISABLE_STATUS_UPDATES = os.getenv("ML_DISABLE_STATUS_UPDATES", "0") == "1"

ML_API = "https://api.mercadolibre.com"
ML_OAUTH_AUTH = "https://auth.mercadolivre.com.br/authorization"
ML_OAUTH_TOKEN = "https://api.mercadolibre.com/oauth/token"

# ======================================================
# FASTAPI APP
# ======================================================

app = FastAPI(
    title="LogMarket API",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# ======================================================
# CORS
# ======================================================


app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://orange-glacier-025d6730f.2.azurestaticapps.net",
        "https://logmarket.azurewebsites.net",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ======================================================
# DATABASE
# ======================================================

def db():
    try:
        return pyodbc.connect(AZURE_SQL_CONN_STR, timeout=5)
    except Exception as e:
        raise RuntimeError(f"Erro ao conectar no banco de dados: {str(e)}")

def utcnow_naive() -> datetime:
    return datetime.utcnow()

# =========================
# LOG INTERNO (SAFE)
# =========================
def log(tipo: str, mensagem: str, **kwargs):
    """
    Log seguro para não quebrar a aplicação.
    Pode ser expandido depois para gravar em tabela.
    """
    try:
        print(f"[{tipo}] {mensagem} | {kwargs}")
    except Exception:
        pass



# =========================
# AUTH
# =========================
class LoginIn(BaseModel):
    email: str
    senha: str


class CreateUserIn(BaseModel):
    nome: str
    email: str
    senha: str
    empresa_nome: str | None = None  # usado no bootstrap (opcional)



def create_token(payload: dict) -> str:
    exp = datetime.utcnow() + timedelta(minutes=JWT_EXPIRES_MIN)

    data = dict(payload)
    data["exp"] = int(exp.timestamp())  # ✅ timestamp UNIX

    return jwt.encode(
        data,
        JWT_SECRET,
        algorithm=JWT_ALG
    )


def verify_token(token: str) -> dict:
    try:
        payload = jwt.decode(
            token,
            JWT_SECRET,
            algorithms=[JWT_ALG],
            options={
                "verify_exp": True
            }
        )
        return payload

    except ExpiredSignatureError:
        raise HTTPException(
            status_code=401,
            detail="Token expirado."
        )

    except JWTError:
        raise HTTPException(
            status_code=401,
            detail="Token inválido."
        )


security = HTTPBearer()


def require_auth(credentials: HTTPAuthorizationCredentials = Security(security)):
    return verify_token(credentials.credentials)


def require_admin(credentials: HTTPAuthorizationCredentials = Security(security)):
    payload = verify_token(credentials.credentials)
    if payload.get("perfil") not in ("admin", "super_admin"):
        raise HTTPException(
            status_code=403,
            detail="Acesso restrito a administradores."
        )
    return payload


def require_super_admin(credentials: HTTPAuthorizationCredentials = Security(security)):
    payload = verify_token(credentials.credentials)
    if payload.get("perfil") != "super_admin":
        raise HTTPException(status_code=403, detail="Acesso restrito ao super administrador.")
    return payload


# =========================
# HEALTH
# =========================
@app.get("/health")
def health():
    return {"status": "ok"}


# =========================
# LOGIN
# =========================
@app.post("/auth/login")
def login_user(data: LoginIn):
    cn = db()
    cur = cn.cursor()

    cur.execute("""
        SELECT
            u.id,
            u.nome,
            u.email,
            u.senha_hash,
            u.perfil,
            u.ativo,
            u.empresa_id,
            e.ativo AS empresa_ativa
        FROM usuarios u
        LEFT JOIN empresas e ON e.id = u.empresa_id
        WHERE u.email = ?
    """, data.email)

    row = cur.fetchone()
    cn.close()

    # 1️⃣ Usuário existe e está ativo
    if not row or not bool(row[5]):
        raise HTTPException(status_code=401, detail="Usuário ou senha inválidos.")

    # 2️⃣ Valida senha
    senha_hash_db = row[3]
    if isinstance(senha_hash_db, str):
        senha_hash_db = senha_hash_db.encode("utf-8")

    if not bcrypt.checkpw(
        data.senha.encode("utf-8"),
        senha_hash_db
    ):
        raise HTTPException(status_code=401, detail="Usuário ou senha inválidos.")

    perfil = (row[4] or "usuario").strip().lower()
    empresa_id = row[6]
    empresa_ativa = row[7]

    # 3️⃣ Regra: só super_admin pode não ter empresa
    if perfil != "super_admin" and empresa_id is None:
        raise HTTPException(
            status_code=403,
            detail="Usuário sem empresa vinculada."
        )

    # 4️⃣ Regra: empresa precisa estar ativa
    if perfil != "super_admin" and not empresa_ativa:
        raise HTTPException(
            status_code=403,
            detail="Empresa inativa. Entre em contato com o administrador."
        )

    # 5️⃣ Gera token
    token_payload = {
        "sub": str(row[0]),
        "email": row[2],
        "nome": row[1],
        "perfil": perfil
    }

    if empresa_id is not None:
        token_payload["empresa_id"] = int(empresa_id)

    token = create_token(token_payload)

    return {
        "access_token": token,
        "user": {
            "id": int(row[0]),
            "nome": row[1],
            "email": row[2],
            "perfil": perfil,
            "empresa_id": empresa_id
        }
    }

   
# =========================
# SUPER ADMIN EMPRESAS
# =========================
class EmpresaIn(BaseModel):
    nome: str

@app.post("/empresas")
def criar_empresa(
    data: EmpresaIn,
    payload=Depends(require_super_admin)
):
    cn = db()
    cur = cn.cursor()

    cur.execute("""
        INSERT INTO empresas (nome, ativo)
        OUTPUT INSERTED.id
        VALUES (?, 1)
    """, data.nome)

    empresa_id = cur.fetchone()[0]
    cn.commit()
    cn.close()

    return {
        "empresa_id": empresa_id,
        "nome": data.nome
    }

# =========================
# SUPER ADMIN EMPRESAS - LISTAR
# =========================
@app.get("/empresas")
def listar_empresas(payload=Depends(require_super_admin)):
    cn = db()
    cur = cn.cursor()

    cur.execute("""
        SELECT
            id,
            nome,
            ativo,
            criado_em
        FROM dbo.empresas
        ORDER BY nome
    """)

    rows = cur.fetchall()
    cn.close()

    return [
        {
            "id": int(r.id),
            "nome": r.nome,
            "ativo": bool(r.ativo),
            "criado_em": r.criado_em.isoformat() if r.criado_em else None
        }
        for r in rows
    ]


# =========================
# SUPER ADMIN EMPRESAS - CRIAR USUARIO
# =========================

class CreateAdminIn(BaseModel):
    nome: str
    email: str
    senha: str


@app.post("/empresas/{empresa_id}/admin")
def criar_admin(
    empresa_id: int,
    data: CreateAdminIn,
    payload=Depends(require_super_admin)
):
    cn = db()
    cur = cn.cursor()

    senha_hash = bcrypt.hashpw(
        data.senha.encode("utf-8"),
        bcrypt.gensalt()
    ).decode("utf-8")

    cur.execute("""
        INSERT INTO usuarios (nome, email, senha_hash, perfil, ativo, empresa_id)
        VALUES (?, ?, ?, 'admin', 1, ?)
    """, data.nome, data.email, senha_hash, empresa_id)

    cn.commit()
    cn.close()

    return {"status": "admin criado"}

# =========================
# SUPER ADMIN - LISTAR ADMINS DA EMPRESA
# =========================
@app.get("/empresas/{empresa_id}/admins")
def listar_admins_empresa(
    empresa_id: int,
    payload=Depends(require_super_admin)
):
    cn = db()
    cur = cn.cursor()

    cur.execute("""
        SELECT id, nome, email, ativo, criado_em
        FROM usuarios
        WHERE empresa_id = ?
          AND perfil = 'admin'
        ORDER BY nome
    """, empresa_id)

    rows = cur.fetchall()
    cn.close()

    return [
        {
            "id": r.id,
            "nome": r.nome,
            "email": r.email,
            "ativo": bool(r.ativo),
            "criado_em": r.criado_em.isoformat() if r.criado_em else None
        }
        for r in rows
    ]

# =========================
# SUPER ADMIN - ATIVAR / INATIVAR EMPRESA
# =========================
@app.put("/empresas/{empresa_id}/status")
def alterar_status_empresa(
    empresa_id: int,
    payload: dict,
    user=Depends(require_super_admin)
):
    ativo = payload.get("ativo")

    if ativo is None:
        raise HTTPException(status_code=400, detail="Campo 'ativo' obrigatório")

    cn = db()
    cur = cn.cursor()

    cur.execute("""
        UPDATE empresas
        SET ativo = ?
        WHERE id = ?
    """, int(bool(ativo)), empresa_id)

    cn.commit()
    cn.close()

    return {"ok": True, "ativo": bool(ativo)}

# =========================
# SUPER ADMIN - ATIVAR / INATIVAR USUÁRIO
# =========================
@app.put("/usuarios/{user_id}/status")
def alterar_status_usuario(
    user_id: int,
    payload: dict,
    payload_user=Depends(require_super_admin)
):
    ativo = payload.get("ativo")

    if ativo is None:
        raise HTTPException(
            status_code=400,
            detail="Campo 'ativo' é obrigatório"
        )

    cn = db()
    cur = cn.cursor()

    cur.execute("""
        UPDATE usuarios
        SET ativo = ?
        WHERE id = ?
    """, int(bool(ativo)), user_id)

    if cur.rowcount == 0:
        cn.close()
        raise HTTPException(status_code=404, detail="Usuário não encontrado")

    cn.commit()
    cn.close()

    return {
        "ok": True,
        "ativo": bool(ativo)
    }

# =========================
# SUPER ADMIN - EDITAR USUÁRIO
# =========================
class UpdateUsuarioIn(BaseModel):
    nome: str
    email: str
    senha: str | None = None


@app.put("/usuarios/{user_id}")
def atualizar_usuario(
    user_id: int,
    data: UpdateUsuarioIn,
    payload=Depends(require_super_admin)
):
    cn = db()
    cur = cn.cursor()

    if data.senha:
        senha_hash = bcrypt.hashpw(
            data.senha.encode("utf-8"),
            bcrypt.gensalt()
        ).decode("utf-8")

        cur.execute("""
            UPDATE usuarios
            SET nome = ?, email = ?, senha_hash = ?
            WHERE id = ?
        """, data.nome, data.email, senha_hash, user_id)

    else:
        cur.execute("""
            UPDATE usuarios
            SET nome = ?, email = ?
            WHERE id = ?
        """, data.nome, data.email, user_id)

    if cur.rowcount == 0:
        cn.close()
        raise HTTPException(status_code=404, detail="Usuário não encontrado")

    cn.commit()
    cn.close()

    return {"ok": True}



# =========================
# USUÁRIOS (ADMIN ONLY)
# =========================
class CreateUserAdminIn(BaseModel):
    nome: str
    email: str
    senha: str
    perfil: str  # admin | usuario


class UpdateUserIn(BaseModel):
    nome: str
    email: str
    perfil: str
    ativo: bool


@app.get("/usuarios")
def listar_usuarios(payload=Depends(require_admin)):
    empresa_id = int(payload["empresa_id"])

    cn = db()
    cur = cn.cursor()

    # Lista somente usuários da mesma empresa (mais seguro em SaaS)
    cur.execute("""
        SELECT id, nome, email, perfil, ativo, criado_em, empresa_id
        FROM dbo.usuarios
        WHERE empresa_id = ?
        ORDER BY nome
    """, empresa_id)

    rows = cur.fetchall()
    cn.close()

    return [
        {
            "id": int(r.id),
            "nome": r.nome,
            "email": r.email,
            "perfil": (r.perfil or "").strip(),
            "ativo": bool(r.ativo),
            "empresa_id": int(r.empresa_id) if r.empresa_id is not None else None,
            "criado_em": r.criado_em.isoformat() if r.criado_em else None
        }
        for r in rows
    ]


@app.post("/usuarios")
def criar_usuario(data: CreateUserAdminIn, payload=Depends(require_admin)):
    empresa_id = int(payload["empresa_id"])

    perfil = data.perfil.strip().lower()
    if perfil not in ("admin", "usuario"):
        raise HTTPException(status_code=400, detail="Perfil inválido.")

    senha_hash = bcrypt.hashpw(
        data.senha.encode("utf-8"),
        bcrypt.gensalt()
    ).decode("utf-8")

    cn = db()
    cur = cn.cursor()

    try:
        cur.execute("""
            INSERT INTO dbo.usuarios (nome, email, senha_hash, perfil, ativo, empresa_id)
            VALUES (?,?,?,?,1,?)
        """, data.nome, data.email, senha_hash, perfil, empresa_id)
        cn.commit()
        return {"ok": True}
    except Exception as e:
        cn.rollback()
        raise HTTPException(status_code=400, detail=str(e))
    finally:
        cn.close()


@app.put("/usuarios/{user_id}")
def atualizar_usuario(user_id: int, data: UpdateUserIn, payload=Depends(require_admin)):
    empresa_id = int(payload["empresa_id"])

    cn = db()
    cur = cn.cursor()

    # Só permite alterar usuário da própria empresa
    cur.execute("SELECT id FROM dbo.usuarios WHERE id = ? AND empresa_id = ?", user_id, empresa_id)
    if not cur.fetchone():
        cn.close()
        raise HTTPException(status_code=404, detail="Usuário não encontrado nesta empresa.")

    cur.execute("""
        UPDATE dbo.usuarios
        SET nome = ?, email = ?, perfil = ?, ativo = ?
        WHERE id = ? AND empresa_id = ?
    """, data.nome, data.email, data.perfil, int(data.ativo), user_id, empresa_id)

    cn.commit()
    cn.close()
    return {"ok": True}


@app.delete("/usuarios/{user_id}")
def excluir_usuario(user_id: int, payload=Depends(require_admin)):
    empresa_id = int(payload["empresa_id"])

    cn = db()
    cur = cn.cursor()

    cur.execute("""
        UPDATE dbo.usuarios
        SET ativo = 0
        WHERE id = ? AND empresa_id = ?
    """, user_id, empresa_id)

    cn.commit()
    cn.close()
    return {"ok": True}


# Opcional: endpoint para criar o primeiro usuário (use uma vez e depois desabilite)
@app.post("/auth/bootstrap-user")
def bootstrap_user(data: CreateUserIn):
    key = os.getenv("BOOTSTRAP_KEY", "")
    if not key:
        raise HTTPException(status_code=403, detail="BOOTSTRAP_KEY não configurada.")

    # Cria empresa + cria usuário admin vinculado
    empresa_nome = (data.empresa_nome or "Minha Empresa").strip()

    senha_hash = bcrypt.hashpw(data.senha.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

    cn = db()
    cur = cn.cursor()
    try:
        # criar empresa
        cur.execute("INSERT INTO dbo.empresas (nome, ativo) VALUES (?, 1);", empresa_nome)
        cur.execute("SELECT SCOPE_IDENTITY();")
        empresa_id = int(cur.fetchone()[0])

        # criar usuário admin
        cur.execute("""
            INSERT INTO dbo.usuarios (nome, email, senha_hash, perfil, ativo, empresa_id)
            VALUES (?,?,?,?,1,?)
        """, data.nome, data.email, senha_hash, "admin", empresa_id)

        cn.commit()
    except Exception as e:
        cn.rollback()
        cn.close()
        raise HTTPException(status_code=400, detail=f"Falha ao criar bootstrap: {str(e)}")

    cn.close()
    return {"ok": True}

# =========================
# HELPER MERCADO LIVRE
# =========================

def extract_ml_sku_and_tipo(it: dict):
    """
    Extrai SKU e tipo de anúncio do Mercado Livre considerando:
    - Anúncios com variação
    - Anúncios de catálogo sem variação (SKU em attributes)
    """

    seller_sku = None

    # ============================
    # 1️⃣ SKU NAS VARIAÇÕES (PRIORIDADE)
    # ============================
    for v in it.get("variations", []) or []:
        sku = v.get("seller_custom_field")
        if sku:
            seller_sku = sku.strip()
            break

    # ============================
    # 2️⃣ SKU EM ATTRIBUTES (CATÁLOGO SEM VARIAÇÃO)
    # ============================
    if not seller_sku:
        for a in it.get("attributes", []) or []:
            if a.get("id") == "SELLER_SKU":
                val = a.get("value_name")
                if val:
                    seller_sku = val.strip()
                    break

    # ============================
    # 3️⃣ TIPO DE ANÚNCIO
    # ============================
    is_catalogo = bool(it.get("catalog_product_id"))
    tipo_anuncio = "CATALOGO" if is_catalogo else "LISTA"

    return seller_sku, is_catalogo, tipo_anuncio

# =========================
# BUSCAR FULL MERCADO LIVRE
# =========================

def extract_ml_logistica(item: dict):
    shipping = item.get("shipping") or {}
    logistic_type = shipping.get("logistic_type")
    is_full = logistic_type == "fulfillment"

    return logistic_type, is_full



def auto_vincular_sku_por_seller_sku(
    cur,
    empresa_id: int,
    sku_id: int,
    sku_codigo: str
) -> tuple[int, list[str]]:
    """
    Vincula automaticamente anúncios do ML ao SKU
    usando seller_sku = sku.codigo

    Retorna:
    - quantidade de vínculos criados
    - lista de ml_item_id vinculados
    """

    cur.execute("""
        SELECT ml_item_id
        FROM dbo.ml_anuncios_cache
        WHERE empresa_id = ?
          AND seller_sku = ?
    """, empresa_id, sku_codigo)

    itens = [r.ml_item_id for r in cur.fetchall()]

    vinculados = 0
    vinculados_ids = []

    for ml_item_id in itens:
        # não sobrescreve vínculo existente (manual ou auto)
        cur.execute("""
            SELECT 1
            FROM dbo.sku_anuncios
            WHERE ml_item_id = ?
        """, ml_item_id)

        if cur.fetchone():
            continue

        cur.execute("""
            INSERT INTO dbo.sku_anuncios (
                sku_id,
                ml_item_id,
                origem_vinculo
            )
            VALUES (?, ?, 'AUTO')
        """, sku_id, ml_item_id)

        vinculados += 1
        vinculados_ids.append(ml_item_id)

    return vinculados, vinculados_ids

# =========================
# INTEGRAÇÕES — MERCADO LIVRE (OAuth + Refresh)
# =========================

def ml_oauth_url(state: str) -> str:
    if not ML_CLIENT_ID or not ML_REDIRECT_URI:
        raise HTTPException(status_code=500, detail="ML_CLIENT_ID / ML_REDIRECT_URI não configurados.")
    return (
        f"{ML_OAUTH_AUTH}"
        f"?response_type=code"
        f"&client_id={ML_CLIENT_ID}"
        f"&redirect_uri={ML_REDIRECT_URI}"
        f"&state={state}"
    )


@app.get("/integracoes/mercadolivre/status")
def ml_status(payload=Depends(require_auth)):
    empresa_id = int(payload["empresa_id"])

    cn = db()
    cur = cn.cursor()
    cur.execute("""
        SELECT TOP 1 nickname, ml_user_id, expires_at
        FROM dbo.integracoes_mercadolivre
        WHERE empresa_id = ?
        ORDER BY id DESC
    """, empresa_id)

    row = cur.fetchone()
    cn.close()

    if not row:
        return {"connected": False}

    expires_at = row.expires_at
    expired = False
    if expires_at:
        expired = expires_at < utcnow_naive()

    return {
        "connected": True,
        "nickname": row.nickname,
        "ml_user_id": row.ml_user_id,
        "expires_at": expires_at.isoformat() if expires_at else None,
        "expired": expired
    }


@app.get("/integracoes/mercadolivre/auth")
def ml_auth(payload=Depends(require_auth)):
    # state = empresa_id (modelo correto SaaS)
    empresa_id = int(payload["empresa_id"])
    return {"url": ml_oauth_url(str(empresa_id))}


@app.get("/integracoes/mercadolivre/callback")
def ml_callback(code: str, state: str):
    # state = empresa_id
    if not ML_CLIENT_ID or not ML_CLIENT_SECRET or not ML_REDIRECT_URI:
        raise HTTPException(status_code=500, detail="ML_CLIENT_ID / ML_CLIENT_SECRET / ML_REDIRECT_URI não configurados.")

    try:
        empresa_id = int(state)
    except Exception:
        raise HTTPException(status_code=400, detail="State inválido (empresa_id).")

    r = requests.post(ML_OAUTH_TOKEN, data={
        "grant_type": "authorization_code",
        "client_id": ML_CLIENT_ID,
        "client_secret": ML_CLIENT_SECRET,
        "code": code,
        "redirect_uri": ML_REDIRECT_URI,
    }, timeout=30)

    if r.status_code != 200:
        raise HTTPException(status_code=400, detail=r.text)

    data = r.json()
    access_token = data["access_token"]
    refresh_token = data["refresh_token"]
    expires_in = int(data.get("expires_in") or 0)

    me = requests.get(
        f"{ML_API}/users/me",
        headers={"Authorization": f"Bearer {access_token}"},
        timeout=30
    ).json()

    cn = db()
    cur = cn.cursor()

    cur.execute("""
        MERGE dbo.integracoes_mercadolivre AS t
        USING (SELECT ? AS empresa_id) s
        ON t.empresa_id = s.empresa_id
        WHEN MATCHED THEN UPDATE SET
            ml_user_id = ?,
            nickname = ?,
            access_token = ?,
            refresh_token = ?,
            expires_at = DATEADD(second, ?, SYSUTCDATETIME()),
            atualizado_em = SYSUTCDATETIME()
        WHEN NOT MATCHED THEN INSERT
            (empresa_id, ml_user_id, nickname, access_token, refresh_token, expires_at)
        VALUES (?, ?, ?, ?, ?, DATEADD(second, ?, SYSUTCDATETIME()));
    """,
    empresa_id,
    me.get("id"), me.get("nickname"), access_token, refresh_token, expires_in,
    empresa_id, me.get("id"), me.get("nickname"), access_token, refresh_token, expires_in)

    cn.commit()
    cn.close()

    # Ajuste para sua rota real do front
    return RedirectResponse(url="https://orange-glacier-025d6730f.2.azurestaticapps.net/integracoes.html")


# ---------- Token válido (refresh automático) ----------
def get_ml_token(empresa_id: int) -> str:
    cn = db()
    cur = cn.cursor()

    cur.execute("""
        SELECT access_token, refresh_token, expires_at
        FROM dbo.integracoes_mercadolivre
        WHERE empresa_id = ?
    """, empresa_id)

    row = cur.fetchone()
    if not row:
        cn.close()
        raise HTTPException(status_code=400, detail="Conta Mercado Livre não conectada.")

    access_token, refresh_token, expires_at = row

    # margem de 2 min para evitar expirar no meio de uma chamada
    if expires_at and expires_at > utcnow_naive() + timedelta(minutes=2):
        cn.close()
        return access_token

    # Refresh token
    if not refresh_token:
        cn.close()
        raise HTTPException(status_code=401, detail="Refresh token ausente. Reconecte o Mercado Livre.")

    r = requests.post(ML_OAUTH_TOKEN, data={
        "grant_type": "refresh_token",
        "client_id": ML_CLIENT_ID,
        "client_secret": ML_CLIENT_SECRET,
        "refresh_token": refresh_token
    }, timeout=30)

    if r.status_code != 200:
        cn.close()
        raise HTTPException(status_code=401, detail=f"Falha ao renovar token do Mercado Livre: {r.text}")

    data = r.json()
    new_access = data["access_token"]
    new_refresh = data.get("refresh_token") or refresh_token
    expires_in = int(data.get("expires_in") or 0)

    cur.execute("""
        UPDATE dbo.integracoes_mercadolivre
        SET access_token = ?,
            refresh_token = ?,
            expires_at = DATEADD(second, ?, SYSUTCDATETIME()),
            atualizado_em = SYSUTCDATETIME()
        WHERE empresa_id = ?
    """, new_access, new_refresh, expires_in, empresa_id)

    cn.commit()
    cn.close()

    return new_access


def ml_headers_empresa(empresa_id: int) -> dict:
    token = get_ml_token(empresa_id)
    return {"Authorization": f"Bearer {token}"}


def ml_get_empresa(url: str, empresa_id: int, params=None):
    r = requests.get(
        url,
        headers=ml_headers_empresa(empresa_id),
        params=params,
        timeout=30
    )
    if r.status_code >= 400:
        raise HTTPException(status_code=502, detail=f"Erro ML GET: {r.status_code} - {r.text[:800]}")
    return r.json()


def ml_put_empresa(url: str, empresa_id: int, payload: dict):
    r = requests.put(
        url,
        headers={**ml_headers_empresa(empresa_id), "Content-Type": "application/json"},
        json=payload,
        timeout=30
    )
    if r.status_code >= 400:
        raise HTTPException(status_code=502, detail=f"Erro ML PUT: {r.status_code} - {r.text[:800]}")
    return r.json()


def ml_me(empresa_id: int):
    return ml_get_empresa(f"{ML_API}/users/me", empresa_id=empresa_id)


# ---- STATUS PT ----
_STATUS_PT = {
    "active": "ativo",
    "paused": "pausado",
    "closed": "encerrado",
    "under_review": "em análise",
    "inactive": "inativo",
    "not_yet_active": "ainda não ativo",
}


def status_pt(ml_status: str | None) -> str | None:
    if ml_status is None:
        return None
    return _STATUS_PT.get(ml_status, ml_status)


def ml_list_all_item_ids(user_id: int, empresa_id: int, limit=50, hard_limit=5000):
    item_ids = []
    offset = 0

    while True:
        data = ml_get_empresa(
            f"{ML_API}/users/{user_id}/items/search",
            empresa_id=empresa_id,
            params={
                "limit": limit,
                "offset": offset
            }
        )

        results = data.get("results", [])
        if not results:
            break

        item_ids.extend(results)

        offset += limit
        if offset >= hard_limit:
            break

    return list(dict.fromkeys(item_ids))



def ml_fetch_items_batch(item_ids: list[str], empresa_id: int):
    if not item_ids:
        return []

    out = []
    for i in range(0, len(item_ids), 20):
        ch = item_ids[i:i + 20]
        ids = ",".join(ch)
        data = ml_get_empresa(f"{ML_API}/items", empresa_id=empresa_id, params={"ids": ids})

        for e in data:
            if e.get("code") == 200 and e.get("body"):
                out.append(e["body"])

    uniq = {}
    for it in out:
        iid = it.get("id")
        if iid:
            uniq[iid] = it
    return list(uniq.values())


def ml_pause_item(item_id: str, empresa_id: int):
    if ML_DISABLE_STATUS_UPDATES:
        raise HTTPException(status_code=400, detail="Operação de pausar/ativar desabilitada (ML_DISABLE_STATUS_UPDATES=1).")
    return ml_put_empresa(f"{ML_API}/items/{item_id}", empresa_id=empresa_id, payload={"status": "paused"})


def ml_activate_item(item_id: str, empresa_id: int):
    if ML_DISABLE_STATUS_UPDATES:
        raise HTTPException(status_code=400, detail="Operação de pausar/ativar desabilitada (ML_DISABLE_STATUS_UPDATES=1).")
    return ml_put_empresa(f"{ML_API}/items/{item_id}", empresa_id=empresa_id, payload={"status": "active"})


def _parse_ml_dt(dt_str: str) -> datetime:
    if not dt_str:
        return datetime.now(timezone.utc)
    try:
        return datetime.fromisoformat(dt_str.replace("Z", "+00:00"))
    except Exception:
        return datetime.now(timezone.utc)


def ml_fetch_paid_orders_since(dt_from: datetime, empresa_id: int, hard_limit=1000) -> list[dict]:
    if not ML_SELLER_ID:
        raise HTTPException(status_code=400, detail="ML_SELLER_ID não configurado.")

    results = []
    offset = 0
    limit = 50

    while True:
        params = {
            "seller": ML_SELLER_ID,
            "order.status": "paid",
            "sort": "date_desc",
            "limit": limit,
            "offset": offset
        }
        data = ml_get_empresa(f"{ML_API}/orders/search", empresa_id=empresa_id, params=params)
        page = data.get("results", []) or []
        if not page:
            break

        stop = False
        for order in page:
            dc = _parse_ml_dt(order.get("date_created", ""))
            if dc >= dt_from:
                results.append(order)
            else:
                stop = True
                break

        if stop:
            break

        offset += limit
        if offset >= hard_limit:
            break

    return results


# ============== SKU APIs ==============
class SkuCreateIn(BaseModel):
    codigo: str
    nome: str
    estoque_central: int
    estoque_minimo: int




class SkuUpdateIn(BaseModel):
    estoque_central: int | None = None
    estoque_minimo: int | None = None



class LinkItemIn(BaseModel):
    ml_item_id: str
    variacao_id: str | None = None


@app.get("/sku")
def list_skus(payload=Depends(require_auth)):
    empresa_id = int(payload["empresa_id"])

    cn = db()
    cur = cn.cursor()

    cur.execute("""
        SELECT
            id,
            codigo,
            nome,
            estoque_central,
            estoque_minimo
        FROM dbo.sku
        WHERE ativo = 1
          AND empresa_id = ?
        ORDER BY codigo
    """, empresa_id)

    rows = cur.fetchall()
    cn.close()

    return [
        {
            "id": int(r.id),
            "codigo": r.codigo,
            "nome": r.nome,
            "estoque_central": int(r.estoque_central or 0),
            "estoque_minimo": int(r.estoque_minimo or 0)
        }
        for r in rows
    ]



@app.post("/sku")
def create_sku(data: SkuCreateIn, payload=Depends(require_auth)):
    empresa_id = int(payload["empresa_id"])

    codigo = (data.codigo or "").strip()
    nome = (data.nome or "").strip()
    estoque_minimo = int(data.estoque_minimo)
    estoque_central = int(data.estoque_central)

    if not codigo:
        raise HTTPException(status_code=400, detail="Código do SKU é obrigatório.")

    if estoque_minimo < 0:
        raise HTTPException(status_code=400, detail="Estoque mínimo inválido.")

    if estoque_central < 0:
        raise HTTPException(status_code=400, detail="Estoque central inválido.")

    cn = db()
    cur = cn.cursor()

    try:
        # 🔍 Verifica SKU existente
        cur.execute("""
            SELECT id, ativo
            FROM dbo.sku
            WHERE codigo = ?
              AND empresa_id = ?
        """, codigo, empresa_id)

        row = cur.fetchone()

        # ==========================================
        # 🔁 SKU EXISTE
        # ==========================================
        if row:
            sku_id = int(row.id)
            ativo = int(row.ativo)

            if ativo == 1:
                raise HTTPException(status_code=400, detail="SKU já existe (ativo).")

            # 🔄 Reativar SKU
            cur.execute("""
                UPDATE dbo.sku
                SET nome = ?,
                    estoque_minimo = ?,
                    estoque_central = ?,
                    ativo = 1,
                    atualizado_em = SYSUTCDATETIME()
                WHERE id = ?
                  AND empresa_id = ?
            """,
                nome,
                estoque_minimo,
                estoque_central,
                sku_id,
                empresa_id
            )

            # 🔗 vínculo automático
            auto_vinculados, auto_vinculados_ids = auto_vincular_sku_por_seller_sku(
                  cur,
                  empresa_id,
                  sku_id,
                  codigo
              )

            cn.commit()

            log(
                "CREATE",
                f"SKU reativado com estoque {estoque_central}",
                sku_id=sku_id,
                auto_vinculados=auto_vinculados
            )

            return {
              "ok": True,
              "reativado": True,
              "sku_id": sku_id,
              "auto_vinculados": auto_vinculados,
              "auto_vinculos": auto_vinculados_ids
          }


        # ==========================================
        # ➕ NOVO SKU
        # ==========================================
        cur.execute("""
            INSERT INTO dbo.sku (
                codigo,
                nome,
                estoque_minimo,
                estoque_central,
                ativo,
                empresa_id,
                atualizado_em
            )
            OUTPUT INSERTED.id
            VALUES (?,?,?,?,1,?,SYSUTCDATETIME())
        """,
            codigo,
            nome,
            estoque_minimo,
            estoque_central,
            empresa_id
        )

        sku_id = int(cur.fetchone()[0])

        # 🔗 vínculo automático
        auto_vinculados, auto_vinculados_ids = auto_vincular_sku_por_seller_sku(
              cur,
              empresa_id,
              sku_id,
              codigo
          )


        cn.commit()

        log(
            "CREATE",
            f"SKU criado com estoque {estoque_central}",
            sku_id=sku_id,
            auto_vinculados=auto_vinculados
        )

        return {
            "ok": True,
            "reativado": False,
            "sku_id": sku_id,
            "auto_vinculados": auto_vinculados,
            "auto_vinculos": auto_vinculados_ids
        }



    except HTTPException:
        cn.rollback()
        raise

    except Exception as e:
        cn.rollback()
        raise HTTPException(status_code=400, detail=str(e))

    finally:
        cn.close()



@app.put("/sku/{sku_id}")
def update_sku(sku_id: int, data: SkuUpdateIn, payload=Depends(require_auth)):
    cn = db()
    cur = cn.cursor()

    cur.execute(
        "SELECT id FROM dbo.sku WHERE id = ? AND ativo = 1",
        sku_id
    )
    if not cur.fetchone():
        cn.close()
        raise HTTPException(status_code=404, detail="SKU não encontrado.")

    campos = []
    valores = []

    if data.estoque_central is not None:
        if data.estoque_central < 0:
            raise HTTPException(status_code=400, detail="Estoque central inválido.")
        campos.append("estoque_central = ?")
        valores.append(int(data.estoque_central))

    if data.estoque_minimo is not None:
        if data.estoque_minimo < 0:
            raise HTTPException(status_code=400, detail="Estoque mínimo inválido.")
        campos.append("estoque_minimo = ?")
        valores.append(int(data.estoque_minimo))

    if not campos:
        cn.close()
        raise HTTPException(status_code=400, detail="Nenhum campo para atualizar.")

    sql = f"""
        UPDATE dbo.sku
        SET {', '.join(campos)},
            atualizado_em = SYSUTCDATETIME()
        WHERE id = ?
    """

    try:
        cur.execute(sql, *valores, sku_id)
        cn.commit()

        log(
            "AJUSTE",
            f"Atualização SKU: {', '.join(campos)}",
            sku_id=sku_id
        )

        return {"ok": True}

    except Exception as e:
        cn.rollback()
        raise HTTPException(status_code=400, detail=str(e))
    finally:
        cn.close()


@app.delete("/sku/{sku_id}")
def delete_sku(sku_id: int, payload=Depends(require_auth)):
    cn = db()
    cur = cn.cursor()

    cur.execute("SELECT id FROM dbo.sku WHERE id = ? AND ativo = 1", sku_id)
    if not cur.fetchone():
        cn.close()
        raise HTTPException(status_code=404, detail="SKU não encontrado ou já excluído.")

    cur.execute("SELECT TOP 1 1 FROM dbo.sku_anuncios WHERE sku_id = ?", sku_id)
    if cur.fetchone():
        cn.close()
        raise HTTPException(status_code=400, detail="Este SKU não pode ser excluído pois possui anúncios vinculados.")

    try:
        cur.execute("""
            UPDATE dbo.sku
            SET ativo = 0, atualizado_em = SYSUTCDATETIME()
            WHERE id = ?
        """, sku_id)
        cn.commit()
        log("AJUSTE", "SKU excluído (soft delete)", sku_id=sku_id)
        return {"ok": True}
    except Exception as e:
        cn.rollback()
        raise HTTPException(status_code=400, detail=f"Erro ao excluir SKU: {str(e)}")
    finally:
        cn.close()


# ============================
# VÍNCULOS SKU <-> ANÚNCIOS
# ============================
@app.get("/sku/{sku_id}/anuncios")
def list_sku_anuncios(sku_id: int, payload=Depends(require_auth)):
    cn = db()
    cur = cn.cursor()

    cur.execute("SELECT id FROM dbo.sku WHERE id = ? AND ativo = 1", sku_id)
    if not cur.fetchone():
        cn.close()
        raise HTTPException(status_code=404, detail="SKU não encontrado.")

    cur.execute("""
        SELECT ml_item_id, variacao_id
        FROM dbo.sku_anuncios
        WHERE sku_id = ?
        ORDER BY ml_item_id
    """, sku_id)
    rows = cur.fetchall()
    cn.close()

    return [{"ml_item_id": r.ml_item_id, "variacao_id": r.variacao_id} for r in rows]


@app.post("/sku/{sku_id}/vincular")
def vincular_anuncio(sku_id: int, data: LinkItemIn, payload=Depends(require_auth)):
    ml_item_id = (data.ml_item_id or "").strip()
    variacao_id = (data.variacao_id or "").strip() if data.variacao_id else None

    if not ml_item_id:
        raise HTTPException(status_code=400, detail="ml_item_id é obrigatório.")

    cn = db()
    cur = cn.cursor()

    cur.execute("SELECT id FROM dbo.sku WHERE id = ? AND ativo = 1", sku_id)
    if not cur.fetchone():
        cn.close()
        raise HTTPException(status_code=404, detail="SKU não encontrado.")

    try:
        cur.execute("SELECT TOP 1 sku_id FROM dbo.sku_anuncios WHERE ml_item_id = ?", ml_item_id)
        row = cur.fetchone()

        if row:
            cur.execute("""
                UPDATE dbo.sku_anuncios
                  SET
                      sku_id = ?,
                      variacao_id = ?,
                      origem_vinculo = 'MANUAL'
                  WHERE ml_item_id = ?
            """, sku_id, variacao_id, ml_item_id)
            cn.commit()
            log("AJUSTE", f"Vínculo atualizado: {ml_item_id} -> sku_id={sku_id}", sku_id=sku_id, ml_item_id=ml_item_id)
            return {"ok": True, "updated": True}

        cur.execute("""
            INSERT INTO dbo.sku_anuncios (
                  sku_id,
                  ml_item_id,
                  variacao_id,
                  origem_vinculo
              )
              VALUES (?, ?, ?, 'MANUAL')
        """, sku_id, ml_item_id, variacao_id, )

        cn.commit()
        log("AJUSTE", f"Vinculado anúncio {ml_item_id}", sku_id=sku_id, ml_item_id=ml_item_id)
        return {"ok": True, "updated": False}

    except Exception as e:
        cn.rollback()
        raise HTTPException(status_code=400, detail=f"Falha ao vincular anúncio: {str(e)}")
    finally:
        cn.close()

# =========================
# JOBS (FILA NO BANCO) — UPGRADE 3 (Parte A)
# =========================

JOB_STATUS_PENDENTE = "PENDENTE"
JOB_STATUS_PROCESSANDO = "PROCESSANDO"
JOB_STATUS_SUCESSO = "SUCESSO"
JOB_STATUS_ERRO = "ERRO"


def job_create(tipo: str, empresa_id: int) -> int:
    cn = db()
    cur = cn.cursor()

    cur.execute("""
        INSERT INTO dbo.ml_jobs (empresa_id, tipo, status)
        OUTPUT INSERTED.id
        VALUES (?, ?, ?);
    """, empresa_id, tipo, JOB_STATUS_PENDENTE)

    row = cur.fetchone()
    cn.commit()
    cn.close()

    if not row or row[0] is None:
        raise Exception("Falha ao obter job_id (OUTPUT INSERTED.id retornou NULL)")

    return int(row[0])

def job_set_processing(job_id: int):
    cn = db()
    cur = cn.cursor()
    cur.execute("""
        UPDATE dbo.ml_jobs
        SET status = ?, iniciado_em = SYSUTCDATETIME(), erro = NULL
        WHERE id = ?;
    """, JOB_STATUS_PROCESSANDO, job_id)
    cn.commit()
    cn.close()


def job_set_success(job_id: int, resultado: dict | None = None):
    cn = db()
    cur = cn.cursor()
    resultado_json = json.dumps(resultado or {}, ensure_ascii=False)
    cur.execute("""
        UPDATE dbo.ml_jobs
        SET status = ?, finalizado_em = SYSUTCDATETIME(), resultado_json = ?, erro = NULL
        WHERE id = ?;
    """, JOB_STATUS_SUCESSO, resultado_json, job_id)
    cn.commit()
    cn.close()


def job_set_error(job_id: int, err_msg: str):
    cn = db()
    cur = cn.cursor()
    # limita para não estourar tamanho em logs
    err_msg = (err_msg or "")[:4000]
    cur.execute("""
        UPDATE dbo.ml_jobs
        SET status = ?, finalizado_em = SYSUTCDATETIME(), erro = ?
        WHERE id = ?;
    """, JOB_STATUS_ERRO, err_msg, job_id)
    cn.commit()
    cn.close()


def job_get(job_id: int, empresa_id: int) -> dict | None:
    cn = db()
    cur = cn.cursor()
    cur.execute("""
        SELECT id, empresa_id, tipo, status, criado_em, iniciado_em, finalizado_em, resultado_json, erro
        FROM dbo.ml_jobs
        WHERE id = ? AND empresa_id = ?;
    """, job_id, empresa_id)
    r = cur.fetchone()
    cn.close()

    if not r:
        return None

    return {
        "id": int(r.id),
        "empresa_id": int(r.empresa_id),
        "tipo": r.tipo,
        "status": r.status,
        "criado_em": r.criado_em.isoformat() if r.criado_em else None,
        "iniciado_em": r.iniciado_em.isoformat() if r.iniciado_em else None,
        "finalizado_em": r.finalizado_em.isoformat() if r.finalizado_em else None,
        "resultado": json.loads(r.resultado_json) if r.resultado_json else None,
        "erro": r.erro
    }



# ============================
# PROCESSO EM BACKGROUND
# ============================
def worker_sync_anuncios(job_id: int, empresa_id: int):
    job_set_processing(job_id)

    try:
        me = ml_me(empresa_id)
        user_id = me["id"]

        item_ids = ml_list_all_item_ids(
            user_id=user_id,
            empresa_id=empresa_id,
            limit=50
        )

        base_items = ml_fetch_items_batch(item_ids, empresa_id=empresa_id)

        cn = db()
        cur = cn.cursor()

        # LIMPA CACHE
        cur.execute("""
            DELETE FROM dbo.ml_anuncios_cache
            WHERE empresa_id = ?;
        """, empresa_id)

        for it_base in base_items:
            # 🔹 ITEM COMPLETO (NECESSÁRIO PARA FULL)
            it = ml_get_item_full(it_base["id"], empresa_id)

            seller_sku, is_catalogo, tipo_anuncio = extract_ml_sku_and_tipo(it)
            logistic_type, is_full = extract_ml_logistica(it)

            if not seller_sku:
                log(
                    "WARN",
                    "Anúncio sem seller_sku",
                    ml_item_id=it.get("id"),
                    titulo=it.get("title"),
                    logistic_type=logistic_type
                )

            cur.execute("""
                INSERT INTO dbo.ml_anuncios_cache (
                    empresa_id,
                    ml_item_id,
                    titulo,
                    seller_sku,
                    is_catalogo,
                    tipo_anuncio,
                    status,
                    status_raw,
                    preco,
                    estoque_ml,
                    logistic_type,
                    is_full,
                    atualizado_em
                )
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,SYSUTCDATETIME())
            """,
                empresa_id,
                it.get("id"),
                it.get("title"),
                seller_sku,
                int(is_catalogo),
                tipo_anuncio,
                status_pt(it.get("status")),
                it.get("status"),
                it.get("price"),
                it.get("available_quantity"),
                logistic_type,
                1 if is_full else 0
            )

        cn.commit()
        cn.close()

        job_set_success(job_id, {
            "ml_user_id": user_id,
            "total_anuncios": len(base_items),
            "sincronizado_em": utcnow_naive().isoformat()
        })

    except Exception as e:
        job_set_error(job_id, str(e))

# ============================
# LISTAR ANÚNCIOS DO ML
# ============================
@app.get("/ml/anuncios")
def ml_anuncios(payload=Depends(require_auth)):
    empresa_id = int(payload["empresa_id"])

    cn = db()
    cur = cn.cursor()

    # ============================
    # CACHE DE ANÚNCIOS (ML)
    # ============================
    cur.execute("""
        SELECT
            mac.ml_item_id,
            mac.titulo,
            mac.seller_sku,
            mac.tipo_anuncio,
            mac.is_catalogo,
            mac.status,
            mac.status_raw,
            mac.preco,
            mac.estoque_ml,
            mac.is_full,
            mac.logistic_type,
            sa.origem_vinculo
        FROM dbo.ml_anuncios_cache mac
        LEFT JOIN dbo.sku_anuncios sa
          ON sa.ml_item_id = mac.ml_item_id
         AND sa.sku_id IS NOT NULL
        WHERE mac.empresa_id = ?
        ORDER BY mac.titulo;
    """, empresa_id)

    anuncios = cur.fetchall()

    # ============================
    # VÍNCULOS SKU
    # ============================
    cur.execute("""
        SELECT
            sa.ml_item_id,
            s.codigo,
            s.nome,
            s.estoque_central
        FROM dbo.sku_anuncios sa
        JOIN dbo.sku s ON s.id = sa.sku_id
        WHERE s.ativo = 1;
    """)

    vinc = {}
    for r in cur.fetchall():
        vinc[str(r.ml_item_id)] = {
            "sku_codigo": r.codigo,
            "sku_nome": r.nome,
            "estoque_central": int(r.estoque_central or 0)
        }

    cn.close()

    # ============================
    # SERIALIZAÇÃO FINAL
    # ============================
    out = []
    for a in anuncios:
        out.append({
            "ml_item_id": a.ml_item_id,
            "titulo": a.titulo,
            "seller_sku": a.seller_sku,
            "tipo_anuncio": a.tipo_anuncio,
            "is_catalogo": bool(a.is_catalogo),
            "status": a.status,
            "status_raw": a.status_raw,
            "estoque_ml": a.estoque_ml,
            "preco": a.preco,

            # 🔥 NOVOS CAMPOS FULL
            "is_full": bool(a.is_full),
            "logistic_type": a.logistic_type,

            # SKU VINCULADO
            "sku": vinc.get(str(a.ml_item_id))
        })

    return out



@app.post("/ml/anuncios/sync")
def ml_anuncios_sync(payload=Depends(require_auth)):
    empresa_id = int(payload["empresa_id"])

    try:
        me = ml_me(empresa_id)
        user_id = me["id"]

        item_ids = ml_list_all_item_ids(
            user_id=user_id,
            empresa_id=empresa_id,
            limit=50
        )

        items = ml_fetch_items_batch(item_ids, empresa_id=empresa_id)

        cn = db()
        cur = cn.cursor()

        # Limpa cache anterior
        cur.execute(
            "DELETE FROM dbo.ml_anuncios_cache WHERE empresa_id = ?",
            empresa_id
        )

        # 🔁 LOOP CORRETO
        for it in items:
            seller_sku, is_catalogo, tipo_anuncio = extract_ml_sku_and_tipo(it)

            cur.execute("""
                INSERT INTO dbo.ml_anuncios_cache (
                    empresa_id,
                    ml_item_id,
                    titulo,
                    seller_sku,
                    is_catalogo,
                    tipo_anuncio,
                    status,
                    status_raw,
                    preco,
                    estoque_ml,
                    atualizado_em
                )
                VALUES (?,?,?,?,?,?,?,?,?,?,SYSUTCDATETIME())
            """,
            empresa_id,
            it.get("id"),
            it.get("title"),
            seller_sku,
            int(is_catalogo),
            tipo_anuncio,
            status_pt(it.get("status")),
            it.get("status"),
            it.get("price"),
            it.get("available_quantity")
            )

        cn.commit()
        cn.close()

        return {
            "ok": True,
            "empresa_id": empresa_id,
            "total": len(items),
            "atualizado_em": utcnow_naive().isoformat()
        }

    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"ERRO REAL NO SYNC: {str(e)}"
        )


@app.get("/jobs/{job_id}")
def get_job(job_id: int, payload=Depends(require_auth)):
    empresa_id = int(payload["empresa_id"])

    job = job_get(job_id, empresa_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job não encontrado para esta empresa.")

    return job



# ============================
# SINCRONIZAR (STATUS) — mantém como estava
# ============================
@app.post("/sku/{sku_id}/sincronizar")
def sync_sku_stock(sku_id: int, payload=Depends(require_auth)):
    empresa_id = int(payload["empresa_id"])

    cn = db()
    cur = cn.cursor()
    cur.execute("SELECT estoque_central, codigo FROM dbo.sku WHERE id = ? AND ativo = 1", sku_id)
    sku = cur.fetchone()
    if not sku:
        cn.close()
        raise HTTPException(status_code=404, detail="SKU não encontrado.")

    estoque = int(sku.estoque_central or 0)

    cur.execute("SELECT ml_item_id, variacao_id FROM dbo.sku_anuncios WHERE sku_id = ?", sku_id)
    itens = cur.fetchall()
    cn.close()

    if not itens:
        raise HTTPException(status_code=400, detail="Nenhum anúncio vinculado a este SKU.")

    ok_count = 0
    fail = []

    for r in itens:
        item_id = r.ml_item_id
        try:
            if estoque <= 0:
                ml_pause_item(item_id, empresa_id=empresa_id)
                log("SYNC", "Estoque=0 -> anúncio pausado", sku_id=sku_id, ml_item_id=item_id)
            else:
                ml_activate_item(item_id, empresa_id=empresa_id)
                log("SYNC", "Estoque>0 -> anúncio ativado", sku_id=sku_id, ml_item_id=item_id)

            ok_count += 1
        except Exception as e:
            fail.append({"ml_item_id": item_id, "erro": str(e)})
            log("ERRO", f"Falha ao aplicar status: {str(e)}", sku_id=sku_id, ml_item_id=item_id)

    return {"ok": True, "aplicados": ok_count, "estoque_central": estoque, "falhas": fail}


# ============================
# JOB DE VENDAS (PRODUÇÃO) — mantém como estava
# ============================
def get_last_run(cur) -> Optional[datetime]:
    cur.execute("SELECT ultima_execucao FROM dbo.ml_job_controle WHERE id = 1;")
    row = cur.fetchone()
    return row[0] if row else None


def set_last_run(cur, dt_utc: datetime):
    cur.execute(
        "UPDATE dbo.ml_job_controle SET ultima_execucao = ? WHERE id = 1;",
        dt_utc
    )


def already_processed(cur, empresa_id: int, order_id: str, item_id: str) -> bool:
    cur.execute("""
        SELECT 1
        FROM dbo.ml_vendas_processadas
        WHERE empresa_id = ?
          AND ml_order_id = ?
          AND ml_item_id = ?;
    """, empresa_id, order_id, item_id)
    return cur.fetchone() is not None


def mark_processed(cur, empresa_id: int, order_id: str, ml_item_id: str, qty: int):
    cur.execute("""
        INSERT INTO dbo.ml_vendas_processadas
          (empresa_id, ml_order_id, ml_item_id, quantidade)
        VALUES (?,?,?,?);
    """, empresa_id, order_id, ml_item_id, qty)


def get_sku_id_by_item(cur, ml_item_id: str) -> Optional[int]:
    cur.execute("""
        SELECT TOP 1 sku_id
        FROM dbo.sku_anuncios
        WHERE ml_item_id = ?;
    """, ml_item_id)
    r = cur.fetchone()
    return int(r[0]) if r else None

def buscar_ultimo_job(tipo: str, empresa_id: int):
    cn = db()
    cur = cn.cursor()

    cur.execute("""
        SELECT TOP 1
          finalizado_em,
          JSON_VALUE(resultado_json, '$.dt_from') AS dt_from
        FROM dbo.ml_jobs
        WHERE tipo = ?
          AND empresa_id = ?
          AND status = 'SUCESSO'
        ORDER BY finalizado_em DESC;
    """, tipo, empresa_id)

    r = cur.fetchone()
    cn.close()

    if not r:
        return {
            "finalizado_em": None,
            "dt_from": None
        }

    return {
        "finalizado_em": r.finalizado_em,
        "dt_from": r.dt_from
    }


@app.post("/ml/processar-vendas")
def processar_vendas(payload=Depends(require_auth)):
    empresa_id = payload.get("empresa_id")
    if not empresa_id:
        raise HTTPException(status_code=401, detail="Token inválido")

    empresa_id = int(empresa_id)

    job_id = job_create("PROCESSAR_VENDAS", empresa_id)
    job_set_processing(job_id)

    try:
        resultado = worker_processar_vendas_sync(job_id, empresa_id)
        job_set_success(job_id, resultado)

        return {
            "ok": True,
            "job_id": job_id,
            "status": "SUCESSO",
            "resultado": resultado
        }

    except Exception as e:
        job_set_error(job_id, str(e))
        raise HTTPException(status_code=500, detail=str(e))


def worker_processar_vendas_sync(job_id: int, empresa_id: int):
    now_utc = datetime.now(timezone.utc)

    cn = db()
    cur = cn.cursor()

    last_run = get_last_run(cur)

    if last_run is None:
        dt_from = now_utc - timedelta(hours=24)
    else:
        if last_run.tzinfo is None:
            last_run = last_run.replace(tzinfo=timezone.utc)
        dt_from = last_run - timedelta(minutes=int(JOB_LOOKBACK_MIN or 10))

    orders = ml_fetch_paid_orders_since(dt_from, empresa_id=empresa_id) or []

    processadas = 0
    unidades = 0

    for order in orders:
        order_id = str(order.get("id"))

        for oi in order.get("order_items", []) or []:
            ml_item_id = (oi.get("item") or {}).get("id")
            qty = int(oi.get("quantity") or 0)

            if not ml_item_id or qty <= 0:
                continue

            if already_processed(cur, empresa_id, order_id, ml_item_id):
                continue

            sku_id = get_sku_id_by_item(cur, ml_item_id)
            if not sku_id:
                continue

            mark_processed(cur, empresa_id, order_id, ml_item_id, qty)
            processadas += 1
            unidades += qty

    set_last_run(cur, now_utc)
    cn.commit()
    cn.close()

    return {
        "processadas": processadas,
        "unidades": unidades,
        "dt_from": dt_from.isoformat()
    }


# ============================
#ENDPOINT REPOSIÇÃO
# ============================
@app.get("/reposicao")
def listar_reposicao(payload=Depends(require_auth)):
    empresa_id = int(payload["empresa_id"])

    cn = db()
    cur = cn.cursor()

    cur.execute("""
        SELECT
          v.sku_id,
          v.sku_codigo,
          v.sku_nome,
          v.estoque_central,
          v.total_vendido,
          v.saldo,
          v.estoque_minimo
        FROM vw_sku_estoque v
        WHERE
          EXISTS (
            SELECT 1
            FROM dbo.sku_anuncios sa
            JOIN dbo.ml_anuncios_cache mac
              ON mac.ml_item_id = sa.ml_item_id
            WHERE sa.sku_id = v.sku_id
              AND mac.empresa_id = ?
          )
        OR NOT EXISTS (
            SELECT 1
            FROM dbo.sku_anuncios sa2
            WHERE sa2.sku_id = v.sku_id
        )
        ORDER BY v.saldo ASC;
    """, empresa_id)

    rows = cur.fetchall()
    cn.close()

    data = [
        {
            "sku_id": int(r.sku_id),
            "codigo": r.sku_codigo,
            "nome": r.sku_nome,
            "estoque": int(r.estoque_central),
            "vendido": int(r.total_vendido),
            "saldo": int(r.saldo),
            "estoque_minimo": int(r.estoque_minimo),
            "status": "REPOR" if r.saldo <= r.estoque_minimo else "OK"
        }
        for r in rows
    ]

    meta = buscar_ultimo_job("PROCESSAR_VENDAS", empresa_id)

    return {
        "meta": meta,
        "data": data
    }

# ============================
# SALVAR ESTOQUE MINIMO DA TELA DE REPOSIÇÃO
# ============================

@app.post("/sku/{sku_id}/estoque-minimo")
def atualizar_estoque_minimo(
    sku_id: int,
    payload: dict,
    user=Depends(require_auth)
):
    empresa_id = int(user["empresa_id"])
    estoque_minimo = payload.get("estoque_minimo")

    if estoque_minimo is None:
        raise HTTPException(status_code=400, detail="Estoque mínimo obrigatório")

    cn = db()
    cur = cn.cursor()

    cur.execute("""
        UPDATE dbo.sku
        SET estoque_minimo = ?, atualizado_em = SYSUTCDATETIME()
        WHERE id = ?
          AND empresa_id = ?
          AND ativo = 1
    """, int(estoque_minimo), sku_id, empresa_id)

    if cur.rowcount == 0:
        cn.close()
        raise HTTPException(
            status_code=404,
            detail="SKU não encontrado para esta empresa"
        )

    cn.commit()
    cn.close()

    return {
        "ok": True,
        "sku_id": sku_id,
        "estoque_minimo": int(estoque_minimo)
    }

# ============================
# HELPER IMPORTAÇÃO
# ============================

def read_upload_text(file: UploadFile) -> list[str]:
    raw = file.file.read()

    # 1) tenta UTF-8 (com BOM)
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        # 2) fallback padrão BR (Excel/Windows)
        text = raw.decode("latin-1")

    # normaliza quebras de linha
    return text.splitlines()


# ============================
# IMPORTAÇÃO DE PREVIEW
# ============================

@app.post("/sku/import/preview")
def preview_import_skus(
    file: UploadFile = File(...),
    payload=Depends(require_auth)
):
    empresa_id = int(payload["empresa_id"])

    if not file.filename.lower().endswith((".csv", ".txt")):
        raise HTTPException(status_code=400, detail="Arquivo inválido. Use CSV ou TXT.")

    content = read_upload_text(file)

    if not content:
        raise HTTPException(status_code=400, detail="Arquivo vazio.")

    # detecta delimitador (vírgula ou ponto e vírgula)
    sample = "\n".join(content[:5])
    try:
        dialect = csv.Sniffer().sniff(sample, delimiters=",;")
        reader = csv.DictReader(content, dialect=dialect)
    except Exception:
        reader = csv.DictReader(content)

    required = {"codigo", "nome", "estoque_central", "estoque_minimo"}

    fieldnames = {
        f.strip().replace("\ufeff", "")
        for f in (reader.fieldnames or [])
    }

    if not reader.fieldnames or not required.issubset(fieldnames):
        raise HTTPException(
            status_code=400,
            detail="Cabeçalho CSV inválido. Esperado: codigo,nome,estoque_central,estoque_minimo"
        )

    preview = []
    erros = []

    cn = db()
    cur = cn.cursor()

    for linha, row in enumerate(reader, start=2):
        # normaliza chaves e valores
        row = {
            (k or "").strip().replace("\ufeff", ""): (v or "").strip()
            for k, v in row.items()
        }

        try:
            codigo = row.get("codigo", "")
            nome = row.get("nome", "")

            if not codigo or not nome:
                raise ValueError("Código ou nome vazio")

            estoque_central = int(row.get("estoque_central", -1))
            estoque_minimo = int(row.get("estoque_minimo", -1))

            if estoque_central < 0 or estoque_minimo < 0:
                raise ValueError("Estoque não pode ser negativo")

            cur.execute("""
                SELECT id
                FROM dbo.sku
                WHERE codigo = ?
                  AND empresa_id = ?
            """, codigo, empresa_id)

            existente = cur.fetchone()

            preview.append({
                "linha": linha,
                "codigo": codigo,
                "nome": nome,
                "estoque_central": estoque_central,
                "estoque_minimo": estoque_minimo,
                "acao": "ATUALIZAR" if existente else "INSERIR"
            })

        except Exception as e:
            erros.append({
                "linha": linha,
                "erro": str(e),
                "dados": row
            })

    cn.close()

    return {
        "ok": True,
        "preview": preview,
        "erros": erros,
        "validos": len(preview),
        "invalidos": len(erros)
    }




# ============================
# IMPORTAÇÃO DE CONFIRMAÇÃO
# ============================

@app.post("/sku/import/confirm")
def importar_skus(
    file: UploadFile = File(...),
    payload=Depends(require_auth)
):
    empresa_id = int(payload["empresa_id"])

    if not file.filename.lower().endswith((".csv", ".txt")):
        raise HTTPException(status_code=400, detail="Arquivo inválido. Use CSV ou TXT.")

    content = read_upload_text(file)

    if not content:
        raise HTTPException(status_code=400, detail="Arquivo vazio.")

    # detecta delimitador
    sample = "\n".join(content[:5])
    try:
        dialect = csv.Sniffer().sniff(sample, delimiters=",;")
        reader = csv.DictReader(content, dialect=dialect)
    except Exception:
        reader = csv.DictReader(content)

    required = {"codigo", "nome", "estoque_central", "estoque_minimo"}

    fieldnames = {
        f.strip().replace("\ufeff", "")
        for f in (reader.fieldnames or [])
    }

    if not reader.fieldnames or not required.issubset(fieldnames):
        raise HTTPException(
            status_code=400,
            detail="Cabeçalho CSV inválido. Esperado: codigo,nome,estoque_central,estoque_minimo"
        )

    cn = db()
    cur = cn.cursor()

    inseridos = 0
    atualizados = 0
    ignorados = 0

    try:
        for linha, row in enumerate(reader, start=2):
            row = {
                (k or "").strip().replace("\ufeff", ""): (v or "").strip()
                for k, v in row.items()
            }

            try:
                codigo = row.get("codigo", "")
                nome = row.get("nome", "")

                if not codigo or not nome:
                    ignorados += 1
                    continue

                estoque_central = int(row.get("estoque_central", -1))
                estoque_minimo = int(row.get("estoque_minimo", -1))

                if estoque_central < 0 or estoque_minimo < 0:
                    ignorados += 1
                    continue

                cur.execute("""
                    SELECT id
                    FROM dbo.sku
                    WHERE codigo = ?
                      AND empresa_id = ?
                """, codigo, empresa_id)

                sku = cur.fetchone()

                if sku:
                    cur.execute("""
                        UPDATE dbo.sku
                        SET nome = ?,
                            estoque_central = ?,
                            estoque_minimo = ?,
                            ativo = 1,
                            atualizado_em = SYSUTCDATETIME()
                        WHERE id = ?
                    """, nome, estoque_central, estoque_minimo, sku.id)
                    atualizados += 1
                else:
                    cur.execute("""
                        INSERT INTO dbo.sku (
                            codigo,
                            nome,
                            estoque_central,
                            estoque_minimo,
                            ativo,
                            empresa_id,
                            atualizado_em
                        )
                        VALUES (?,?,?,?,1,?,SYSUTCDATETIME())
                    """, codigo, nome, estoque_central, estoque_minimo, empresa_id)
                    inseridos += 1

            except Exception:
                ignorados += 1

        cn.commit()

    except Exception as e:
        cn.rollback()
        raise HTTPException(status_code=400, detail=str(e))

    finally:
        cn.close()

    return {
        "ok": True,
        "inseridos": inseridos,
        "atualizados": atualizados,
        "ignorados": ignorados
    }


# ============================
# MODELO IMPORTACAO 
# ============================
@app.get("/sku/import/modelo")
def baixar_modelo_importacao():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    caminho = os.path.join(base_dir, "modelo", "modelo_importacao_skus.csv")

    if not os.path.exists(caminho):
        raise HTTPException(
            status_code=404,
            detail="Arquivo de modelo não encontrado."
        )

    return FileResponse(
        path=caminho,
        media_type="text/csv",
        filename="modelo_importacao_skus.csv"
    )



# ============================
# DESVINCULAR ANÚNCIO
# ============================
class UnlinkItemIn(BaseModel):
    ml_item_id: str


@app.post("/anuncios/desvincular")
def desvincular_anuncio(data: UnlinkItemIn, payload=Depends(require_auth)):
    cn = db()
    cur = cn.cursor()

    ml_item_id = (data.ml_item_id or "").strip()
    if not ml_item_id:
        cn.close()
        raise HTTPException(status_code=400, detail="ml_item_id é obrigatório.")

    cur.execute(
        "SELECT sku_id FROM dbo.sku_anuncios WHERE ml_item_id = ?",
        ml_item_id
    )
    row = cur.fetchone()

    if not row:
        cn.close()
        raise HTTPException(status_code=404, detail="Anúncio não possui vínculo com SKU.")

    sku_id = row.sku_id

    try:
        cur.execute(
            "DELETE FROM dbo.sku_anuncios WHERE ml_item_id = ?",
            ml_item_id
        )
        cn.commit()

        log("AJUSTE", f"Desvinculado anúncio {ml_item_id} do SKU {sku_id}", sku_id=sku_id, ml_item_id=ml_item_id)

    except Exception as e:
        cn.rollback()
        cn.close()
        raise HTTPException(status_code=400, detail=f"Falha ao desvincular anúncio: {str(e)}")

    cn.close()
    return {"ok": True}












