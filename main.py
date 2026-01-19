import os
import json
import csv
import bcrypt
import pyodbc
import requests
import traceback
import time

from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import FastAPI, HTTPException, Depends, Security, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import RedirectResponse, FileResponse
from pydantic import BaseModel
from jose import jwt,JWTError, ExpiredSignatureError
from fastapi import BackgroundTasks



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
    """
    Determina corretamente se o anúncio é FULL (Mercado Envios Full)

    Regras oficiais:
    - shipping.logistic_type == 'fulfillment'
    - OU tag 'fulfillment' presente
    """

    shipping = item.get("shipping") or {}
    logistic_type = shipping.get("logistic_type")

    tags = item.get("tags") or []

    is_full = (
        logistic_type == "fulfillment"
        or "fulfillment" in tags
    )

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


# =========================
# MERCADO LIVRE — MULTI CD / WAREHOUSE
# =========================
class EstoqueCDIn(BaseModel):
    seller_sku: str
    ml_user_product_id: str
    store_id: str
    quantidade: int


@app.post("/ml/depositos/sync")
def ml_sync_depositos(payload=Depends(require_auth)):
    empresa_id = int(payload["empresa_id"])

    me = ml_me(empresa_id)
    ml_user_id = me["id"]

    data = ml_get_empresa(
        f"{ML_API}/users/{ml_user_id}/stores/search",
        empresa_id=empresa_id,
        params={"tags": "stock_location"}
    )

    stores = data.get("results", [])

    cn = db()
    cur = cn.cursor()

    for s in stores:
        cur.execute("""
            MERGE dbo.ml_depositos AS t
            USING (
                SELECT ? AS empresa_id, ? AS store_id
            ) s
            ON t.empresa_id = s.empresa_id
           AND t.store_id = s.store_id
            WHEN MATCHED THEN UPDATE SET
                network_node_id = ?,
                descricao = ?,
                status = ?,
                endereco = ?,
                cidade = ?,
                estado = ?,
                cep = ?,
                atualizado_em = SYSUTCDATETIME()
            WHEN NOT MATCHED THEN INSERT (
                empresa_id,
                store_id,
                network_node_id,
                descricao,
                status,
                endereco,
                cidade,
                estado,
                cep,
                criado_em
            ) VALUES (
                ?, ?, ?, ?, ?, ?, ?, ?, ?, SYSUTCDATETIME()
            );
        """,
            empresa_id,
            s["id"],
            s["network_node_id"],
            s["description"],
            s["status"],
            s["location"]["address_line"],
            s["location"]["city"],
            s["location"]["state"],
            s["location"]["zip_code"],
            empresa_id,
            s["id"],
            s["network_node_id"],
            s["description"],
            s["status"],
            s["location"]["address_line"],
            s["location"]["city"],
            s["location"]["state"],
            s["location"]["zip_code"]
        )

    cn.commit()
    cn.close()

    return {
        "ok": True,
        "depositos": len(stores)
    }

@app.put("/ml/estoque/cd/update")
def ml_update_estoque_cd(
    data: EstoqueCDIn,
    payload=Depends(require_auth)
):
    empresa_id = int(payload["empresa_id"])

    if data.quantidade < 0:
        raise HTTPException(status_code=400, detail="Quantidade inválida")

    url = f"{ML_API}/user-products/{data.ml_user_product_id}/stock/type/seller_warehouse"

    payload_ml = {
        "locations": [
            {
                "store_id": data.store_id,
                "quantity": data.quantidade
            }
        ]
    }

    ml_put_empresa(url, empresa_id=empresa_id, payload=payload_ml)

    cn = db()
    cur = cn.cursor()

    cur.execute("""
        MERGE dbo.ml_estoque_deposito AS t
        USING (
            SELECT ? AS empresa_id, ? AS seller_sku, ? AS store_id
        ) s
        ON t.empresa_id = s.empresa_id
       AND t.seller_sku = s.seller_sku
       AND t.store_id = s.store_id
        WHEN MATCHED THEN UPDATE SET
            quantidade = ?,
            ultima_sincronizacao = SYSUTCDATETIME(),
            atualizado_em = SYSUTCDATETIME()
        WHEN NOT MATCHED THEN INSERT (
            empresa_id,
            seller_sku,
            ml_user_product_id,
            store_id,
            quantidade,
            ultima_sincronizacao,
            criado_em
        ) VALUES (
            ?, ?, ?, ?, ?, SYSUTCDATETIME(), SYSUTCDATETIME()
        );
    """,
        empresa_id,
        data.seller_sku,
        data.store_id,
        data.quantidade,
        empresa_id,
        data.seller_sku,
        data.ml_user_product_id,
        data.store_id,
        data.quantidade
    )

    cn.commit()
    cn.close()

    return {
        "ok": True,
        "sku": data.seller_sku,
        "store_id": data.store_id,
        "quantidade": data.quantidade
    }

@app.get("/ml/estoque/cd/{seller_sku}")
def ml_get_estoque_por_cd(
    seller_sku: str,
    payload=Depends(require_auth)
):
    empresa_id = int(payload["empresa_id"])

    cn = db()
    cur = cn.cursor()

    cur.execute("""
        SELECT
            d.store_id,
            d.descricao,
            d.network_node_id,
            e.quantidade,
            e.ultima_sincronizacao
        FROM dbo.ml_estoque_deposito e
        JOIN dbo.ml_depositos d
          ON d.store_id = e.store_id
         AND d.empresa_id = e.empresa_id
        WHERE e.empresa_id = ?
          AND e.seller_sku = ?
        ORDER BY d.descricao
    """, empresa_id, seller_sku)

    rows = cur.fetchall()
    cn.close()

    total = sum(int(r.quantidade or 0) for r in rows)

    return {
        "seller_sku": seller_sku,
        "estoque_total": total,
        "depositos": [
            {
                "store_id": r.store_id,
                "descricao": r.descricao,
                "network_node_id": r.network_node_id,
                "quantidade": int(r.quantidade or 0),
                "ultima_sincronizacao": (
                    r.ultima_sincronizacao.isoformat()
                    if r.ultima_sincronizacao else None
                )
            }
            for r in rows
        ]
    }



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

@app.post("/ml/sincronizar-anuncios")
def sincronizar_anuncios(
    background_tasks: BackgroundTasks,
    payload=Depends(require_auth)
):
    empresa_id = int(payload["empresa_id"])

    job_id = job_create("SYNC_ANUNCIOS", empresa_id)

    background_tasks.add_task(
        worker_sync_anuncios,
        job_id,
        empresa_id
    )

    return {
        "ok": True,
        "job_id": job_id,
        "status": "PROCESSANDO",
        "mensagem": "Sincronização de anúncios iniciada. Aguarde..."
    }




# ============================
# PROCESSO EM BACKGROUND
# ============================
def ml_get_item_full(ml_item_id: str, empresa_id: int):
    """
    Busca o item completo no Mercado Livre.
    Necessário para obter shipping.logistic_type (FULFILLMENT / FLEX)
    """
    return ml_get_empresa(
        f"{ML_API}/items/{ml_item_id}",
        empresa_id=empresa_id
    )


# ============================
# PROCESSO EM BACKGROUND
# ============================
def worker_sync_anuncios(job_id: int, empresa_id: int):
    job_set_processing(job_id)

    try:
        # =====================================================
        # 1️⃣ DADOS DA CONTA
        # =====================================================
        me = ml_me(empresa_id)
        user_id = me["id"]

        # =====================================================
        # 2️⃣ LISTA TODOS OS IDS DE ITENS
        # =====================================================
        item_ids = ml_list_all_item_ids(
            user_id=user_id,
            empresa_id=empresa_id,
            limit=50
        )

        # =====================================================
        # 3️⃣ FETCH BÁSICO (BATCH)
        # =====================================================
        base_items = ml_fetch_items_batch(
            item_ids,
            empresa_id=empresa_id
        )

        cn = db()
        cur = cn.cursor()

        # =====================================================
        # 4️⃣ LIMPA CACHE (CACHE AUTORITATIVO)
        # =====================================================
        cur.execute("""
            DELETE FROM dbo.ml_anuncios_cache
            WHERE empresa_id = ?;
        """, empresa_id)

        # =====================================================
        # 5️⃣ PROCESSA ITEM COMPLETO (DETALHE)
        # =====================================================
        for it_base in base_items:
            it = ml_get_item_full(it_base["id"], empresa_id)

            seller_sku, is_catalogo, tipo_anuncio = extract_ml_sku_and_tipo(it)
            logistic_type, is_full = extract_ml_logistica(it)

            # 🔹 NOVO: user_product_id (ESSENCIAL PARA MULTI-CD)
            ml_user_product_id = it.get("user_product_id")

            cur.execute("""
                INSERT INTO dbo.ml_anuncios_cache (
                    empresa_id,
                    ml_item_id,
                    ml_user_product_id,
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
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,SYSUTCDATETIME())
            """,
                empresa_id,
                it.get("id"),
                ml_user_product_id,              # ✅ NOVO
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

        # =====================================================
        # 6️⃣ FINALIZA JOB
        # =====================================================
        job_set_success(job_id, {
            "total": len(base_items),
            "sincronizado_em": utcnow_naive().isoformat()
        })

    except Exception as e:
        job_set_error(job_id, str(e))
        raise

# ============================
# LISTAR ANÚNCIOS DO ML (CONSOLIDADO)
# ============================
@app.get("/ml/anuncios")
def ml_anuncios(payload=Depends(require_auth)):
    empresa_id = int(payload["empresa_id"])

    cn = db()
    cur = cn.cursor()

    # ============================
    # ANÚNCIOS + ESTOQUE FULL
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

            ISNULL(ef.quantidade, 0) AS estoque_full,

            sa.origem_vinculo
        FROM dbo.ml_anuncios_cache mac
        LEFT JOIN dbo.ml_estoque_full ef
               ON ef.ml_item_id = mac.ml_item_id
              AND ef.empresa_id = mac.empresa_id
        LEFT JOIN dbo.sku_anuncios sa
               ON sa.ml_item_id = mac.ml_item_id
              AND sa.sku_id IS NOT NULL
        WHERE mac.empresa_id = ?
        ORDER BY mac.titulo;
    """, empresa_id)

    anuncios = cur.fetchall()

    # ============================
    # VÍNCULOS SKU + ESTOQUE CD
    # ============================
    cur.execute("""
        SELECT
            sa.ml_item_id,
            s.codigo,
            s.nome,
            s.estoque_central,

            ISNULL((
                SELECT SUM(e.quantidade)
                FROM dbo.ml_estoque_deposito e
                WHERE e.empresa_id = ?
                  AND e.seller_sku = s.codigo
            ), 0) AS estoque_cd
        FROM dbo.sku_anuncios sa
        JOIN dbo.sku s
          ON s.id = sa.sku_id
        WHERE s.ativo = 1
          AND s.empresa_id = ?;
    """, empresa_id, empresa_id)

    vinc = {}
    for r in cur.fetchall():
        vinc[str(r.ml_item_id)] = {
            "sku_codigo": r.codigo,
            "sku_nome": r.nome,
            "estoque_cd": int(r.estoque_cd or 0),
            "estoque_central": int(r.estoque_central or 0)
        }

    cn.close()

    # ============================
    # SERIALIZAÇÃO FINAL (PRONTA PARA UI)
    # ============================
    out = []
    for a in anuncios:
        sku = vinc.get(str(a.ml_item_id))

        estoque_full = int(a.estoque_full or 0)
        estoque_cd = int(sku["estoque_cd"]) if sku else 0

        out.append({
            "ml_item_id": a.ml_item_id,
            "titulo": a.titulo,
            "seller_sku": a.seller_sku,

            "tipo_anuncio": a.tipo_anuncio,          # CATALOGO / LISTA
            "is_catalogo": bool(a.is_catalogo),

            "status": a.status,
            "preco": a.preco,

            "is_full": bool(a.is_full),
            "logistic_type": a.logistic_type,

            "estoque_full": estoque_full,
            "estoque_cd": estoque_cd,
            "estoque_total": estoque_full + estoque_cd,

            "sku": sku,

            # 🔥 CONTROLE DE UX
            "acao": "DESVINCULAR" if sku else "VINCULAR"
        })

    return out

# ============================
# WORKER BOOTSTRAP ESTOQUE CD
# ============================
def worker_bootstrap_estoque_cd(job_id: int, empresa_id: int):
    job_set_processing(job_id)

    cn = db()
    cur = cn.cursor()

    inseridos = 0
    ignorados = 0
    produtos_processados = 0

    try:
        cur.execute("""
            SELECT DISTINCT
                seller_sku,
                ml_user_product_id
            FROM dbo.ml_anuncios_cache
            WHERE empresa_id = ?
              AND ml_user_product_id IS NOT NULL
              AND seller_sku IS NOT NULL
        """, empresa_id)

        produtos = cur.fetchall()

        for p in produtos:
            seller_sku = p.seller_sku
            user_product_id = p.ml_user_product_id
            produtos_processados += 1

            data = ml_get_empresa(
                f"{ML_API}/user-products/{user_product_id}/stock",
                empresa_id=empresa_id
            )

            locations = data.get("locations") or []

            for loc in locations:
                if loc.get("type") != "seller_warehouse":
                    ignorados += 1
                    continue

                store_id = loc.get("store_id")
                if not store_id:
                    ignorados += 1
                    continue

                network_node_id = loc.get("network_node_id")
                qtd = int(loc.get("quantity") or 0)

                cur.execute("""
                    SELECT 1
                    FROM dbo.ml_estoque_deposito
                    WHERE empresa_id = ?
                      AND seller_sku = ?
                      AND store_id = ?
                """, empresa_id, seller_sku, store_id)

                if cur.fetchone():
                    ignorados += 1
                    continue

                cur.execute("""
                    INSERT INTO dbo.ml_estoque_deposito (
                        empresa_id,
                        seller_sku,
                        ml_user_product_id,
                        store_id,
                        network_node_id,
                        quantidade,
                        ultima_sincronizacao,
                        criado_em,
                        atualizado_em
                    )
                    VALUES (?, ?, ?, ?, ?, ?, SYSUTCDATETIME(), SYSUTCDATETIME(), SYSUTCDATETIME())
                """,
                    empresa_id,
                    seller_sku,
                    user_product_id,
                    store_id,
                    network_node_id,
                    qtd
                )

                inseridos += 1

            cn.commit()  # commit por produto (seguro)

        job_set_success(job_id, {
            "produtos_processados": produtos_processados,
            "registros_inseridos": inseridos,
            "registros_ignorados": ignorados
        })

    except Exception as e:
        cn.rollback()
        job_set_error(job_id, str(e))
        raise

    finally:
        cn.close()


# ============================
# update cd ML
# ============================


class AtualizarEstoqueCDPayload(BaseModel):
    seller_sku: str
    ml_user_product_id: str
    store_id: str
    quantidade: int


@app.put("/ml/estoque/cd/update")
def atualizar_estoque_cd(
    payload: AtualizarEstoqueCDPayload,
    auth=Depends(require_auth)
):
    empresa_id = int(auth["empresa_id"])

    body = {
        "locations": [
            {
                "store_id": payload.store_id,
                "available_quantity": payload.quantidade
            }
        ]
    }

    resp = ml_put_empresa(
        f"{ML_API}/user-products/{payload.ml_user_product_id}/stock",
        empresa_id=empresa_id,
        payload=body
    )

    return {
        "ok": True,
        "seller_sku": payload.seller_sku,
        "ml_user_product_id": payload.ml_user_product_id,
        "store_id": payload.store_id,
        "quantidade": payload.quantidade,
        "ml_response": resp
    }



def worker_ativar_cd_automatico(job_id: int, empresa_id: int):
    job_set_processing(job_id)

    cn = db()
    cur = cn.cursor()

    ativados = 0
    ignorados = 0
    erros = 0
    processados = 0

    try:
        # 🔹 Produtos com user_product_id
        cur.execute("""
            SELECT DISTINCT
                mac.seller_sku,
                mac.ml_user_product_id
            FROM dbo.ml_anuncios_cache mac
            WHERE mac.empresa_id = ?
              AND mac.ml_user_product_id IS NOT NULL
        """, empresa_id)

        produtos = cur.fetchall()

        for p in produtos:
            seller_sku = p.seller_sku
            user_product_id = p.ml_user_product_id
            processados += 1

            try:
                # 🔎 Consulta produto no ML
                data = ml_get_empresa(
                    f"{ML_API}/user-products/{user_product_id}/stock",
                    empresa_id=empresa_id
                )

                locations = data.get("locations") or []

                if locations:
                    ignorados += 1
                    continue


                # 🔹 Ativa CD com quantidade 0
                payload_ml = {
                    "locations": [
                        {
                            "store_id": None,
                            "available_quantity": 0
                        }
                    ]
                }

                ml_put_empresa(
                    f"{ML_API}/user-products/{user_product_id}/stock",
                    empresa_id=empresa_id,
                    payload=payload_ml
                )

                ativados += 1

            except Exception as e:
                erros += 1
                log(
                    "ERRO",
                    "Falha ao ativar CD automático",
                    sku=seller_sku,
                    user_product_id=user_product_id,
                    erro=str(e)
                )

            # 🧠 RATE LIMIT SAFE (ML + Azure)
            time.sleep(0.35)

            # 🔄 Commit periódico (a cada 20)
            if processados % 20 == 0:
                cn.commit()

        cn.commit()

        job_set_success(job_id, {
            "produtos_total": len(produtos),
            "processados": processados,
            "cd_ativados": ativados,
            "ignorados": ignorados,
            "erros": erros,
            "sleep_por_item": 0.35
        })

    except Exception as e:
        cn.rollback()
        job_set_error(job_id, str(e))
        raise

    finally:
        cn.close()



@app.post("/ml/estoque/cd/ativar-automatico")
def ativar_cd_automatico(
    background_tasks: BackgroundTasks,
    payload=Depends(require_auth)
):
    empresa_id = int(payload["empresa_id"])

    # 🔒 Só permite se multi-CD estiver ativo
    cn = db()
    cur = cn.cursor()
    cur.execute("""
        SELECT warehouse_management
        FROM dbo.ml_configuracao_conta
        WHERE empresa_id = ?
    """, empresa_id)

    cfg = cur.fetchone()
    cn.close()

    if not cfg or int(cfg.warehouse_management) != 1:
        raise HTTPException(
            status_code=400,
            detail="Conta não configurada para estoque multi-CD."
        )

    job_id = job_create("ATIVAR_CD_AUTOMATICO", empresa_id)

    background_tasks.add_task(
        worker_ativar_cd_automatico,
        job_id,
        empresa_id
    )

    return {
        "ok": True,
        "job_id": job_id,
        "status": "PROCESSANDO",
        "mensagem": "Ativação automática de CD iniciada."
    }


# ============================
# ENDPOINT BOOTSTRAP
# ============================
@app.post("/ml/estoque/cd/bootstrap")
def bootstrap_estoque_cd(
    background_tasks: BackgroundTasks,
    payload=Depends(require_auth)
):
    empresa_id = int(payload["empresa_id"])

    # 🔒 Só permite se multi-CD estiver ativo
    cn = db()
    cur = cn.cursor()
    cur.execute("""
        SELECT warehouse_management
        FROM dbo.ml_configuracao_conta
        WHERE empresa_id = ?
    """, empresa_id)

    cfg = cur.fetchone()
    cn.close()

    if not cfg or int(cfg.warehouse_management) != 1:
        raise HTTPException(
            status_code=400,
            detail="Conta não configurada para estoque multi-CD."
        )

    job_id = job_create("BOOTSTRAP_ESTOQUE_CD", empresa_id)

    background_tasks.add_task(
        worker_bootstrap_estoque_cd,
        job_id,
        empresa_id
    )

    return {
        "ok": True,
        "job_id": job_id,
        "status": "PROCESSANDO",
        "mensagem": "Bootstrap inicial de estoque por CD iniciado."
    }





def worker_reconciliar_estoque_ml(job_id: int, empresa_id: int):
    cn = db()
    cur = cn.cursor()

    try:
        job_set_processing(job_id)

        reconciliados = 0
        divergencias = 0
        produtos_analisados = 0
        bootstrap = False

        # =====================================================
        # 1️⃣ EXISTE ESTOQUE POR CD PARA A EMPRESA?
        # =====================================================
        cur.execute("""
            SELECT COUNT(1)
            FROM dbo.ml_estoque_deposito
            WHERE empresa_id = ?
        """, empresa_id)

        total_registros = int(cur.fetchone()[0] or 0)

        # =====================================================
        # 2️⃣ BOOTSTRAP AUTOMÁTICO (TABELA VAZIA)
        # =====================================================
        if total_registros == 0:
            bootstrap = True

            cur.execute("""
                SELECT DISTINCT
                    seller_sku,
                    ml_item_id,
                    ml_user_product_id
                FROM dbo.ml_anuncios_cache
                WHERE empresa_id = ?
                  AND ml_user_product_id IS NOT NULL
            """, empresa_id)

            produtos_bootstrap = cur.fetchall()

            for p in produtos_bootstrap:
                seller_sku = p.seller_sku
                ml_item_id = p.ml_item_id
                user_product_id = p.ml_user_product_id
                produtos_analisados += 1

                # 🔹 ESTOQUE REAL POR CD (API CORRETA)
                data = ml_get_empresa(
                    f"{ML_API}/user-products/{user_product_id}/stock",
                    empresa_id=empresa_id
                )

                locations = data.get("locations") or []

                for loc in locations:
                    store_id = loc.get("store_id")

                    # ❗ IGNORA LOCAIS SEM STORE_ID (meli_facility etc)
                    if not store_id:
                        continue

                    network_node_id = loc.get("network_node_id")
                    qtd = int(loc.get("quantity") or 0)

                    # 🔒 Idempotência
                    cur.execute("""
                        SELECT 1
                        FROM dbo.ml_estoque_deposito
                        WHERE empresa_id = ?
                          AND seller_sku = ?
                          AND store_id = ?
                    """, empresa_id, seller_sku, store_id)

                    if cur.fetchone():
                        continue

                    cur.execute("""
                        INSERT INTO dbo.ml_estoque_deposito (
                            empresa_id,
                            seller_sku,
                            ml_item_id,
                            ml_user_product_id,
                            store_id,
                            quantidade,
                            network_node_id,
                            ultima_sincronizacao,
                            criado_em,
                            atualizado_em
                        )
                        VALUES (?, ?, ?, ?, ?, ?, ?, SYSUTCDATETIME(), SYSUTCDATETIME(), SYSUTCDATETIME())
                    """,
                        empresa_id,
                        seller_sku,
                        ml_item_id,
                        user_product_id,
                        store_id,
                        qtd,
                        network_node_id
                    )

            cn.commit()

        # =====================================================
        # 3️⃣ RECONCILIAÇÃO (ML = FONTE DA VERDADE)
        # =====================================================
        cur.execute("""
            SELECT DISTINCT
                seller_sku,
                ml_item_id,
                ml_user_product_id,
                store_id,
                quantidade
            FROM dbo.ml_estoque_deposito
            WHERE empresa_id = ?
        """, empresa_id)

        registros = cur.fetchall()

        for r in registros:
            seller_sku = r.seller_sku
            ml_item_id = r.ml_item_id
            user_product_id = r.ml_user_product_id
            store_id = r.store_id
            qtd_banco = int(r.quantidade or 0)

            produtos_analisados += 1

            data = ml_get_empresa(
                f"{ML_API}/user-products/{user_product_id}/stock",
                empresa_id=empresa_id
            )

            locations = data.get("locations") or []

            for loc in locations:
                if loc.get("store_id") != store_id:
                    continue

                qtd_ml = int(loc.get("quantity") or 0)

                if qtd_ml != qtd_banco:
                    divergencias += 1

                    cur.execute("""
                        UPDATE dbo.ml_estoque_deposito
                        SET quantidade = ?,
                            ultima_sincronizacao = SYSUTCDATETIME(),
                            atualizado_em = SYSUTCDATETIME()
                        WHERE empresa_id = ?
                          AND seller_sku = ?
                          AND store_id = ?
                    """, qtd_ml, empresa_id, seller_sku, store_id)

                    cur.execute("""
                        INSERT INTO dbo.ml_reconciliacao_log (
                            empresa_id,
                            seller_sku,
                            ml_item_id,
                            ml_user_product_id,
                            store_id,
                            qtd_ml,
                            qtd_banco,
                            diferenca,
                            criado_em
                        )
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, SYSUTCDATETIME())
                    """,
                        empresa_id,
                        seller_sku,
                        ml_item_id,
                        user_product_id,
                        store_id,
                        qtd_ml,
                        qtd_banco,
                        qtd_ml - qtd_banco
                    )

                    reconciliados += 1

        cn.commit()

        # =====================================================
        # 4️⃣ FINALIZA JOB
        # =====================================================
        resultado = {
            "bootstrap_executado": bootstrap,
            "produtos_analisados": produtos_analisados,
            "divergencias_encontradas": divergencias,
            "registros_ajustados": reconciliados
        }

        job_set_success(job_id, resultado)

    except Exception as e:
        cn.rollback()
        job_set_error(job_id, str(e))
        raise

    finally:
        cn.close()

# ============================
# consulta estoque full
# ============================
def worker_sync_estoque_full(job_id: int, empresa_id: int):
    cn = db()
    cur = cn.cursor()

    processados = 0
    inseridos = 0
    atualizados = 0

    try:
        # 🔹 Busca anúncios da empresa
        cur.execute("""
            SELECT DISTINCT
                ml_item_id,
                seller_sku
            FROM dbo.ml_anuncios_cache
            WHERE empresa_id = ?
              AND ml_item_id IS NOT NULL
        """, empresa_id)

        anuncios = cur.fetchall()

        for a in anuncios:
            ml_item_id = a.ml_item_id
            seller_sku = a.seller_sku
            processados += 1

            # 🔹 Consulta item no ML
            item = ml_get_empresa(
                f"{ML_API}/items/{ml_item_id}",
                empresa_id=empresa_id
            )

            shipping = item.get("shipping") or {}
            logistic_type = shipping.get("logistic_type")

            # ❗ Só FULL
            if logistic_type != "fulfillment":
                continue

            quantidade = int(item.get("available_quantity") or 0)

            # 🔹 UPSERT
            cur.execute("""
                MERGE dbo.ml_estoque_full AS tgt
                USING (SELECT ? AS empresa_id, ? AS ml_item_id) AS src
                ON tgt.empresa_id = src.empresa_id
               AND tgt.ml_item_id = src.ml_item_id
                WHEN MATCHED THEN
                    UPDATE SET
                        quantidade = ?,
                        seller_sku = ?,
                        logistic_type = 'fulfillment',
                        ultima_sincronizacao = SYSUTCDATETIME(),
                        atualizado_em = SYSUTCDATETIME()
                WHEN NOT MATCHED THEN
                    INSERT (
                        empresa_id,
                        ml_item_id,
                        seller_sku,
                        quantidade,
                        logistic_type,
                        ultima_sincronizacao,
                        criado_em,
                        atualizado_em
                    )
                    VALUES (?, ?, ?, ?, 'fulfillment', SYSUTCDATETIME(), SYSUTCDATETIME(), SYSUTCDATETIME());
            """,
                empresa_id, ml_item_id,
                quantidade, seller_sku,
                empresa_id, ml_item_id, seller_sku, quantidade
            )

            if cur.rowcount == 1:
                inseridos += 1
            else:
                atualizados += 1

        cn.commit()

        job_set_success(job_id, {
                "processados": processados,
                "inseridos": inseridos,
                "atualizados": atualizados
            })

    except Exception as e:
        cn.rollback()
        job_set_error(job_id, str(e))
        raise


@app.get("/ml/estoque/full/{seller_sku}")
def get_estoque_full(
    seller_sku: str,
    payload=Depends(require_auth)
):
    empresa_id = int(payload["empresa_id"])

    cn = db()
    cur = cn.cursor()

    cur.execute("""
        SELECT
            ml_item_id,
            quantidade,
            ultima_sincronizacao
        FROM dbo.ml_estoque_full
        WHERE empresa_id = ?
          AND seller_sku = ?
    """, empresa_id, seller_sku)

    row = cur.fetchone()

    if not row:
        return {
            "seller_sku": seller_sku,
            "estoque_full": 0,
            "ultima_sincronizacao": None
        }

    return {
        "seller_sku": seller_sku,
        "estoque_full": row.quantidade,
        "ultima_sincronizacao": row.ultima_sincronizacao
    }


# ============================
# SINCRONIZAR ESTOQUE FULL (ML)
# ============================
@app.post("/ml/estoque/full/sync")
def sync_estoque_full(
    background_tasks: BackgroundTasks,
    payload=Depends(require_auth)
):
    empresa_id = int(payload["empresa_id"])

    # cria job
    job_id = job_create("SYNC_ESTOQUE_FULL", empresa_id)

    # executa em background
    background_tasks.add_task(
        worker_sync_estoque_full,
        job_id,
        empresa_id
    )

    return {
        "ok": True,
        "job_id": job_id,
        "status": "PROCESSANDO",
        "mensagem": "Sincronização de estoque FULL iniciada."
    }



@app.post("/ml/reconciliar-estoque")
def reconciliar_estoque(
    background_tasks: BackgroundTasks,
    payload=Depends(require_auth)
):
    empresa_id = int(payload["empresa_id"])

    job_id = job_create("RECONCILIAR_ESTOQUE", empresa_id)
    job_set_processing(job_id)

    background_tasks.add_task(
        worker_reconciliar_estoque_ml,
        job_id,
        empresa_id
    )

    return {
        "ok": True,
        "job_id": job_id,
        "status": "PROCESSANDO"
    }



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

    # =====================================================
    # 🔒 BLOQUEIO DE ESTOQUE SIMPLES (MULTI-CD ATIVO)
    # =====================================================
    cur.execute("""
        SELECT warehouse_management
        FROM dbo.ml_configuracao_conta
        WHERE empresa_id = ?
    """, empresa_id)

    cfg = cur.fetchone()

    if cfg and int(cfg.warehouse_management) == 1:
        cn.close()
        raise HTTPException(
            status_code=400,
            detail=(
                "Conta configurada para estoque multi-CD. "
                "Sincronização via estoque central está desabilitada."
            )
        )

    # =====================================================
    # 🔎 BUSCA SKU
    # =====================================================
    cur.execute("""
        SELECT estoque_central, codigo
        FROM dbo.sku
        WHERE id = ?
          AND ativo = 1
    """, sku_id)

    sku = cur.fetchone()
    if not sku:
        cn.close()
        raise HTTPException(status_code=404, detail="SKU não encontrado.")

    estoque = int(sku.estoque_central or 0)

    # =====================================================
    # 🔎 BUSCA ANÚNCIOS VINCULADOS
    # =====================================================
    cur.execute("""
        SELECT ml_item_id, variacao_id
        FROM dbo.sku_anuncios
        WHERE sku_id = ?
    """, sku_id)

    itens = cur.fetchall()
    cn.close()

    if not itens:
        raise HTTPException(
            status_code=400,
            detail="Nenhum anúncio vinculado a este SKU."
        )

    # =====================================================
    # 🔁 SINCRONIZA STATUS NO MERCADO LIVRE
    # =====================================================
    ok_count = 0
    fail = []

    for r in itens:
        item_id = r.ml_item_id
        try:
            if estoque <= 0:
                ml_pause_item(item_id, empresa_id=empresa_id)
                log(
                    "SYNC",
                    "Estoque=0 -> anúncio pausado",
                    sku_id=sku_id,
                    ml_item_id=item_id
                )
            else:
                ml_activate_item(item_id, empresa_id=empresa_id)
                log(
                    "SYNC",
                    "Estoque>0 -> anúncio ativado",
                    sku_id=sku_id,
                    ml_item_id=item_id
                )

            ok_count += 1

        except Exception as e:
            fail.append({
                "ml_item_id": item_id,
                "erro": str(e)
            })
            log(
                "ERRO",
                "Falha ao aplicar status",
                sku_id=sku_id,
                ml_item_id=item_id,
                erro=str(e)
            )

    return {
        "ok": True,
        "aplicados": ok_count,
        "estoque_central": estoque,
        "falhas": fail
    }

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

def baixar_estoque_cd(
    cur,
    empresa_id: int,
    seller_sku: str,
    network_node_id: str,
    quantidade: int
):
    # Localiza o CD
    cur.execute("""
        SELECT store_id
        FROM dbo.ml_depositos
        WHERE empresa_id = ?
          AND network_node_id = ?
          AND status = 'active'
    """, empresa_id, network_node_id)

    row = cur.fetchone()
    if not row:
        raise Exception(f"CD não encontrado para network_node_id={network_node_id}")

    store_id = row.store_id

    # Baixa estoque (sem deixar negativo)
    cur.execute("""
        UPDATE dbo.ml_estoque_deposito
        SET quantidade = CASE
            WHEN quantidade >= ? THEN quantidade - ?
            ELSE 0
        END,
        atualizado_em = SYSUTCDATETIME()
        WHERE empresa_id = ?
          AND seller_sku = ?
          AND store_id = ?
    """, quantidade, quantidade, empresa_id, seller_sku, store_id)

    if cur.rowcount == 0:
        raise Exception(
            f"Estoque não encontrado para SKU={seller_sku} no CD={store_id}"
        )



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

    # =====================================================
    # 🔒 TRAVA MULTI-CD: só baixa por CD se warehouse_management = 1
    # =====================================================
    cur.execute("""
        SELECT warehouse_management
        FROM dbo.ml_configuracao_conta
        WHERE empresa_id = ?
    """, empresa_id)

    cfg = cur.fetchone()
    multi_cd = bool(cfg and int(cfg.warehouse_management) == 1)

    orders = ml_fetch_paid_orders_since(dt_from, empresa_id=empresa_id) or []

    processadas = 0
    unidades = 0

    for order in orders:
        order_id = str(order.get("id"))

        # 🔎 CD de expedição (vem no pedido)
        network_node_id = (
            order.get("shipping", {})
                 .get("receiver_address", {})
                 .get("network_node_id")
        )

        for oi in order.get("order_items", []) or []:
            ml_item_id = (oi.get("item") or {}).get("id")
            qty = int(oi.get("quantity") or 0)

            if not ml_item_id or qty <= 0:
                continue

            if already_processed(cur, empresa_id, order_id, ml_item_id):
                continue

            # 🔎 Localiza SKU vinculado
            cur.execute("""
                SELECT s.codigo
                FROM dbo.sku_anuncios sa
                JOIN dbo.sku s ON s.id = sa.sku_id
                WHERE sa.ml_item_id = ?
            """, ml_item_id)

            sku_row = cur.fetchone()
            if not sku_row:
                continue

            seller_sku = sku_row.codigo

            # 🔻 BAIXA ESTOQUE POR CD (APENAS SE MULTI-CD)
            if multi_cd and network_node_id:
                try:
                    baixar_estoque_cd(
                        cur=cur,
                        empresa_id=empresa_id,
                        seller_sku=seller_sku,
                        network_node_id=network_node_id,
                        quantidade=qty
                    )
                except Exception as e:
                    log(
                        "ERRO",
                        "Falha ao baixar estoque por CD",
                        sku=seller_sku,
                        network_node_id=network_node_id,
                        erro=str(e)
                    )

            # ✔️ Marca venda como processada (mantém seu fluxo)
            mark_processed(cur, empresa_id, order_id, ml_item_id, qty)
            processadas += 1
            unidades += qty

    set_last_run(cur, now_utc)
    cn.commit()
    cn.close()

    return {
        "processadas": processadas,
        "unidades": unidades,
        "dt_from": dt_from.isoformat(),
        "multi_cd": multi_cd
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

          -- 🔥 ESTOQUE REAL (MULTI-CD OU CENTRAL)
          ISNULL((
              SELECT SUM(e.quantidade)
              FROM dbo.ml_estoque_deposito e
              WHERE e.empresa_id = ?
                AND e.seller_sku = v.sku_codigo
          ), v.estoque_central) AS estoque_real,

          v.total_vendido,

          -- 🔥 SALDO REAL
          ISNULL((
              SELECT SUM(e.quantidade)
              FROM dbo.ml_estoque_deposito e
              WHERE e.empresa_id = ?
                AND e.seller_sku = v.sku_codigo
          ), v.estoque_central) - v.total_vendido AS saldo_real,

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
        ORDER BY saldo_real ASC;
    """, empresa_id, empresa_id, empresa_id)

    rows = cur.fetchall()
    cn.close()

    data = [
        {
            "sku_id": int(r.sku_id),
            "codigo": r.sku_codigo,
            "nome": r.sku_nome,
            "estoque": int(r.estoque_real or 0),
            "vendido": int(r.total_vendido or 0),
            "saldo": int(r.saldo_real or 0),
            "estoque_minimo": int(r.estoque_minimo or 0),
            "status": "REPOR" if (r.saldo_real or 0) <= (r.estoque_minimo or 0) else "OK"
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



