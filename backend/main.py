import os
from datetime import datetime, timedelta, timezone
from typing import List, Optional

from fastapi import FastAPI, HTTPException, Depends, status, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel, EmailStr
from passlib.context import CryptContext
import jwt

from database import db, create_document, get_documents
from schemas import Profile, Category, Article, UserArticleStatus

# Config
JWT_SECRET = os.getenv("JWT_SECRET", "dev-secret")
JWT_ALG = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")

app = FastAPI(title="Praktycznik API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Simple collections naming
USERS_COL = "user"
PROFILES_COL = "profile"
CATEGORIES_COL = "category"
ARTICLES_COL = "article"
STATUSES_COL = "userarticlestatus"

# Models
class UserCreate(BaseModel):
    email: EmailStr
    password: str

class LoginIn(BaseModel):
    email: EmailStr
    password: str

class UserOut(BaseModel):
    id: str
    email: EmailStr

class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"

# Helpers

def get_user_by_email(email: str):
    if db is None:
        raise HTTPException(status_code=500, detail="Database not configured")
    return db[USERS_COL].find_one({"email": email})

def get_user_by_id(user_id: str):
    from bson import ObjectId
    if db is None:
        raise HTTPException(status_code=500, detail="Database not configured")
    try:
        return db[USERS_COL].find_one({"_id": ObjectId(user_id)})
    except Exception:
        return None


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, JWT_SECRET, algorithm=JWT_ALG)


def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
        user_id: str = payload.get("sub")
        if user_id is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
        user = get_user_by_id(user_id)
        if not user:
            raise HTTPException(status_code=401, detail="User not found")
        return user
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")


def require_admin(user = Depends(get_current_user)):
    prof = db[PROFILES_COL].find_one({"user_id": str(user["_id"])}) if db else None
    if not prof or prof.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin only")
    return user

# Routes
@app.get("/")
def root():
    return {"name": "Praktycznik API"}

@app.get("/test")
def test():
    ok = db is not None
    return {"backend": "running", "database": ok}

# Auth
@app.post("/auth/register", response_model=Token)
def register(data: UserCreate):
    if get_user_by_email(data.email):
        raise HTTPException(status_code=400, detail="Email already registered")
    hashed = pwd_context.hash(data.password)
    user_doc = {"email": str(data.email), "password": hashed, "created_at": datetime.now(timezone.utc)}
    uid = db[USERS_COL].insert_one(user_doc).inserted_id
    create_document(PROFILES_COL, Profile(user_id=str(uid), role="user"))
    access = create_access_token({"sub": str(uid)})
    return Token(access_token=access)

@app.post("/auth/login", response_model=Token)
def login(payload: LoginIn):
    user = get_user_by_email(str(payload.email))
    if not user or not pwd_context.verify(payload.password, user.get("password")):
        raise HTTPException(status_code=400, detail="Invalid credentials")
    access = create_access_token({"sub": str(user["_id"])})
    return Token(access_token=access)

# Reset password (simple tokenless demo endpoint)
class ResetPasswordIn(BaseModel):
    email: EmailStr
    new_password: str

@app.post("/auth/reset-password")
def reset_password(payload: ResetPasswordIn):
    user = get_user_by_email(str(payload.email))
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    hashed = pwd_context.hash(payload.new_password)
    db[USERS_COL].update_one({"_id": user["_id"]}, {"$set": {"password": hashed, "updated_at": datetime.now(timezone.utc)}})
    return {"status": "ok"}

# Categories CRUD (admin)
class CategoryIn(BaseModel):
    name: str
    description: Optional[str] = None

@app.post("/admin/categories")
def create_category(cat: CategoryIn, user=Depends(require_admin)):
    cid = create_document(CATEGORIES_COL, Category(name=cat.name, description=cat.description))
    return {"id": cid}

@app.get("/admin/categories")
def list_categories_admin(user=Depends(require_admin)):
    return get_documents(CATEGORIES_COL)

@app.put("/admin/categories/{category_id}")
def update_category(category_id: str, cat: CategoryIn, user=Depends(require_admin)):
    from bson import ObjectId
    db[CATEGORIES_COL].update_one({"_id": ObjectId(category_id)}, {"$set": {"name": cat.name, "description": cat.description, "updated_at": datetime.now(timezone.utc)}})
    return {"status": "ok"}

@app.delete("/admin/categories/{category_id}")
def delete_category(category_id: str, user=Depends(require_admin)):
    from bson import ObjectId
    db[CATEGORIES_COL].delete_one({"_id": ObjectId(category_id)})
    return {"status": "ok"}

# Articles CRUD (admin)
class ArticleIn(BaseModel):
    title: str
    content: str
    bibliography: Optional[str] = None
    category_id: str
    images: Optional[List[str]] = None

@app.post("/admin/articles")
def create_article(payload: ArticleIn, user=Depends(require_admin)):
    aid = create_document(ARTICLES_COL, Article(**payload.model_dump()))
    return {"id": aid}

@app.get("/admin/articles")
def list_articles_admin(user=Depends(require_admin)):
    return get_documents(ARTICLES_COL)

@app.put("/admin/articles/{article_id}")
def update_article(article_id: str, payload: ArticleIn, user=Depends(require_admin)):
    from bson import ObjectId
    db[ARTICLES_COL].update_one({"_id": ObjectId(article_id)}, {"$set": {**payload.model_dump(), "updated_at": datetime.now(timezone.utc)}})
    return {"status": "ok"}

@app.delete("/admin/articles/{article_id}")
def delete_article(article_id: str, user=Depends(require_admin)):
    from bson import ObjectId
    db[ARTICLES_COL].delete_one({"_id": ObjectId(article_id)})
    return {"status": "ok"}

# Public endpoints
@app.get("/categories")
def list_categories():
    return get_documents(CATEGORIES_COL)

@app.get("/categories/{category_id}/articles")
def articles_by_category(category_id: str):
    return get_documents(ARTICLES_COL, {"category_id": category_id})

@app.get("/articles/{article_id}")
def get_article(article_id: str):
    from bson import ObjectId
    doc = db[ARTICLES_COL].find_one({"_id": ObjectId(article_id)})
    if not doc:
        raise HTTPException(404, "Not found")
    return doc

# Progress tracking
class StatusIn(BaseModel):
    status: str

@app.post("/articles/{article_id}/status")
def set_status(article_id: str, payload: StatusIn, user=Depends(get_current_user)):
    uid = str(user["_id"])
    existing = db[STATUSES_COL].find_one({"user_id": uid, "article_id": article_id})
    if existing:
        db[STATUSES_COL].update_one({"_id": existing["_id"]}, {"$set": {"status": payload.status, "updated_at": datetime.now(timezone.utc)}})
    else:
        create_document(STATUSES_COL, UserArticleStatus(user_id=uid, article_id=article_id, status=payload.status))
    return {"status": "ok"}

@app.get("/articles/{article_id}/status")
def get_status(article_id: str, user=Depends(get_current_user)):
    uid = str(user["_id"])
    doc = db[STATUSES_COL].find_one({"user_id": uid, "article_id": article_id})
    return doc or {"status": None}

# Global search
@app.get("/search")
def search(q: str):
    if not q:
        return []
    regex = {"$regex": q, "$options": "i"}
    cursor = db[ARTICLES_COL].find({"$or": [{"title": regex}, {"content": regex}, {"bibliography": regex}]})
    return list(cursor)

# Simple image upload endpoint (stores base64 via multipart for demo)
@app.post("/admin/upload")
def upload_image(file: UploadFile = File(...), user=Depends(require_admin)):
    content = file.file.read()  # Placeholder to mimic processing
    return {"url": f"/uploads/{file.filename}"}

if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
