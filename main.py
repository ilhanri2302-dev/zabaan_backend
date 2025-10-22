# main.py
from datetime import datetime, timedelta
from typing import Optional, List

from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from pydantic import BaseModel
from sqlmodel import SQLModel, Field, Session, create_engine, select
from passlib.context import CryptContext
from jose import JWTError, jwt

# ----- Config -----
DATABASE_URL = "sqlite:////tmp/zabaan.db"
SECRET_KEY = "CHANGE_THIS_TO_A_SECURE_RANDOM_STRING"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7  # 7 days

# ----- DB setup -----
engine = create_engine(DATABASE_URL, echo=False)

# ----- Models -----
class User(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    username: str = Field(index=True, nullable=False, unique=True)
    hashed_password: str

class Phrase(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    text: str
    type: str
    created_at: datetime = Field(default_factory=datetime.utcnow)
    owner_id: Optional[int] = Field(default=None, foreign_key="user.id")

class Settings(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    user_id: int = Field(foreign_key="user.id")
    confidence_threshold: float = 0.7
    vibration_on: bool = True
    sound_on: bool = True
    theme: str = "dark"

class Routine(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    title: str
    type: str
    done: bool = False
    created_at: datetime = Field(default_factory=datetime.utcnow)
    owner_id: Optional[int] = Field(default=None, foreign_key="user.id")

# ----- Create tables -----
def create_db_and_tables():
    SQLModel.metadata.create_all(engine)

# ----- Security -----
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

def verify_password(plain, hashed):
    return pwd_context.verify(plain, hashed)

def get_password_hash(password):
    # bcrypt only supports 72 bytes; enforce limit safely
    return pwd_context.hash(password[:72])

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

# ----- App and CORS -----
app = FastAPI(title="Zabaan Backend", version="1.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # for dev - restrict in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ----- Pydantic Schemas -----
class PhraseCreate(BaseModel):
    text: str
    type: str

class UserCreate(BaseModel):
    username: str
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str

class SettingsUpdate(BaseModel):
    confidence_threshold: Optional[float]
    vibration_on: Optional[bool]
    sound_on: Optional[bool]
    theme: Optional[str]

class RoutineCreate(BaseModel):
    title: str
    type: str

# ----- Dependencies -----
def get_session():
    with Session(engine) as session:
        yield session

def get_user_by_username(session: Session, username: str) -> Optional[User]:
    statement = select(User).where(User.username == username)
    return session.exec(statement).first()

def authenticate_user(session: Session, username: str, password: str):
    user = get_user_by_username(session, username)
    if not user:
        return None
    if not verify_password(password, user.hashed_password):
        return None
    return user

async def get_current_user(token: str = Depends(oauth2_scheme), session: Session = Depends(get_session)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = get_user_by_username(session, username)
    if user is None:
        raise credentials_exception
    return user

# ----- Startup -----
@app.on_event("startup")
def on_startup():
    create_db_and_tables()

# ----- Root -----
@app.get("/")
def root():
    return {"message": "Zabaan Backend (DB) is running 🚀"}

# ----- Auth -----
@app.post("/register", response_model=dict)
def register(data: UserCreate, session: Session = Depends(get_session)):
    if get_user_by_username(session, data.username):
        raise HTTPException(status_code=400, detail="Username already exists")
    user = User(username=data.username, hashed_password=get_password_hash(data.password))
    session.add(user)
    session.commit()
    session.refresh(user)
    settings = Settings(user_id=user.id)
    session.add(settings)
    session.commit()
    return {"message": "User created", "username": user.username}

@app.post("/token", response_model=Token)
def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), session: Session = Depends(get_session)):
    user = authenticate_user(session, form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=400, detail="Incorrect username or password")
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(data={"sub": user.username}, expires_delta=access_token_expires)
    return {"access_token": access_token, "token_type": "bearer"}

# ----- Phrases -----
@app.get("/phrases", response_model=List[Phrase])
def read_phrases(session: Session = Depends(get_session), current_user: User = Depends(get_current_user)):
    statement = select(Phrase).where(Phrase.owner_id == current_user.id).order_by(Phrase.created_at.desc())
    return session.exec(statement).all()

@app.post("/phrases", response_model=Phrase, status_code=201)
def create_phrase(payload: PhraseCreate, session: Session = Depends(get_session), current_user: User = Depends(get_current_user)):
    phrase = Phrase(text=payload.text, type=payload.type, owner_id=current_user.id)
    session.add(phrase)
    session.commit()
    session.refresh(phrase)
    return phrase

@app.put("/phrases/{phrase_id}", response_model=Phrase)
def update_phrase(phrase_id: int, payload: PhraseCreate, session: Session = Depends(get_session), current_user: User = Depends(get_current_user)):
    phrase = session.get(Phrase, phrase_id)
    if not phrase or phrase.owner_id != current_user.id:
        raise HTTPException(status_code=404, detail="Phrase not found")
    phrase.text, phrase.type = payload.text, payload.type
    session.add(phrase)
    session.commit()
    session.refresh(phrase)
    return phrase

@app.delete("/phrases/{phrase_id}")
def delete_phrase(phrase_id: int, session: Session = Depends(get_session), current_user: User = Depends(get_current_user)):
    phrase = session.get(Phrase, phrase_id)
    if not phrase or phrase.owner_id != current_user.id:
        raise HTTPException(status_code=404, detail="Phrase not found")
    session.delete(phrase)
    session.commit()
    return {"message": "Phrase deleted"}

# ----- Settings -----
@app.get("/settings")
def get_settings(session: Session = Depends(get_session), current_user: User = Depends(get_current_user)):
    statement = select(Settings).where(Settings.user_id == current_user.id)
    settings = session.exec(statement).first()
    if not settings:
        settings = Settings(user_id=current_user.id)
        session.add(settings)
        session.commit()
        session.refresh(settings)
    return settings

@app.put("/settings")
def update_settings(payload: SettingsUpdate, session: Session = Depends(get_session), current_user: User = Depends(get_current_user)):
    statement = select(Settings).where(Settings.user_id == current_user.id)
    settings = session.exec(statement).first() or Settings(user_id=current_user.id)
    for key, value in payload.dict(exclude_unset=True).items():
        setattr(settings, key, value)
    session.add(settings)
    session.commit()
    session.refresh(settings)
    return {"message": "Settings updated"}

# ----- Routines -----
@app.get("/routines", response_model=List[Routine])
def read_routines(session: Session = Depends(get_session), current_user: User = Depends(get_current_user)):
    statement = select(Routine).where(Routine.owner_id == current_user.id).order_by(Routine.created_at.desc())
    return session.exec(statement).all()

@app.post("/routines", response_model=Routine, status_code=201)
def create_routine(data: RoutineCreate, session: Session = Depends(get_session), current_user: User = Depends(get_current_user)):
    r = Routine(title=data.title, type=data.type, owner_id=current_user.id)
    session.add(r)
    session.commit()
    session.refresh(r)
    return r

@app.put("/routines/{routine_id}", response_model=Routine)
def update_routine(routine_id: int, data: RoutineCreate, session: Session = Depends(get_session), current_user: User = Depends(get_current_user)):
    r = session.get(Routine, routine_id)
    if not r or r.owner_id != current_user.id:
        raise HTTPException(status_code=404, detail="Not found")
    r.title, r.type = data.title, data.type
    session.add(r)
    session.commit()
    session.refresh(r)
    return r

@app.delete("/routines/{routine_id}")
def delete_routine(routine_id: int, session: Session = Depends(get_session), current_user: User = Depends(get_current_user)):
    r = session.get(Routine, routine_id)
    if not r or r.owner_id != current_user.id:
        raise HTTPException(status_code=404, detail="Not found")
    session.delete(r)
    session.commit()
    return {"message": "Deleted"}

# ----- Fixed Dev Helper -----
@app.post("/create_dev_user")
def create_dev_user(session: Session = Depends(get_session)):
    """Creates or repairs the default dev user for testing"""
    existing = get_user_by_username(session, "dev")
    if existing:
        return {"message": "Dev user already exists"}
    password = "devpass"
    hashed = get_password_hash(password[:72])
    user = User(username="dev", hashed_password=hashed)
    session.add(user)
    session.commit()
    session.refresh(user)
    settings = Settings(user_id=user.id)
    session.add(settings)
    session.commit()
    return {"message": "Dev user created", "username": "dev", "password": password}

