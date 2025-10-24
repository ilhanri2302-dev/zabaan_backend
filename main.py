# main.py (no-auth, open backend)
from datetime import datetime
from typing import Optional, List

from fastapi import FastAPI, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from sqlmodel import SQLModel, Field, Session, create_engine, select

# ----- Config -----
DATABASE_URL = "sqlite:////tmp/zabaan.db"

# ----- DB setup -----
engine = create_engine(DATABASE_URL, echo=False)

# ----- Models -----
class User(SQLModel, table=True):  # kept so existing DB doesn’t break; unused
    id: Optional[int] = Field(default=None, primary_key=True)
    username: str = Field(index=True, nullable=False, unique=True)
    hashed_password: str

class Phrase(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    text: str
    type: str  # "Feedback" | "Button"
    created_at: datetime = Field(default_factory=datetime.utcnow)
    owner_id: Optional[int] = Field(default=None, foreign_key="user.id")  # kept, ignored

class Settings(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    # No more per-user settings; treat as global settings row
    user_id: Optional[int] = Field(default=None, foreign_key="user.id")  # kept, ignored
    confidence_threshold: float = 0.7
    vibration_on: bool = True
    sound_on: bool = True
    theme: str = "dark"

class Routine(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    title: str
    type: str  # "Therapeutic" | "General"
    done: bool = False
    created_at: datetime = Field(default_factory=datetime.utcnow)
    owner_id: Optional[int] = Field(default=None, foreign_key="user.id")  # kept, ignored

# ----- Create tables -----
def create_db_and_tables():
    SQLModel.metadata.create_all(engine)

# ----- App and CORS -----
app = FastAPI(title="Zabaan Backend (No-Auth)", version="1.1")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],   # tighten in prod if needed
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ----- Schemas -----
class PhraseCreate(BaseModel):
    text: str
    type: str

class SettingsUpdate(BaseModel):
    confidence_threshold: Optional[float] = None
    vibration_on: Optional[bool] = None
    sound_on: Optional[bool] = None
    theme: Optional[str] = None

class RoutineCreate(BaseModel):
    title: str
    type: str

# ----- Dependency -----
def get_session():
    with Session(engine) as session:
        yield session

# ----- Startup -----
@app.on_event("startup")
def on_startup():
    create_db_and_tables()

# ----- Root -----
@app.get("/")
def root():
    return {"message": "Zabaan Backend (No-Auth) is running 🚀"}

# =======================
# PHRASES (open access)
# =======================
@app.get("/phrases", response_model=List[Phrase])
def read_phrases(session: Session = Depends(get_session)):
    statement = select(Phrase).order_by(Phrase.created_at.desc())
    return session.exec(statement).all()

@app.post("/phrases", response_model=Phrase, status_code=201)
def create_phrase(payload: PhraseCreate, session: Session = Depends(get_session)):
    phrase = Phrase(text=payload.text, type=payload.type)
    session.add(phrase)
    session.commit()
    session.refresh(phrase)
    return phrase

@app.put("/phrases/{phrase_id}", response_model=Phrase)
def update_phrase(phrase_id: int, payload: PhraseCreate, session: Session = Depends(get_session)):
    phrase = session.get(Phrase, phrase_id)
    if not phrase:
        raise HTTPException(status_code=404, detail="Phrase not found")
    phrase.text = payload.text
    phrase.type = payload.type
    session.add(phrase)
    session.commit()
    session.refresh(phrase)
    return phrase

@app.delete("/phrases/{phrase_id}")
def delete_phrase(phrase_id: int, session: Session = Depends(get_session)):
    phrase = session.get(Phrase, phrase_id)
    if not phrase:
        raise HTTPException(status_code=404, detail="Phrase not found")
    session.delete(phrase)
    session.commit()
    return {"message": "Phrase deleted"}

# =======================
# SETTINGS (global row)
# =======================
def _get_or_create_global_settings(session: Session) -> Settings:
    settings = session.exec(select(Settings).order_by(Settings.id.asc())).first()
    if not settings:
        settings = Settings()
        session.add(settings)
        session.commit()
        session.refresh(settings)
    return settings

@app.get("/settings")
def get_settings(session: Session = Depends(get_session)):
    s = _get_or_create_global_settings(session)
    return {
        "confidence_threshold": s.confidence_threshold,
        "vibration_on": s.vibration_on,
        "sound_on": s.sound_on,
        "theme": s.theme,
    }

@app.put("/settings")
def update_settings(payload: SettingsUpdate, session: Session = Depends(get_session)):
    s = _get_or_create_global_settings(session)
    if payload.confidence_threshold is not None:
        s.confidence_threshold = payload.confidence_threshold
    if payload.vibration_on is not None:
        s.vibration_on = payload.vibration_on
    if payload.sound_on is not None:
        s.sound_on = payload.sound_on
    if payload.theme is not None:
        s.theme = payload.theme
    session.add(s)
    session.commit()
    session.refresh(s)
    return {"message": "Settings updated"}

# =======================
# ROUTINES (open access)
# =======================
@app.get("/routines", response_model=List[Routine])
def read_routines(session: Session = Depends(get_session)):
    statement = select(Routine).order_by(Routine.created_at.desc())
    return session.exec(statement).all()

@app.post("/routines", response_model=Routine, status_code=201)
def create_routine(data: RoutineCreate, session: Session = Depends(get_session)):
    r = Routine(title=data.title, type=data.type)
    session.add(r)
    session.commit()
    session.refresh(r)
    return r

@app.put("/routines/{routine_id}", response_model=Routine)
def update_routine(routine_id: int, data: RoutineCreate, session: Session = Depends(get_session)):
    r = session.get(Routine, routine_id)
    if not r:
        raise HTTPException(status_code=404, detail="Not found")
    r.title, r.type = data.title, data.type
    session.add(r)
    session.commit()
    session.refresh(r)
    return r

@app.delete("/routines/{routine_id}")
def delete_routine(routine_id: int, session: Session = Depends(get_session)):
    r = session.get(Routine, routine_id)
    if not r:
        raise HTTPException(status_code=404, detail="Not found")
    session.delete(r)
    session.commit()
    return {"message": "Deleted"}

