from fastapi import FastAPI, Request, Form, Depends
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

from sqlalchemy.orm import Session

from database import Base, engine, get_db
from models import User, AuditLog
from auth import hash_password, verify_password

# -------------------------
# Database
# -------------------------

Base.metadata.create_all(bind=engine)

# -------------------------
# App
# -------------------------

app = FastAPI()

app.add_middleware(
    SessionMiddleware,
    secret_key="super-secret-key"
)

templates = Jinja2Templates(directory="templates")

# -------------------------
# Helper Functions
# -------------------------

def current_user(request: Request):
    return request.session.get("username")


def current_role(request: Request):
    return request.session.get("role")


def log_action(
    db: Session,
    username: str,
    action: str,
    ip: str
):
    log = AuditLog(
        username=username,
        action=action,
        ip_address=ip
    )

    db.add(log)
    db.commit()


def login_required(request: Request):
    if not current_user(request):
        return False
    return True


def admin_required(request: Request):
    if current_role(request) != "admin":
        return False
    return True


# -------------------------
# Home
# -------------------------

@app.get("/", response_class=HTMLResponse)
def home(request: Request):

    return templates.TemplateResponse(
        request=request,
        name="login.html",
        context={}
    )


# -------------------------
# Register Page
# -------------------------

@app.get("/register", response_class=HTMLResponse)
def register_page(request: Request):

    return templates.TemplateResponse(
        request=request,
        name="register.html",
        context={}
    )


# -------------------------
# Register
# -------------------------

@app.post("/register", response_class=HTMLResponse)
def register(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db)
):

    user = (
        db.query(User)
        .filter(User.username == username)
        .first()
    )

    if user:
        return templates.TemplateResponse(
            request=request,
            name="register.html",
            context={
                "error": "Username already exists!"
            },
            status_code=400
        )

    role = "admin"

    if db.query(User).count() > 0:
        role = "user"

    new_user = User(
        username=username,
        password=hash_password(password),
        role=role
    )

    db.add(new_user)
    db.commit()

    log_action(
        db,
        username,
        "Registered",
        request.client.host
    )

    return RedirectResponse(
        "/",
        status_code=303
    )

# -------------------------
# Login
# -------------------------

@app.post("/login", response_class=HTMLResponse)
def login(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db)
):

    user = (
        db.query(User)
        .filter(User.username == username)
        .first()
    )

    if not user or not verify_password(password, user.password):

        log_action(
            db,
            username,
            "Login Failed",
            request.client.host
        )

        return templates.TemplateResponse(
            request=request,
            name="login.html",
            context={
                "error": "Invalid username or password!"
            },
            status_code=401
        )

    request.session["username"] = user.username
    request.session["role"] = user.role

    log_action(
        db,
        user.username,
        "Login Success",
        request.client.host
    )

    return RedirectResponse(
        "/dashboard",
        status_code=303
    )


# -------------------------
# Dashboard
# -------------------------

@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(
    request: Request,
    db: Session = Depends(get_db)
):

    if not login_required(request):
        return RedirectResponse("/", status_code=303)

    username = current_user(request)
    role = current_role(request)

    log_action(
        db,
        username,
        "Viewed Dashboard",
        request.client.host
    )

    return templates.TemplateResponse(
        request=request,
        name="dashboard.html",
        context={
            "username": username,
            "role": role
        }
    )


# -------------------------
# Admin Page
# -------------------------

@app.get("/admin", response_class=HTMLResponse)
def admin_page(
    request: Request,
    db: Session = Depends(get_db)
):

    if not login_required(request):
        return RedirectResponse("/", status_code=303)

    if not admin_required(request):

        return templates.TemplateResponse(
            request=request,
            name="dashboard.html",
            context={
                "username": current_user(request),
                "role": current_role(request),
                "error": "Access Denied! Admins only."
            },
            status_code=403
        )

    users = db.query(User).all()

    log_action(
        db,
        current_user(request),
        "Viewed Admin Page",
        request.client.host
    )

    return templates.TemplateResponse(
        request=request,
        name="admin.html",
        context={
            "username": current_user(request),
            "users": users
        }
    )

# -------------------------
# Logout
# -------------------------

@app.get("/logout")
def logout(
    request: Request,
    db: Session = Depends(get_db)
):

    username = current_user(request)

    if username:
        log_action(
            db,
            username,
            "Logout",
            request.client.host
        )

    request.session.clear()

    return RedirectResponse("/", status_code=303)


# -------------------------
# Audit Logs
# -------------------------

@app.get("/logs", response_class=HTMLResponse)
def audit_logs(
    request: Request,
    db: Session = Depends(get_db)
):

    if not login_required(request):
        return RedirectResponse("/", status_code=303)

    # if not admin_required(request):

    #     return templates.TemplateResponse(
    #         request=request,
    #         name="dashboard.html",
    #         context={
    #             "username": current_user(request),
    #             "role": current_role(request),
    #             "error": "Access Denied! Admins only."
    #         },
    #         status_code=403
    #     )

    logs = (
        db.query(AuditLog)
        .order_by(AuditLog.timestamp.desc())
        .all()
    )

    log_action(
        db,
        current_user(request),
        "Viewed Audit Logs",
        request.client.host
    )

    return templates.TemplateResponse(
        request=request,
        name="logs.html",
        context={
            "username": current_user(request),
            "logs": logs
        }
    )