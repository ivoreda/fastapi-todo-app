from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from mongoengine import connect
from jose import jwt
from passlib.context import CryptContext
import json
from datetime import timedelta, datetime

from models import Todo, NewTodo, EditTodoRequest, MarkAsDone, User, NewUser

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

def get_password_hash(password):
    return pwd_context.hash(password)

connect(db="todo_app", host="localhost", port=27017)

SECRET_KEY = "550b45a38717374d8e8c747cb23735adcdc63213214369bdd8eda23988adae9a"
ALGORITHM = "HS256"

app = FastAPI()

@app.get('/get_todo/{todo_id}')
async def get_todo(todo_id):
    todo = json.loads(Todo.objects.get(todo_id=todo_id).to_json())
    return {"todo item": todo}


@app.post('/new_todo')
async def new_todo(todo: NewTodo):
    todo = Todo(todo_id=Todo.objects.count() + 1,
                name=todo.name,
                details=todo.details)
    todo.save()
    return {"message": "todo created successfully"}

@app.patch('/edit_todo/{todo_id}')
async def edit_todo(data: EditTodoRequest, todo_id):
    todo = Todo.objects.get(todo_id=todo_id)
    print(todo.to_json())
    if todo:
        if data.name is not None:
            todo.name = data.name
        if data.details is not None:
            todo.details = data.details
        if data.done is not None:
            todo.done = data.done
        todo.save()
        return {"message": "todo editted successfully"}
    else:
        return {"detail":f"todo with id {todo_id} does not exist"}

@app.patch('/mark_as_done/{todo_id}')
async def mark_as_done(data: MarkAsDone, todo_id):
    todo = Todo.objects.get(todo_id=todo_id)
    if todo:
        if data.done is not None:
            todo.done = data.done
        todo.save()
        return {"message": "todo marked as done successfully"}
    else:
        return {"detail":f"todo with id {todo_id} does not exist"}

@app.get('/get_all_todos')
async def get_all_todos():
    todos = json.loads(Todo.objects().to_json())
    return {"todos": todos}

@app.delete('/delete_todo/{todo_id}')
async def delete_todo(todo_id):
    todo = Todo.objects.get(todo_id=todo_id)
    if todo:
        todo.delete()
        return {"message": "todo deleted successfully"}
    else:
        raise HTTPException(status_code=404, detail="todo could not be found")


@app.post('/create_user')
async def create_user(data: NewUser):
    user = User(username=data.username, password=get_password_hash(data.password),
                firstname=data.firstname,lastname=data.lastname,
                gender=data.gender, email=data.email)
    user.save()
    return {"message": "New user created"}


def authenticate_user(username, password):
    try:
        user = json.loads(User.objects.get(username=username).to_json())
        password_check = pwd_context.verify(password, user['password'])
        return password_check
    except User.DoesNotExist:
        return False

def create_access_token(data: dict, expires_delta: timedelta):
    to_encode = data.copy()
    expire = datetime.utcnow() + expires_delta

    to_encode.update({"exp": expire})


    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

    return encoded_jwt


@app.post('/token')
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    username = form_data.username
    password = form_data.password

    if authenticate_user(username, password):
        access_token = create_access_token(data={"sub":username}, expires_delta=timedelta(minutes=30))
        return {"access_token": access_token, "token_type":"bearer"}
    else:
        raise HTTPException(status_code=400, detail="incorrect username or password")

@app.post('/')
async def home(token: str = Depends(oauth2_scheme)):
    return {"token": token}


def fake_decode_token(token):
    return User(
        username=token + "fakedecoded", email="john@example.com", full_name="John Doe"
    )

async def get_current_user(token: str = Depends(oauth2_scheme)):
    user = fake_decode_token(token)
    return user


@app.get("/users/me")
async def read_users_me(current_user: User = Depends(get_current_user)):
    return current_user