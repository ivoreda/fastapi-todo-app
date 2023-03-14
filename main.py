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
async def get_todo(todo_id, token:str = Depends(oauth2_scheme)):
    todo = json.loads(Todo.objects.get(todo_id=todo_id).to_json())
    return {"todo item": todo}


@app.post('/new_todo')
async def new_todo(todo: NewTodo, token:str = Depends(oauth2_scheme)):
    user = jwt.decode(token, SECRET_KEY, algorithms=ALGORITHM)
    username = user['sub']
    todo = Todo(todo_id=Todo.objects.count() + 1,
                name=todo.name,
                details=todo.details,
                user=username)
    todo.save()
    return {"message": "todo created successfully"}

@app.patch('/edit_todo/{todo_id}')
async def edit_todo(data: EditTodoRequest, todo_id, token:str = Depends(oauth2_scheme)):
    todo = Todo.objects.get(todo_id=todo_id)
    user = jwt.decode(token, SECRET_KEY, algorithms=ALGORITHM)
    username = user['sub']
    if todo:
        if username == todo.user:
            if data.name is not None:
                todo.name = data.name
            if data.details is not None:
                todo.details = data.details
            if data.done is not None:
                todo.done = data.done
            todo.save()
            return {"message": "todo editted successfully"}
        else:
            return {"message": "you cannot edit this todo item. it is not yours."}
    else:
        return {"detail":f"todo with id {todo_id} does not exist"}

@app.patch('/mark_as_done/{todo_id}')
async def mark_as_done(data: MarkAsDone, todo_id, token:str = Depends(oauth2_scheme)):
    todo = Todo.objects.get(todo_id=todo_id)
    user = jwt.decode(token, SECRET_KEY, algorithms=ALGORITHM)
    username = user['sub']
    if todo:
        if username == todo.user:
            if data.done is not None:
                todo.done = data.done
            todo.save()
            return {"message": "todo marked as done successfully"}
        else:
            return {"message": "you cannot edit this todo item. it is not yours."}
    else:
        return {"detail":f"todo with id {todo_id} does not exist"}

@app.get('/get_all_todos')
async def get_all_todos(token:str = Depends(oauth2_scheme)):
    todos = json.loads(Todo.objects().to_json())
    user = jwt.decode(token, SECRET_KEY, algorithms=ALGORITHM)
    username = user['sub']
    my_todo = []
    for i in todos:
        if i['user'] == username:
            my_todo.append(i)
    print(my_todo)
    return {"todos": my_todo}

@app.delete('/delete_todo/{todo_id}')
async def delete_todo(todo_id, token:str = Depends(oauth2_scheme)):
    todo = Todo.objects.get(todo_id=todo_id)
    user = jwt.decode(token, SECRET_KEY, algorithms=ALGORITHM)
    username = user['sub']
    if todo:
        if username == todo.user:
            todo.delete()
            return {"message": "todo deleted successfully"}
        else:
            return {"message": "you cannot delete this todo item. it is not yours."}
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
