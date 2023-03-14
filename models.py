from pydantic import BaseModel
from typing import Optional
from uuid import UUID
from enum import Enum

from mongoengine import Document, StringField, EmailField, IntField, BooleanField, ReferenceField

class Gender(str, Enum):
    male = "male"
    female = "female"

class User(Document):
    user_id: int = IntField(min_value=1)
    username: str = StringField(max_length=15, required=True)
    password: str = StringField(required=True)
    firstname: str = StringField(max_length=15, required=True)
    lastname: str = StringField(max_length=15, required=True)
    gender: Gender = StringField(required=True)
    email: str = EmailField(required=True)

class NewUser(BaseModel):
    username: str
    password: str
    firstname: str
    lastname: str
    gender: Gender
    email: str



class Todo(Document):
    todo_id: int = IntField(min_value=1)
    name: str = StringField(max_length=255, required=True)
    user: str = StringField()
    details: Optional[str] = StringField(required=True)
    done: bool = BooleanField(required=True, default=False)

class NewTodo(BaseModel):
    name: str
    details: Optional[str]

class EditTodoRequest(BaseModel):
    name: str
    details: Optional[str]

class MarkAsDone(BaseModel):
    done: bool