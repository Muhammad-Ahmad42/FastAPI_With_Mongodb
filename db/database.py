import os
from dotenv import load_dotenv
from pymongo import MongoClient
load_dotenv()

MONGODB_URL = os.getenv("MONGODB_URL")
DATABASE_NAME = os.getenv("DATABASE_NAME")

client = MongoClient(MONGODB_URL)
db = client[DATABASE_NAME]
medicine_collection = db["Medicines"] 
user_collection=db["users"]

def get_client():
    return client

def get_db():
    return db

def get_medicine_collection():
    return medicine_collection

def get_user_collection():
    return user_collection