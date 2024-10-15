from sys import argv
from fastapi import FastAPI, HTTPException, Depends
from typing import List, Dict, Optional
import uvicorn
from ElementalDB import ElementalDB
from auth import (
    get_password_hash,
    authenticate_user,
    create_access_token,
    ACCESS_TOKEN_EXPIRE_MINUTES,
    Token,
    TokenData,
    User,
    UserResponse,
    get_current_user
)
from datetime import timedelta
from fastapi.security import OAuth2PasswordRequestForm
from http import HTTPStatus
# Initialize FastAPI and the ElementalDB instance
app = FastAPI()
auth_enabled = True
db = ElementalDB('database')  # Initialize the database

def matchRole(searchedRole: str,token: TokenData):
    """ 
    Verifies that a certain user has an specific role.

    Args:
        searchedRole: The role to be searched.
        user: The user object.

    Raises:
        HTTPException: If the user isn't found or doesn't match with the searched role
    """

    if not auth_enabled:
        return

    if token == None or token.role:
        raise HTTPException(status_code=HTTPStatus.NOT_FOUND)
    if not searchedRole in token.role:
        raise HTTPException(status_code=HTTPStatus.UNAUTHORIZED)

@app.post("/signup")
async def signup(newUser: User):
    """
    Create a new user account.

    Args:
        user (UserCreate): The user information containing username and password.

    Returns:
        UserResponse: The created user information.

    Raises:
        HTTPException: If the username already exists or if there is a database error.
    """

    # Checks if user already exists
    existing_users = await db.get("USERS", "username", newUser.username)
    if existing_users:
        raise HTTPException(status_code=HTTPStatus.BAD_REQUEST, detail="Username already registered")

    hashed_password = get_password_hash(newUser.password)
    user_record = {
        "username": newUser.username,
        "password": hashed_password,
        "role": newUser.role
    }

    try: 
        await db.add("USERS", user_record)
        created_users = await db.get("USERS", "username", newUser.username)
        if not created_users:
            raise HTTPException(status_code=HTTPStatus.BAD_REQUEST, detail="Error retrieving created user")

        created_user = created_users[0]

        # return UserResponse(id=created_user['id'], username=created_user['username'], role=created_user['role'])
        return {"id":created_user['id'],"username":created_user['username'],"role":created_user['role']}
    except HTTPException as e:
        raise HTTPException(status_code=HTTPStatus.BAD_REQUEST, detail=str(e))

@app.post("/login", response_model=Token)
async def login(form_data: OAuth2PasswordRequestForm = Depends(), auth_enabled: bool = True):
    """
    Authenticate a user and return a JWT token.

    Args:
        form_data (OAuth2PasswordRequestForm): The form data containing username and password.

    Returns:
        Token: The access token and token type.

    Raises:
        HTTPException: If authentication fails.
    """
    if not auth_enabled:
        return
    
    user = await authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=HTTPStatus.UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"}
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username, "role": user.role}, 
        expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/add")
async def add_item(table_name: str, columns: List[str], values: List[str], token: TokenData = Depends(get_current_user), auth_enabled: bool = True):
    """
    Add a new item to a specified table in the database.

    Args:
        table_name (str): The name of the table to add the item.
        columns (list): The list of column names corresponding to the values.
        values (list): The list of values to be added to the specified columns.

    Returns:
        dict: A success message if the item is added successfully.

    Raises:
        HTTPException: If there is an error during the addition of the item.
    """

    matchRole("w",token)

    if len(columns) != len(values):
        raise HTTPException(status_code=422, detail="Columns and values length must match.")

    try:
        # Prepare a dictionary of column-value pairs
        record = dict(zip(columns, values))
        await db.add(table_name, record)  # Pass the record to the DB
        return {"message": "Item added successfully"}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.get("/get/{table_name}")
async def get_items(table_name: str, token: TokenData = Depends(get_current_user)):
    """
    Retrieve all items from a specified table in the database.

    Args:
        table_name (str): The name of the table from which to retrieve items.

    Returns:
        list: A list of items in the specified table.

    Raises:
        HTTPException: If the table does not exist or if an error occurs during retrieval.
    """

    matchRole("r",token)

    try:
        items = await db.get(table_name)
        if not items:
            raise HTTPException(status_code=404, detail="Table not found or is empty")
        return items
    except Exception as e:
        raise HTTPException(status_code=404, detail=str(e))

@app.delete("/delete/{table_name}/{id}")
async def delete_item(table_name: str, id: int, token: TokenData = Depends(get_current_user), auth_enabled: bool = auth_enabled):
    """
    Delete a specific item from a table by its ID.

    Args:
        table_name (str): The name of the table from which to delete the item.
        id (int): The unique identifier of the item to be deleted.

    Returns:
        dict: A success message if the item is deleted successfully.

    Raises:
        HTTPException: If the item does not exist or if an error occurs during deletion.
    """

    matchRole("d",token)

    try:
        await db.delete(table_name, id)
        return {"message": "Item deleted successfully"}
    except Exception as e:
        raise HTTPException(status_code=404, detail=str(e))

@app.put("/update")
async def update_item(table_name: str, row_id: int, updates: Dict[str, str], token: TokenData = Depends(get_current_user), auth_enabled: bool = auth_enabled):
    """
    Update a specific item in a table by its ID.

    Args:
        table_name (str): The name of the table where the item resides.
        row_id (int): The unique identifier of the row to be updated.
        updates (dict): A dictionary of column-value pairs representing the updates.

    Returns:
        dict: A success message if the item is updated successfully.

    Raises:
        HTTPException: If the item does not exist, or if an error occurs during the update.
    """

    matchRole("w",token)

    try:
        await db.update(table_name, row_id, updates)
        return {"message": "Item updated successfully"}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

if __name__ == "__main__":
    if len(argv) < 2:
        uvicorn.run(app, host="127.0.0.1", port=8000)
    else:
        uvicorn.run(app, host=argv[1].split(":")[0], port=argv[1].split(":")[1])
