from pydantic import BaseModel
from fastapi import FastAPI, Request, HTTPException

import hmac
import hashlib
import urllib.parse

from dotenv import load_dotenv
import os


def validate_telegram_data(init_data: str, bot_token: str) -> bool:
    # Parse the query string into a dictionary
    data = dict(urllib.parse.parse_qsl(init_data))
    received_hash = data.pop("hash", None)
    if not received_hash:
        raise HTTPException(status_code=400, detail="Missing hash in initData")
    
    # Build the data-check string: sort keys alphabetically and join as "key=<value>" separated by \n
    data_check_arr = [f"{key}={data[key]}" for key in sorted(data.keys())]
    data_check_string = "\n".join(data_check_arr)
    
    # Compute the secret key using HMAC-SHA256: bot_token is the message, "WebAppData" is the key.
    # (Note: the order here is per Telegram’s spec)
    secret_key = hmac.new(key=b"WebAppData", msg=bot_token.encode(), digestmod=hashlib.sha256).digest()
    
    # Compute the HMAC of the data-check string using the computed secret key
    computed_hash = hmac.new(key=secret_key, msg=data_check_string.encode(), digestmod=hashlib.sha256).hexdigest()
    
    # Compare the computed hash with the received hash in a secure way
    if hmac.compare_digest(computed_hash, received_hash):
        return True
    else:
        return False


app = FastAPI()

load_dotenv()
BOT_TOKEN = os.getenv("BOT_TOKEN")

@app.post("/validate-telegram-data")
async def validate_data(request: Request):
    # Expect the client to send the initData string (e.g., in a JSON payload)
    payload = await request.json()
    init_data = payload.get("initData")
    if not init_data:
        raise HTTPException(status_code=400, detail="initData is required")
    
    if validate_telegram_data(init_data, BOT_TOKEN):
        return {"status": "ok", "message": "Data is valid"}
    else:
        raise HTTPException(status_code=400, detail="Data validation failed")
