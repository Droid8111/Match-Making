import json
import uuid
import jwt
import base64
from fastapi import FastAPI, HTTPException, BackgroundTasks, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field
from typing import List, Optional
import databases
import os
from dotenv import load_dotenv

load_dotenv()

# --- STEP 1: SANITIZE ENVIRONMENT STRINGS ---
RAW_DATABASE_URL = os.getenv("DATABASE_URL", "").strip("'\"").strip()
RAW_JWT_SECRET = os.getenv("SUPABASE_JWT_SECRET", "").strip("'\"").strip()
SUPABASE_PROJECT_ID = os.getenv("SUPABASE_PROJECT_ID", "").strip("'\"").strip()
RAW_SERVICE_ROLE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY", "").strip("'\"").strip()

DATABASE_URL = RAW_DATABASE_URL
SUPABASE_JWT_SECRET = RAW_JWT_SECRET

database = databases.Database(DATABASE_URL)

# --- STEP 2: INITIALIZE THE LIVE ASYMMETRIC KEY STREAM CLIENT ---
# This client connects directly to your Supabase project's public directory to cache signing certificates
JWKS_URL = f"https://{SUPABASE_PROJECT_ID}.supabase.co/auth/v1/.well-known/jwks.json"
jwk_client = jwt.PyJWKClient(JWKS_URL)


# Fallback decoder logic for standard symmetric HS256 operations
def get_legacy_hs256_key(secret_str: str) -> bytes:
    if "-" in secret_str and len(secret_str) == 36:
        return secret_str.encode('utf-8')
    try:
        normalized = secret_str.replace('-', '+').replace('_', '/')
        padding_needed = len(normalized) % 4
        if padding_needed:
            normalized += '=' * (4 - padding_needed)
        return base64.b64decode(normalized)
    except Exception:
        return secret_str.encode('utf-8')

LEGACY_HS256_KEY = get_legacy_hs256_key(RAW_JWT_SECRET)

security = HTTPBearer()
app = FastAPI(title="Round-Based Dating API")

@app.on_event("startup")
async def startup():
    await database.connect()

@app.on_event("shutdown")
async def shutdown():
    await database.disconnect()

# --- PYDANTIC SCHEMAS ---
class PreferenceUpdate(BaseModel):
    min_age: int = Field(18, ge=18, le=99)
    max_age: int = Field(35, ge=18, le=100)
    max_distance_km: int = Field(25, gt=0, le=150)

class MatchResponse(BaseModel):
    match_id: str
    first_name: str
    age: int
    bio: Optional[str]
    photos: List[str]
    prompts: List[dict]

# --- STEP 3: HYBRID AUTHENTICATION DEPENDENCY ---
async def get_current_user_id(credentials: HTTPAuthorizationCredentials = Depends(security)) -> str:
    """
    Decodes and verifies incoming Supabase JWT tokens. Supports both high-security 
    asymmetric algorithms (ES256/RS256 via JWKS) and legacy symmetric keys (HS256).
    """
    token = credentials.credentials
    try:
        # 1. Extract the token header to check the signature characteristics
        unverified_header = jwt.get_unverified_header(token)
        token_alg = unverified_header.get("alg", "HS256")

        if token_alg.lower() == "none":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Access Denied: The 'none' signing algorithm is strictly prohibited."
            )

        # 2. ALGORITHM-AGNOSTIC DECOVERY
        # If a 'kid' (Key ID) exists in the header, it's an asymmetric token.
        # PyJWKClient will automatically fetch and load the right key format (RSA or Elliptic Curve).
        if "kid" in unverified_header:
            signing_key = jwk_client.get_signing_key_from_jwt(token)
            verification_key = signing_key.key
        else:
            # If no 'kid' exists, it's a legacy shared-secret token (HS256)
            verification_key = LEGACY_HS256_KEY

        # 3. Decrypt and check the user session attributes safely
        payload = jwt.decode(
            token, 
            verification_key, 
            algorithms=[token_alg],
            audience="authenticated"
        )
        
        user_id: str = payload.get("sub")
        if not user_id:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, 
                detail="Authentication failed: Token payload missing target user identity."
            )
        return user_id

    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, 
            detail="Access Denied: The session token has expired."
        )
    except jwt.InvalidSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, 
            detail="Access Denied: Cryptographic token verification failed. Public key mismatch."
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, 
            detail=f"Access Denied: Token validation failed: {str(e)}"
        )

# --- ADMIN AUTHORIZATION DEPENDENCY ---
async def verify_admin_access(credentials: HTTPAuthorizationCredentials = Depends(security)) -> bool:
    """
    Validates internal administrative authority by comparing the incoming token 
    directly with the project's secure master service_role environment key.
    """
    incoming_token = credentials.credentials.strip()
    
    # 1. Check if the environment variable is configured properly
    if not RAW_SERVICE_ROLE_KEY:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Server Configuration Error: Admin verification key is missing from environment variables."
        )
        
    # 2. Perform a direct string match comparison
    if incoming_token == RAW_SERVICE_ROLE_KEY:
        return True
        
    # 3. Handle unauthorized keys gracefully
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN, 
        detail="Access Denied: Insufficient permissions. Invalid administrative key token."
    )

# --- PROTECTED APP ENDPOINTS ---

@app.get("/users/me/current-match", response_model=Optional[MatchResponse])
async def get_current_match(user_id: str = Depends(get_current_user_id)):
    # Changed :user_id::uuid to CAST(:user_id AS UUID)
    match_query = """
        SELECT m.id AS match_row_id, m.user_one_id, m.user_two_id
        FROM matches m
        JOIN rounds r ON m.round_id = r.id
        WHERE r.status = 'active' 
          AND m.status = 'paired' 
          AND (CAST(:user_id AS UUID) = m.user_one_id OR CAST(:user_id AS UUID) = m.user_two_id)
        LIMIT 1;
    """
    match_record = await database.fetch_one(query=match_query, values={"user_id": user_id})
    if not match_record:
        return None

    target_id = match_record["user_two_id"] if str(match_record["user_one_id"]) == str(user_id) else match_record["user_one_id"]

    # Changed :target_id::uuid to CAST(:target_id AS UUID)
    profile_query = """
        SELECT p.user_id, p.first_name, EXTRACT(YEAR FROM AGE(p.birth_date))::int AS age, p.bio,
            COALESCE(jsonb_agg(DISTINCT ph.photo_url) FILTER (WHERE ph.photo_url IS NOT NULL), '[]'::jsonb) AS photos,
            COALESCE(jsonb_agg(DISTINCT jsonb_build_object('question', pr.prompt_question, 'answer', pr.prompt_answer)) FILTER (WHERE pr.id IS NOT NULL), '[]'::jsonb) AS prompts
        FROM profiles p
        LEFT JOIN profile_photos ph ON p.user_id = ph.user_id
        LEFT JOIN profile_prompts pr ON p.user_id = pr.user_id
        WHERE p.user_id = CAST(:target_id AS UUID)
        GROUP BY p.user_id;
    """
    profile_record = await database.fetch_one(query=profile_query, values={"target_id": str(target_id)})
    if not profile_record:
        raise HTTPException(status_code=404, detail="Match profile data missing.")

    photos_list = json.loads(profile_record["photos"]) if isinstance(profile_record["photos"], str) else profile_record["photos"]
    prompts_list = json.loads(profile_record["prompts"]) if isinstance(profile_record["prompts"], str) else profile_record["prompts"]

    return MatchResponse(
        match_id=str(match_record["match_row_id"]), first_name=profile_record["first_name"], age=profile_record["age"],
        bio=profile_record["bio"], photos=photos_list, prompts=prompts_list
    )

@app.put("/users/me/preferences", status_code=200)
async def update_preferences(prefs: PreferenceUpdate, user_id: str = Depends(get_current_user_id)):
    # Changed :user_id::uuid to CAST(:user_id AS UUID)
    query = """
        INSERT INTO dating_preferences (user_id, min_age, max_age, max_distance_km, updated_at)
        VALUES (CAST(:user_id AS UUID), :min_age, :max_age, :max_distance_km, NOW())
        ON CONFLICT (user_id) DO UPDATE SET min_age = EXCLUDED.min_age, max_age = EXCLUDED.max_age, max_distance_km = EXCLUDED.max_distance_km, updated_at = NOW();
    """
    await database.execute(query=query, values={"user_id": user_id, **prefs.dict()})
    return {"status": "success", "message": "Preferences updated successfully."}


# --- BACKGROUND BATCH ENGINE ---

async def execute_batch_matching(round_id: uuid.UUID):
    # Notice that round_id is typed strictly as a UUID object here too
    matching_query = """
        SELECT p1.user_id AS u1, p2.user_id AS u2
        FROM profiles p1
        JOIN users u1 ON p1.user_id = u1.id
        JOIN dating_preferences pref1 ON p1.user_id = pref1.user_id
        JOIN profiles p2 ON p1.user_id < p2.user_id
        JOIN users u2 ON p2.user_id = u2.id
        JOIN dating_preferences pref2 ON p2.user_id = pref2.user_id
        WHERE u1.account_status = 'active' AND u2.account_status = 'active'
          AND (p1.preference_gender = p2.gender OR p1.preference_gender = 'everyone')
          AND (p2.preference_gender = p1.gender OR p2.preference_gender = 'everyone')
          AND EXTRACT(YEAR FROM AGE(p2.birth_date)) BETWEEN pref1.min_age AND pref1.max_age
          AND EXTRACT(YEAR FROM AGE(p1.birth_date)) BETWEEN pref2.min_age AND pref2.max_age
          AND ST_DWithin(p1.location, p2.location, pref1.max_distance_km * 1000, true)
          AND ST_DWithin(p2.location, p1.location, pref2.max_distance_km * 1000, true);
    """
    potential_pairs = await database.fetch_all(query=matching_query)
    assigned_users = set()
    insert_pairs = []

    for pair in potential_pairs:
        u1, u2 = pair["u1"], pair["u2"]
        if u1 not in assigned_users and u2 not in assigned_users:
            assigned_users.add(u1)
            assigned_users.add(u2)
            insert_pairs.append({"round_id": str(round_id), "user_one_id": u1, "user_two_id": u2})

    if insert_pairs:
        insert_query = """
            INSERT INTO matches (round_id, user_one_id, user_two_id, status)
            VALUES (:round_id, :user_one_id, :user_two_id, 'paired');
        """
        await database.execute_many(query=insert_query, values=insert_pairs)
    
    await database.execute("UPDATE rounds SET status = 'active' WHERE id = :round_id", {"round_id": str(round_id)})
    print(f"Batch processing completed safely for Round: {round_id}")


@app.post("/admin/rounds/{round_id}/trigger-match")
async def trigger_round_matching(
    round_id: uuid.UUID,
    background_tasks: BackgroundTasks,
    is_admin: bool = Depends(verify_admin_access)
):
    """
    Admin command route to calculate matches. Requires the Supabase service_role key to run.
    """
    background_tasks.add_task(execute_batch_matching, round_id)
    return {"status": "processing", "message": "Match calculation engine started safely."}