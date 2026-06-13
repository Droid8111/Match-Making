import json
import uuid
import jwt
import base64
from datetime import datetime, timedelta
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

# --- PYDANTIC SCHEMAS FOR SCHEDULING LOGIC ---
class ScheduleProposalRequest(BaseModel):
    match_id: uuid.UUID
    google_place_id: str = Field(..., max_length=255)
    name: str = Field(..., max_length=255)
    address: str
    latitude: float = Field(..., ge=-90.0, le=90.0)
    longitude: float = Field(..., ge=-180.0, le=180.0)
    scheduled_time: datetime

class ScheduleResponse(BaseModel):
    status: str
    is_confirmed: bool
    scheduled_time: datetime
    tracking_start: datetime
    tracking_end: datetime
    message: str

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
            audience="authenticated",
            leeway=60
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

@app.post("/users/me/match/schedule", response_model=ScheduleResponse)
async def upsert_match_schedule(
    payload: ScheduleProposalRequest, 
    user_id: str = Depends(get_current_user_id)
):
    """
    Processes match scheduling proposals, explicit confirmations, and dynamic route adjustments.
    Outputs strict ring-fenced time boundaries to control client background GPS power loops.
    """
    # 1. Verification Wall: Ensure target match exists and is active
    match_query = """
        SELECT id, user_one_id, user_two_id 
        FROM public.matches 
        WHERE id = CAST(:match_id AS UUID) AND status = 'paired';
    """
    match_rec = await database.fetch_one(query=match_query, values={"match_id": str(payload.match_id)})
    if not match_rec:
        raise HTTPException(status_code=404, detail="Active match session not found.")
    
    is_user_one = str(match_rec["user_one_id"]) == str(user_id)
    is_user_two = str(match_rec["user_two_id"]) == str(user_id)
    
    if not (is_user_one or is_user_two):
        raise HTTPException(status_code=403, detail="Unauthorized: You are not a participant in this match.")

    # 2. Dynamic Venue Execution: Cache or write Google Places values using PostGIS coordinates
    venue_query = "SELECT id FROM public.venues WHERE google_place_id = :google_place_id LIMIT 1;"
    venue_rec = await database.fetch_one(query=venue_query, values={"google_place_id": payload.google_place_id})
    
    if venue_rec:
        venue_uuid = venue_rec["id"]
    else:
        insert_venue_query = """
            INSERT INTO public.venues (google_place_id, name, address, location)
            VALUES (:google_place_id, :name, :address, ST_SetSRID(ST_MakePoint(:lng, :lat), 4326))
            RETURNING id;
        """
        venue_uuid = await database.execute(
            query=insert_venue_query,
            values={
                "google_place_id": payload.google_place_id,
                "name": payload.name,
                "address": payload.address,
                "lng": payload.longitude,
                "lat": payload.latitude
            }
        )

    # 3. Decision Matrix: Evaluate proposals vs confirmations
    sched_query = """
        SELECT id, venue_id, scheduled_time, user_one_agreed, user_two_agreed 
        FROM public.scheduled_dates 
        WHERE match_id = CAST(:match_id AS UUID) LIMIT 1;
    """
    sched_rec = await database.fetch_one(query=sched_query, values={"match_id": str(payload.match_id)})
    
    u1_status = True if is_user_one else False
    u2_status = True if is_user_two else False
    current_status = "proposed"
    
    if sched_rec:
        same_time = sched_rec["scheduled_time"] == payload.scheduled_time
        same_venue = sched_rec["venue_id"] == venue_uuid
        
        if same_time and same_venue:
            # User is confirming the counter-party's open proposal
            u1_status = True if is_user_one else sched_rec["user_one_agreed"]
            u2_status = True if is_user_two else sched_rec["user_two_agreed"]
        else:
            # User altered the details. Resets agreement flags, forcing a re-verify sequence.
            u1_status = True if is_user_one else False
            u2_status = True if is_user_two else False
            
        if u1_status and u2_status:
            current_status = "confirmed"
            
        update_query = """
            UPDATE public.scheduled_dates
            SET venue_id = CAST(:venue_id AS UUID),
                scheduled_time = :scheduled_time,
                user_one_agreed = :u1,
                user_two_agreed = :u2,
                status = :status,
                updated_at = NOW()
            WHERE id = CAST(:id AS UUID);
        """
        await database.execute(
            query=update_query,
            values={
                "id": str(sched_rec["id"]), "venue_id": str(venue_uuid),
                "scheduled_time": payload.scheduled_time, "u1": u1_status, "u2": u2_status, "status": current_status
            }
        )
    else:
        # Initial proposal declaration
        insert_sched_query = """
            INSERT INTO public.scheduled_dates (match_id, venue_id, scheduled_time, user_one_agreed, user_two_agreed, status)
            VALUES (CAST(:match_id AS UUID), CAST(:venue_id AS UUID), :scheduled_time, :u1, :u2, :status);
        """
        await database.execute(
            query=insert_sched_query,
            values={
                "match_id": str(payload.match_id), "venue_id": str(venue_uuid),
                "scheduled_time": payload.scheduled_time, "u1": u1_status, "u2": u2_status, "status": current_status
            }
        )

    # 4. Compute Dynamic Verification Windows
    is_confirmed = current_status == "confirmed"
    tracking_start = payload.scheduled_time - timedelta(minutes=30)
    tracking_end = payload.scheduled_time + timedelta(minutes=30)
    
    msg = "Date locked in! Background tracking window generated." if is_confirmed else "Proposal logged. Waiting for match confirmation."

    return ScheduleResponse(
        status=current_status,
        is_confirmed=is_confirmed,
        scheduled_time=payload.scheduled_time,
        tracking_start=tracking_start,
        tracking_end=tracking_end,
        message=msg
    )


# --- BACKGROUND BATCH ENGINE ---

async def execute_batch_matching(round_id: uuid.UUID):
    """
    Highly optimized batch-matching algorithm. Evaluates localized candidate pools
    using multi-gender array overlap metrics and indexed age calculations.
    """
    matching_query = """
    SELECT 
        p1.user_id AS user_one_id, 
        p2.user_id AS user_two_id
    FROM public.profiles p1
    JOIN public.users u1 ON p1.user_id = u1.id
    JOIN public.dating_preferences pref1 ON p1.user_id = pref1.user_id

    JOIN public.profiles p2 ON p1.user_id < p2.user_id
    JOIN public.users u2 ON p2.user_id = u2.id
    JOIN public.dating_preferences pref2 ON p2.user_id = pref2.user_id

    WHERE 
        u1.account_status = 'active' 
        AND u2.account_status = 'active'
        
        -- 1. INCLUSIVE MUTUAL GENDER ATTRACTIVITY OVERLAP
        AND pref1.preference_genders && ARRAY[p2.gender]::VARCHAR[]
        AND pref2.preference_genders && ARRAY[p1.gender]::VARCHAR[]
        
        -- 2. MUTUAL AGE BRACKET VALIDATION (OPTIMIZED USING COALESCED CORES)
        AND p2.calculated_age BETWEEN pref1.min_age AND pref1.max_age
        AND p1.calculated_age BETWEEN pref2.min_age AND pref2.max_age
        
        -- 3. MUTUAL POSTGIS GEOSPATIAL DISTANCE THRESHOLDS
        AND ST_DWithin(p1.location, p2.location, pref1.max_distance_km * 1000, true)
        AND ST_DWithin(p2.location, p1.location, pref2.max_distance_km * 1000, true);
    """
    potential_pairs = await database.fetch_all(query=matching_query)
    assigned_users = set()
    insert_pairs = []

    for pair in potential_pairs:
        u1 = pair["user_one_id"]
        u2 = pair["user_two_id"]
        
        if u1 not in assigned_users and u2 not in assigned_users:
            assigned_users.add(u1)
            assigned_users.add(u2)
            insert_pairs.append({
                "round_id": str(round_id), 
                "user_one_id": str(u1), 
                "user_two_id": str(u2)
            })

    if insert_pairs:
        insert_query = """
            INSERT INTO public.matches (round_id, user_one_id, user_two_id, status)
            VALUES (:round_id, :user_one_id, :user_two_id, 'paired');
        """
        await database.execute_many(query=insert_query, values=insert_pairs)
    
    await database.execute(
        "UPDATE public.rounds SET status = 'active' WHERE id = :round_id", 
        {"round_id": str(round_id)}
    )
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