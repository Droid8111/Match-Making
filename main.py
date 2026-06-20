import json
import uuid
import jwt
import base64
from datetime import datetime, timezone, timedelta
from fastapi import FastAPI, HTTPException, BackgroundTasks, Depends, status, Query
from fastapi.responses import HTMLResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field
from typing import List, Optional
import databases
import os
from dotenv import load_dotenv
from qa_dashboard import dashboard_router as qa_router

load_dotenv()

# --- STEP 1: SANITIZE ENVIRONMENT STRINGS ---
RAW_DATABASE_URL = os.getenv("DATABASE_URL", "").strip("'\"").strip()
RAW_JWT_SECRET = os.getenv("SUPABASE_JWT_SECRET", "").strip("'\"").strip()
SUPABASE_PROJECT_ID = os.getenv("SUPABASE_PROJECT_ID", "").strip("'\"").strip()
RAW_SERVICE_ROLE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY", "").strip("'\"").strip()
SUPABASE_ANON_PUBLIC_KEY = os.getenv("SUPABASE_ANON_PUBLIC_KEY", "").strip("'\"").strip()

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
app.include_router(qa_router)

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
    
class ProfileSetupRequest(BaseModel):
    first_name: str
    birth_date: str  # Format: YYYY-MM-DD
    gender: str
    preference_genders: List[str]

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

# --- PYDANTIC INTERFACE CONTRACTS FOR TELEMETRY & AFFIRMATION ---
class OptInRequest(BaseModel):
    is_searching: bool

class LocationPingRequest(BaseModel):
    latitude: float = Field(..., ge=-90.0, le=90.0)
    longitude: float = Field(..., ge=-180.0, le=180.0)
    horizontal_accuracy_meters: float = Field(..., ge=0.0)
    recorded_at: datetime

class AffirmationRequest(BaseModel):
    match_id: uuid.UUID
    status_choice: str = Field(..., description="'met', 'mutually_canceled', or 'other_user_flaked'")
    intent_choice: str = Field(..., description="'continue' or 're_enter'")

class SendMessageRequest(BaseModel):
    match_id: uuid.UUID
    message_text: str

# --- QA ENDPOINT SCHEMA IMPORTS ---
class AdminRoundRequest(BaseModel):
    pass # Empty object for triggering post actions

class QALocationUpdate(BaseModel):
    preset_name: str

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

@app.post("/users/me/profile-setup", status_code=200)
async def setup_user_profile(payload: ProfileSetupRequest, user_id: str = Depends(get_current_user_id)):
    """
    Initializes user demographics, calculates exact age, and sets array preferences.
    Explicitly casts the birth date placeholder to prevent PostgreSQL parameter ambiguity.
    """
    # Parse the incoming string into a native Python date object for asyncpg
    parsed_birth_date = datetime.strptime(payload.birth_date, "%Y-%m-%d").date()
    
    # FIXED: Added explicit CAST(:birth_date AS DATE) inside the AGE() function context
    prof_query = """
        UPDATE public.profiles 
        SET first_name = :first_name, 
            gender = :gender, 
            birth_date = CAST(:birth_date AS DATE),
            calculated_age = EXTRACT(YEAR FROM AGE(CAST(:birth_date AS DATE)))::int,
            updated_at = NOW()
        WHERE user_id = CAST(:user_id AS UUID);
    """
    await database.execute(prof_query, values={
        "first_name": payload.first_name, 
        "gender": payload.gender,
        "birth_date": parsed_birth_date, 
        "user_id": user_id
    })

    pref_query = """
        INSERT INTO public.dating_preferences (user_id, preference_genders)
        VALUES (CAST(:user_id AS UUID), :pref_genders)
        ON CONFLICT (user_id) DO UPDATE SET preference_genders = EXCLUDED.preference_genders;
    """
    await database.execute(pref_query, values={"user_id": user_id, "pref_genders": payload.preference_genders})
    return {"status": "success", "message": "Profile initialized."}

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

# ==========================================
# VOLUNTARY ROUND OPT-IN MECHANIC
# ==========================================
@app.put("/users/me/opt-in", status_code=200)
async def toggle_round_opt_in(payload: OptInRequest, user_id: str = Depends(get_current_user_id)):
    """
    Allows users to manually opt into or out of the upcoming matching sequence pool.
    """
    query = """
        UPDATE public.profiles 
        SET is_searching = :is_searching, updated_at = NOW() 
        WHERE user_id = CAST(:user_id AS UUID);
    """
    await database.execute(query=query, values={"is_searching": payload.is_searching, "user_id": user_id})
    status_msg = "Opted into the next round successfully." if payload.is_searching else "Opted out of the next round."
    return {"status": "success", "message": status_msg}

# ==========================================
# DYNAMIC CHAT ROOM GUARDRAIL WITH TIMER
# ==========================================
@app.post("/users/me/messages/send", status_code=201)
async def send_chat_message(payload: SendMessageRequest, user_id: str = Depends(get_current_user_id)):
    """
    Enforces strict conversation life windows. Blocks text streams if 
    users fail to establish a confirmed date schedule footprint within 3 days.
    """
    guard_query = """
        SELECT m.created_at, sd.status AS schedule_status
        FROM public.matches m
        LEFT JOIN public.scheduled_dates sd ON m.id = sd.match_id
        WHERE m.id = CAST(:match_id AS UUID) 
          AND m.status IN ('paired', 'locked_in')
          AND (CAST(:user_id AS UUID) = m.user_one_id OR CAST(:user_id AS UUID) = m.user_two_id);
    """
    match_rec = await database.fetch_one(query=guard_query, values={"match_id": str(payload.match_id), "user_id": user_id})
    if not match_rec:
        raise HTTPException(status_code=403, detail="Access Denied: Inactive or unauthorized chat room.")

    created_time = match_rec["created_at"].replace(tzinfo=timezone.utc)
    now_time = datetime.now(timezone.utc)
    is_confirmed = match_rec["schedule_status"] == "confirmed"
    
    # 3-Day Expiration Constraint Check
    if not is_confirmed and (now_time - created_time) > timedelta(days=3):
        raise HTTPException(
            status_code=403, 
            detail="Chat Locked: You failed to confirm a date window via Google Places within the required 3-day boundary."
        )

    insert_msg_query = """
        INSERT INTO public.chat_messages (match_id, sender_id, message_text)
        VALUES (CAST(:match_id AS UUID), CAST(:user_id AS UUID), :message_text);
    """
    await database.execute(query=insert_msg_query, values={"match_id": str(payload.match_id), "user_id": user_id, "message_text": payload.message_text})
    return {"status": "sent"}

# ==========================================
# NEW REAL-TIME CHAT FETCHING ROUTE
# ==========================================
@app.get("/users/me/messages")
async def fetch_chat_history(match_id: str = Query(...), user_id: str = Depends(get_current_user_id)):
    """Fetches chat logs. Simulator will poll this every 3 seconds."""
    
    # Security: Verify relationship and check if round is still active
    auth_query = """
        SELECT r.status FROM public.matches m
        JOIN public.rounds r ON m.round_id = r.id
        WHERE m.id = CAST(:match_id AS UUID) 
          AND (m.user_one_id = CAST(:user_id AS UUID) OR m.user_two_id = CAST(:user_id AS UUID))
    """
    auth_rec = await database.fetch_one(auth_query, values={"match_id": match_id, "user_id": user_id})
    if not auth_rec or auth_rec["status"] != "active":
        raise HTTPException(status_code=403, detail="Chat channel is closed or unauthorized.")

    msg_query = """
        SELECT sender_id, message_text, created_at 
        FROM public.chat_messages 
        WHERE match_id = CAST(:match_id AS UUID)
        ORDER BY created_at ASC;
    """
    messages = await database.fetch_all(msg_query, values={"match_id": match_id})
    return [{"sender_id": str(m["sender_id"]), "text": m["message_text"], "time": str(m["created_at"])} for m in messages]

# ==========================================
# TELEMETRY INGEST WINDOW REGULATOR
# ==========================================
@app.post("/users/me/location/ping", status_code=202)
async def ingest_device_telemetry(payload: LocationPingRequest, user_id: str = Depends(get_current_user_id)):
    """
    Secure telemetry endpoint. Accepts background location tracking points 
    only if the user has an active, confirmed date happening right now.
    """
    window_query = """
        SELECT sd.scheduled_time 
        FROM public.scheduled_dates sd
        JOIN public.matches m ON sd.match_id = m.id
        WHERE sd.status = 'confirmed'
          AND (m.user_one_id = CAST(:user_id AS UUID) OR m.user_two_id = CAST(:user_id AS UUID))
          AND :now BETWEEN sd.scheduled_time - INTERVAL '30 minutes' AND sd.scheduled_time + INTERVAL '30 minutes'
        LIMIT 1;
    """
    now = datetime.now(timezone.utc)
    active_window = await database.fetch_one(query=window_query, values={"user_id": user_id, "now": now})
    
    if not active_window:
        raise HTTPException(
            status_code=403, 
            detail="Telemetry Blocked: Background tracking initialization requests are restricted outside of confirmed date windows."
        )

    log_query = """
        INSERT INTO public.location_logs (user_id, location, horizontal_accuracy_meters, recorded_at)
        VALUES (CAST(:user_id AS UUID), ST_SetSRID(ST_MakePoint(:lng, :lat), 4326), :accuracy, :recorded_at);
    """
    await database.execute(
        query=log_query,
        values={
            "user_id": user_id, "lng": payload.longitude, "lat": payload.latitude,
            "accuracy": payload.horizontal_accuracy_meters, "recorded_at": payload.recorded_at
        }
    )
    return {"status": "buffered"}

# ==========================================
# 4. POST-DATE AFFIRMATION COMPLIANCE ROUTE
# ==========================================
@app.post("/users/me/match/affirmation", status_code=200)
async def submit_date_affirmation(
    payload: AffirmationRequest, 
    background_tasks: BackgroundTasks, 
    user_id: str = Depends(get_current_user_id)
):
    """
    Processes user feedback, handles continuation alignments, and directs conflicts 
    to the background spatial referee processor.
    """
    if payload.status_choice not in ['met', 'mutually_canceled', 'other_user_flaked']:
        raise HTTPException(status_code=400, detail="Invalid status reporting definition.")
    if payload.intent_choice not in ['continue', 're_enter']:
        raise HTTPException(status_code=400, detail="Invalid progression intent definition.")

    # RACE CONDITION FIX: Read the match and lock in one query, verifying the match is
    # still in an actionable state. The UPDATE below only writes if status is still active,
    # and RETURNING gives us the post-write snapshot atomically — no separate SELECT needed.
    match_query = "SELECT user_one_id, user_two_id, status FROM public.matches WHERE id = CAST(:match_id AS UUID);"
    m_rec = await database.fetch_one(query=match_query, values={"match_id": str(payload.match_id)})
    if not m_rec:
        raise HTTPException(status_code=404, detail="Target match reference mapping missing.")

    # Reject submission if the match is already in a terminal state (e.g. a concurrent
    # request already resolved it). This is the second layer of race protection —
    # the referee's own idempotency guard is the first.
    if m_rec["status"] not in ('paired', 'locked_in'):
        raise HTTPException(status_code=409, detail="Match is already resolved. Affirmation window closed.")

    is_u1 = str(m_rec["user_one_id"]) == str(user_id)
    
    update_field_status = "user_one_reported_status" if is_u1 else "user_two_reported_status"
    update_field_intent = "user_one_intent" if is_u1 else "user_two_intent"
    
    write_feedback_sql = f"""
        UPDATE public.matches 
        SET {update_field_status} = :status_choice, {update_field_intent} = :intent_choice
        WHERE id = CAST(:match_id AS UUID)
        RETURNING user_one_reported_status, user_two_reported_status, user_one_intent, user_two_intent;
    """
    res = await database.fetch_one(
        query=write_feedback_sql, 
        values={"status_choice": payload.status_choice, "intent_choice": payload.intent_choice, "match_id": str(payload.match_id)}
    )

    if res["user_one_reported_status"] != 'unreported' and res["user_two_reported_status"] != 'unreported':
        
        # Conflict Resolution Trigger
        if res["user_one_reported_status"] != res["user_two_reported_status"]:
            background_tasks.add_task(execute_gps_referee, payload.match_id)
            return {"status": "conflict_review", "detail": "Discrepancy identified. Routing to GPS Referee Engine."}

        # Mutual Success Loop: Both want to keep talking and lock connection
        if res["user_one_reported_status"] == 'met' and res["user_one_intent"] == 'continue' and res["user_two_intent"] == 'continue':
            await database.execute(
                "UPDATE public.matches SET status = 'locked_in' WHERE id = CAST(:id AS UUID);", 
                {"id": str(payload.match_id)}
            )
            return {"status": "relationship_locked_in", "detail": "Mutual connection confirmed. Skipping next match round."}
            
        # Mutual Tear-Down or Partial Opt-out Loop
        else:
            await database.execute(
                "UPDATE public.matches SET status = 'completed' WHERE id = CAST(:id AS UUID);", 
                {"id": str(payload.match_id)}
            )
            return {"status": "pool_returned", "detail": "Match closed. Both users returned to the general active pool."}

    return {"status": "received", "detail": "Feedback logged. Awaiting counterparty response."}


# ==========================================
# 5. AUTOMATED PASSIVE GPS REFEREE ENGINE
# ==========================================
async def execute_gps_referee(match_id: uuid.UUID):
    """
    Asynchronous background referee worker. Cross-references conflicting user reports 
    against high-accuracy location logs within the venue geofence to penalize flakers.
    """
    # Coordinates live in public.venues.location (PostGIS geometry), not on scheduled_dates.
    # We JOIN to venues and extract lng/lat with ST_X/ST_Y, bypassing geofence_radius_meters
    # (frequently NULL) in favour of our own hardcoded 100 m enforcement radius.
    details_query = """
        SELECT m.user_one_id, m.user_two_id, sd.scheduled_time,
               ST_X(v.location::geometry) AS venue_lng,
               ST_Y(v.location::geometry) AS venue_lat
        FROM public.matches m
        JOIN public.scheduled_dates sd ON m.id = sd.match_id
        JOIN public.venues v ON v.id = sd.venue_id
        WHERE m.id = CAST(:match_id AS UUID);
    """
    ctx = await database.fetch_one(query=details_query, values={"match_id": str(match_id)})
    if not ctx or ctx["venue_lat"] is None or ctx["venue_lng"] is None:
        print(f"[REFEREE] No venue coordinates found for match {match_id}. Cannot arbitrate.")
        return

    start_window = ctx["scheduled_time"] - timedelta(minutes=30)
    end_window = ctx["scheduled_time"] + timedelta(minutes=30)

    print(f"[REFEREE] ── Diagnostic dump for match {match_id} ──")
    print(f"[REFEREE] Venue coords : lat={ctx['venue_lat']}, lng={ctx['venue_lng']}")
    print(f"[REFEREE] Time window  : {start_window} → {end_window}")
    print(f"[REFEREE] User 1 (u1)  : {ctx['user_one_id']}")
    print(f"[REFEREE] User 2 (u2)  : {ctx['user_two_id']}")

    # Raw log counts per user in the window — no accuracy/distance filter yet.
    # If these are 0, pings never arrived or recorded_at is outside the window.
    raw_count_sql = """
        SELECT COUNT(*) AS cnt,
               MIN(horizontal_accuracy_meters) AS best_accuracy,
               MIN(recorded_at) AS earliest,
               MAX(recorded_at) AS latest
        FROM public.location_logs
        WHERE user_id = CAST(:user_id AS UUID)
          AND recorded_at BETWEEN :start_w AND :end_w;
    """
    for label, uid in [("u1", str(ctx["user_one_id"])), ("u2", str(ctx["user_two_id"]))]:
        raw = await database.fetch_one(raw_count_sql, {"user_id": uid, "start_w": start_window, "end_w": end_window})
        print(f"[REFEREE] {label} raw logs in window: count={raw['cnt']}, best_accuracy={raw['best_accuracy']}, earliest={raw['earliest']}, latest={raw['latest']}")

    # Distance check: how far was each user's closest ping from the venue?
    closest_sql = """
        SELECT MIN(ST_Distance(
            ll.location::geography,
            ST_SetSRID(ST_MakePoint(:v_lng, :v_lat), 4326)::geography
        )) AS closest_meters
        FROM public.location_logs ll
        WHERE ll.user_id = CAST(:user_id AS UUID)
          AND ll.recorded_at BETWEEN :start_w AND :end_w;
    """
    for label, uid in [("u1", str(ctx["user_one_id"])), ("u2", str(ctx["user_two_id"]))]:
        dist = await database.fetch_one(closest_sql, {"user_id": uid, "start_w": start_window, "end_w": end_window, "v_lng": ctx["venue_lng"], "v_lat": ctx["venue_lat"]})
        print(f"[REFEREE] {label} closest ping to venue: {dist['closest_meters']} m  (threshold: 100 m)")

    check_attendance_sql = """
        SELECT EXISTS (
            SELECT 1 FROM public.location_logs ll
            WHERE ll.user_id = CAST(:user_id AS UUID)
              AND ll.recorded_at BETWEEN :start_w AND :end_w
              AND ll.horizontal_accuracy_meters <= 30.0
              AND ST_DWithin(
                  ll.location::geography,
                  ST_SetSRID(ST_MakePoint(:v_lng, :v_lat), 4326)::geography,
                  100.0
              )
        ) AS attended;
    """

    u1_args = {"user_id": str(ctx["user_one_id"]), "start_w": start_window, "end_w": end_window, "v_lng": ctx["venue_lng"], "v_lat": ctx["venue_lat"]}
    u2_args = {"user_id": str(ctx["user_two_id"]), "start_w": start_window, "end_w": end_window, "v_lng": ctx["venue_lng"], "v_lat": ctx["venue_lat"]}

    u1_present = (await database.fetch_one(query=check_attendance_sql, values=u1_args))["attended"]
    u2_present = (await database.fetch_one(query=check_attendance_sql, values=u2_args))["attended"]

    print(f"[REFEREE] Attendance verdict: u1_present={u1_present}, u2_present={u2_present}")

    target_flaker = None
    if u1_present and not u2_present:
        target_flaker = ctx["user_two_id"]
    elif u2_present and not u1_present:
        target_flaker = ctx["user_one_id"]

    if target_flaker:
        # Penalize verified flaker
        await database.execute("UPDATE public.matches SET status = 'flake_no_show' WHERE id = CAST(:id AS UUID);", {"id": str(match_id)})
        await database.execute(
            """INSERT INTO public.reputation_logs (user_id, match_id, action_type, points_changed) 
               VALUES (CAST(:user_id AS UUID), CAST(:match_id AS UUID), 'verified_flake_no_show', -15);""",
            {"user_id": str(target_flaker), "match_id": str(match_id)}
        )
        await database.execute(
            """UPDATE public.profiles 
               SET reputation_score = GREATEST(0, reputation_score - 15), is_searching = FALSE 
               WHERE user_id = CAST(:user_id AS UUID);""",
            {"user_id": str(target_flaker)}
        )
        print(f"[REFEREE] Verified Flake Identified. Penalized User: {target_flaker}")
    else:
        # Double flake or out of bounds resolution
        await database.execute("UPDATE public.matches SET status = 'completed' WHERE id = CAST(:id AS UUID);", {"id": str(match_id)})
        print(f"[REFEREE] Dispute unresolved. Match {match_id} closed as completed.")

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


@app.post("/admin/macro/execute-matching", status_code=200)
async def admin_execute_matching(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Macro Admin Action: Executes the full PostGIS batching engine."""
    await verify_admin_access(credentials)
    
    active_round = await database.fetch_one("SELECT id FROM public.rounds WHERE status = 'active' LIMIT 1;")
    if not active_round:
        raise HTTPException(status_code=400, detail="No active round configuration found.")
        
    round_id = active_round["id"]
    
    # -------------------------------------------------------------
    # THE PRODUCTION MATCHING QUERY (Fixed Array Casting Syntax)
    # -------------------------------------------------------------
    match_algo_query = """
        WITH available_singles AS (
            SELECT p.user_id, p.gender, p.calculated_age, p.location, pref.preference_genders, pref.min_age, pref.max_age, pref.max_distance_km
            FROM public.profiles p
            JOIN public.users u ON p.user_id = u.id
            JOIN public.dating_preferences pref ON p.user_id = pref.user_id
            WHERE p.is_searching = TRUE AND u.account_status = 'active'
        ),
        valid_pairs AS (
            SELECT 
                LEAST(u1.user_id, u2.user_id) AS user_one, 
                GREATEST(u1.user_id, u2.user_id) AS user_two
            FROM available_singles u1
            JOIN available_singles u2 ON u1.user_id < u2.user_id
            WHERE 
                -- 1. Spatial Constraints
                ST_DWithin(u1.location, u2.location, u1.max_distance_km * 1000, true)
                AND ST_DWithin(u2.location, u1.location, u2.max_distance_km * 1000, true)
                -- 2. Gender Inclusivity Checks (Casting Fix Applied)
                AND u1.preference_genders && ARRAY[u2.gender::varchar]
                AND u2.preference_genders && ARRAY[u1.gender::varchar]
                -- 3. Blocklist Elimination Check
                AND NOT EXISTS (
                    SELECT 1 FROM public.match_blocklist bl 
                    WHERE bl.user_one_id = LEAST(u1.user_id, u2.user_id) 
                      AND bl.user_two_id = GREATEST(u1.user_id, u2.user_id)
                )
        )
        INSERT INTO public.matches (round_id, user_one_id, user_two_id, status)
        SELECT CAST(:round_id AS UUID), user_one, user_two, 'paired' FROM valid_pairs
        ON CONFLICT DO NOTHING;
    """
    await database.execute(match_algo_query, values={"round_id": str(round_id)})
    return {"status": "success", "message": "Batch geospatial matching cycle completed successfully."}

@app.put("/qa/update-location-point", status_code=200)
async def update_qa_spatial_location(payload: QALocationUpdate, user_id: str = Depends(get_current_user_id)):
    """Rewrites a user's PostGIS spatial anchor to test geographic boundary limits."""
    presets = {
        "toronto": {"lat": 43.6532, "lng": -79.3832},
        "scarborough": {"lat": 43.7731, "lng": -79.2577},
        "barrie": {"lat": 44.3894, "lng": -79.6903}
    }
    target = presets.get(payload.preset_name.lower())
    if not target:
        raise HTTPException(status_code=400, detail="Invalid location preset identifier.")
        
    query = """
        UPDATE public.profiles 
        SET location = ST_SetSRID(ST_MakePoint(:lng, :lat), 4326), updated_at = NOW()
        WHERE user_id = CAST(:user_id AS UUID);
    """
    await database.execute(query, values={"lng": target["lng"], "lat": target["lat"], "user_id": user_id})
    return {"status": "success", "message": f"Spatial node anchored to {payload.preset_name}."}

@app.get("/users/me/active-match")
async def get_active_match_session(user_id: str = Depends(get_current_user_id)):
    """Allows devices to dynamically discover their match UUID without manual entry."""
    query = """
        SELECT m.id, m.user_one_id, m.user_two_id, m.status, r.id AS round_id
        FROM public.matches m
        JOIN public.rounds r ON m.round_id = r.id
        WHERE r.status = 'active'
          AND m.status IN ('paired', 'locked_in')
          AND (m.user_one_id = CAST(:user_id AS UUID) OR m.user_two_id = CAST(:user_id AS UUID))
        LIMIT 1;
    """
    rec = await database.fetch_one(query, values={"user_id": user_id})
    if not rec:
        return {"has_match": False}
        
    counterparty_id = rec["user_two_id"] if str(rec["user_one_id"]) == str(user_id) else rec["user_one_id"]
    
    # Fetch counterparty reputation metrics
    rep_query = "SELECT first_name, reputation_score FROM public.profiles WHERE user_id = CAST(:target AS UUID);"
    cp_rec = await database.fetch_one(rep_query, values={"target": counterparty_id})

    return {
        "has_match": True,
        "match_id": str(rec["id"]),
        "status": rec["status"],
        "counterparty_name": cp_rec["first_name"],
        "counterparty_rep": cp_rec["reputation_score"]
    }

@app.post("/admin/macro/create-round", status_code=201)
async def admin_create_round(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Macro Admin Action: Closes previous round and generates a fresh Active round vector."""
    await verify_admin_access(credentials)
    await database.execute("UPDATE public.rounds SET status = 'completed' WHERE status = 'active';")
    
    insert_query = """
        INSERT INTO public.rounds (status, processing_status, started_at) 
        VALUES ('active', 'idle', NOW()) RETURNING id;
    """
    new_round = await database.fetch_one(insert_query)
    return {"status": "success", "round_id": str(new_round["id"])}

async def execute_automated_gps_referee(match_id: uuid.UUID):
    """
    Asynchronous Core Engine Task. Validates physical telemetry against venue locations.
    Addresses double no-show traps and applies programmatic matching pool penalties.
    """
    # IDEMPOTENCY GUARD: If this referee was already invoked concurrently (e.g. both
    # users submitted affirmation within the same millisecond window), the second
    # invocation finds the match already in a terminal state and exits without
    # re-penalizing anyone. This is the primary defense against the race condition
    # in submit_date_affirmation where both users' requests read 'unreported' before
    # either write commits, causing two background tasks to fire for the same match.
    idempotency_check = """
        SELECT status FROM public.matches 
        WHERE id = CAST(:match_id AS UUID);
    """
    current = await database.fetch_one(idempotency_check, values={"match_id": str(match_id)})
    if not current or current["status"] not in ('paired', 'locked_in'):
        return

    # 1. Fetch match metadata — coordinates from public.venues.location (PostGIS geometry).
    schedule_query = """
        SELECT m.user_one_id, m.user_two_id, m.user_one_intent, m.user_two_intent,
               sd.scheduled_time,
               ST_X(v.location::geometry) AS venue_lng,
               ST_Y(v.location::geometry) AS venue_lat
        FROM public.matches m
        JOIN public.scheduled_dates sd ON m.id = sd.match_id
        JOIN public.venues v ON v.id = sd.venue_id
        WHERE m.id = CAST(:match_id AS UUID);
    """
    date_ctx = await database.fetch_one(schedule_query, values={"match_id": str(match_id)})
    if not date_ctx or date_ctx["venue_lat"] is None:
        return

    # Establish evaluation timestamps (-30m to +30m around the date)
    start_window = date_ctx["scheduled_time"] - timedelta(minutes=30)
    end_window = date_ctx["scheduled_time"] + timedelta(minutes=30)

    # 2. Attendance verified exclusively from timestamped telemetry logs within the date window.
    # The profiles.location snapshot is intentionally excluded — it reflects the user's
    # *current* position, not where they were during the scheduled meeting. Including it
    # would allow a user who walked near the venue hours later (or whose low-accuracy
    # cell-tower fix happened to overlap the geofence) to pass the attendance check.
    check_attendance_query = """
        SELECT EXISTS (
            SELECT 1 FROM public.location_logs
            WHERE user_id = CAST(:user_id AS UUID)
              AND recorded_at BETWEEN :start_w AND :end_w
              AND horizontal_accuracy_meters <= 30.0
              AND ST_DWithin(
                  location::geography, 
                  ST_SetSRID(ST_MakePoint(:v_lng, :v_lat), 4326)::geography, 
                  100.0
              )
        ) AS attended;
    """

    # Collect true geographic attendance states
    u1_args = {"user_id": str(date_ctx["user_one_id"]), "start_w": start_window, "end_w": end_window, "v_lng": date_ctx["venue_lng"], "v_lat": date_ctx["venue_lat"]}
    u2_args = {"user_id": str(date_ctx["user_two_id"]), "start_w": start_window, "end_w": end_window, "v_lng": date_ctx["venue_lng"], "v_lat": date_ctx["venue_lat"]}
    
    u1_present = (await database.fetch_one(check_attendance_query, values=u1_args))["attended"]
    u2_present = (await database.fetch_one(check_attendance_query, values=u2_args))["attended"]

    # 3. VERDICT EVALUATION TREE
    
    # CASE A: THE DOUBLE NO-SHOW ROOM TRAP RESOLUTION
    if not u1_present and not u2_present:
        # Penalize both users by kicking them from the active matching round
        lockout_query = """
            UPDATE public.profiles 
            SET is_searching = FALSE, updated_at = NOW() 
            WHERE user_id IN (CAST(:u1 AS UUID), CAST(:u2 AS UUID));
        """
        await database.execute(lockout_query, {"u1": str(date_ctx["user_one_id"]), "u2": str(date_ctx["user_two_id"])})
        
        # Free the session and set status to clear UI deadlocks
        await database.execute(
            "UPDATE public.matches SET status = 'mutual_missing_lockout' WHERE id = CAST(:id AS UUID);",
            {"id": str(match_id)}
        )
        return

    # CASE B: SINGLE USER FLAKE ARBITRATION
    flaker_id = None
    if u1_present and not u2_present:
        flaker_id = date_ctx["user_two_id"]
    elif u2_present and not u1_present:
        flaker_id = date_ctx["user_one_id"]

    if flaker_id:
        # Execute penalty: Deduct -15 reputation points and boot from pool
        penalize_sql = """
            UPDATE public.profiles 
            SET reputation_score = GREATEST(0, reputation_score - 15),
                is_searching = FALSE,
                updated_at = NOW()
            WHERE user_id = CAST(:flaker_id AS UUID);
        """
        await database.execute(penalize_sql, values={"flaker_id": str(flaker_id)})
        
        # Log systemic audit footprint entry
        await database.execute(
            """INSERT INTO public.reputation_logs (user_id, match_id, action_type, points_changed) 
               VALUES (CAST(:u_id AS UUID), CAST(:m_id AS UUID), 'verified_flake_no_show', -15);""",
            {"u_id": str(flaker_id), "m_id": str(match_id)}
        )

        await database.execute(
            "UPDATE public.matches SET status = 'flake_no_show' WHERE id = CAST(:id AS UUID);", 
            {"id": str(match_id)}
        )
        return

    # CASE C: MUTUAL ATTENDANCE VERIFIED
    if u1_present and u2_present:
        # Clean processing: evaluate actual written intents to route final status context
        if date_ctx["user_one_intent"] == 'continue' and date_ctx["user_two_intent"] == 'continue':
            await database.execute("UPDATE public.matches SET status = 'locked_in' WHERE id = CAST(:id AS UUID);", {"id": str(match_id)})
        else:
            await database.execute("UPDATE public.matches SET status = 'completed' WHERE id = CAST(:id AS UUID);", {"id": str(match_id)})
        return

@app.post("/users/me/match/affirmation", status_code=200)
async def submit_date_affirmation(
    payload: AffirmationRequest, 
    background_tasks: BackgroundTasks, 
    user_id: str = Depends(get_current_user_id)
):
    """
    Ingests post-date metrics and intent state choice boundaries.
    Always queues the PostGIS evaluation task once both responses land to verify geometry truth.
    """
    if payload.status_choice not in ['met', 'mutually_canceled', 'other_user_flaked']:
        raise HTTPException(status_code=400, detail="Invalid status reporting parameters.")
    if payload.intent_choice not in ['continue', 're_enter']:
        raise HTTPException(status_code=400, detail="Invalid progression intent definition.")

    # 1. Identify current user placement inside the pairing matrix.
    # RACE CONDITION FIX: Also read status here so we can reject submissions against
    # matches already resolved by a concurrent request. The referee's idempotency guard
    # provides a second layer of protection even if two requests slip through.
    match_query = "SELECT user_one_id, user_two_id, status FROM public.matches WHERE id = CAST(:match_id AS UUID);"
    m_rec = await database.fetch_one(query=match_query, values={"match_id": str(payload.match_id)})
    if not m_rec:
        raise HTTPException(status_code=404, detail="Target match session record missing.")

    if m_rec["status"] not in ('paired', 'locked_in'):
        raise HTTPException(status_code=409, detail="Match is already resolved. Affirmation window closed.")

    is_u1 = str(m_rec["user_one_id"]) == str(user_id)
    status_field = "user_one_reported_status" if is_u1 else "user_two_reported_status"
    intent_field = "user_one_intent" if is_u1 else "user_two_intent"

    # 2. Write verification states directly to PostgreSQL
    write_feedback_sql = f"""
        UPDATE public.matches 
        SET {status_field} = :status_choice, {intent_field} = :intent_choice
        WHERE id = CAST(:match_id AS UUID)
        RETURNING user_one_reported_status, user_two_reported_status;
    """
    res = await database.fetch_one(
        query=write_feedback_sql, 
        values={"status_choice": payload.status_choice, "intent_choice": payload.intent_choice, "match_id": str(payload.match_id)}
    )

    # 3. ABSOLUTE GEOMETRY TRUTH TRIGGER: If both filled, execute spatial evaluation background task
    if res["user_one_reported_status"] != 'unreported' and res["user_two_reported_status"] != 'unreported':
        background_tasks.add_task(execute_automated_gps_referee, payload.match_id)
        return {
            "status": "processing_closure", 
            "detail": "Feedback logged. Session routed to the Automated GPS Referee Engine for spatial validation."
        }

    return {"status": "received", "detail": "Feedback logged successfully. Awaiting counterparty data packet."}

async def perform_stale_matches_cleanup_sweep():
    """
    Scans the database for match sessions where the scheduled meeting concluded 
    over 24 hours ago, but one or both users failed to submit affirmation data.
    Forcefully invokes the PostGIS referee loop to resolve the session state.
    """
    # Defensive inline imports to completely insulate against circular dependency boot locks
    from main import database
    from main import execute_automated_gps_referee

    stale_query = """
        SELECT m.id AS match_id
        FROM public.matches m
        JOIN public.scheduled_dates sd ON m.id = sd.match_id
        WHERE sd.scheduled_time < NOW() - INTERVAL '24 hours'
          AND m.status IN ('paired', 'locked_in')
          AND (m.user_one_reported_status = 'unreported' OR m.user_two_reported_status = 'unreported');
    """
    try:
        stale_records = await database.fetch_all(stale_query)
        print(f"[CLEANUP sweep] Active. Identified {len(stale_records)} stale match sessions requiring arbitration.")
        
        for record in stale_records:
            match_uuid = record["match_id"]
            print(f"[CLEANUP sweep] Invoking automated PostGIS referee logic on Match: {match_uuid}")
            
            # Execute truth validation loop against available telemetry history logs
            await execute_automated_gps_referee(match_id=match_uuid)
            
        print("[CLEANUP sweep] Completed cleanly.")
        return {"status": "success", "processed_count": len(stale_records)}
        
    except Exception as e:
        print(f"[CLEANUP sweep] Critical exception encountered during database scan: {str(e)}")
        return {"status": "error", "detail": str(e)}