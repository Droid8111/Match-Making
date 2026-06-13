import json
import uuid
import jwt
import base64
from datetime import datetime, timezone, timedelta
from fastapi import FastAPI, HTTPException, BackgroundTasks, Depends, status
from fastapi.responses import HTMLResponse
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

# ==========================================
# 1. VOLUNTARY ROUND OPT-IN MECHANIC
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
# 2. DYNAMIC CHAT ROOM GUARDRAIL WITH TIMER
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
# 3. TELEMETRY INGEST WINDOW REGULATOR
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

    match_query = "SELECT user_one_id, user_two_id, status FROM public.matches WHERE id = CAST(:match_id AS UUID);"
    m_rec = await database.fetch_one(query=match_query, values={"match_id": str(payload.match_id)})
    if not m_rec:
        raise HTTPException(status_code=404, detail="Target match reference mapping missing.")

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
    details_query = """
        SELECT m.user_one_id, m.user_two_id, sd.venue_id, sd.scheduled_time
        FROM public.matches m
        JOIN public.scheduled_dates sd ON m.id = sd.match_id
        WHERE m.id = CAST(:match_id AS UUID);
    """
    ctx = await database.fetch_one(query=details_query, values={"match_id": str(match_id)})
    if not ctx or not ctx["venue_id"]:
        return

    start_window = ctx["scheduled_time"] - timedelta(minutes=30)
    end_window = ctx["scheduled_time"] + timedelta(minutes=30)
    
    check_attendance_sql = """
        SELECT EXISTS (
            SELECT 1 FROM public.location_logs ll
            JOIN public.venues v ON v.id = :venue_id
            WHERE ll.user_id = CAST(:user_id AS UUID)
              AND ll.recorded_at BETWEEN :start_w AND :end_w
              AND ll.horizontal_accuracy_meters <= 30.0
              AND ST_DWithin(ll.location, v.location, v.geofence_radius_meters, true)
        ) AS attended;
    """
    
    u1_present = (await database.fetch_one(query=check_attendance_sql, values={"venue_id": str(ctx["venue_id"]), "user_id": str(ctx["user_one_id"]), "start_w": start_window, "end_w": end_window}))["attended"]
    u2_present = (await database.fetch_one(query=check_attendance_sql, values={"venue_id": str(ctx["venue_id"]), "user_id": str(ctx["user_two_id"]), "start_w": start_window, "end_w": end_window}))["attended"]

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


@app.get("/qa/dashboard", response_class=HTMLResponse)
async def render_qa_dashboard():
    """
    Renders an interactive, visual HTML/JS debugging dashboard to perform
    live end-to-end user lifecycles, GPS spoofing, and referee validations.
    """
    html_content = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>App Architecture QA Dashboard</title>
        <script src="https://cdn.jsdelivr.net/npm/@tailwindcss/browser@4"></script>
        <style>
            .log-entry {{ font-family: 'Courier New', Courier, monospace; font-size: 0.85rem; }}
        </style>
    </head>
    <body class="bg-slate-900 text-slate-100 min-h-screen p-6">
        <div class="max-w-7xl mx-auto space-y-6">
            
            <header class="bg-slate-800 p-6 rounded-xl border border-slate-700 flex flex-col md:flex-row md:items-center md:justify-between gap-4">
                <div>
                    <h1 class="text-2xl font-bold text-emerald-400">System Core QA & Admin Dashboard</h1>
                    <p class="text-slate-400 text-sm">Visually validate live scheduling state transitions, spatial telemetry, and GPS referee arbitration.</p>
                </div>
                <div class="flex flex-wrap items-center gap-3 bg-slate-900/60 p-3 rounded-lg border border-slate-700">
                    <span class="text-xs font-semibold uppercase text-slate-400">Simulated Identity Switcher:</span>
                    <button onclick="fastLogin('hamza@testapp.com', 'HamzaPass123!')" class="px-3 py-1.5 bg-sky-600 hover:bg-sky-500 rounded text-xs font-medium transition">Log In as Hamza</button>
                    <button onclick="fastLogin('sarah@testapp.com', 'SarahPass123!')" class="px-3 py-1.5 bg-rose-600 hover:bg-rose-500 rounded text-xs font-medium transition">Log In as Sarah</button>
                    <div class="w-full md:w-auto mt-2 md:mt-0">
                        <input type="text" id="customToken" placeholder="Or manual paste JWT here..." oninput="saveManualToken(this.value)" class="w-full bg-slate-800 border border-slate-600 rounded px-2 py-1 text-xs focus:outline-none focus:border-emerald-500 text-slate-300">
                    </div>
                </div>
            </header>

            <section class="bg-slate-800/40 p-3 px-6 rounded-lg border border-slate-800 flex justify-between items-center text-xs text-slate-400">
                <div><span class="font-bold text-slate-300">Target Supabase App Node:</span> {SUPABASE_PROJECT_ID}.supabase.co</div>
                <div><span class="font-bold text-slate-300">Session Status:</span> <span id="authBadge" class="text-amber-400 font-semibold">No Token Loaded</span></div>
            </section>

            <main class="grid grid-cols-1 lg:grid-cols-3 gap-6">

                <div class="bg-slate-800 p-5 rounded-xl border border-slate-700 flex flex-col justify-between">
                    <div class="space-y-4">
                        <div class="border-b border-slate-700 pb-2 flex justify-between items-center">
                            <h2 class="font-bold text-lg text-amber-400">1. Google Places Scheduling</h2>
                            <span class="text-[10px] bg-amber-500/10 text-amber-400 border border-amber-500/20 px-1.5 py-0.5 rounded font-mono">POST</span>
                        </div>
                        <div class="space-y-3 text-sm">
                            <div>
                                <label class="block text-xs text-slate-400 mb-1">Target Match Session UUID</label>
                                <input type="text" id="sched_match_id" value="2bb58b5e-ea11-4f72-bce8-5925d9ef6182" class="w-full bg-slate-900 border border-slate-700 rounded p-2 text-xs focus:ring-1 focus:ring-amber-500 outline-none">
                            </div>
                            <div>
                                <label class="block text-xs text-slate-400 mb-1">Google Place ID Look-up Anchor</label>
                                <input type="text" id="sched_place_id" value="ChIJ_6t9uS0zK4gRcsN5p_v0MhI" class="w-full bg-slate-900 border border-slate-700 rounded p-2 text-xs focus:ring-1 focus:ring-amber-500 outline-none">
                            </div>
                            <div class="grid grid-cols-2 gap-2">
                                <div>
                                    <label class="block text-xs text-slate-400 mb-1">Venue Name</label>
                                    <input type="text" id="sched_name" value="Quantum Coffee" class="w-full bg-slate-900 border border-slate-700 rounded p-2 text-xs focus:ring-1 focus:ring-amber-500 outline-none">
                                </div>
                                <div>
                                    <label class="block text-xs text-slate-400 mb-1">Address Matrix</label>
                                    <input type="text" id="sched_address" value="460 King St W, Toronto" class="w-full bg-slate-900 border border-slate-700 rounded p-2 text-xs focus:ring-1 focus:ring-amber-500 outline-none">
                                </div>
                            </div>
                            <div class="grid grid-cols-2 gap-2">
                                <div>
                                    <label class="block text-xs text-slate-400 mb-1">Latitude Coordinate</label>
                                    <input type="number" step="any" id="sched_lat" value="43.6452" class="w-full bg-slate-900 border border-slate-700 rounded p-2 text-xs focus:ring-1 focus:ring-amber-500 outline-none">
                                </div>
                                <div>
                                    <label class="block text-xs text-slate-400 mb-1">Longitude Coordinate</label>
                                    <input type="number" step="any" id="sched_lng" value="-79.3952" class="w-full bg-slate-900 border border-slate-700 rounded p-2 text-xs focus:ring-1 focus:ring-amber-500 outline-none">
                                </div>
                            </div>
                            <div>
                                <label class="block text-xs text-slate-400 mb-1">Target Meeting ISO Timestamp (Local Target)</label>
                                <input type="datetime-local" id="sched_time" class="w-full bg-slate-900 border border-slate-700 rounded p-2 text-xs focus:ring-1 focus:ring-amber-500 outline-none">
                            </div>
                        </div>
                    </div>
                    <button onclick="submitSchedule()" class="w-full mt-4 py-2.5 bg-amber-600 hover:bg-amber-500 font-semibold rounded-lg transition text-sm cursor-pointer shadow-lg shadow-amber-900/20">Submit / Accept Proposal</button>
                </div>

                <div class="bg-slate-800 p-5 rounded-xl border border-slate-700 flex flex-col justify-between">
                    <div class="space-y-4">
                        <div class="border-b border-slate-700 pb-2 flex justify-between items-center">
                            <h2 class="font-bold text-lg text-sky-400">2. Background GPS Spoofer</h2>
                            <span class="text-[10px] bg-sky-500/10 text-sky-400 border border-sky-500/20 px-1.5 py-0.5 rounded font-mono">POST</span>
                        </div>
                        <p class="text-xs text-slate-400">Simulate a hardware device location coordinate log packet transmission directly into our high-frequency tracking pipeline matrix.</p>
                        <div class="space-y-3 text-sm pt-2">
                            <div class="grid grid-cols-2 gap-2">
                                <div>
                                    <label class="block text-xs text-slate-400 mb-1">Spoofed Latitude</label>
                                    <input type="number" step="any" id="gps_lat" value="43.6453" class="w-full bg-slate-900 border border-slate-700 rounded p-2 text-xs focus:ring-1 focus:ring-sky-500 outline-none">
                                </div>
                                <div>
                                    <label class="block text-xs text-slate-400 mb-1">Spoofed Longitude</label>
                                    <input type="number" step="any" id="gps_lng" value="-79.3951" class="w-full bg-slate-900 border border-slate-700 rounded p-2 text-xs focus:ring-1 focus:ring-sky-500 outline-none">
                                </div>
                            </div>
                            <div>
                                <label class="block text-xs text-slate-400 mb-1">Horizontal Accuracy Margin (meters)</label>
                                <input type="number" id="gps_accuracy" value="5.2" class="w-full bg-slate-900 border border-slate-700 rounded p-2 text-xs focus:ring-1 focus:ring-sky-500 outline-none">
                                <p class="text-[10px] text-slate-500 mt-1">Referee checks reject telemetry with accuracy margins > 30 meters.</p>
                            </div>
                            <div class="bg-slate-900/40 p-3 rounded border border-slate-700/60 space-y-2 mt-2">
                                <span class="text-[11px] block font-semibold text-slate-300">Quick Testing Presets (Toronto Venue):</span>
                                <div class="flex gap-2">
                                    <button onclick="setGPSPreset(43.6452, -79.3952)" class="text-[10px] bg-slate-700 px-2 py-1 rounded hover:bg-slate-600 transition">Inside Geofence (43.6452, -79.3952)</button>
                                    <button onclick="setGPSPreset(43.6532, -79.3832)" class="text-[10px] bg-red-950/40 text-red-400 border border-red-950/80 px-2 py-1 rounded hover:bg-red-900/30 transition">Outside (Eaton Centre)</button>
                                </div>
                            </div>
                        </div>
                    </div>
                    <button onclick="transmitGPS()" class="w-full mt-4 py-2.5 bg-sky-600 hover:bg-sky-500 font-semibold rounded-lg transition text-sm cursor-pointer shadow-lg shadow-sky-900/20">Transmit GPS Ingest Ping</button>
                </div>

                <div class="bg-slate-800 p-5 rounded-xl border border-slate-700 flex flex-col justify-between">
                    <div class="space-y-4">
                        <div class="border-b border-slate-700 pb-2 flex justify-between items-center">
                            <h2 class="font-bold text-lg text-emerald-400">3. Post-Date Affirmation Loops</h2>
                            <span class="text-[10px] bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 px-1.5 py-0.5 rounded font-mono">POST</span>
                        </div>
                        <div class="space-y-4 text-sm">
                            <div>
                                <label class="block text-xs text-slate-400 mb-1">Target Match Session UUID</label>
                                <input type="text" id="aff_match_id" value="2bb58b5e-ea11-4f72-bce8-5925d9ef6182" class="w-full bg-slate-900 border border-slate-700 rounded p-2 text-xs focus:ring-1 focus:ring-emerald-500 outline-none">
                            </div>
                            
                            <div>
                                <label class="block text-xs font-semibold text-slate-300 mb-2">Behavioral Status Choice</label>
                                <div class="space-y-2 bg-slate-900/50 p-3 rounded border border-slate-700">
                                    <label class="flex items-center gap-2 text-xs cursor-pointer"><input type="radio" name="status_choice" value="met" checked class="accent-emerald-500"> We Met Up Safely ('met')</label>
                                    <label class="flex items-center gap-2 text-xs cursor-pointer"><input type="radio" name="status_choice" value="mutually_canceled" class="accent-emerald-500"> Mutually Canceled / Postponed</label>
                                    <label class="flex items-center gap-2 text-xs cursor-pointer"><input type="radio" name="status_choice" value="other_user_flaked" class="accent-emerald-500 text-rose-500"> Counterparty Ghosted/Flaked me</label>
                                </div>
                            </div>

                            <div>
                                <label class="block text-xs font-semibold text-slate-300 mb-2">Future Intent Selection</label>
                                <div class="grid grid-cols-2 gap-2">
                                    <label class="flex flex-col items-center justify-center p-2 bg-slate-900 border border-slate-700 rounded cursor-pointer text-center hover:bg-slate-700/30 transition">
                                        <input type="radio" name="intent_choice" value="continue" checked class="accent-emerald-500 mb-1">
                                        <span class="text-xs font-bold text-emerald-400">Continue</span>
                                        <span class="text-[9px] text-slate-400">Lock Chat & Pair</span>
                                    </label>
                                    <label class="flex flex-col items-center justify-center p-2 bg-slate-900 border border-slate-700 rounded cursor-pointer text-center hover:bg-slate-700/30 transition">
                                        <input type="radio" name="intent_choice" value="re_enter" class="accent-emerald-500 mb-1">
                                        <span class="text-xs font-bold text-rose-400">Re-enter</span>
                                        <span class="text-[9px] text-slate-400">Freeze Room & Return Pool</span>
                                    </label>
                                </div>
                            </div>
                        </div>
                    </div>
                    <button onclick="submitAffirmation()" class="w-full mt-4 py-2.5 bg-emerald-600 hover:bg-emerald-500 font-semibold rounded-lg transition text-sm cursor-pointer shadow-lg shadow-emerald-900/20">Submit Affirmation State</button>
                </div>

            </main>

            <footer class="bg-slate-950 p-4 rounded-xl border border-slate-800 space-y-2 shadow-inner">
                <div class="flex justify-between items-center border-b border-slate-800 pb-2">
                    <div class="flex items-center gap-2">
                        <span class="w-2.5 h-2.5 bg-emerald-500 rounded-full animate-pulse"></span>
                        <span class="text-xs font-bold uppercase tracking-wider text-slate-300">Real-time Event Logger Feed</span>
                    </div>
                    <button onclick="clearConsole()" class="text-[10px] text-slate-500 hover:text-slate-300 transition">Clear Console Logs</button>
                </div>
                <div id="consoleLogStream" class="h-64 overflow-y-auto space-y-1.5 p-2 bg-slate-900/40 rounded text-slate-300 font-mono text-xs flex flex-col-reverse">
                    <div class="text-slate-500 text-center py-12 italic">Awaiting integration interactions... Click an action above to track server payloads.</div>
                </div>
            </footer>

        </div>

        <script>
            // Synchronize datetime-local baseline configuration inputs to right now
            document.getElementById('sched_time').value = new Date(new Date().getTime() - new Date().getTimezoneOffset() * 60000).toISOString().slice(0, 16);

            // Set background authorization token state visualization rules
            function updateTokenUI() {{
                const token = localStorage.getItem('user_token');
                const badge = document.getElementById('authBadge');
                if (token) {{
                    const payload = JSON.parse(atob(token.split('.')[1]));
                    badge.innerText = `Active Session: ${{payload.email || 'Verified Account'}}`;
                    badge.className = "text-emerald-400 font-bold";
                }} else {{
                    badge.innerText = "No Token Loaded";
                    badge.className = "text-amber-400 font-semibold";
                }}
            }}
            updateTokenUI();

            function saveManualToken(val) {{
                if (val.trim()) {{
                    localStorage.setItem('user_token', val.trim());
                }} else {{
                    localStorage.removeItem('user_token');
                }}
                updateTokenUI();
            }}

            function setGPSPreset(lat, lng) {{
                document.getElementById('gps_lat').value = lat;
                document.getElementById('gps_lng').value = lng;
                logEvent('SYSTEM', `GPS fields updated to preset coordinates (${{lat}}, ${{lng}})`);
            }}

            function clearConsole() {{
                document.getElementById('consoleLogStream').innerHTML = '<div class="text-slate-500 text-center py-12 italic">Console logs cleared.</div>';
            }}

            function logEvent(type, message, isError = false) {{
                const stream = document.getElementById('consoleLogStream');
                
                // Clear out splash default text if present
                if (stream.innerHTML.includes('Awaiting integration interactions')) {{
                    stream.innerHTML = '';
                }}
                
                const timeStr = new Date().toLocaleTimeString();
                const colorClass = isError ? 'text-rose-400' : (type === 'SYSTEM' ? 'text-sky-400' : 'text-emerald-400');
                
                const logItem = document.createElement('div');
                logItem.className = "p-1.5 rounded bg-slate-950/50 border-l-2 " + (isError ? "border-rose-500" : "border-emerald-500") + " log-entry";
                logItem.innerHTML = `<span class="text-slate-500">[${{timeStr}}]</span> <span class="${{colorClass}} font-bold">${{type}}</span>: ${{message}}`;
                
                stream.insertBefore(logItem, stream.firstChild);
            }}

            // CLIENT SIDE PASS THROUGH TO CLOUD SUPABASE SIGN-IN HANDSHAKE
            async function fastLogin(email, password) {{
                logEvent('SYSTEM', `Authenticating directly with cloud node for user: ${{email}}...`);
                try {{
                    const response = await fetch('https://{SUPABASE_PROJECT_ID}.supabase.co/auth/v1/token?grant_type=password', {{
                        method: 'POST',
                        headers: {{
                            'apikey': '{SUPABASE_ANON_PUBLIC_KEY}',
                            'Content-Type': 'application/json'
                        }},
                        body: JSON.stringify({{ email: email, password: password }})
                    }});
                    
                    const data = await response.json();
                    if (response.ok && data.access_token) {{
                        localStorage.setItem('user_token', data.access_token);
                        document.getElementById('customToken').value = data.access_token;
                        logEvent('SYSTEM', `Login Success! Extracted and cached JWT Access Signature Token.`);
                        updateTokenUI();
                    }} else {{
                        logEvent('AUTH_ERROR', data.error_description || JSON.stringify(data), true);
                    }}
                }} catch (err) {{
                    logEvent('NETWORK_CRASH', err.message, true);
                }}
            }}

            async function secureFetch(url, method, payload) {{
                const token = localStorage.getItem('user_token');
                if (!token) {{
                    logEvent('SECURITY_EXCEPTION', 'Execution Blocked: You must activate a user session profile first.', true);
                    return;
                }}

                const headers = {{
                    'Authorization': 'Bearer ' + token,
                    'Content-Type': 'application/json'
                }};

                try {{
                    const response = await fetch(url, {{
                        method: method,
                        headers: headers,
                        body: payload ? JSON.stringify(payload) : null
                    }});

                    const text = await response.text();
                    let formattedBody;
                    try {{
                        formattedBody = JSON.stringify(JSON.parse(text), null, 2);
                    }} catch {{
                        formattedBody = text;
                    }}

                    const outputLog = `HTTP ${{response.status}}\\nResponse Body: ${{formattedBody}}`;
                    logEvent(method + ' ' + url, outputLog, !response.ok);
                }} catch (err) {{
                    logEvent('HTTP_CRASH', err.message, true);
                }}
            }}

            // OPERATION SUBMISSIONS PIPELINES
            function submitSchedule() {{
                const payload = {{
                    match_id: document.getElementById('sched_match_id').value,
                    google_place_id: document.getElementById('sched_place_id').value,
                    name: document.getElementById('sched_name').value,
                    address: document.getElementById('sched_address').value,
                    latitude: parseFloat(document.getElementById('sched_lat').value),
                    longitude: parseFloat(document.getElementById('sched_lng').value),
                    scheduled_time: new Date(document.getElementById('sched_time').value).toISOString()
                }};
                secureFetch('/users/me/match/schedule', 'POST', payload);
            }}

            function transmitGPS() {{
                const payload = {{
                    latitude: parseFloat(document.getElementById('gps_lat').value),
                    longitude: parseFloat(document.getElementById('gps_lng').value),
                    horizontal_accuracy_meters: parseFloat(document.getElementById('gps_accuracy').value),
                    recorded_at: new Date().toISOString()
                }};
                secureFetch('/users/me/location/ping', 'POST', payload);
            }}

            function submitAffirmation() {{
                const statusRadio = document.querySelector('input[name="status_choice"]:checked');
                const intentRadio = document.querySelector('input[name="intent_choice"]:checked');
                
                const payload = {{
                    match_id: document.getElementById('aff_match_id').value,
                    status_choice: statusRadio ? statusRadio.value : '',
                    intent_choice: intentRadio ? intentRadio.value : ''
                }};
                secureFetch('/users/me/match/affirmation', 'POST', payload);
            }}
        </script>
    </body>
    </html>
    """
    return HTMLResponse(content=html_content, status_code=200)