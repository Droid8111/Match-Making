import os
import requests
from dotenv import load_dotenv

# Load the environment variables from the .env file
load_dotenv()

# --- CONFIGURATION MATRIX ---
SUPABASE_PROJECT_ID = os.getenv("SUPABASE_PROJECT_ID")
SUPABASE_ANON_PUBLIC_KEY = os.getenv("SUPABASE_ANON_PUBLIC_KEY")

# Safety check to ensure environment variables are loading correctly
if not SUPABASE_PROJECT_ID or not SUPABASE_ANON_PUBLIC_KEY:
    raise ValueError("Missing Supabase configuration in .env file. Please check your keys.")

# Mock profile targets
TEST_EMAIL = "fresh_test_user_99@testapp.com"
TEST_PASSWORD = "Password123!"

# Routing configurations
SUPABASE_AUTH_URL = f"https://{SUPABASE_PROJECT_ID}.supabase.co/auth/v1"
LOCAL_FASTAPI_URL = "http://127.0.0.1:8000"

def run_integration_test():
    session = requests.Session()
    
    # Base headers required by Supabase API gateway endpoints
    supabase_headers = {
        "apikey": SUPABASE_ANON_PUBLIC_KEY,
        "Content-Type": "application/json"
    }

    print("--- STEP 1: SIMULATING USER REGISTRATION ---")
    signup_payload = {
        "email": TEST_EMAIL,
        "password": TEST_PASSWORD,
        # Move "data" to the root level for raw HTTP requests
        "data": {
            "first_name": "Hamza",
            "birth_date": "1998-11-15"
        }
    }
    
    signup_response = session.post(f"{SUPABASE_AUTH_URL}/signup", json=signup_payload, headers=supabase_headers)
    
    if signup_response.status_code in [200, 201]:
        print("[SUCCESS] Account created. Database triggers are mirroring record to public.users schema.")
    elif signup_response.status_code == 422 and "already registered" in signup_response.text:
        print("[INFO] User already registered. Proceeding directly to sign-in phase.")
    else:
        print(f"[FAIL] Signup failed: {signup_response.status_code} - {signup_response.text}")
        return

    print("\n--- STEP 2: ATTEMPTING USER SIGN-IN (OAUTH HANDSHAKE) ---")
    login_payload = {
        "email": TEST_EMAIL,
        "password": TEST_PASSWORD
    }
    
    # Requesting token generation from Supabase Auth Engine via password grant type
    login_response = session.post(
        f"{SUPABASE_AUTH_URL}/token?grant_type=password", 
        json=login_payload, 
        headers=supabase_headers
    )

    if login_response.status_code != 200:
        print(f"[FAIL] Login failed: {login_response.status_code} - {login_response.text}")
        return
        
    auth_data = login_response.json()
    access_token = auth_data.get("access_token")
    print("[SUCCESS] Login successful! Extracted Supabase Signed Access JWT.")

    print("\n--- STEP 3: TESTING PROTECTED LOCAL FASTAPI ROUTE WITH JWT ---")
    # Attach our new token as a Bearer string into our local API request header matrix
    local_api_headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json"
    }

    # Test preference selection update route
    pref_payload = {
        "min_age": 20,
        "max_age": 28,
        "max_distance_km": 15
    }
    
    pref_response = requests.put(
        f"{LOCAL_FASTAPI_URL}/users/me/preferences", 
        json=pref_payload, 
        headers=local_api_headers
    )
    
    # Defensive Output Printing
    print(f"[PREFERENCES] HTTP Status Code: {pref_response.status_code}")
    print(f"[PREFERENCES] Raw Text Response Body: '{pref_response.text}'")
    
    if pref_response.text.strip():
        try:
            print(f"[PREFERENCES] Parsed JSON: {pref_response.json()}")
        except Exception as e:
            print(f"[PREFERENCES] JSON parsing failed: {e}")
    else:
        print("[PREFERENCES] Warning: Server returned an entirely empty body.")

    print("-" * 40)

    # Test profile viewing matching extraction route
    match_response = requests.get(
        f"{LOCAL_FASTAPI_URL}/users/me/current-match", 
        headers=local_api_headers
    )
    
    print(f"[CURRENT-MATCH] HTTP Status Code: {match_response.status_code}")
    print(f"[CURRENT-MATCH] Raw Text Response Body: '{match_response.text}'")
    
    if match_response.text.strip():
        try:
            print(f"[CURRENT-MATCH] Parsed JSON: {match_response.json()}")
        except Exception as e:
            print(f"[CURRENT-MATCH] JSON parsing failed: {e}")
    else:
        print("[CURRENT-MATCH] Warning: Server returned an entirely empty body.")

if __name__ == "__main__":
    run_integration_test()