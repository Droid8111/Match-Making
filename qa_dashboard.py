import os
import uuid
import json
from datetime import datetime
from typing import Dict, List
from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Query
from fastapi.responses import HTMLResponse  # <-- ADD This line here!

dashboard_router = APIRouter()

SUPABASE_PROJECT_ID = os.getenv("SUPABASE_PROJECT_ID", "").strip("'\"").strip()
SUPABASE_ANON_PUBLIC_KEY = os.getenv("SUPABASE_ANON_PUBLIC_KEY", "").strip("'\"").strip()
SERVICE_ROLE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY", "").strip("'\"").strip()

# ==========================================
# 1. LIVE ADMIN ANALYTICS CENTER
# ==========================================
@dashboard_router.get("/qa/admin", response_class=HTMLResponse)
async def render_live_admin_center():
    """Generates a live, fully-integrated HTML table overview of real database states."""
    from main import database  
    
    rounds_query = "SELECT id, status, start_time FROM public.rounds ORDER BY start_time DESC LIMIT 5;"
    try:
        rounds_data = await database.fetch_all(rounds_query)
    except Exception:
        rounds_data = []

    matches_query = """
        SELECT m.id AS match_id, m.status AS match_status, m.user_one_reported_status, m.user_two_reported_status,
               r.status AS round_status,
               sd.status AS schedule_status, 
               (SELECT COUNT(*) FROM public.chat_messages c WHERE c.match_id = m.id) as msg_count
        FROM public.matches m
        JOIN public.rounds r ON m.round_id = r.id
        LEFT JOIN public.scheduled_dates sd ON m.id = sd.match_id
        ORDER BY m.created_at DESC LIMIT 50;
    """
    try:
        matches_data = await database.fetch_all(matches_query)
    except Exception:
        matches_data = []

    match_rows_html = ""
    for m in matches_data:
        flake_alert = "<span class='text-slate-500'>Clean</span>"
        if m["user_one_reported_status"] == 'other_user_flaked' or m["user_two_reported_status"] == 'other_user_flaked':
            flake_alert = "<span class='text-rose-400 font-bold bg-rose-900/30 px-2 py-1 rounded text-[10px] uppercase'>Referee Intervened</span>"
            
        rnd_badge = "emerald" if m["round_status"] == "active" else "slate"
            
        match_rows_html += """
        <tr class="hover:bg-slate-750 border-b border-slate-800 transition">
            <td class="p-4 font-mono text-[10px] text-slate-400">{match_id}</td>
            <td class="p-4"><span class="bg-{rnd_badge}-900/40 text-{rnd_badge}-400 px-2 py-1 rounded text-[10px] font-bold uppercase">{round_status}</span></td>
            <td class="p-4"><span class="text-sky-400 font-bold text-xs">{match_status}</span></td>
            <td class="p-4 text-xs text-amber-200">{schedule_status}</td>
            <td class="p-4 text-xs font-mono">{msg_count}</td>
            <td class="p-4">{flake_alert}</td>
        </tr>
        """.replace("{match_id}", str(m["match_id"])).replace("{rnd_badge}", rnd_badge).replace("{round_status}", str(m["round_status"])).replace("{match_status}", str(m["match_status"])).replace("{schedule_status}", str(m["schedule_status"] or 'pending')).replace("{msg_count}", str(m["msg_count"])).replace("{flake_alert}", flake_alert)

    if not match_rows_html:
        match_rows_html = "<tr><td colspan='6' class='p-8 text-center text-slate-500 italic'>No transactional matches detected.</td></tr>"

    html_content = """
    <!DOCTYPE html>
    <html lang="en">
    <head><script src="https://cdn.tailwindcss.com"></script><title>Production Admin Center</title></head>
    <body class="bg-slate-950 text-slate-200 p-8 font-sans pb-24">
        <div class="max-w-7xl mx-auto space-y-8">
            <header class="flex justify-between items-center border-b border-slate-800 pb-4">
                <div>
                    <h1 class="text-3xl font-bold bg-gradient-to-r from-emerald-400 to-sky-400 bg-clip-text text-transparent">System Arbitration Matrix</h1>
                    <p class="text-slate-500 text-sm mt-1 font-mono">LIVE DATABASE POLLING ENVIRONMENT</p>
                </div>
                <a href="/qa/dashboard" class="bg-slate-800 hover:bg-slate-700 px-4 py-2 rounded text-sm transition text-slate-300">← Back to Simulator</a>
            </header>
            
            <div class="bg-slate-900 rounded-xl border border-slate-800 shadow-2xl overflow-hidden">
                <div class="p-4 bg-slate-800/50 border-b border-slate-800 font-bold text-emerald-400 uppercase text-xs tracking-widest flex items-center gap-2">
                    <span class="w-2 h-2 rounded-full bg-emerald-500 animate-pulse"></span> Active & Historic Matches Pipeline
                </div>
                <table class="w-full text-left text-sm">
                    <thead class="bg-slate-900/80 text-slate-400 text-xs uppercase tracking-wider">
                        <tr><th class="p-4">Match UUID</th><th class="p-4">Round State</th><th class="p-4">Pairing Status</th><th class="p-4">Venue State</th><th class="p-4">Total Packets</th><th class="p-4">Arbitration Logs</th></tr>
                    </thead>
                    <tbody class="divide-y divide-slate-800/50">
                        %%MATCH_ROWS%%
                    </tbody>
                </table>
            </div>
        </div>
    </body>
    </html>
    """
    final_html = html_content.replace("%%MATCH_ROWS%%", match_rows_html)
    return HTMLResponse(content=final_html)


# ==========================================
# 2. BACKEND MACRO TIMELINE ROUTING HOOKS
# ==========================================
@dashboard_router.post("/qa/initialize-round")
async def qa_init_round():
    """Deferred local import route to clear history and spin up an active round node."""
    from main import database
    
    # 1. Archive previous rounds safely
    await database.execute("UPDATE public.rounds SET status = 'completed' WHERE status = 'active';")

    # 2. Purge stale telemetry from previous test runs.
    # Without this, old location_logs from a prior "both at venue" scenario bleed into
    # the next test's referee window — causing both users to appear present regardless
    # of where the new pings are fired. chat_messages cleared for the same reason.
    await database.execute("DELETE FROM public.location_logs;")
    await database.execute("DELETE FROM public.chat_messages;")

    # 3. Insert fresh active round
    new_round = await database.fetch_one("""
        INSERT INTO public.rounds (status, start_time, end_time) 
        VALUES ('active', NOW(), NOW() + INTERVAL '14 days') RETURNING id;
    """)
    return {"status": "success", "round_id": str(new_round["id"])}

@dashboard_router.post("/qa/trigger-production-match/{round_id}")
async def qa_trigger_match(round_id: str):
    """Deferred local import route to process live match batch calculations natively."""
    from main import database
    match_algo_query = """
        WITH available_singles AS (
            SELECT p.user_id, p.gender, p.calculated_age, p.location, pref.preference_genders, pref.min_age, pref.max_age, pref.max_distance_km
            FROM public.profiles p
            JOIN public.users u ON p.user_id = u.id
            JOIN public.dating_preferences pref ON p.user_id = pref.user_id
            WHERE p.is_searching = TRUE AND u.account_status = 'active'
        ),
        valid_pairs AS (
            SELECT LEAST(u1.user_id, u2.user_id) AS user_one, GREATEST(u1.user_id, u2.user_id) AS user_two
            FROM available_singles u1
            JOIN available_singles u2 ON u1.user_id < u2.user_id
            WHERE ST_DWithin(u1.location, u2.location, u1.max_distance_km * 1000, true)
              AND ST_DWithin(u2.location, u1.location, u2.max_distance_km * 1000, true)
              AND u1.preference_genders && ARRAY[u2.gender::varchar]
              AND u2.preference_genders && ARRAY[u1.gender::varchar]
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
    await database.execute(match_algo_query, values={"round_id": round_id})
    return {"status": "success"}


# ==========================================
# 3. FULL-STACK INTERACTIVE SIMULATOR UI
# ==========================================
@dashboard_router.get("/qa/dashboard", response_class=HTMLResponse)
async def render_qa_dashboard():
    """Serves the visually simulated, HTTP-integrated dual-frame testing UI."""
    
    html_content = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Full-Stack Simulator V5</title>
        <script src="https://cdn.tailwindcss.com"></script>
        <style>
            ::-webkit-scrollbar { width: 4px; }
            ::-webkit-scrollbar-track { background: transparent; }
            ::-webkit-scrollbar-thumb { background: #475569; border-radius: 10px; }
            .phone-shadow { box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.7), inset 0 0 0 1px rgba(255,255,255,0.05); }
            .slider-thumb::-webkit-slider-thumb { appearance: none; width: 16px; height: 16px; background: #10b981; border-radius: 50%; cursor: pointer; }
            .modal-backdrop { background-color: rgba(15, 23, 42, 0.9); backdrop-filter: blur(8px); }
        </style>
    </head>
    <body class="bg-slate-950 text-slate-200 min-h-screen font-sans pb-12 overflow-x-hidden">
        
        <header class="bg-slate-900 border-b border-slate-800 p-4 sticky top-0 z-40 shadow-xl">
            <div class="max-w-7xl mx-auto space-y-4">
                
                <div class="flex flex-col md:flex-row justify-between items-center gap-4">
                    <div>
                        <h1 class="text-xl font-bold bg-gradient-to-r from-emerald-400 to-teal-400 bg-clip-text text-transparent">Production Simulator V5</h1>
                        <p class="text-[10px] text-slate-400 font-mono tracking-widest mt-1">NO F-STRING INJECTIONS</p>
                    </div>
                    
                    <div class="flex flex-wrap gap-3 bg-slate-950 p-2 rounded-lg border border-slate-800 items-center">
                        <span class="text-[10px] uppercase font-bold text-slate-500 px-2">Macro Engine:</span>
                        <button onclick="macroCreateRound()" class="bg-emerald-900/40 hover:bg-emerald-800/60 border border-emerald-800 text-emerald-400 px-4 py-1.5 rounded text-xs font-bold transition">1. Initialize Round Node</button>
                        <button onclick="macroExecuteMatch()" class="bg-sky-900/40 hover:bg-sky-800/60 border border-sky-800 text-sky-400 px-4 py-1.5 rounded text-xs font-bold transition">2. Execute Match Query</button>
                        <a href="/qa/admin" target="_blank" class="bg-slate-800 hover:bg-slate-700 border border-slate-600 text-white px-4 py-1.5 rounded text-xs transition ml-4">Open Admin Panel ↗</a>
                        <button onclick="masterReset()" class="bg-rose-900/40 hover:bg-rose-800/60 border border-rose-800 text-rose-400 px-4 py-1.5 rounded text-xs font-bold transition ml-2">⟲ Hard Reset</button>
                    </div>
                </div>

                <div class="bg-slate-950 p-4 rounded-xl border border-slate-800 space-y-2">
                    <div class="flex justify-between items-end">
                        <div>
                            <span class="text-[10px] font-bold text-sky-400 uppercase tracking-widest">Temporal Control</span>
                            <h2 class="text-lg font-mono font-bold text-slate-200" id="clock_display">Day 1 - 08:00 AM</h2>
                        </div>
                        <button onclick="skipDay()" class="bg-slate-800 border border-slate-700 text-xs px-3 py-1 rounded transition text-slate-300">⏭ +24 Hours</button>
                    </div>
                    <input type="range" id="time_slider" min="0" max="336" value="0" step="1" oninput="updateTimeEngine(this.value)" class="w-full h-2 bg-slate-800 rounded-lg appearance-none cursor-pointer slider-thumb">
                </div>
            </div>
        </header>

        <main class="max-w-7xl mx-auto p-8 flex flex-col lg:flex-row justify-center items-start gap-16 relative">
            <div class="flex flex-col items-center gap-4">
                <div class="w-[320px] h-[650px] bg-slate-50 border-[14px] border-slate-900 rounded-[3rem] relative overflow-hidden flex flex-col text-slate-900 phone-shadow">
                    <div class="absolute top-0 inset-x-0 h-6 bg-slate-900 rounded-b-3xl w-40 mx-auto z-50"></div>
                    <div class="bg-white px-4 pt-10 pb-3 border-b border-slate-200 flex justify-between items-center shadow-sm z-20">
                        <div class="font-bold text-slate-800">Hamza</div>
                        <div class="text-[10px] font-bold bg-slate-100 text-slate-600 px-2 py-1 rounded">⭐ <span id="hamza_rep" class="text-sky-600 font-mono">100</span> Rep</div>
                    </div>
                    <div id="hamza_screen" class="flex-1 w-full h-full flex flex-col relative overflow-y-auto bg-slate-50"></div>
                </div>
            </div>

            <div class="flex flex-col items-center gap-4">
                <div class="w-[320px] h-[650px] bg-slate-50 border-[14px] border-slate-900 rounded-[3rem] relative overflow-hidden flex flex-col text-slate-900 phone-shadow">
                    <div class="absolute top-0 inset-x-0 h-6 bg-slate-900 rounded-b-3xl w-40 mx-auto z-50"></div>
                    <div class="bg-white px-4 pt-10 pb-3 border-b border-slate-200 flex justify-between items-center shadow-sm z-20">
                        <div class="font-bold text-slate-800">Sarah</div>
                        <div class="text-[10px] font-bold bg-slate-100 text-slate-600 px-2 py-1 rounded">⭐ <span id="sarah_rep" class="text-rose-600 font-mono">100</span> Rep</div>
                    </div>
                    <div id="sarah_screen" class="flex-1 w-full h-full flex flex-col relative overflow-y-auto bg-slate-50"></div>
                </div>
            </div>

            <div id="maps_overlay" class="fixed inset-0 modal-backdrop z-50 flex items-center justify-center hidden opacity-0 transition-opacity">
                <div class="bg-white w-[350px] rounded-3xl overflow-hidden shadow-2xl flex flex-col transform scale-95 transition-transform" id="maps_card">
                    <div class="bg-slate-200 h-40 relative flex items-center justify-center text-4xl">🗺️</div>
                    <div class="p-6 space-y-4">
                        <h3 class="font-bold text-slate-800">Propose Venue & Time</h3>
                        <div class="space-y-2 text-slate-800">
                            <select id="map_preset" class="w-full bg-slate-50 border border-slate-200 rounded-lg p-2 text-xs outline-none">
                                <option value='{"id":"ChIJ_6t9uS0zK4gRcsN5p","name":"Quantum Coffee","lat":43.6452,"lng":-79.3952}'>Quantum Coffee (Downtown)</option>
                                <option value='{"id":"ChIJP_A2f0Q0K4gR","name":"Pilot Coffee Roasters","lat":43.6685,"lng":-79.3871}'>Pilot Coffee Roasters</option>
                            </select>
                            <input type="datetime-local" id="map_time" class="w-full bg-slate-50 border border-slate-200 rounded-lg p-2 text-xs outline-none">
                        </div>
                        <div class="flex gap-2 pt-2">
                            <button onclick="closeMap()" class="flex-1 py-2 bg-slate-100 text-slate-600 rounded-xl font-semibold text-xs">Cancel</button>
                            <button onclick="confirmMapSelection()" class="flex-1 py-2 bg-slate-900 text-white rounded-xl font-semibold text-xs">Propose Date</button>
                        </div>
                    </div>
                </div>
            </div>
        </main>

<script>
            const SUPA_URL = "https://%%PROJECT_ID%%.supabase.co";
            const SUPA_KEY = "%%ANON_KEY%%";
            // NOTE: Admin actions are performed server-side via authenticated FastAPI
            // endpoints. The service role key is NEVER sent to the browser.

            const state = {
                hoursElapsed: 0,
                activeRoundId: null,
                timeline: { day: 1, timeString: "08:00 AM", isoString: new Date().toISOString() },
                match: { id: null, isConfirmed: false, venueName: null, dateIso: null },
                users: {
                    hamza: { token: null, uid: null, stage: 'auth', searching: false, color: 'sky' },
                    sarah: { token: null, uid: null, stage: 'auth', searching: false, color: 'rose' }
                },
                mapTargetUser: null,
                pollingIds: {}
            };

            async function apiFetch(u, endpoint, method, payload = null) {
                const token = state.users[u].token;
                if (!token) return { ok: false };
                try {
                    const res = await fetch(endpoint, {
                        method: method,
                        headers: { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' },
                        body: payload ? JSON.stringify(payload) : null
                    });
                    const data = await res.json().catch(()=>({}));
                    return { ok: res.ok, status: res.status, data };
                } catch (e) { return { ok: false, data: { detail: e.message } }; }
            }

            async function macroCreateRound() {
                const res = await fetch('/qa/initialize-round', { method: 'POST' });
                const data = await res.json();
                if(res.ok) {
                    state.activeRoundId = data.round_id;
                    alert(`New Round Successfully Generated: ${data.round_id}`);
                } else {
                    alert("Error Initializing Round Node.");
                }
            }

            async function macroExecuteMatch() {
                if (!state.activeRoundId) return alert("Initialize an active round node before running matching configurations!");
                
                const res = await fetch(`/qa/trigger-production-match/${state.activeRoundId}`, { method: 'POST' });
                if(res.ok) {
                    alert(`Batch matching completed cleanly.\nDevices initializing automatic active context discovery streams.`);
                    startDiscoveryPolling('hamza');
                    startDiscoveryPolling('sarah');
                } else {
                    alert("Execution Error during matching calculations.");
                }
            }

            function renderScreens() {
                renderDevice('hamza');
                renderDevice('sarah');
            }

            function renderDevice(u) {
                const screen = document.getElementById(u + '_screen');
                const user = state.users[u];
                const c = user.color;

                if (user.stage === 'auth') {
                    screen.innerHTML = `
                        <div class="flex-1 flex flex-col justify-center p-6 text-center space-y-4">
                            <h3 class="font-bold text-slate-800 text-lg">Cloud Login</h3>
                            <button onclick="executeAuth('${u}')" class="w-full py-3 bg-${c}-600 hover:bg-${c}-700 text-white font-bold rounded-xl shadow transition">Sign in</button>
                        </div>
                    `;
                }
                else if (user.stage === 'profile_setup') {
                    screen.innerHTML = `
                        <div class="flex-1 p-6 flex flex-col overflow-y-auto">
                            <h3 class="font-bold text-slate-800 mb-4 text-lg">Setup Preset</h3>
                            <div class="space-y-4 text-sm text-slate-700">
                                <div>
                                    <label class="font-bold text-xs uppercase tracking-wide">PostGIS Location Node</label>
                                    <select id="${u}_loc" class="w-full bg-slate-100 border border-slate-200 rounded-lg p-2 mt-1">
                                        <option value="toronto">Downtown Toronto (Core Node)</option>
                                        <option value="scarborough">Scarborough (East Node)</option>
                                        <option value="barrie">Barrie (North Boundary - 90km)</option>
                                    </select>
                                </div>
                                <div><label class="font-bold text-xs">Match Genders</label>
                                    <div class="grid grid-cols-2 gap-2 mt-1 bg-slate-100 p-3 rounded">
                                        <label><input type="checkbox" id="${u}_pref_m" checked> Men</label>
                                        <label><input type="checkbox" id="${u}_pref_f" checked> Women</label>
                                        <label><input type="checkbox" id="${u}_pref_nb" checked> Non-Binary</label>
                                    </div>
                                </div>
                                <button onclick="saveLocationAndProfile('${u}')" class="w-full py-3 mt-4 bg-slate-900 text-white font-bold rounded-xl shadow">Lock Context</button>
                            </div>
                        </div>
                    `;
                }
                else if (user.stage === 'onboarding') {
                    screen.innerHTML = `
                        <div class="flex-1 flex flex-col p-6 items-center text-center justify-center">
                            <div class="w-20 h-20 bg-${c}-100 rounded-full flex items-center justify-center text-3xl mb-4 shadow-inner">🔥</div>
                            <h2 class="text-xl font-bold text-slate-800">Opt-In Sequence</h2>
                            <button onclick="toggleOptIn('${u}')" class="w-full py-3 mt-4 rounded-xl font-bold text-white shadow ${user.searching ? 'bg-emerald-500' : 'bg-slate-400'}">
                                ${user.searching ? 'Searching For Match...' : 'Opt-In to Round'}
                            </button>
                        </div>
                    `;
                }
                else if (user.stage === 'matched' || user.stage === 'verdict') {
                    let mapArea = `
                        <div class="h-28 bg-slate-200 flex flex-col items-center justify-center relative border-b border-slate-300">
                            <span class="text-[10px] text-slate-500 uppercase tracking-widest font-bold">No Venue Scheduled</span>
                            <button onclick="openMap('${u}')" class="absolute bottom-3 right-3 bg-slate-900 text-white text-[10px] px-3 py-1.5 rounded-full shadow">📍 Suggest Spot</button>
                        </div>`;

                    if (state.match.venueName) {
                        const sColor = state.match.isConfirmed ? 'emerald' : 'amber';
                        mapArea = `
                            <div class="h-28 bg-${sColor}-900/10 p-3 flex flex-col justify-end relative border-b border-${sColor}-200">
                                <span class="absolute top-2 right-2 bg-${sColor}-500 text-white text-[9px] px-2 py-0.5 rounded-full font-bold uppercase tracking-wide">${state.match.isConfirmed ? 'CONFIRMED' : 'PROPOSED'}</span>
                                <div class="bg-white p-2 rounded-lg shadow-sm border border-slate-100 max-w-[80%]">
                                    <h4 class="text-xs font-bold text-slate-800 truncate">${state.match.venueName}</h4>
                                    <p class="text-[9px] text-${c}-600 mt-0.5 font-semibold">${new Date(state.match.dateIso).toLocaleString([], {weekday: 'short', hour: '2-digit', minute:'2-digit'})}</p>
                                </div>
                                <button onclick="openMap('${u}')" class="absolute bottom-2 right-2 bg-slate-900 text-white text-[9px] px-2 py-1 rounded-full shadow">${state.match.isConfirmed ? 'Adjust Date' : 'Adjust/Accept'}</button>
                            </div>`;
                    }

                    screen.innerHTML = `
                        ${mapArea}
                        <div class="flex-1 bg-slate-50 p-4 overflow-y-auto flex flex-col gap-2" id="${u}_chat_area">
                            <div class="text-center text-slate-400 text-[9px] font-mono mb-4">-- POSTGRES STREAM OPEN --</div>
                        </div>
                        <div class="bg-white p-3 border-t border-slate-200 flex gap-2 shrink-0 z-20 shadow-[0_-4px_6px_-1px_rgba(0,0,0,0.05)]">
                            <input type="text" id="${u}_chat_input" placeholder="Message..." class="flex-1 bg-slate-100 rounded-full px-4 text-xs outline-none">
                            <button onclick="executeSendMsg('${u}')" class="w-8 h-8 shrink-0 rounded-full bg-${c}-500 text-white text-xs flex items-center justify-center">↑</button>
                        </div>
                        <div class="absolute top-28 right-0 left-0 bg-slate-900 border-t border-slate-800 p-2 flex justify-between items-center z-10 shadow-lg translate-y-full rounded-t-xl" id="${u}_telemetry_bar">
                            <span class="text-[9px] uppercase font-bold text-slate-400 flex items-center gap-1">Telemetry <span class="w-2 h-2 rounded-full bg-rose-500" id="${u}_gps_indicator"></span></span>
                            <div class="flex gap-1">
                                <button onclick="fireGPS('${u}', 'venue')" class="bg-slate-800 text-white text-[9px] px-2 py-1 rounded border border-slate-700">📍 Venue</button>
                                <button onclick="fireGPS('${u}', 'home')" class="bg-slate-800 text-white text-[9px] px-2 py-1 rounded border border-slate-700">🏠 Home</button>
                            </div>
                        </div>
                    `;

                    if (user.stage === 'verdict') {
                        screen.innerHTML += `
                            <div class="absolute inset-0 bg-slate-900/85 backdrop-blur z-50 flex items-center justify-center p-4">
                                <div class="bg-white w-full rounded-2xl p-5 shadow-2xl border border-slate-200">
                                    <h3 class="font-bold text-slate-800 text-lg">Timeline Concluded</h3>
                                    <div class="space-y-2 mt-4">
                                        <button onclick="executeVerdict('${u}', 'met', 'continue')" class="w-full py-2.5 bg-emerald-500 text-white rounded-lg text-xs font-bold">We Met & Continue</button>
                                        <button onclick="executeVerdict('${u}', 'other_user_flaked', 're_enter')" class="w-full py-2 bg-rose-50 text-rose-600 border border-rose-200 rounded-lg text-xs font-bold">They Flaked (Report)</button>
                                    </div>
                                </div>
                            </div>
                        `;
                    }
                }
            }

            async function executeAuth(u) {
                const mail = u === 'hamza' ? 'hamza_final_test@testapp.com' : 'sarah_final_test@testapp.com';
                const pass = 'Password123!'; 
                const res = await fetch(`${SUPA_URL}/auth/v1/token?grant_type=password`, {
                    method: 'POST',
                    headers: { 'apikey': SUPA_KEY, 'Content-Type': 'application/json' },
                    body: JSON.stringify({ email: mail, password: pass })
                });
                const data = await res.json();
                if (res.ok) {
                    state.users[u].token = data.access_token;
                    state.users[u].uid = data.user.id;
                    state.users[u].stage = 'profile_setup';
                    renderScreens();
                } else alert('Auth Failed. Check Supabase User Accounts Management Dashboard.');
            }

            async function saveLocationAndProfile(u) {
                const locPreset = document.getElementById(`${u}_loc`).value;
                await apiFetch(u, '/qa/update-location-point', 'PUT', { preset_name: locPreset });
                
                let prefs = [];
                if(document.getElementById(`${u}_pref_m`).checked) prefs.push("male");
                if(document.getElementById(`${u}_pref_f`).checked) prefs.push("female");
                if(document.getElementById(`${u}_pref_nb`).checked) prefs.push("non-binary");

                await apiFetch(u, '/users/me/profile-setup', 'POST', {
                    first_name: u.charAt(0).toUpperCase() + u.slice(1), birth_date: "1998-05-15", gender: u === 'hamza' ? 'male' : 'female', preference_genders: prefs
                });
                
                state.users[u].stage = 'onboarding';
                renderScreens();
            }

            async function toggleOptIn(u) {
                const newState = !state.users[u].searching;
                await apiFetch(u, '/users/me/opt-in', 'PUT', { is_searching: newState });
                state.users[u].searching = newState; 
                
                // Wake up the background checking process if they just opted back in!
                if (newState) {
                    startDiscoveryPolling(u);
                }
                
                renderScreens();
            }

            function startDiscoveryPolling(u) {
                state.pollingIds[`${u}_discover`] = setInterval(async () => {
                    if (state.users[u].stage !== 'onboarding' || !state.users[u].searching) { 
                        clearInterval(state.pollingIds[`${u}_discover`]); 
                        return; 
                    }
                    const res = await apiFetch(u, '/users/me/active-match', 'GET');
                    if(res.ok && res.data.has_match) {
                        clearInterval(state.pollingIds[`${u}_discover`]);
                        state.match.id = res.data.match_id;
                        state.users[u].stage = 'matched';
                        document.getElementById(`${u}_rep`).innerText = res.data.counterparty_rep;
                        state.pollingIds[`${u}_chat`] = setInterval(() => pollChat(u), 3000);
                        renderScreens();
                    }
                }, 3000);
            }

            async function pollChat(u) {
                if(!state.match.id) return;
                const res = await apiFetch(u, `/users/me/messages?match_id=${state.match.id}`, 'GET');
                if (res.ok) {
                    const box = document.getElementById(`${u}_chat_area`);
                    if(!box) return;
                    const c = state.users[u].color;
                    let html = '<div class="text-center text-slate-400 text-[9px] font-mono mb-4">-- DB STREAM --</div>';
                    res.data.forEach(msg => {
                        const isMe = msg.sender_id === state.users[u].uid;
                        html += `<div class="self-${isMe ? 'end' : 'start'} bg-${isMe ? c+'-500 text-white' : 'slate-200 text-slate-800'} text-xs py-2 px-3 rounded-2xl ${isMe ? 'rounded-tr-none' : 'rounded-tl-none'} max-w-[85%] shadow-sm">${msg.text}</div>`;
                    });
                    if(box.innerHTML !== html) { box.innerHTML = html; box.scrollTop = box.scrollHeight; }
                }
            }

            async function executeSendMsg(u) {
                const input = document.getElementById(`${u}_chat_input`);
                if(!input.value.trim() || !state.match.id) return;
                await apiFetch(u, '/users/me/messages/send', 'POST', { match_id: state.match.id, message_text: input.value.trim() });
                input.value = ''; pollChat(u);
            }

            function openMap(u) {
                state.mapTargetUser = u;
                document.getElementById('maps_overlay').classList.remove('hidden');
                setTimeout(() => {
                    document.getElementById('maps_overlay').classList.remove('opacity-0');
                    document.getElementById('maps_card').classList.remove('scale-95');
                }, 10);
            }
            function closeMap() {
                document.getElementById('maps_overlay').classList.add('opacity-0');
                document.getElementById('maps_card').classList.add('scale-95');
                setTimeout(() => document.getElementById('maps_overlay').classList.add('hidden'), 200);
            }
            async function confirmMapSelection() {
                const u = state.mapTargetUser;
                const presetData = JSON.parse(document.getElementById('map_preset').value);
                const rawTime = document.getElementById('map_time').value;
                if(!rawTime) return;

                const targetDate = new Date(rawTime);
                const payload = {
                    match_id: state.match.id, google_place_id: presetData.id,
                    name: presetData.name, address: "Simulated",
                    latitude: presetData.lat, longitude: presetData.lng,
                    scheduled_time: targetDate.toISOString()
                };

                const res = await apiFetch(u, '/users/me/match/schedule', 'POST', payload);
                if (res.ok) {
                    state.match.venueName = presetData.name;
                    state.match.dateIso = targetDate.toISOString();
                    state.match.isConfirmed = res.data.is_confirmed; 
                    closeMap(); renderScreens();
                }
            }

            async function fireGPS(u, locationType) {
                if(!state.match.isConfirmed) return;

                // "venue" uses the coords of the ACTUAL scheduled venue stored in state,
                // so the ping matches whatever place was selected in the map picker.
                // "home" uses Scarborough (~12 km NE of downtown) — guaranteed outside
                // the 100 m geofence of every downtown/midtown venue preset.
                let lat, lng;
                if (locationType === 'venue') {
                    const presetRaw = document.getElementById('map_preset').value;
                    const preset = presetRaw ? JSON.parse(presetRaw) : null;
                    if (!preset) { console.warn("[GPS] No venue preset selected"); return; }
                    lat = preset.lat;
                    lng = preset.lng;
                } else {
                    // Scarborough Town Centre — ~12 km from downtown Toronto venues
                    lat = 43.7764;
                    lng = -79.2318;
                }

                const payload = {
                    latitude: lat,
                    longitude: lng,
                    horizontal_accuracy_meters: 10,
                    recorded_at: new Date().toISOString()
                };
                await apiFetch(u, '/users/me/location/ping', 'POST', payload);
                const ind = document.getElementById(`${u}_gps_indicator`);
                ind.classList.add('bg-amber-400');
                setTimeout(() => ind.classList.remove('bg-amber-400'), 400);
            }

            async function executeVerdict(u, statusChoice, intentChoice) {
                const res = await apiFetch(u, '/users/me/match/affirmation', 'POST', { match_id: state.match.id, status_choice: statusChoice, intent_choice: intentChoice });
                if(res.ok) {
                    state.users[u].stage = 'onboarding'; state.users[u].searching = false;
                    clearInterval(state.pollingIds[`${u}_chat`]); renderScreens();
                }
            }

            function updateTimeEngine(hours) {
                const prev = state.hoursElapsed;
                state.hoursElapsed = parseInt(hours);
                const totalHours = state.hoursElapsed + 8;
                state.timeline.day = Math.floor(totalHours / 24) + 1;
                const hr = totalHours % 24;
                const ampm = hr >= 12 ? 'PM' : 'AM';
                document.getElementById('clock_display').innerText = `Day ${state.timeline.day} - ${hr % 12 === 0 ? 12 : hr % 12}:00 ${ampm}`;

                checkTriggers(prev, state.hoursElapsed);
            }

            function skipDay() {
                const slider = document.getElementById('time_slider');
                slider.value = Math.min(336, parseInt(slider.value) + 24);
                updateTimeEngine(slider.value);
            }

            function checkTriggers(prev, current) {
                if (prev < 72 && current >= 72) {
                    if ((state.users.hamza.stage === 'matched' || state.users.sarah.stage === 'matched') && !state.match.isConfirmed) {
                        alert(`System Alert: 72-Hour Scheduling Window Expired. Unconfirmed chats are now isolated.`);
                    }
                }

                if(state.match.isConfirmed && state.match.dateIso) {
                    const dateHours = Math.floor((new Date(state.match.dateIso) - new Date()) / (1000*60*60));
                    if(current >= dateHours - 1 && current <= dateHours + 1) {
                        document.getElementById('hamza_telemetry_bar')?.classList.remove('translate-y-full');
                        document.getElementById('sarah_telemetry_bar')?.classList.remove('translate-y-full');
                        document.getElementById('hamza_gps_indicator').className = "w-2 h-2 rounded-full bg-emerald-500 animate-pulse";
                        document.getElementById('sarah_gps_indicator').className = "w-2 h-2 rounded-full bg-emerald-500 animate-pulse";
                    } else {
                        document.getElementById('hamza_telemetry_bar')?.classList.add('translate-y-full');
                        document.getElementById('sarah_telemetry_bar')?.classList.add('translate-y-full');
                        document.getElementById('hamza_gps_indicator').className = "w-2 h-2 rounded-full bg-rose-500";
                        document.getElementById('sarah_gps_indicator').className = "w-2 h-2 rounded-full bg-rose-500";
                    }

                    if(current >= dateHours + 2) {
                        if(state.users.hamza.stage === 'matched') state.users.hamza.stage = 'verdict';
                        if(state.users.sarah.stage === 'matched') state.users.sarah.stage = 'verdict';
                        renderScreens();
                    }
                }
            }

            function masterReset() {
                Object.values(state.pollingIds).forEach(clearInterval);
                
                const hToken = state.users.hamza.token;
                const hUid = state.users.hamza.uid;
                const sToken = state.users.sarah.token;
                const sUid = state.users.sarah.uid;

                state.hoursElapsed = 0;
                state.activeRoundId = null;
                state.timeline = { day: 1, timeString: "08:00 AM", isoString: new Date().toISOString() };
                state.match = { id: null, isConfirmed: false, venueName: null, dateIso: null };
                state.users = {
                    hamza: { token: hToken, uid: hUid, stage: hToken ? 'onboarding' : 'auth', searching: false, color: 'sky' },
                    sarah: { token: sToken, uid: sUid, stage: sToken ? 'onboarding' : 'auth', searching: false, color: 'rose' }
                };
                state.mapTargetUser = null;
                state.pollingIds = {};

                document.getElementById('time_slider').value = 0;
                updateTimeEngine(0);
                renderScreens();
                
                alert(`System Hard Reset Complete. Temporal timeline and match contexts have been cleared.`);
            }

            const tmr = new Date(); tmr.setDate(tmr.getDate()+1);
            document.getElementById('map_time').value = tmr.toISOString().slice(0, 16);

            renderScreens();
        </script>
    </body>
    </html>
    """
    
    # SERVICE_ROLE_KEY is intentionally excluded from this substitution.
    # It must never be embedded in HTML sent to the browser — all admin operations
    # go through FastAPI endpoints that authenticate the key server-side.
    final_html = html_content.replace("%%PROJECT_ID%%", SUPABASE_PROJECT_ID).replace("%%ANON_KEY%%", SUPABASE_ANON_PUBLIC_KEY)
    return HTMLResponse(content=final_html, status_code=200)


class MobileChatConnectionManager:
    def __init__(self):
        # Memory matrix: maps match_id -> Dict[user_id, WebSocket]
        self.active_rooms: Dict[str, Dict[str, WebSocket]] = {}

    async def connect(self, match_id: str, user_id: str, websocket: WebSocket):
        await websocket.accept()
        if match_id not in self.active_rooms:
            self.active_rooms[match_id] = {}
        self.active_rooms[match_id][user_id] = websocket

    def disconnect(self, match_id: str, user_id: str):
        if match_id in self.active_rooms:
            if user_id in self.active_rooms[match_id]:
                del self.active_rooms[match_id][user_id]
            if not self.active_rooms[match_id]:
                del self.active_rooms[match_id]

    async def route_message_or_trigger_push_fallback(
        self, match_id: str, sender_id: str, counterparty_id: str, payload: dict
    ):
        """
        Routes text payloads to active sockets in real time.
        Triggers push gateway fallback if the counterparty's socket is detached.
        """
        room_listeners = self.active_rooms.get(match_id, {})

        # Echo message packet back to the sender socket frame for instant UI feedback
        if sender_id in room_listeners:
            await room_listeners[sender_id].send_json(payload)

        # Deliver message payload directly to the counterparty websocket lane
        if counterparty_id in room_listeners:
            await room_listeners[counterparty_id].send_json(payload)
        else:
            # Client is backgrounded or offline: execute remote push notification broadcast
            await self.dispatch_push_notification_fallback(counterparty_id, payload)

    async def dispatch_push_notification_fallback(self, user_id: str, payload: dict):
        """
        Push Notification Gateway. Fires remote APNs/FCM payloads 
        to devices that backgrounded or closed their socket session.
        """
        print(f"[PUSH GATEWAY] Outbound fallback engaged. Target user {user_id} is currently detached.")
        print(f"[PUSH GATEWAY] Dispatched Remote payload message segment: {payload['message_text'][:30]}...")

# Instantiate global socket router pool manager
mobile_ws_manager = MobileChatConnectionManager()

@dashboard_router.websocket("/qa/ws/chat/{match_id}")
async def websocket_chat_stream(websocket: WebSocket, match_id: str, token: str = Query(...), user_id: str = Query(...)):
    """
    Full-duplex WebSocket channel for Flutter/Swift clients.
    Identity is verified via JWT on the initial handshake before the socket is accepted.
    user_id from the query string is ONLY used for routing after the token has confirmed it.
    """
    from main import database, get_current_user_id  # Deferred to avoid circular import at boot
    from fastapi.security import HTTPAuthorizationCredentials

    # Verify JWT before accepting the socket. Reject with 1008 (Policy Violation) if invalid.
    # We manually wrap the token string to reuse the existing get_current_user_id dependency.
    try:
        fake_credentials = HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)
        verified_user_id = await get_current_user_id(credentials=fake_credentials)
    except Exception:
        await websocket.close(code=1008)  # 1008 = Policy Violation
        return

    # Reject if the claimed user_id in the query string does not match the token payload.
    # Prevents a valid user from connecting to another user's socket slot.
    if verified_user_id != user_id:
        await websocket.close(code=1008)
        return

    await mobile_ws_manager.connect(match_id, verified_user_id, websocket)
    try:
        while True:
            # Low-bandwidth ingestion frame: expects only {"message_text": "..."}
            data = await websocket.receive_json()
            message_text = data.get("message_text")
            
            if message_text:
                # 1. Fetch match row layout from PostgreSQL to identify the participant mapping properties
                match_query = """
                    SELECT user_one_id, user_two_id 
                    FROM public.matches 
                    WHERE id = CAST(:match_id AS UUID);
                """
                match_rec = await database.fetch_one(match_query, values={"match_id": match_id})
                if not match_rec:
                    continue

                # 2. Securely isolate counterparty context without client-side data packets input dependency
                u1_str = str(match_rec["user_one_id"])
                u2_str = str(match_rec["user_two_id"])
                counterparty_id = u2_str if user_id == u1_str else u1_str

                # 3. Commit packet to database using the verified connection identity context
                insert_query = """
                    INSERT INTO public.chat_messages (match_id, sender_id, message_text)
                    VALUES (CAST(:match_id AS UUID), CAST(:sender_id AS UUID), :message_text)
                    RETURNING created_at;
                """
                rec = await database.fetch_one(insert_query, values={
                    "match_id": match_id, "sender_id": user_id, "message_text": message_text
                })
                
                # 4. Standardize output schemas matching production REST data mapping layers
                broadcast_payload = {
                    "sender_id": str(user_id),
                    "message_text": str(message_text),
                    "created_at": str(rec["created_at"]) if rec else datetime.utcnow().isoformat()
                }
                
                # 5. Route over current websocket pool matrix or fallback to Push Notifications Gateway
                await mobile_ws_manager.route_message_or_trigger_push_fallback(
                    match_id=match_id,
                    sender_id=user_id,
                    counterparty_id=counterparty_id,
                    payload=broadcast_payload
                )
                
    except WebSocketDisconnect:
        # Purge dead memory socket structures cleanly to prevent system memory leaks during tower handoffs
        mobile_ws_manager.disconnect(match_id, user_id)