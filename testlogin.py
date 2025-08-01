#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Python script to mimic the network traffic captured in login.json using requests and json libraries.
This script replicates the sequence of HTTP requests observed in the login.json file:
1. Device registration for push notifications (unauthenticated).
2. Device information submission (version info).
3. OAuth2 user login (with email/password) to obtain an access token.
4. Register device for notifications under the user session (authenticated).
5. Set user preferences (language).
6. Retrieve user profile and list of vehicles.
7. For the first vehicle, retrieve detailed profile, send a remote command (pre-wakeup),
   check valet mode, get last parked location, check final destination, get user-vehicle link info,
   and fetch the latest vehicle status.
Each step is implemented in a function for clarity.
"""

import requests
from urllib.parse import urlparse, parse_qs
import uuid


BASE_URL = "https://prd.eu-ccapi.kia.com:8080"
AUTH_BASE = "https://idpconnect-eu.kia.com"
SERVICE_ID = "fdc85c00-0a2f-4c64-bcb4-2cfb1500730a"
APP_ID = "1518dd6b-2759-4995-9ae5-c9ad4a9ddad1"
CLIENT_ID = SERVICE_ID
CLIENT_SECRET = "secret"
# User credentials (are read from a seperate config file)
USER_EMAIL = "read from config.py"
USER_PASSWORD = "read from config.py"
# Device and push info (use actual device token if available, else dummy for simulation)
PUSH_REG_ID = "DUMMY_PUSH_TOKEN_ABC123"
DEVICE_UUID = str(uuid.uuid4())
device_id = ""

# Initialize a session and set common headers
session = requests.Session()
session.headers.update({
    "ccsp-service-id": SERVICE_ID,
    "ccsp-application-id": APP_ID,
    "User-Agent": "okhttp/4.10.0",
    "Accept-Encoding": "gzip",
    "offset": "2"
})


# Note: The 'Stamp' header seen in login.json is not generated here due to its unknown algorithm.
def read_config():
    # config.py should contain
    # username = "myusername"
    # password = "mypassword"

    import config
    username = config.username
    password = config.password
    print(f"[OK] Username and password read")
    return username, password


def register_device(session, push_reg_id, device_uuid):
    url = f"{BASE_URL}/api/v1/spa/notifications/register"
    payload = {"pushRegId": push_reg_id, "uuid": device_uuid, "pushType": "GCM"}
    resp = session.post(url, json=payload)
    resp.raise_for_status()
    data = resp.json()
    if data.get("retCode") != "S":
        raise Exception(f"Device registration failed: {data.get('resMsg')}")
    device_id = data["resMsg"]["deviceId"]
    session.headers.update({"ccsp-device-id": device_id})
    print(f"[OK] Device registered with deviceId: {device_id}")
    return device_id


def send_device_info(session):
    url = f"{BASE_URL}/api/v1/spa/devices/version"
    info_payload = {
        "phoneType": "sdk_gphone64_arm64",
        "teleType": "none",
        "appVer": "2.1.24",
        "osType": "android",
        "buildVer": "13",
        "osVer": "13"
    }
    resp = session.post(url, json=info_payload)
    resp.raise_for_status()
    print("[OK] Device version info sent.")
    return resp.json()


def login_and_get_token(session, username, password):
    # Step 1: Hit the authorize endpoint to initiate OAuth (and set cookies)
    auth_url = f"{AUTH_BASE}/auth/api/v2/user/oauth2/authorize"
    params = {
        "response_type": "code",
        "client_id": CLIENT_ID,
        "redirect_uri": f"{BASE_URL}/api/v1/user/oauth2/redirect",
        "state": "ccsp",
        "lang": "en"
    }
    resp = session.get(auth_url, params=params)
    # Step 2: Submit login form with credentials
    login_url = f"{AUTH_BASE}/auth/account/signin"
    login_data = {
        "username": username,
        "password": password,
        "encryptedPassword": "false",
        "remember_me": "false",
        "redirect_uri": f"{BASE_URL}/api/v1/user/oauth2/redirect",
        "state": "ccsp",
        "client_id": CLIENT_ID
    }
    resp = session.post(login_url, data=login_data, allow_redirects=False)
    if resp.status_code != 302:
        raise Exception(f"Login failed (status code {resp.status_code}). Check credentials.")
    redirect_url = resp.headers.get("Location", "")
    query = urlparse(redirect_url).query
    params = parse_qs(query)
    auth_code = params.get("code", [None])[0]
    if not auth_code:
        raise Exception("Authorization code not found after login.")
    print("[OK] Logged in, auth code received.")

    # Step 3: Exchange authorization code for access token
    token_url = f"{AUTH_BASE}/auth/api/v2/user/oauth2/token"
    token_data = {
        "grant_type": "authorization_code",
        "code": auth_code,
        "redirect_uri": f"{BASE_URL}/api/v1/user/oauth2/redirect",
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET
    }
    resp = session.post(token_url, data=token_data)
    resp.raise_for_status()
    token_info = resp.json()
    access_token = token_info.get("access_token")
    if not access_token:
        raise Exception("Access token not found in token response.")
    session.headers.update({"Authorization": f"Bearer {access_token}"})
    print("[OK] Access token obtained.")
    return token_info  # includes access_token, refresh_token, etc.


def finalize_session_registration(session, device_id):
    # First call the same register endpoint (with Authorization now set)
    url1 = f"{BASE_URL}/api/v1/spa/notifications/register"
    payload = {"pushRegId": PUSH_REG_ID, "uuid": DEVICE_UUID, "pushType": "GCM"}
    resp1 = session.post(url1, json=payload)
    resp1.raise_for_status()
    # Then confirm device registration by hitting the specific device register endpoint
    url2 = f"{BASE_URL}/api/v1/spa/notifications/{device_id}/register"
    resp2 = session.post(url2)
    resp2.raise_for_status()
    print("[OK] Device registration confirmed for user session.")


def set_preferred_language(session, device_id, language="en"):
    url = f"{BASE_URL}/api/v1/spa/devices/{device_id}/setting/language"
    payload = {"language": language.upper()}
    resp = session.post(url, json=payload)
    # API might return 200 or 204 No Content for success
    if resp.status_code not in (200, 204):
        resp.raise_for_status()
    print(f"[OK] Preferred language set to {language.upper()}.")


def get_user_profile(session):
    url = f"{BASE_URL}/api/v1/user/profile"
    resp = session.get(url)
    resp.raise_for_status()
    profile_data = resp.json()
    name = profile_data.get("name") or profile_data.get("username")
    print(f"[OK] User profile retrieved (Name: {name}).")
    return profile_data


def get_vehicles(session):
    url = f"{BASE_URL}/api/v1/spa/vehicles"
    resp = session.get(url)
    resp.raise_for_status()
    data = resp.json()
    vehicles = data.get("resMsg", {}).get("vehicles", [])
    print(f"[OK] Retrieved {len(vehicles)} vehicle(s) linked to the account.")
    return vehicles


def get_vehicle_profile(session, vehicle_id):
    url = f"{BASE_URL}/api/v1/spa/vehicles/{vehicle_id}/profile"
    resp = session.get(url)
    resp.raise_for_status()
    print("[OK] Vehicle profile data retrieved.")
    return resp.json()


def send_engine_prewakeup(session, vehicle_id, device_id):
    url = f"{BASE_URL}/api/v1/spa/vehicles/{vehicle_id}/control/engine"
    payload = {"action": "prewakeup", "deviceId": device_id}
    resp = session.post(url, json=payload)
    resp.raise_for_status()
    print("[OK] Pre-wakeup command sent to vehicle.")
    return resp.json()


def get_valet_mode(session, vehicle_id):
    url = f"{BASE_URL}/api/v1/spa/vehicles/{vehicle_id}/status/valet"
    resp = session.get(url)
    resp.raise_for_status()
    data = resp.json()
    mode = data.get("resMsg", {}).get("valetMode")
    print(f"[OK] Valet mode status retrieved (mode={mode}).")
    return data


def get_park_location(session, vehicle_id):
    url = f"{BASE_URL}/api/v1/spa/vehicles/{vehicle_id}/location/park"
    resp = session.get(url)
    resp.raise_for_status()
    data = resp.json()
    coord = data.get("resMsg", {}).get("coord")
    if coord:
        lat = coord.get("lat")
        lon = coord.get("lon")
        print(f"[OK] Last parked location: lat={lat}, lon={lon}.")
    else:
        print("[OK] No parked location data available.")
    return data


def get_final_destination(session, vehicle_id):
    url = f"{BASE_URL}/api/v1/spa/vehicles/{vehicle_id}/finaldestination"
    resp = session.get(url)
    resp.raise_for_status()
    data = resp.json()
    if data.get("retCode") == "F":
        print("[OK] Final destination not available.")
    else:
        print("[OK] Final destination data retrieved.")
    return data


def get_user_vehicle_link(session, user_id, vehicle_id):
    url = f"{BASE_URL}/api/v1/profile/users/{user_id}/cars/{vehicle_id}"
    resp = session.get(url)
    resp.raise_for_status()
    print("[OK] User-vehicle link info retrieved.")
    return resp.json()


def get_vehicle_status(session, vehicle_id):
    url = f"{BASE_URL}/api/v1/spa/vehicles/{vehicle_id}/ccs2/carstatus/latest"
    resp = session.get(url)
    resp.raise_for_status()
    status_data = resp.json()
    # Try to extract battery level from the status for an example output
    res_msg = status_data.get("resMsg", {})
    battery_level = None
    # Different keys might hold battery info depending on type
    if "battery" in res_msg:
        # Possibly EV data structure
        bat_info = res_msg["battery"]
        # 'batSoc' might be battery state of charge in some data
        battery_level = bat_info.get("batSoc") or bat_info.get("batteryLevel")
    if battery_level is None:
        # Try alternative location
        ev_status = res_msg.get("evStatus") or {}
        battery_level = ev_status.get("batteryStatus") or ev_status.get("batterySoc")
    if battery_level is not None:
        print(f"[OK] Vehicle status retrieved (Battery SOC: {battery_level}%).")
    else:
        print("[OK] Vehicle status retrieved.")
    return status_data


# ---- Main execution of the workflow ----
if __name__ == "__main__":
    try:
        # Step 0: Read username and password
        USER_EMAIL, USER_PASSWORD = read_config()
        # Step 1: Register device (unauthenticated)
        device_id = register_device(session, PUSH_REG_ID, DEVICE_UUID)
        # Step 2: Send device version info
        send_device_info(session)
        # Step 3: Perform user login to get tokens
        token_info = login_and_get_token(session, USER_EMAIL, USER_PASSWORD)
        # Step 4: Finalize device registration under user session
        finalize_session_registration(session, device_id)
        # Also set preferred language (optional, but included in traffic)
        set_preferred_language(session, device_id, language="en")
        # Step 5: Retrieve user profile and vehicle list
        profile = get_user_profile(session)
        user_id = profile.get("id") or profile.get("userId") or profile.get("masterId")
        vehicles = get_vehicles(session)
        if not vehicles:
            print("No vehicles associated with this account.")
        else:
            # For demonstration, use the first vehicle in the list
            vehicle = vehicles[0]
            vehicle_id = vehicle.get("vehicleId")
            nickname = vehicle.get("nickname") or vehicle.get("vehicleName") or vehicle.get("vin")
            print(f"Target Vehicle: {nickname} (ID: {vehicle_id})")
            # Get detailed vehicle profile
            get_vehicle_profile(session, vehicle_id)
            # Send a remote prewakeup command to the vehicle
            send_engine_prewakeup(session, vehicle_id, device_id)
            # Check valet mode status
            get_valet_mode(session, vehicle_id)
            # Get last parked location
            get_park_location(session, vehicle_id)
            # Check final destination info (if any)
            get_final_destination(session, vehicle_id)
            # Get user-vehicle link info, if user_id is known
            if user_id:
                get_user_vehicle_link(session, user_id, vehicle_id)
            # Get latest vehicle status (like battery, door locks, etc.)
            get_vehicle_status(session, vehicle_id)
            print(f"[DONE] Workflow completed for vehicle: {nickname}")
    except requests.HTTPError as http_err:
        print(f"HTTP error occurred: {http_err}")
    except Exception as err:
        print(f"Error: {err}")
