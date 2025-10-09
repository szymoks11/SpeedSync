"""
Assetto Corsa Lap Statistics Plugin
Tracks lap times, sector times, and theoretical best times via API integration.
"""

import sys
import os
import platform
import tempfile

# Setup Python path based on architecture
if platform.architecture()[0] == "64bit":
    sys.path.insert(0, "apps/python/SpeedSync/stdlib64")
else:
    sys.path.insert(0, "apps/python/SpeedSync/stdlib")
os.environ['PATH'] = os.environ['PATH'] + ";."

# Core imports
import ac
import acsys
from datetime import datetime
import json
import urllib.request
import urllib.parse
import threading
import queue
import time
import ctypes
import mmap
import hashlib
import base64
# Local imports
from physics import SPageFilePhysics
from graphic import SPageFileGraphic

# Constants
API_CONFIG = {
    'base_url': 'https://speedsync.pl/api',
    'api_key': None,
    'username': None,
    'password': None
}

SHM_NAME_PHYSICS = "Local\\acpmf_physics"
SHM_NAME_GRAPHICS = "Local\\acpmf_graphics"

# Global state
class AppState:
    def __init__(self):
        # Timing and lap tracking
        self.timer = 0
        self.last_lap_count = -1
        self.lap_invalid_flag = False
        
        # Memory mapped files
        self.mmf_physics = None
        self.mmf_graphics = None
        
        # Session management
        self.session_index = None
        self.session_start_time = None
        self.current_track_car_combo = None  # Track current track/car combo
        
        # Sector tracking
        self.last_sector_index = -1
        self.completed_sectors = {}
        
        # Best times
        self.best_sector_times = {}
        self.session_best_sector_times = {}
        self.session_theoretical_best = None
        self.best_times_loaded = False
        
        # Authentication
        self.current_user_id = None
        self.current_username = None
        self.is_logged_in = False
        
        # UI elements
        self.login_window = None
        self.username_input = None
        self.password_input = None
        self.login_button = None
        self.register_button = None
        self.login_status_label = None
        self.remember_me_checkbox = None
        self.remember_me_state = False
        self.logout_button = None
        
        # Threading
        self.lap_queue = queue.Queue()
        self.worker_thread = None


# Global app state instance
app_state = AppState()

# =============================================================================
# LOGGING SYSTEM
# =============================================================================

class Logger:
    def __init__(self):
        self.log_file = None
        try:
            log_path = os.path.join(os.path.dirname(__file__), "speedsync.log")
            self.log_file = open(log_path, "a", encoding='utf-8')
        except Exception as e:
            print("[Logger Init Error] Could not open log file: {}".format(e))
    
    def log(self, message):
        try:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            formatted = "[{}] {}\n".format(timestamp, message)
            
            if self.log_file and hasattr(self.log_file, "write"):
                self.log_file.write(formatted)
                self.log_file.flush()
            else:
                print(formatted)
        except Exception as e:
            print("[Logger Error] Failed to write log: {}".format(e))
            print(message)

logger = Logger()
log = logger.log

# =============================================================================
# API CLIENT
# =============================================================================

class APIClient:
    @staticmethod
    def make_request(endpoint, method='GET', data=None, require_auth=True):
        """Make authenticated API request to server"""
        try:
            url = API_CONFIG['base_url'] + endpoint
            
            headers = {
                'Content-Type': 'application/json',
                'User-Agent': 'AssettoCorsaSpeedSync/1.0'
            }
            
            if require_auth and API_CONFIG.get('api_key'):
                headers['X-API-Key'] = API_CONFIG['api_key']
            
            if data:
                json_data = json.dumps(data).encode('utf-8')
                req = urllib.request.Request(url, data=json_data, headers=headers, method=method)
            else:
                req = urllib.request.Request(url, headers=headers, method=method)
            
            with urllib.request.urlopen(req, timeout=10) as response:
                response_data = response.read().decode('utf-8')
                return json.loads(response_data), response.status
                
        except urllib.error.HTTPError as e:
            error_data = e.read().decode('utf-8')
            try:
                error_json = json.loads(error_data)
                log("API HTTP Error {}: {}".format(e.code, error_json.get('error', 'Unknown error')))
                return error_json, e.code
            except:
                log("API HTTP Error {}: {}".format(e.code, error_data))
                return {'error': 'HTTP Error {}'.format(e.code)}, e.code
                
        except urllib.error.URLError as e:
            log("API URL Error: {}".format(e))
            return {'error': 'Connection failed'}, 0
            
        except Exception as e:
            log("API Request Error: {}".format(e))
            return {'error': 'Request failed'}, 0
    
    @staticmethod
    def test_connection():
        """Test API connectivity"""
        try:
            response, status = APIClient.make_request('/health', require_auth=False)
            if status == 200:
                log("API connection test successful")
                return True
            else:
                log("API connection test failed with status: {}".format(status))
                return False
        except Exception as e:
            log("API connection test failed: {}".format(e))
            return False
# =============================================================================
# AUTHENTICATION SYSTEM
# =============================================================================

class AuthManager:
    @staticmethod
    def authenticate_user(username, password):
        """Authenticate user via API"""
        try:
            data = {'username': username, 'password': password}
            response, status = APIClient.make_request('/auth/login', 'POST', data, require_auth=False)
            
            if status == 200 and response.get('status') == 'success':
                API_CONFIG['api_key'] = response.get('api_key')
                API_CONFIG['username'] = username
                log("User '{}' authenticated via API".format(username))
                return True, response.get('user_id'), "Success"
            else:
                error_msg = response.get('error', 'Authentication failed')
                log("API authentication failed: {}".format(error_msg))
                return False, None, error_msg
                
        except Exception as e:
            log("authenticate_user error: {}".format(e))
            return False, None, "Connection error"
    
    @staticmethod
    def _get_machine_id():
        """Generate a machine-specific identifier"""
        try:
            # Combine multiple system-specific values
            machine_info = "{}{}{}".format(
                platform.node(),  # Computer name
                platform.machine(),  # Machine type
                os.environ.get('USERNAME', os.environ.get('USER', 'default'))  # Username
            )
            return hashlib.sha256(machine_info.encode('utf-8')).digest()
        except:
            # Fallback to a default if anything fails
            return hashlib.sha256(b'SpeedSyncAC_Default').digest()
    
    @staticmethod
    def _xor_cipher(data, key):
        """Simple XOR cipher for encryption/decryption"""
        key_length = len(key)
        return bytes(b ^ key[i % key_length] for i, b in enumerate(data))
    
    @staticmethod
    def encrypt_password(password):
        """Encrypt password for local storage using machine-specific key"""
        try:
            # Use machine-specific key
            cipher_key = AuthManager._get_machine_id()
            password_bytes = password.encode('utf-8')
            
            # Add random salt for additional security
            salt = os.urandom(8)
            data_to_encrypt = salt + password_bytes
            
            encrypted = AuthManager._xor_cipher(data_to_encrypt, cipher_key)
            return base64.b64encode(encrypted).decode('utf-8')
        except Exception as e:
            log("Error encrypting password: {}".format(e))
            return None
    
    @staticmethod
    def decrypt_password(encrypted_password):
        """Decrypt password from local storage using machine-specific key"""
        try:
            cipher_key = AuthManager._get_machine_id()
            encrypted_bytes = base64.b64decode(encrypted_password)
            
            decrypted = AuthManager._xor_cipher(encrypted_bytes, cipher_key)
            
            # Remove salt (first 8 bytes)
            password_bytes = decrypted[8:]
            return password_bytes.decode('utf-8')
        except Exception as e:
            log("Error decrypting password: {}".format(e))
            return None

    @staticmethod
    def save_login_data(username, password, remember=True):
        """Save login credentials to file"""
        try:
            log("Starting save_login_data for user: {}".format(username))
            
            encrypted_password = AuthManager.encrypt_password(password)
            if not encrypted_password:
                log("Failed to encrypt password")
                return None
            
            log("Password encrypted successfully")
            
            login_data = {
                'username': username,
                'password_encrypted': encrypted_password,
                'api_key': API_CONFIG.get('api_key'),
                'remember': remember
            }
            
            possible_paths = [
                os.path.join(os.path.dirname(__file__), "login_data.json"),
                os.path.join(tempfile.gettempdir(), "ac_SpeedSync_login.json")
            ]
            
            log("Attempting to save to paths: {}".format(possible_paths))
            
            for login_file_path in possible_paths:
                try:
                    abs_path = os.path.abspath(login_file_path)
                    dir_path = os.path.dirname(abs_path)
                    
                    log("Checking path: {}".format(abs_path))
                    log("Directory: {}".format(dir_path))
                    
                    # Check if directory exists and is writable
                    if not os.path.exists(dir_path):
                        log("Directory does not exist: {}".format(dir_path))
                        continue
                        
                    if not os.access(dir_path, os.W_OK):
                        log("Directory not writable: {}".format(dir_path))
                        continue
                    
                    # Write the file
                    with open(abs_path, 'w', encoding='utf-8') as f:
                        json.dump(login_data, f, indent=2, ensure_ascii=False)
                    
                    log("File written to: {}".format(abs_path))
                    
                    # Verify the file was created
                    if os.path.exists(abs_path):
                        file_size = os.path.getsize(abs_path)
                        log("Login data saved successfully: {} (size: {} bytes)".format(abs_path, file_size))
                        
                        # Verify content
                        with open(abs_path, 'r', encoding='utf-8') as f:
                            verify_data = json.load(f)
                            log("Verified data keys: {}".format(verify_data.keys()))
                        
                        return abs_path
                    else:
                        log("File not found after writing: {}".format(abs_path))
                        
                except Exception as e:
                    log("Failed to save to {}: {} - {}".format(login_file_path, type(e).__name__, e))
                    import traceback
                    log("Traceback: {}".format(traceback.format_exc()))
                    continue
            
            log("ERROR: Failed to save to any location")
            return None
                    
        except Exception as e:
            log("ERROR in save_login_data: {} - {}".format(type(e).__name__, e))
            import traceback
            log("Traceback: {}".format(traceback.format_exc()))
            return None

    @staticmethod
    def load_login_data():
        """Load saved login credentials"""
        possible_paths = [
            os.path.join(os.path.dirname(__file__), "login_data.json"),
            os.path.join(tempfile.gettempdir(), "ac_SpeedSync_login.json")
        ]
        
        appdata = os.environ.get('APPDATA', '')
        if appdata:
            possible_paths.append(os.path.join(appdata, "AC_SpeedSync", "login_data.json"))
        
        for login_file_path in possible_paths:
            try:
                abs_path = os.path.abspath(login_file_path)
                if os.path.exists(abs_path):
                    with open(abs_path, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                    
                    # Decrypt password if present
                    if 'password_encrypted' in data and data['password_encrypted']:
                        decrypted = AuthManager.decrypt_password(data['password_encrypted'])
                        if decrypted:
                            data['password'] = decrypted
                            log("Login data loaded and decrypted from: {}".format(abs_path))
                            return data
                        else:
                            log("Failed to decrypt password from: {}".format(abs_path))
                            # Return None so user has to re-login
                            return None
                    else:
                        # Handle legacy plain-text password
                        log("Login data loaded from: {}".format(abs_path))
                        return data
            except Exception as e:
                log("Failed to load login data from {}: {}".format(login_file_path, e))
        
        log("No login data found in any location")
        return None

    @staticmethod
    def get_decrypted_credentials():
        """Get decrypted username and password for auto-login"""
        data = AuthManager.load_login_data()
        if data and data.get('remember'):
            return {
                'username': data.get('username'),
                'password': data.get('password'),
                'api_key': data.get('api_key')
            }
        return None
    
    @staticmethod
    def clear_login_data():
        """Clear saved login credentials"""
        possible_paths = [
            os.path.join(os.path.dirname(__file__), "login_data.json"),
            os.path.join(tempfile.gettempdir(), "ac_SpeedSync_login.json")
        ]
        
        appdata = os.environ.get('APPDATA', '')
        if appdata:
            possible_paths.append(os.path.join(appdata, "AC_SpeedSync", "login_data.json"))
        
        cleared_any = False
        for login_file_path in possible_paths:
            try:
                abs_path = os.path.abspath(login_file_path)
                if os.path.exists(abs_path):
                    os.remove(abs_path)
                    log("Login data cleared from: {}".format(abs_path))
                    cleared_any = True
            except Exception as e:
                log("Failed to clear login data from {}: {}".format(login_file_path, e))
        
        if not cleared_any:
            log("No login data files found to clear")
# =============================================================================
# SESSION AND TIMING MANAGEMENT
# =============================================================================

class SessionManager:
    @staticmethod
    def reset_session_best_times():
        """Reset session-specific best sector times"""
        app_state.session_best_sector_times.clear()
        app_state.session_theoretical_best = None
        log("Session best times reset for new session")
    
    @staticmethod
    def update_session_best_sector_times(lap_number, sector_times):
        """Update session-specific best sector times (legacy batch method)"""
        updated_sectors = []
        
        for sector_index, sector_time in sector_times.items():
            if sector_time > 0:
                current_best = app_state.session_best_sector_times.get(sector_index)
                if current_best is None or sector_time < current_best:
                    app_state.session_best_sector_times[sector_index] = sector_time
                    updated_sectors.append(sector_index)
        
        if updated_sectors:
            old_theoretical = app_state.session_theoretical_best
            app_state.session_theoretical_best = SessionManager.get_session_theoretical_best()
            if app_state.session_theoretical_best != old_theoretical:
                log("Batch updated session theoretical best: {}ms ({:.3f}s)".format(
                    app_state.session_theoretical_best, 
                    app_state.session_theoretical_best / 1000.0))
        
        return updated_sectors
    
    @staticmethod
    def get_session_theoretical_best():
        """Calculate session-specific theoretical best lap time"""
        if all(i in app_state.session_best_sector_times for i in [0, 1, 2]):
            total = sum(app_state.session_best_sector_times[i] for i in [0, 1, 2])
            log("Calculated session theoretical best: {} + {} + {} = {}ms".format(
                app_state.session_best_sector_times[0],
                app_state.session_best_sector_times[1], 
                app_state.session_best_sector_times[2],
                total))
            return total
        else:
            missing_sectors = [i for i in [0, 1, 2] if i not in app_state.session_best_sector_times]
            log("Cannot calculate theoretical best - missing sectors: {}".format(missing_sectors))
            return None
    
    @staticmethod
    def generate_session_index():
        """Generate unique session identifier and reset session data"""
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            carId = ac.getFocusedCar()
            raw_track_name = ac.getTrackName(carId)
            track_layout = ac.getTrackConfiguration(carId)
            hash_input = "{}_{}_{}_".format(timestamp, raw_track_name, track_layout or 'default')
            short_hash = hashlib.md5(hash_input.encode()).hexdigest()[:6]
            session_id = "{}_{}".format(timestamp, short_hash)
            log("Generated session index: {}".format(session_id))
            
            # Don't reset session best times here - only reset when explicitly starting new session
            return session_id
            
        except Exception as e:
            log("Failed to generate session index: {}".format(e))
            return datetime.now().strftime("%Y%m%d_%H%M%S")
    
    @staticmethod
    def get_or_create_session_index():
        """Get current session index or create new one"""
        if app_state.session_index is None:
            app_state.session_index = SessionManager.generate_session_index()
            app_state.session_start_time = datetime.now()
            log("New session started: {}".format(app_state.session_index))
        return app_state.session_index

# =============================================================================
# DATA COLLECTION AND PROCESSING
# =============================================================================

class DataCollector:
    @staticmethod
    def clean_name(name):
        """Clean AC internal names for display"""
        if name.startswith("ks_"):
            name = name[3:]
        return name.replace("_", " ").title()
    
    @staticmethod
    def format_track_name(base, layout):
        """Format track name with layout"""
        base = DataCollector.clean_name(base)
        if layout.startswith("layout_"):
            layout = layout[7:]
        layout = DataCollector.clean_name(layout)
        layout = layout.replace("Layout", "").strip()
        if layout.lower() in ("", "default", "gp"):
            return base
        return "{} {}".format(base, layout)
    
    @staticmethod
    def get_graphics_data():
        """Get graphics data from shared memory"""
        try:
            if app_state.mmf_graphics is None:
                try:
                    app_state.mmf_graphics = mmap.mmap(-1, ctypes.sizeof(SPageFileGraphic), SHM_NAME_GRAPHICS)
                except Exception as e:
                    log("Failed to create graphics mmap: {}".format(e))
                    return {"tyre_compound": "Unknown", "currentSectorIndex": -1, "lastSectorTime": 0}
            
            if app_state.mmf_graphics is None:
                return {"tyre_compound": "Unknown", "currentSectorIndex": -1, "lastSectorTime": 0}
            
            app_state.mmf_graphics.seek(0)
            buffer = app_state.mmf_graphics.read(ctypes.sizeof(SPageFileGraphic))
            
            if buffer is None:
                return {"tyre_compound": "Unknown", "currentSectorIndex": -1, "lastSectorTime": 0}
            
            graphics_data = SPageFileGraphic.from_buffer_copy(buffer)
            return {
                "tyre_compound": getattr(graphics_data, 'tyreCompound', "Unknown"),
                "currentSectorIndex": getattr(graphics_data, 'currentSectorIndex', -1),
                "lastSectorTime": getattr(graphics_data, 'lastSectorTime', 0)
            }
            
        except Exception as e:
            log("Failed to read graphics data: {}".format(e))
            return {"tyre_compound": "Unknown", "currentSectorIndex": -1, "lastSectorTime": 0}

# =============================================================================
# SECTOR TRACKING
# =============================================================================

class SectorTracker:
    @staticmethod
    def track_sector_progress(graphics_data, current_lap):
        """Track sector completion and times"""
        current_sector = graphics_data["currentSectorIndex"]
        sector_time = graphics_data["lastSectorTime"]
        
        if current_lap not in app_state.completed_sectors:
            app_state.completed_sectors[current_lap] = {}
        
        # Handle first initialization - if we're mid-lap when plugin starts
        if app_state.last_sector_index == -1 and current_sector >= 0:
            log("Plugin initialized mid-lap {} at sector {}".format(current_lap, current_sector))
            app_state.last_sector_index = current_sector
            return
        
        # Only process if we have a valid sector time and sector change
        if (app_state.last_sector_index != -1 and 
            current_sector != app_state.last_sector_index and 
            sector_time > 0):
            
            # Determine which sector was just completed
            completed_sector = app_state.last_sector_index
            target_lap = current_lap
            
            # Handle sector progression
            if current_sector == app_state.last_sector_index + 1:
                # Normal sector progression (0->1, 1->2)
                completed_sector = app_state.last_sector_index
                target_lap = current_lap
            elif app_state.last_sector_index == 2 and current_sector == 0:
                # Lap completion (sector 2 -> sector 0, new lap)
                completed_sector = 2
                target_lap = current_lap - 1
            else:
                # Handle other transitions
                completed_sector = app_state.last_sector_index
                target_lap = current_lap if current_sector >= app_state.last_sector_index else current_lap - 1
            
            # Store the sector time
            if target_lap >= 0:  # Allow lap 0
                if target_lap not in app_state.completed_sectors:
                    app_state.completed_sectors[target_lap] = {}
                app_state.completed_sectors[target_lap][completed_sector] = sector_time
                log("Lap {} Sector {} completed: {}ms".format(target_lap, completed_sector, sector_time))
                
                # Update best times immediately when sector completes
                SectorTracker.update_sector_best_times(target_lap, completed_sector, sector_time)
        
        app_state.last_sector_index = current_sector
    
    @staticmethod
    def update_sector_best_times(lap_number, sector_index, sector_time):
        """Update session best times for a completed sector"""
        if sector_time <= 0:
            return
        
        # Only update session best (removed all-time best tracking)
        current_session_best = app_state.session_best_sector_times.get(sector_index)
        if current_session_best is None or sector_time < current_session_best:
            app_state.session_best_sector_times[sector_index] = sector_time
            log("New session best for Sector {}: {}ms (was: {})".format(
                sector_index, sector_time, current_session_best or 'None'))
            
            # Recalculate session theoretical best
            session_theoretical = SessionManager.get_session_theoretical_best()
            if session_theoretical != app_state.session_theoretical_best:
                app_state.session_theoretical_best = session_theoretical
                if session_theoretical:
                    log("Updated session theoretical best: {}ms ({:.3f}s) from session sectors".format(
                        session_theoretical, session_theoretical / 1000.0))
    
    @staticmethod
    def handle_lap_completion(completed_lap_number, graphics_data):
        """Handle final sector when lap completes"""
        if completed_lap_number not in app_state.completed_sectors:
            app_state.completed_sectors[completed_lap_number] = {}
        
        sectors = app_state.completed_sectors[completed_lap_number]
        log("Lap {} sectors at completion: {}".format(completed_lap_number, sectors))
        
        # For first lap (lap 0), try to reconstruct missing sectors from lap time
        if completed_lap_number == 0 and len(sectors) < 3:
            log("First lap incomplete - attempting to reconstruct sectors")
            
            # Get current lap time and sector time
            sector_time = graphics_data["lastSectorTime"]
            current_sector = graphics_data["currentSectorIndex"]
            
            # If we're at sector 0 of next lap and have sector time, this is sector 2 completion
            if current_sector == 0 and sector_time > 0 and 2 not in sectors:
                sectors[2] = sector_time
                log("Added reconstructed final sector 2 for lap {}: {}ms".format(completed_lap_number, sector_time))
                SectorTracker.update_sector_best_times(completed_lap_number, 2, sector_time)
            
            # If we still don't have complete sectors, mark lap as having incomplete data
            if len(sectors) < 3:
                log("First lap {} has incomplete sector data: {} - this is normal for plugin startup".format(
                    completed_lap_number, list(sectors.keys())))
        else:
            # Ensure we have sector 2 for completed lap
            if 2 not in sectors:
                sector_time = graphics_data["lastSectorTime"]
                current_sector = graphics_data["currentSectorIndex"]
                
                if current_sector == 0 and sector_time > 0:
                    sectors[2] = sector_time
                    log("Added missing final sector 2 for lap {}: {}ms".format(completed_lap_number, sector_time))
                    SectorTracker.update_sector_best_times(completed_lap_number, 2, sector_time)
        
        # Update session best times with completed lap sectors
        if len(sectors) >= 1:  # Process any sectors we have
            updated_sectors = []
            for sector_idx, sector_time in sectors.items():
                if sector_idx in [0, 1, 2] and sector_time > 0:
                    current_session_best = app_state.session_best_sector_times.get(sector_idx)
                    if current_session_best is None or sector_time < current_session_best:
                        app_state.session_best_sector_times[sector_idx] = sector_time
                        updated_sectors.append(sector_idx)
                        log("Updated session best for Sector {} from completed lap: {}ms".format(sector_idx, sector_time))
            
            # Force recalculate session theoretical best if any sectors were updated
            if updated_sectors or len(app_state.session_best_sector_times) >= 3:
                session_theoretical = SessionManager.get_session_theoretical_best()
                if session_theoretical:
                    app_state.session_theoretical_best = session_theoretical
                    log("Session theoretical best after lap {}: {}ms (updated sectors: {})".format(
                        completed_lap_number, session_theoretical, updated_sectors))
    
    @staticmethod
    def get_sector_times_for_lap(lap_number):
        """Get all sector times for a completed lap"""
        if lap_number in app_state.completed_sectors:
            sectors = app_state.completed_sectors[lap_number]
            # Return whatever sectors we have (don't require all 3 for first lap)
            if lap_number == 0:
                # For first lap, return any sectors we captured
                return {sector_idx: sector_time for sector_idx, sector_time in sectors.items()}
            elif len(sectors) >= 3 and all(i in sectors for i in [0, 1, 2]):
                # For other laps, require all 3 sectors
                return {sector_idx: sector_time for sector_idx, sector_time in sectors.items()}
            else:
                log("Incomplete sectors for lap {}: {}".format(lap_number, list(sectors.keys())))
        return {}
    
    @staticmethod
    def update_best_sector_times(lap_number, sector_times):
        """Update all-time best sector times (legacy method for batch updates)"""
        updated_sectors = []
        
        for sector_index, sector_time in sector_times.items():
            if sector_time > 0:
                current_best = app_state.best_sector_times.get(sector_index)
                if current_best is None or sector_time < current_best:
                    app_state.best_sector_times[sector_index] = sector_time
                    updated_sectors.append(sector_index)
                    log("New personal best for Sector {}: {}ms".format(sector_index, sector_time))
        
        return updated_sectors
    
    @staticmethod
    def get_theoretical_best_lap_time():
        """Calculate all-time theoretical best lap time"""
        if all(i in app_state.best_sector_times for i in [0, 1, 2]):
            total = sum(app_state.best_sector_times[i] for i in [0, 1, 2])
            return total
        return None

# =============================================================================
# LAP DATA MANAGEMENT
# =============================================================================

class LapDataManager:
    @staticmethod
    def save_lap_to_api(data):
        """Save lap data via API"""
        try:
            if not API_CONFIG.get('api_key'):
                log("No API key available for saving lap")
                return False
            
            data['driver_id'] = API_CONFIG.get('username', 'Unknown')
            response, status = APIClient.make_request('/laps', 'POST', data)
            
            if status in [201, 200]:
                lap_number = data.get('lap_number', 'Unknown')
                sectors_count = len(data.get('sector_times', {}))
                theoretical_included = "Yes" if 'theoretical_best_time_ms' in data else "No"
                log("Lap {} saved via API with {} sectors (Theoretical: {})".format(
                    lap_number, sectors_count, theoretical_included))
                return True
            else:
                error_msg = response.get('error', 'Save failed')
                log("Failed to save lap via API: {}".format(error_msg))
                return False
                
        except Exception as e:
            log("save_lap_to_api error: {}".format(e))
            return False
    
    @staticmethod
    def load_best_sector_times_from_api(track_name, car_name):
        """Load best sector times from API (only if not already loaded for this combo)"""
        if not track_name or not car_name or not API_CONFIG.get('api_key'):
            return
        
        # Check if we already loaded data for this track/car combination
        current_combo = "{}/{}".format(track_name, car_name)
        if app_state.current_track_car_combo == current_combo and app_state.best_times_loaded:
            log("Best sector times already loaded for {}, skipping API requests".format(current_combo))
            return
        
        try:
            loaded_times = {}
            for sector_index in [0, 1, 2]:
                try:
                    params = {
                        'track_name': track_name,
                        'car_name': car_name,
                        'sector_index': sector_index
                    }
                    query_string = urllib.parse.urlencode(params)
                    endpoint = '/best-sectors?{}'.format(query_string)
                    response, status = APIClient.make_request(endpoint)
                    
                    if status == 200 and 'best_time' in response:
                        best_time = response['best_time']
                        if best_time and best_time > 0:
                            loaded_times[sector_index] = best_time
                            
                except Exception as e:
                    log("Error loading sector {} best time: {}".format(sector_index, e))
            
            if loaded_times:
                # Only update all-time best times
                app_state.best_sector_times.update(loaded_times)
                # Mark this combo as loaded
                app_state.current_track_car_combo = current_combo
                
                theoretical_best = SectorTracker.get_theoretical_best_lap_time()
                log("Loaded {} all-time sector times via API for {} - All-time theoretical: {}ms".format(
                    len(loaded_times), current_combo, theoretical_best or 'N/A'))
                log("Session best times will be built from current session data only")
            else:
                log("No previous best times found for {}".format(current_combo))
                app_state.current_track_car_combo = current_combo
                
        except Exception as e:
            log("Could not load best sector times via API: {}".format(e))
# =============================================================================
# WORKER THREAD
# =============================================================================

def lap_worker():
    """Background worker for processing lap data"""
    while True:
        lap_data = app_state.lap_queue.get()
        if lap_data is None:
            break
            
        try:
            lap_number = lap_data["lap_number"]
            lap_invalid_flag_local = lap_data.get("lap_invalid")
            
            graphics_data = DataCollector.get_graphics_data()
            tyre_compound = graphics_data["tyre_compound"]
            sector_times = SectorTracker.get_sector_times_for_lap(lap_number)
            
            # Update session best times from this lap's sectors
            if sector_times:
                updated_any = False
                for sector_idx, sector_time in sector_times.items():
                    if sector_idx in [0, 1, 2] and sector_time > 0:
                        current_session_best = app_state.session_best_sector_times.get(sector_idx)
                        if current_session_best is None or sector_time < current_session_best:
                            app_state.session_best_sector_times[sector_idx] = sector_time
                            updated_any = True
                            log("Updated session best for Sector {} from lap {}: {}ms".format(sector_idx, lap_number, sector_time))
                
                if updated_any:
                    app_state.session_theoretical_best = SessionManager.get_session_theoretical_best()
            
            # Get session index without resetting session data
            current_session_index = SessionManager.get_or_create_session_index()
            
            # Calculate theoretical best time
            session_theoretical = None
            lap_time_ms = lap_data["lap_time_ms"]
            
            # For first lap (lap 0), always use lap time as theoretical best if valid
            if lap_number == 0 and not lap_invalid_flag_local and lap_time_ms > 0:
                session_theoretical = lap_time_ms
                log("First lap (lap 0): Using lap time as theoretical best: {}ms".format(session_theoretical))
            # For subsequent laps, use calculated session theoretical best
            else:
                session_theoretical = SessionManager.get_session_theoretical_best()
                if session_theoretical:
                    log("Lap {}: Using calculated session theoretical best: {}ms".format(lap_number, session_theoretical))
            
            # Debug logging for theoretical best calculation
            log("Lap {} processing: Session theoretical = {}ms, Invalid = {}, Session best sectors: {}".format(
                lap_number, session_theoretical or 'None', lap_invalid_flag_local, app_state.session_best_sector_times))
            
            # Log sector information
            if sector_times:
                if len(sector_times) == 3:
                    sector_sum = sum(sector_times.values())
                    log("Lap {} - Sector sum: {}ms, Lap time: {}ms, Session theoretical: {}ms".format(
                        lap_number, sector_sum, lap_time_ms, session_theoretical or 'N/A'))
                else:
                    log("Lap {} - Partial sectors: {}, Lap time: {}ms, Session theoretical: {}ms".format(
                        lap_number, sector_times, lap_time_ms, session_theoretical or 'N/A'))
            else:
                log("Lap {} - No sectors captured, Lap time: {}ms, Session theoretical: {}ms".format(
                    lap_number, lap_time_ms, session_theoretical or 'N/A'))
            
            full_payload = {
                "lap_number": lap_number,
                "lap_time_ms": lap_time_ms,
                "track_name": lap_data["track_name"],
                "car_name": lap_data["car_name"],
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "raw_track_name": lap_data["raw_track_name"],
                "raw_car_name": lap_data["raw_car_name"],
                "lap_invalid": int(lap_invalid_flag_local),
                "tyre_compound": tyre_compound,
                "session_global_key": current_session_index,
                "sector_times": sector_times
            }
            
            # Include theoretical best if we have one
            if session_theoretical is not None and session_theoretical > 0:
                full_payload["theoretical_best_time_ms"] = session_theoretical
                log("Including theoretical best time: {}ms for lap {}".format(session_theoretical, lap_number))
            else:
                log("No theoretical best time available for lap {}".format(lap_number))
            
            LapDataManager.save_lap_to_api(full_payload)
            
        except Exception as e:
            log("[Worker Error] {}".format(e))
        
        app_state.lap_queue.task_done()


# =============================================================================
# UI EVENT HANDLERS
# =============================================================================

def on_login_click(*args):
    """Handle login button click"""
    try:
        username = ac.getText(app_state.username_input)
        password = ac.getText(app_state.password_input)
        
        if not username or not password:
            ac.setText(app_state.login_status_label, "Please enter username and password")
            return
        
        success, user_id, message = AuthManager.authenticate_user(username, password)
        
        if success:
            app_state.current_user_id = user_id
            app_state.current_username = username
            app_state.is_logged_in = True
            
            if app_state.remember_me_state:
                AuthManager.save_login_data(username, password, True)
            else:
                AuthManager.clear_login_data()
            
            update_login_ui()
            log("User '{}' successfully logged in".format(username))
        else:
            ac.setText(app_state.login_status_label, message)
            log("Login failed: {}".format(message))
            
    except Exception as e:
        log("Error in login click handler: {}".format(e))
        ac.setText(app_state.login_status_label, "Login error occurred")

def on_register_click(*args):
    """Handle register button click"""
    try:
        username = ac.getText(app_state.username_input)
        password = ac.getText(app_state.password_input)
        
        if not username or not password:
            ac.setText(app_state.login_status_label, "Please enter username and password")
            return
        
        email = "{}@racing.local".format(username)
        success, message = AuthManager.create_user(username, email, password)
        
        if success:
            ac.setText(app_state.login_status_label, "Registration successful! Please login.")
            log("User '{}' registered successfully".format(username))
        else:
            ac.setText(app_state.login_status_label, message)
            log("Registration failed: {}".format(message))
            
    except Exception as e:
        log("Error in register click handler: {}".format(e))
        ac.setText(app_state.login_status_label, "Registration error occurred")

def on_logout_click(*args):
    """Handle logout button click"""
    try:
        log("User '{}' logging out".format(app_state.current_username or 'Unknown'))
        
        app_state.current_user_id = None
        app_state.current_username = None
        app_state.is_logged_in = False
        API_CONFIG['api_key'] = None
        API_CONFIG['username'] = None
        
        AuthManager.clear_login_data()
        
        ac.setText(app_state.username_input, "")
        ac.setText(app_state.password_input, "")
        app_state.remember_me_state = False
        ac.setValue(app_state.remember_me_checkbox, 0)
        
        update_login_ui()
        log("User successfully logged out")
        
    except Exception as e:
        log("Error in logout click handler: {}".format(e))
        ac.setText(app_state.login_status_label, "Logout error occurred")

def on_checkbox_click(*args):
    """Handle checkbox clicks"""
    try:
        app_state.remember_me_state = not app_state.remember_me_state
        ac.setValue(app_state.remember_me_checkbox, 1 if app_state.remember_me_state else 0)
        log("Checkbox state changed: {}".format(app_state.remember_me_state))
    except Exception as e:
        log("Error in checkbox click handler: {}".format(e))

# =============================================================================
# UI MANAGEMENT
# =============================================================================

def update_login_ui():
    """Update login UI based on current state"""
    try:
        if app_state.is_logged_in:
            # Hide login elements
            for element in [app_state.username_input, app_state.password_input, 
                          app_state.login_button, app_state.register_button, 
                          app_state.remember_me_checkbox]:
                ac.setVisible(element, 0)
            
            # Show logout elements
            ac.setVisible(app_state.logout_button, 1)
            ac.setText(app_state.login_status_label, "Logged in as: {}".format(app_state.current_username))
        else:
            # Show login elements
            for element in [app_state.username_input, app_state.password_input, 
                          app_state.login_button, app_state.register_button, 
                          app_state.remember_me_checkbox]:
                ac.setVisible(element, 1)
            
            # Hide logout elements
            ac.setVisible(app_state.logout_button, 0)
            ac.setText(app_state.login_status_label, "Please login or register")
            
    except Exception as e:
        log("Error updating login UI: {}".format(e))

def create_login_window():
    """Create the login GUI window"""
    try:
        # Attempt auto-login
        saved_data = AuthManager.load_login_data()
        if saved_data and saved_data.get('remember'):
            username = saved_data.get('username')
            password = saved_data.get('password')
            
            if username and password:
                log("Attempting auto-login for user: {}".format(username))
                success, user_id, message = AuthManager.authenticate_user(username, password)
                
                if success:
                    app_state.current_user_id = user_id
                    app_state.current_username = username
                    app_state.is_logged_in = True
                    log("Auto-login successful for user: {}".format(username))
                else:
                    log("Auto-login failed: {}".format(message))
                    AuthManager.clear_login_data()
        
        # Create window
        app_state.login_window = ac.newApp("SpeedSync Login")
        ac.setSize(app_state.login_window, 300, 280)
        ac.setTitle(app_state.login_window, "SpeedSync Login")
        
        # Create UI elements
        username_label = ac.addLabel(app_state.login_window, "Username:")
        ac.setPosition(username_label, 10, 30)
        ac.setSize(username_label, 80, 20)
        
        app_state.username_input = ac.addTextInput(app_state.login_window, "username_input")
        ac.setPosition(app_state.username_input, 100, 30)
        ac.setSize(app_state.username_input, 180, 25)
        
        password_label = ac.addLabel(app_state.login_window, "Password:")
        ac.setPosition(password_label, 10, 60)
        ac.setSize(password_label, 80, 20)
        
        app_state.password_input = ac.addTextInput(app_state.login_window, "password_input")
        ac.setPosition(app_state.password_input, 100, 60)
        ac.setSize(app_state.password_input, 180, 25)
        
        app_state.remember_me_checkbox = ac.addCheckBox(app_state.login_window, "Remember Me")
        ac.setPosition(app_state.remember_me_checkbox, 100, 90)
        ac.setSize(app_state.remember_me_checkbox, 100, 20)
        ac.addOnClickedListener(app_state.remember_me_checkbox, on_checkbox_click)
        
        # Set checkbox state
        if saved_data and saved_data.get('remember', False):
            app_state.remember_me_state = True
            ac.setValue(app_state.remember_me_checkbox, 1)
        else:
            app_state.remember_me_state = False
            ac.setValue(app_state.remember_me_checkbox, 0)
        
        # Create buttons
        app_state.login_button = ac.addButton(app_state.login_window, "Login")
        ac.setPosition(app_state.login_button, 50, 120)
        ac.setSize(app_state.login_button, 80, 30)
        ac.addOnClickedListener(app_state.login_button, on_login_click)
        
        app_state.register_button = ac.addButton(app_state.login_window, "Register")
        ac.setPosition(app_state.register_button, 150, 120)
        ac.setSize(app_state.register_button, 80, 30)
        ac.addOnClickedListener(app_state.register_button, on_register_click)
        
        app_state.logout_button = ac.addButton(app_state.login_window, "Logout")
        ac.setPosition(app_state.logout_button, 100, 160)
        ac.setSize(app_state.logout_button, 100, 30)
        ac.addOnClickedListener(app_state.logout_button, on_logout_click)
        
        app_state.login_status_label = ac.addLabel(app_state.login_window, "Please login or register")
        ac.setPosition(app_state.login_status_label, 10, 200)
        ac.setSize(app_state.login_status_label, 280, 40)
        
        # Pre-fill saved credentials
        if saved_data:
            ac.setText(app_state.username_input, saved_data.get('username', ''))
            ac.setText(app_state.password_input, saved_data.get('password', ''))
        
        update_login_ui()
        log("Login window created successfully")
        return app_state.login_window
        
    except Exception as e:
        log("Error creating login window: {}".format(e))
        return None

# =============================================================================
# MAIN AC FUNCTIONS
# =============================================================================

def acMain(ac_version):
    """Main initialization function"""
    try:
        # Test systems
        log("Testing initialization components...")
        
        if APIClient.test_connection():
            log("API connection test successful")
        else:
            log("API connection test failed")
        
        try:
            test_mmf = mmap.mmap(-1, ctypes.sizeof(SPageFilePhysics), SHM_NAME_PHYSICS)
            if test_mmf:
                log("Physics memory mapping test successful")
                test_mmf.close()
        except Exception as e:
            log("Physics memory mapping test failed: {}".format(e))
        
        # Start worker thread
        app_state.worker_thread = threading.Thread(target=lap_worker, daemon=True)
        app_state.worker_thread.start()
        
        # Create main app
        main_app = ac.newApp("SpeedSync")
        log("Main app window created")
        
        # Create login window
        login_win = create_login_window()
        if login_win:
            log("Login window created successfully")
        else:
            log("ERROR: Failed to create login window")
        
        log("SpeedSync Plugin Initialized with API System")
        return "SpeedSync"
        
    except Exception as e:
        log("ERROR in acMain: {}".format(e))
        return "SpeedSync"

def acUpdate(deltaT):
    """Main update loop"""
    try:
        app_state.timer += deltaT
        if app_state.timer < 0.5:
            return
        
        app_state.timer = 0
        carId = ac.getFocusedCar()
        
        try:
            lap_count = ac.getCarState(carId, acsys.CS.LapCount)
            last_lap_time = ac.getCarState(carId, acsys.CS.LastLap)
            raw_car_name = ac.getCarName(carId)
            raw_track_name = ac.getTrackName(carId)
            track_layout = ac.getTrackConfiguration(carId)
        except Exception as e:
            log("Error getting car state: {}".format(e))
            return
        
        try:
            car_name = DataCollector.clean_name(raw_car_name) if raw_car_name else "Unknown"
            track_name = DataCollector.format_track_name(raw_track_name, track_layout) if raw_track_name else "Unknown"
        except Exception as e:
            log("Error cleaning names: {}".format(e))
            car_name = "Unknown"
            track_name = "Unknown"
        
        # Skip loading best times since we're building session theoretical from current session only
        # Mark as loaded to prevent future attempts
        if not app_state.best_times_loaded:
            app_state.best_times_loaded = True
            log("Skipping historical best times loading - using session-only theoretical best calculation")
        
        # Initialize physics memory
        if app_state.mmf_physics is None:
            try:
                app_state.mmf_physics = mmap.mmap(-1, ctypes.sizeof(SPageFilePhysics), SHM_NAME_PHYSICS)
            except Exception as e:
                log("Could not initialize physics memory: {}".format(e))
                return
        
        # Read physics data
        try:
            if app_state.mmf_physics is not None:
                app_state.mmf_physics.seek(0)
                buffer = app_state.mmf_physics.read(ctypes.sizeof(SPageFilePhysics))
                if buffer is not None:
                    physics_data = SPageFilePhysics.from_buffer_copy(buffer)
                else:
                    return
            else:
                return
        except Exception as e:
            log("Could not read physics data: {}".format(e))
            return
        
        graphics_data = DataCollector.get_graphics_data()
        
        # Track sector progress (this now updates best times immediately)
        try:
            SectorTracker.track_sector_progress(graphics_data, lap_count)
        except Exception as e:
            log("Error tracking sector progress: {}".format(e))
        
        # Check for lap invalidation
        try:
            if hasattr(physics_data, 'numberOfTyresOut') and physics_data.numberOfTyresOut >= 3:
                if not app_state.lap_invalid_flag:
                    log("Lap marked invalid due to off-track (3 tyres out).")
                app_state.lap_invalid_flag = True
        except Exception as e:
            log("Error checking lap invalidation: {}".format(e))
        
        # Handle lap completion
        if lap_count > app_state.last_lap_count and app_state.last_lap_count != -1:
            try:
                if app_state.lap_invalid_flag:
                    log("Completed INVALID lap: {}".format(app_state.last_lap_count))
                else:
                    log("Completed valid lap: {}".format(app_state.last_lap_count))
                
                SectorTracker.handle_lap_completion(app_state.last_lap_count, graphics_data)
                
                # Get final sector times for the completed lap
                sector_times = SectorTracker.get_sector_times_for_lap(app_state.last_lap_count)
                
                # Debug: Show current session best times before queueing
                log("Current session best times before queueing: {}".format(app_state.session_best_sector_times))
                current_theoretical = SessionManager.get_session_theoretical_best()
                log("Current session theoretical best before queueing: {}ms".format(current_theoretical or 'None'))
                
                # Queue the lap data
                app_state.lap_queue.put({
                    "lap_number": app_state.last_lap_count,
                    "lap_time_ms": last_lap_time,
                    "track_name": track_name,
                    "car_name": car_name,
                    "raw_track_name": raw_track_name,
                    "raw_car_name": raw_car_name,
                    "car_id": carId,
                    "lap_invalid": app_state.lap_invalid_flag
                })
                
                app_state.lap_invalid_flag = False
                
            except Exception as e:
                log("Error handling lap completion: {}".format(e))
        
        app_state.last_lap_count = lap_count
        
    except Exception as e:
        log("Critical error in acUpdate: {}".format(e))