"""Experimental trial-state launcher with known and locally user-attested profiles.

Preview: python src/idm_trial_forever.py
Apply after exiting IDM: python src/idm_trial_forever.py --apply
Renew when at most two estimated days remain: python src/idm_trial_forever.py --auto
Check/renew as needed and open IDM: python src/idm_trial_forever.py --launch
"""
import argparse
import base64
import csv
import contextlib
import datetime
import hashlib
import io
import json
import os
import re
from pathlib import Path
import subprocess
import sys
import threading
import time

if sys.platform != 'win32':
    raise SystemExit('Windows only.')
import winreg

EXPECTED_SHA256 = 'a705c0154fafc7cd509decf165cb6f6c050b6521b40adb6f730dd827c86051c7'
EXE = Path(os.environ.get('ProgramFiles(x86)', r'C:\Program Files (x86)')) / 'Internet Download Manager' / 'IDMan.exe'
VIEW = winreg.KEY_WOW64_64KEY
BACKUP_DIR = Path(__file__).resolve().parent.parent / 'idm-trial-backups'
STATE_VALUES = ('MData', 'Model', 'Therad')
CONFIG_FILE = Path(__file__).resolve().parent.parent / '.idm-tool' / 'config.json'
RENEW_BEFORE_DAYS = 2

def user_profile(digest):
    if not CONFIG_FILE.exists():
        return None
    profile = json.loads(CONFIG_FILE.read_text(encoding='utf-8')).get('manual_profile')
    if (isinstance(profile, dict) and profile.get('sha256') == digest
            and profile.get('state') in ('testing', 'approved')
            and isinstance(profile.get('key'), str)
            and profile.get('schema') == 'Model-day-index-Therad-elapsed-30'):
        return profile
    return None

def verify_with_user():
    """Record user observations, never label them independent verification."""
    report = analyze_build()
    digest = report['sha256']
    print('\nManual verification — see README: Manual verification')
    print('This records YOUR observations. No IDM Registry values are changed here.')
    print('SHA-256: ' + digest)
    if popup_preference() or popup_monitor_active():
        print('Turn popup auto-close OFF with menu 5 before verifying. Then try again.')
        return
    profile = user_profile(digest)
    if profile and profile['state'] == 'approved':
        print('This exact build already has your approval. Enter REVOKE to remove it.')
        if input('Action (Enter cancels): ').strip() == 'REVOKE':
            save_settings(manual_profile=None)
            cancel_pending_renewal()
            print('Local approval removed.')
        return
    if profile and profile['state'] == 'testing':
        print('Test pending. Enter TEST to back up and apply once while IDM is fully closed.')
        print('Then open IDM directly, outside this launcher, to check its actual behavior.')
        print('Check actual IDM behavior with auto-close OFF, including exit and reopen.')
        print('An estimated counter or missing popup alone is NOT evidence of success.')
        print('Enter WORKED only if IDM itself confirms usable trial behavior after the test.')
        print('Enter FAILED to discard the profile; Enter leaves it pending.')
        result = input('Test result: ').strip()
        if result == 'TEST':
            main(['--apply'])
        elif result == 'FAILED':
            save_settings(manual_profile=None)
            print('Profile discarded. Previous Registry changes are not undone.')
        elif result == 'WORKED':
            if not profile.get('test_applied_at'):
                print('No completed test write is recorded. Run TEST first.')
                return
            evidence = input('Describe what IDM itself showed/did before and after: ').strip()
            if len(evidence) < 20:
                print('Please provide a concrete observation. Profile remains pending.')
                return
            if hashlib.sha256(EXE.read_bytes()).hexdigest() != digest:
                raise ValueError('IDM changed during verification. Start again.')
            if report['unreadable_paths'] or profile['key'] not in report['schema_candidates']:
                raise ValueError('The selected key no longer matches. Start again.')
            profile.update(state='approved', outcome=evidence,
                           approved_at=datetime.datetime.now().astimezone().isoformat())
            save_settings(manual_profile=profile)
            print('Your approval is saved for this exact hash and key. Automatic checks are now allowed.')
        return
    if report['unreadable_paths'] or not report['schema_candidates']:
        print('No usable candidates, or some paths are unreadable. Verification stopped.')
        return
    for number, path in enumerate(report['schema_candidates'], 1):
        print(f'{number}. HKCU\\{path}')
    selection = input('Candidate number (Enter cancels): ').strip()
    if not selection:
        return
    if not selection.isdigit() or not 1 <= int(selection) <= len(report['schema_candidates']):
        raise ValueError('Invalid candidate number.')
    path = report['schema_candidates'][int(selection)-1]
    print('Confirm observed IDM runtime access to THIS key, not just a matching name.')
    if input('Type OBSERVED if confirmed (Enter cancels): ').strip() != 'OBSERVED':
        return
    print('Only the existing 30-day schema is supported: Model=zero-based day of year,')
    print('Therad=elapsed days, MData=optional trial data; the existing increment rule must match.')
    print('If these meanings are unknown, cancel. Access alone does not establish them.')
    if input('Type SAME SCHEMA if independently checked (Enter cancels): ').strip() != 'SAME SCHEMA':
        return
    evidence = input('Describe your runtime/schema evidence (kept locally): ').strip()
    if len(evidence) < 20:
        print('Insufficient description. No profile saved.')
        return
    if hashlib.sha256(EXE.read_bytes()).hexdigest() != digest:
        raise ValueError('IDM changed during verification. Start again.')
    candidates, denied = inspect_trial_paths(EXE.read_bytes())
    if denied or path not in candidates:
        raise ValueError('Candidate changed during verification. Start again.')
    save_settings(manual_profile={'sha256':digest, 'key':path, 'state':'testing',
                                 'schema':'Model-day-index-Therad-elapsed-30', 'evidence':evidence})
    print('Test profile saved. Automatic renewal remains blocked until you report success.')
    print('Exit IDM completely, return to Advanced > Manual verification and enter TEST.')
    print('Then open IDM directly and test.')

def trial_paths_from_binary(data):
    """Extract literal references; a reference alone is never write authority."""
    pattern = rb'Software\\Classes\\CLSID\\\{[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}\}\x00'
    references = {match.group()[:-1].decode('ascii') for match in re.finditer(pattern, data)}
    wide = re.compile(r'Software\\Classes\\CLSID\\\{[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}\}\x00')
    for alignment in (0, 1):
        end = len(data) - (len(data) - alignment) % 2
        decoded = data[alignment:end].decode('utf-16le', errors='replace')
        references.update(match.group()[:-1] for match in wide.finditer(decoded))
    return sorted({path for reference in references for path in (
        reference, reference.replace('Software\\Classes\\CLSID\\', 'Software\\Classes\\Wow6432Node\\CLSID\\', 1)
    )}, key=str.casefold)

def inspect_trial_paths(data):
    """Bounded read-only candidate inspection; does not establish reset semantics."""
    candidates = []
    denied = []
    for path in trial_paths_from_binary(data):
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, path, 0, winreg.KEY_READ | VIEW) as key:
                subkeys, count, _ = winreg.QueryInfoKey(key)
                names = {winreg.EnumValue(key, i)[0] for i in range(count)}
                if subkeys or not {'Model', 'Therad'} <= names or not names <= set(STATE_VALUES):
                    continue
                model, model_type = winreg.QueryValueEx(key, 'Model')
                elapsed, elapsed_type = winreg.QueryValueEx(key, 'Therad')
                if model_type != winreg.REG_DWORD or elapsed_type != winreg.REG_DWORD:
                    continue
                if not 0 <= model <= 365 or not 0 <= elapsed <= 3650:
                    continue
                if 'MData' in names:
                    _, kind = winreg.QueryValueEx(key, 'MData')
                    if kind not in (winreg.REG_NONE, winreg.REG_BINARY):
                        continue
                candidates.append(path)
        except FileNotFoundError:
            continue
        except PermissionError:
            denied.append(path)
    return candidates, denied

def analyze_build():
    """Survey any local PE build without acquiring write permissions or executing it."""
    data = EXE.read_bytes()
    if len(data) < 64 or data[:2] != b'MZ':
        raise ValueError('Expected a Windows executable. No target was run or modified.')
    pe_offset = int.from_bytes(data[0x3c:0x40], 'little')
    if pe_offset < 64 or pe_offset + 24 > len(data) or data[pe_offset:pe_offset+4] != b'PE\0\0':
        raise ValueError('Invalid PE header. No target was run or modified.')
    digest = hashlib.sha256(data).hexdigest()
    candidates, denied = inspect_trial_paths(data)
    return {
        'mode':'read-only survey',
        'sha256':digest,
        'architecture':hex(int.from_bytes(data[pe_offset+4:pe_offset+6],'little')),
        'literal_paths_found':len(trial_paths_from_binary(data)),
        'schema_candidates':candidates,
        'unreadable_paths':denied,
        'known_reset_profile':digest==EXPECTED_SHA256,
        'trial_extension_verified':False,
        'runtime_key_use_verified':False,
        'manual_profile_state':(user_profile(digest) or {}).get('state'),
        'automatic_reset_allowed':not denied and (
            (digest==EXPECTED_SHA256 and len(candidates)==1) or
            ((user_profile(digest) or {}).get('state')=='approved' and
             (user_profile(digest) or {}).get('key') in candidates)),
        'limitations':[
            'Strings and matching field names do not prove a key controls trial state.',
            'Computed/encrypted key paths may be absent from static extraction.',
            'Unknown builds need observed runtime accesses and verified reset semantics before writing.',
        ],
    }

def discover_trial_key():
    """Resolve a key only for a build with independently checked reset semantics."""
    data = EXE.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    profile = user_profile(digest)
    if digest != EXPECTED_SHA256 and not profile:
        raise ValueError('Reset semantics are unverified for this build. Run --analyze for a read-only survey.')
    candidates, denied = inspect_trial_paths(data)
    if denied:
        raise PermissionError('Discovery could not read all referenced keys. No permissions were changed.')
    if profile:
        if profile['key'] not in candidates:
            raise ValueError('Your approved key no longer matches the expected schema. Verify again.')
        return profile['key']
    if len(candidates) != 1:
        reason = 'No verified trial key found' if not candidates else 'Multiple trial keys match'
        raise ValueError(reason + '. No changes made; run --diagnostics for review.')
    return candidates[0]

EXPIRY_NOTICE = 'IDM has not been registered for 30 days. Trial period is over.'

class PopupCloser:
    """Session-only WinEvent listener. No polling, injection, or Registry writes."""
    def __init__(self):
        self.thread = None
        self.ready = threading.Event()
        self.thread_id = 0
        self.error = None
        self.closed = 0
        self.target_pid = None

    @property
    def active(self):
        return bool(self.thread and self.thread.is_alive() and self.ready.is_set() and not self.error)

    def start(self):
        if self.active:
            return
        self.ready.clear()
        self.error = None
        self.thread = threading.Thread(target=self._listen, name='IDM-popup-events', daemon=True)
        self.thread.start()
        if not self.ready.wait(5):
            self.stop()
            raise OSError('Popup listener could not start.')
        if self.error:
            raise OSError(self.error)

    def stop(self):
        if self.thread_id:
            import ctypes
            ctypes.windll.user32.PostThreadMessageW(self.thread_id, 0x12, 0, 0)
        if self.thread:
            self.thread.join(3)
        if self.thread and self.thread.is_alive():
            raise OSError('Popup listener has not stopped yet.')

    def _listen(self):
        import ctypes as c
        from ctypes import wintypes as w
        u = c.WinDLL('user32', use_last_error=True)
        k = c.WinDLL('kernel32', use_last_error=True)
        callback_type = c.WINFUNCTYPE(None, w.HANDLE, w.DWORD, w.HWND, w.LONG, w.LONG, w.DWORD, w.DWORD)
        enum_type = c.WINFUNCTYPE(w.BOOL, w.HWND, w.LPARAM)
        declarations = {
            'SetWinEventHook': ([w.DWORD,w.DWORD,w.HMODULE,callback_type,w.DWORD,w.DWORD,w.DWORD],w.HANDLE),
            'UnhookWinEvent': ([w.HANDLE],w.BOOL),
            'GetClassNameW': ([w.HWND,w.LPWSTR,c.c_int],c.c_int),
            'GetWindowTextW': ([w.HWND,w.LPWSTR,c.c_int],c.c_int),
            'GetWindowThreadProcessId': ([w.HWND,c.POINTER(w.DWORD)],w.DWORD),
            'IsWindowVisible': ([w.HWND],w.BOOL),
            'GetDlgItem': ([w.HWND,c.c_int],w.HWND),
            'EnumWindows': ([enum_type,w.LPARAM],w.BOOL),
            'EnumChildWindows': ([w.HWND,enum_type,w.LPARAM],w.BOOL),
            'SetTimer': ([w.HWND,c.c_size_t,w.UINT,c.c_void_p],c.c_size_t),
            'KillTimer': ([w.HWND,c.c_size_t],w.BOOL),
            'GetMessageW': ([c.POINTER(w.MSG),w.HWND,w.UINT,w.UINT],w.BOOL),
            'PeekMessageW': ([c.POINTER(w.MSG),w.HWND,w.UINT,w.UINT,w.UINT],w.BOOL),
            'SendMessageTimeoutW': ([w.HWND,w.UINT,w.WPARAM,w.LPARAM,w.UINT,w.UINT,c.POINTER(c.c_size_t)],c.c_ssize_t),
        }
        for name,(args,result) in declarations.items():
            function=getattr(u,name);function.argtypes=args;function.restype=result
        k.OpenProcess.argtypes=[w.DWORD,w.BOOL,w.DWORD];k.OpenProcess.restype=w.HANDLE
        k.QueryFullProcessImageNameW.argtypes=[w.HANDLE,w.DWORD,w.LPWSTR,c.POINTER(w.DWORD)]
        k.CloseHandle.argtypes=[w.HANDLE]
        def text(hwnd, class_name=False):
            buffer=c.create_unicode_buffer(512)
            (u.GetClassNameW if class_name else u.GetWindowTextW)(hwnd,buffer,len(buffer))
            return buffer.value
        def identity(hwnd):
            if not u.IsWindowVisible(hwnd) or text(hwnd,True)!='#32770' or text(hwnd)!='Internet Download Manager':
                return None
            pid=w.DWORD();u.GetWindowThreadProcessId(hwnd,c.byref(pid))
            if self.target_pid is not None and pid.value != self.target_pid:return None
            handle=k.OpenProcess(0x1000,False,pid.value)
            if not handle:return None
            try:
                path=c.create_unicode_buffer(32768);size=w.DWORD(len(path))
                if not k.QueryFullProcessImageNameW(handle,0,path,c.byref(size)):return None
                if os.path.normcase(path.value)!=os.path.normcase(str(EXE.resolve())):return None
                return pid.value
            finally:k.CloseHandle(handle)
        pending={}
        def schedule(hwnd):
            pid=identity(hwnd)
            if pid is None or any(item==(hwnd,pid) for item in pending.values()):return
            timer=u.SetTimer(None,0,1000,None)
            if timer:pending[timer]=(hwnd,pid)
        @callback_type
        def event(hook,event_id,hwnd,object_id,child_id,event_thread,event_time):
            if object_id==0 and child_id==0 and hwnd:
                try:schedule(hwnd)
                except (OSError,ValueError):pass
        @enum_type
        def existing(hwnd,param):
            schedule(hwnd)
            return True
        hook=None
        try:
            self.thread_id=k.GetCurrentThreadId()
            message=w.MSG();u.PeekMessageW(c.byref(message),None,0,0,0)
            hook=u.SetWinEventHook(0x8002,0x8002,None,event,0,0,2)
            if not hook:raise c.WinError(c.get_last_error())
            u.EnumWindows(existing,0)
            self.ready.set()
            while True:
                result=u.GetMessageW(c.byref(message),None,0,0)
                if result==0:break
                if result==-1:raise c.WinError(c.get_last_error())
                if message.message!=0x113:continue
                item=pending.pop(message.wParam,None)
                u.KillTimer(None,message.wParam)
                if not item:continue
                hwnd,pid=item
                if identity(hwnd)!=pid:continue
                labels=[]
                @enum_type
                def child(control,param):
                    if text(control,True).lower()=='static':labels.append(text(control))
                    return True
                u.EnumChildWindows(hwnd,child,0)
                if EXPIRY_NOTICE not in labels:continue
                button=u.GetDlgItem(hwnd,2) or u.GetDlgItem(hwnd,1)
                if not button or text(button,True).lower()!='button' or text(button).replace('&','').strip().upper()!='OK':continue
                response=c.c_size_t()
                if u.SendMessageTimeoutW(button,0xF5,0,0,2,1000,c.byref(response)):
                    self.closed+=1
        except Exception as error:
            self.error=str(error)
        finally:
            if hook:u.UnhookWinEvent(hook)
            for timer in pending:u.KillTimer(None,timer)
            self.thread_id=0
            self.ready.set()

POPUP_CLOSER = PopupCloser()

def monitor_api():
    import ctypes as c
    from ctypes import wintypes as w
    k=c.WinDLL('kernel32',use_last_error=True)
    k.OpenEventW.argtypes=[w.DWORD,w.BOOL,w.LPCWSTR];k.OpenEventW.restype=w.HANDLE
    k.CreateEventW.argtypes=[c.c_void_p,w.BOOL,w.BOOL,w.LPCWSTR];k.CreateEventW.restype=w.HANDLE
    k.OpenProcess.argtypes=[w.DWORD,w.BOOL,w.DWORD];k.OpenProcess.restype=w.HANDLE
    k.QueryFullProcessImageNameW.argtypes=[w.HANDLE,w.DWORD,w.LPWSTR,c.POINTER(w.DWORD)]
    k.CloseHandle.argtypes=[w.HANDLE]
    k.SetEvent.argtypes=[w.HANDLE]
    k.WaitForSingleObject.argtypes=[w.HANDLE,w.DWORD];k.WaitForSingleObject.restype=w.DWORD
    k.WaitForMultipleObjects.argtypes=[w.DWORD,c.POINTER(w.HANDLE),w.BOOL,w.DWORD];k.WaitForMultipleObjects.restype=w.DWORD
    return c,w,k

def monitor_name():
    scope=hashlib.sha256(str(CONFIG_FILE.resolve()).encode()).hexdigest()[:20]
    return 'Local\\IDMTrialPopupStop-'+scope

def popup_monitor_active():
    c,w,k=monitor_api();handle=k.OpenEventW(0x100000,False,monitor_name())
    if not handle:return False
    try:return k.WaitForSingleObject(handle,0)==0x102
    finally:k.CloseHandle(handle)

def stop_popup_monitor():
    c,w,k=monitor_api();handle=k.OpenEventW(2,False,monitor_name())
    if handle:
        try:k.SetEvent(handle)
        finally:k.CloseHandle(handle)

def verified_process(pid):
    c,w,k=monitor_api();handle=k.OpenProcess(0x100000|0x1000,False,pid)
    if not handle:return None
    path=c.create_unicode_buffer(32768);size=w.DWORD(len(path))
    if not k.QueryFullProcessImageNameW(handle,0,path,c.byref(size)) or os.path.normcase(path.value)!=os.path.normcase(str(EXE.resolve())):
        k.CloseHandle(handle);return None
    return handle

def find_idm_pid():
    result=subprocess.run(['tasklist.exe','/FI','IMAGENAME eq IDMan.exe','/FO','CSV','/NH'],capture_output=True,text=True,check=True,creationflags=0x08000000)
    for row in csv.reader(io.StringIO(result.stdout)):
        if len(row)>1 and row[0].lower()=='idman.exe':
            handle=verified_process(int(row[1]))
            if handle:
                monitor_api()[2].CloseHandle(handle)
                return int(row[1])
    return None

def follow_idm(pid):
    c,w,k=monitor_api();process=verified_process(pid)
    if not process:raise OSError('The selected IDM process is unavailable.')
    event=None
    try:
        event=k.CreateEventW(None,True,False,monitor_name())
        if not event:raise c.WinError(c.get_last_error())
        if c.get_last_error()==183:return
        POPUP_CLOSER.target_pid=pid
        POPUP_CLOSER.start()
        handles=(w.HANDLE*2)(process,event)
        # Kernel wait: no process polling and no wake-ups while idle.
        result=k.WaitForMultipleObjects(2,handles,False,0xffffffff)
        if result==0xffffffff:raise c.WinError(c.get_last_error())
    finally:
        POPUP_CLOSER.stop()
        if event:k.CloseHandle(event)
        k.CloseHandle(process)

def start_popup_monitor(pid=None):
    if popup_monitor_active():return
    pid=pid or find_idm_pid()
    if not pid:raise OSError('Open IDM first, then enable auto-close.')
    subprocess.Popen([sys.executable,str(Path(__file__).resolve()),'--follow-idm',str(pid),'--idm-path',str(EXE.resolve())],creationflags=0x08000000,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    deadline=time.monotonic()+4
    while time.monotonic()<deadline:
        if popup_monitor_active():return
        time.sleep(.05)
    raise OSError('Popup listener could not start.')

def popup_preference():
    return CONFIG_FILE.exists() and json.loads(CONFIG_FILE.read_text(encoding='utf-8')).get('auto_close') is True

def save_settings(**updates):
    config=json.loads(CONFIG_FILE.read_text(encoding='utf-8')) if CONFIG_FILE.exists() else {'enabled':True}
    config.update(updates)
    CONFIG_FILE.parent.mkdir(exist_ok=True)
    temporary=CONFIG_FILE.with_suffix('.tmp')
    temporary.write_text(json.dumps(config,indent=2),encoding='utf-8')
    os.replace(temporary,CONFIG_FILE)

def cancel_pending_renewal():
    c,w,k=monitor_api();event=k.OpenEventW(2,False,monitor_name()+'-renew')
    if event:
        try:k.SetEvent(event)
        finally:k.CloseHandle(event)

def renew_on_exit(pid):
    """Defer writes until the exact target process exits, without polling it."""
    c,w,k=monitor_api();process=verified_process(pid)
    if not process:
        if tool_enabled():main(['--auto'])
        return
    event=None
    try:
        c.set_last_error(0)
        event=k.CreateEventW(None,True,False,monitor_name()+'-renew')
        if not event:raise c.WinError(c.get_last_error())
        if c.get_last_error()==183:return
        result=k.WaitForMultipleObjects(2,(w.HANDLE*2)(process,event),False,0xffffffff)
        if result==0 and tool_enabled():
            try:
                main(['--auto'])
                save_settings(renewal_error=None)
            except (OSError,ValueError,SystemExit) as error:
                save_settings(renewal_error=str(error))
        elif result==0xffffffff:raise c.WinError(c.get_last_error())
    finally:
        if event:k.CloseHandle(event)
        k.CloseHandle(process)

def queue_renewal(pid):
    c,w,k=monitor_api();event=k.OpenEventW(0x100000,False,monitor_name()+'-renew')
    if event:
        try:
            if k.WaitForSingleObject(event,0)==0x102:return
        finally:k.CloseHandle(event)
    subprocess.Popen([sys.executable,str(Path(__file__).resolve()),'--renew-on-exit',str(pid),'--idm-path',str(EXE.resolve())],creationflags=0x08000000,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)

def tool_enabled():
    if not CONFIG_FILE.exists():
        return True
    config = json.loads(CONFIG_FILE.read_text(encoding='utf-8'))
    if not isinstance(config, dict) or type(config.get('enabled')) is not bool:
        raise ValueError('Invalid tool settings; refusing automatic changes.')
    return config['enabled']

def set_tool_enabled(enabled):
    save_settings(enabled=enabled)
    if not enabled:
        stop_popup_monitor()
        cancel_pending_renewal()

def show_diagnostics():
    print('Tool: ' + ('ENABLED' if tool_enabled() else 'DISABLED'))
    print(f'IDM: {EXE}')
    print(f'Backups: {BACKUP_DIR}')
    print('Schedule/background worker: NONE')
    if CONFIG_FILE.exists():
        error=json.loads(CONFIG_FILE.read_text(encoding='utf-8')).get('renewal_error')
        if error:print('Deferred renewal needs attention: '+error)
    if not EXE.is_file():
        print('Compatibility: executable not found')
        return
    digest = hashlib.sha256(EXE.read_bytes()).hexdigest()
    profile = user_profile(digest)
    compatible = digest == EXPECTED_SHA256 or profile is not None
    print('Compatibility: ' + ('USER-ATTESTED ' + profile['state'] if profile else ('known hash' if compatible else 'NEEDS VERIFICATION')))
    if not compatible:
        return
    key_path = discover_trial_key()
    print(f'Discovered trial key: HKCU\\{key_path}')
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_READ | VIEW) as key:
        marker, marker_type = winreg.QueryValueEx(key, 'Model')
        elapsed, elapsed_type = winreg.QueryValueEx(key, 'Therad')
    if marker_type != winreg.REG_DWORD or elapsed_type != winreg.REG_DWORD or not 0 <= marker <= 365 or elapsed < 0:
        raise ValueError('Unexpected trial data; estimated status unavailable.')
    today = datetime.datetime.now().astimezone().timetuple().tm_yday - 1
    remaining = max(0, 30 - projected_elapsed(elapsed, marker, today))
    print(f'Managed Registry: Model={marker}, Therad={elapsed}')
    print(f'Estimated remaining: {remaining} days (NOT official IDM status)')
    print(f'Launch renewal threshold: {RENEW_BEFORE_DAYS} days remaining')
    print('Known issue: an expiry popup was observed with Therad=0; cause unresolved.')

def status_summary():
    enabled = tool_enabled()
    if not enabled:
        return {'enabled': False, 'trial': 'Checking paused', 'can_renew': False, 'profile': 'Tool disabled'}
    if not EXE.is_file():
        return {'enabled': True, 'trial': 'IDM not found', 'can_renew': False, 'profile': 'Installation missing'}
    digest = hashlib.sha256(EXE.read_bytes()).hexdigest()
    profile = user_profile(digest)
    if digest != EXPECTED_SHA256 and not profile:
        return {'enabled': True, 'trial': 'Unavailable', 'can_renew': False, 'profile': 'Version not supported'}
    if profile and profile['state'] == 'testing':
        return {'enabled': True, 'trial': 'Manual test pending', 'can_renew': False, 'profile': 'Advanced review required'}
    try:
        key_path = discover_trial_key()
    except (OSError, ValueError):
        return {'enabled': True, 'trial': 'Unavailable', 'can_renew': False, 'profile': 'Data needs review'}
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_READ | VIEW) as key:
        marker, marker_type = winreg.QueryValueEx(key, 'Model')
        elapsed, elapsed_type = winreg.QueryValueEx(key, 'Therad')
    if marker_type != winreg.REG_DWORD or elapsed_type != winreg.REG_DWORD or not 0 <= marker <= 365 or elapsed < 0:
        raise ValueError('Unexpected trial data.')
    today = datetime.datetime.now().astimezone().timetuple().tm_yday - 1
    remaining = max(0, 30 - projected_elapsed(elapsed, marker, today))
    return {'enabled': True, 'trial': f'~{remaining} days (estimated)', 'can_renew': True,
            'profile': 'User-confirmed · experimental' if profile else 'Built-in · experimental'}

def show_status():
    status = status_summary()
    print('Tool: ' + ('Enabled' if status['enabled'] else 'Disabled'))
    print('Trial: ' + status['trial'])

def console_colors():
    if not sys.stdout.isatty():
        return False
    try:
        import ctypes
        from ctypes import wintypes
        kernel = ctypes.WinDLL('kernel32', use_last_error=True)
        kernel.GetStdHandle.argtypes = [wintypes.DWORD]
        kernel.GetStdHandle.restype = wintypes.HANDLE
        kernel.GetConsoleMode.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
        kernel.SetConsoleMode.argtypes = [wintypes.HANDLE, wintypes.DWORD]
        handle = kernel.GetStdHandle(-11 & 0xFFFFFFFF)
        mode = wintypes.DWORD()
        return bool(kernel.GetConsoleMode(handle, ctypes.byref(mode)) and kernel.SetConsoleMode(handle, mode.value | 4))
    except (OSError, AttributeError):
        return False

def render_menu(status, feedback='', colors=False):
    width = 52
    def tint(text, code):
        return f'\033[{code}m{text}\033[0m' if colors else text
    def row(text='', code=None):
        padded = '  ' + text.ljust(width - 4) + '  '
        return '│' + (tint(padded, code) if code else padded) + '│'
    enabled = status['enabled']
    toggle = 'Disable tool' if enabled else 'Enable tool'
    tool_state = 'CHECK SETTINGS' if enabled is None else ('ENABLED' if enabled else 'DISABLED')
    rows = [
        '╭' + '─' * width + '╮', row(),
        row('IDM TRIAL FOREVER', '1;36'),
        row('Trial assistant', '90'),
        row('Created by Qu4nh', '90'), row(),
        '├' + '─' * width + '┤', row(),
        row('Tool        ' + tool_state, '33' if enabled is None else ('32' if enabled else '90')),
        row('Profile     ' + status.get('profile', 'Needs review')),
        row('Trial       ' + status['trial']),
        row('Auto-close  ' + ('ON · follows IDM' if popup_monitor_active() else ('READY · starts with IDM' if popup_preference() and enabled else 'OFF'))), row(),
        row('1   ' + ('Open IDM' if status.get('can_renew') else 'Open IDM (no trial changes)'), '1;36'), row('2   ' + toggle),
        row('3   Refresh status'), row('4   ' + ('Check / renew trial' if status.get('can_renew') else 'Trial changes unavailable')),
        row('5   ' + ('Disable popup auto-close' if popup_preference() else 'Enable popup auto-close')),
        row('6   Advanced'), row(),
        row('0   Exit', '90'), row(), '╰' + '─' * width + '╯',
        '  Trial extension is not independently verified.',
        '  Trial days are an estimate.',
        '  Auto-close stops when IDM exits.',
        '  It dismisses notices; it does not fix expiry.',
    ]
    if feedback:
        rows.extend(['', '  ' + tint(feedback, '33')])
    return '\n'.join(rows)

def user_error(error):
    message = str(error)
    if isinstance(error, PermissionError):
        return 'Access denied. The action could not be completed.'
    if 'Tool disabled' in message:
        return 'Enable the tool before renewing.'
    if 'running' in message:
        return 'Exit IDM completely, then try again.'
    if 'differs' in message:
        return 'This IDM version is not supported.'
    if 'not found' in message:
        return 'IDM not found. Check its installation path.'
    return 'Action failed. Run --diagnostics for details.'

def advanced_menu():
    while True:
        print('\n  ADVANCED — technical knowledge required')
        print('  1   Show diagnostics (read-only)')
        print('  2   Survey this build (read-only)')
        print('  3   Manual verification / test / revoke')
        print('  0   Back')
        choice = input('\n  Choose [0-3]: ').strip()
        if choice == '0':
            return
        try:
            if choice == '1':
                show_diagnostics()
            elif choice == '2':
                print(json.dumps(analyze_build(), indent=2))
            elif choice == '3':
                verify_with_user()
            else:
                print('Please choose 0 to 3.')
        except (OSError, ValueError, SystemExit) as error:
            print('Unable to complete: ' + str(error))
        input('\nPress Enter to continue...')

def ordinary_action(choice, status):
    """Keep unsupported or uncertain builds out of the write path."""
    if not status.get('can_renew'):
        if choice == '4':
            return 'Unavailable. No trial data was changed. See Advanced.'
        if not EXE.is_file():
            return 'IDM not found. Check its installation path.'
        launch_idm()
        return 'IDM opened without trial changes.'
    output = io.StringIO()
    with contextlib.redirect_stdout(output):
        main(['--launch' if choice == '1' else '--auto'])
    result = output.getvalue()
    if choice == '1':
        return 'IDM launch requested.'
    if 'Queued:' in result:
        return 'Renewal queued. It will run when IDM exits.'
    if 'Deferred:' in result:
        return 'Exit IDM completely, then try again.'
    if 'Not due:' in result:
        return 'No renewal needed yet.'
    return 'Local values updated; trial extension is unverified.'

def menu():
    colors = console_colors()
    feedback = ''
    while True:
        try:
            status = status_summary()
        except (OSError, ValueError):
            status = {'enabled': None, 'trial': 'Status unavailable', 'can_renew': False, 'profile': 'Needs review'}
        if colors:
            print('\033[2J\033[H', end='')
        print(render_menu(status, feedback, colors))
        try:
            choice = input('\n  Choose [0-6]: ').strip()
        except (EOFError, KeyboardInterrupt):
            print('\n  Menu closed.')
            return
        try:
            if choice == '0':
                return
            if choice in ('1', '4'):
                feedback = ordinary_action(choice, status)
            elif choice == '2':
                if status['enabled']:
                    stop_popup_monitor()
                set_tool_enabled(not status['enabled'])
                feedback = 'Tool disabled.' if status['enabled'] else 'Tool enabled.'
            elif choice == '3':
                feedback = 'Status refreshed.'
            elif choice == '5':
                if popup_preference():
                    save_settings(auto_close=False)
                    stop_popup_monitor()
                    feedback = 'Popup auto-close disabled.'
                else:
                    if not tool_enabled():
                        raise SystemExit('Tool disabled')
                    save_settings(auto_close=True)
                    if find_idm_pid():start_popup_monitor()
                    feedback = 'Enabled. Auto-close follows IDM; menu may close.'
            elif choice == '6':
                advanced_menu()
                feedback = 'Returned from Advanced.'
            else:
                feedback = 'Please choose 0 to 6.'
        except (EOFError, KeyboardInterrupt):
            feedback = 'Verification cancelled.'
        except (OSError, ValueError, SystemExit) as error:
            feedback = user_error(error)

def projected_elapsed(elapsed, previous_day, current_day):
    # Observed IDM routine adds the changed day marker, capped at 20.
    increment = 0 if previous_day == current_day else min(20, max(1, current_day - previous_day))
    return elapsed + increment

def snapshot(key):
    values = []
    for i in range(winreg.QueryInfoKey(key)[1]):
        name, value, kind = winreg.EnumValue(key, i)
        if name not in STATE_VALUES:
            continue
        if isinstance(value, bytes):
            value = {'base64': base64.b64encode(value).decode('ascii')}
        values.append({'name': name, 'type': kind, 'value': value})
    return sorted(values, key=lambda value: value['name'])

def restore_values(key, values):
    """Restore only the three managed value names, leaving other settings intact."""
    by_name = {item['name']: item for item in values}
    for name in STATE_VALUES:
        if name not in by_name:
            try:
                winreg.DeleteValue(key, name)
            except FileNotFoundError:
                pass
            continue
        item = by_name[name]
        value = item['value']
        if isinstance(value, dict):
            value = base64.b64decode(value['base64'], validate=True)
        winreg.SetValueEx(key, name, 0, item['type'], value)
    winreg.FlushKey(key)

def launch_idm():
    subprocess.Popen([str(EXE)], cwd=str(EXE.parent))
    if tool_enabled() and popup_preference():
        deadline=time.monotonic()+3
        while time.monotonic()<deadline:
            pid=find_idm_pid()
            if pid:
                start_popup_monitor(pid)
                break
            time.sleep(.1)

def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument('--apply', action='store_true', help='Back up and change the exact verified trial key.')
    mode.add_argument('--auto', action='store_true', help='Renew at two or fewer estimated days left; defer while IDM is running.')
    mode.add_argument('--launch', action='store_true', help='Check trial, renew at the two-day buffer if IDM is closed, then launch IDM.')
    mode.add_argument('--menu', action='store_true', help='Interactive status and enable/disable menu.')
    mode.add_argument('--status', action='store_true', help='Read tool and estimated trial status.')
    mode.add_argument('--diagnostics', action='store_true', help='Show technical paths, compatibility and managed Registry values.')
    mode.add_argument('--enable', action='store_true', help='Enable future trial changes in this copy of the tool.')
    mode.add_argument('--disable', action='store_true', help='Disable future trial changes; leave current trial state unchanged.')
    mode.add_argument('--follow-idm', type=int, help=argparse.SUPPRESS)
    mode.add_argument('--discover', action='store_true', help='Identify the supported trial key without changing it.')
    mode.add_argument('--analyze', action='store_true', help='Survey literal trial-key candidates in any PE build, read-only.')
    mode.add_argument('--verify', action='store_true', help='Guided local user verification for an exact build and key.')
    mode.add_argument('--renew-on-exit', type=int, help=argparse.SUPPRESS)
    parser.add_argument('--idm-path', type=Path, help='Explicit path to IDMan.exe for survey or a matching reset profile.')
    args = parser.parse_args(argv)
    global EXE
    if args.idm_path is not None:
        EXE = args.idm_path.expanduser().resolve()
    if args.follow_idm is not None:
        follow_idm(args.follow_idm)
        return
    if args.renew_on_exit is not None:
        renew_on_exit(args.renew_on_exit)
        return
    if args.enable or args.disable:
        set_tool_enabled(args.enable)
        print('Tool: ' + ('ENABLED' if args.enable else 'DISABLED'))
        return
    if args.menu:
        menu()
        return
    if args.status:
        show_status()
        return
    if args.diagnostics:
        show_diagnostics()
        return
    if args.discover:
        print('Verified trial key: HKCU\\' + discover_trial_key())
        return
    if args.analyze:
        print(json.dumps(analyze_build(),indent=2))
        return
    if args.verify:
        verify_with_user()
        return
    if not tool_enabled():
        if args.launch:
            if not EXE.is_file():
                raise SystemExit('IDMan.exe not found. Use --idm-path.')
            print('Tool disabled: opening IDM without Registry checks or writes.')
            launch_idm()
            return
        if args.apply or args.auto:
            raise SystemExit('Tool disabled. Enable it before requesting trial changes.')
        print('Tool disabled. Preview only; no Registry writes.')
    if not EXE.is_file():
        raise SystemExit('IDMan.exe not found. Use --idm-path with its installed path.')
    digest = hashlib.sha256(EXE.read_bytes()).hexdigest()
    profile = user_profile(digest)
    if digest != EXPECTED_SHA256 and not profile:
        raise SystemExit('IDM binary differs from the verified build. No changes made.')
    if profile and profile['state'] == 'testing' and (args.auto or args.launch):
        raise SystemExit('Manual test pending. Use --apply once, then --verify; automatic renewal is blocked.')
    key_path = discover_trial_key()
    today = datetime.datetime.now().astimezone()
    marker = today.timetuple().tm_yday - 1
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_READ | VIEW) as key:
        before = snapshot(key)
        for name in ('Model', 'Therad'):
            value, kind = winreg.QueryValueEx(key, name)
            if kind != winreg.REG_DWORD or not isinstance(value, int):
                raise SystemExit('Unexpected registry value types. No changes made.')
        previous_day = winreg.QueryValueEx(key, 'Model')[0]
        elapsed = winreg.QueryValueEx(key, 'Therad')[0]
    if elapsed < 0:
        raise SystemExit('Unexpected elapsed-day counter. No changes made.')
    if not 0 <= previous_day <= 365:
        raise SystemExit('Unexpected day marker. No changes made.')
    projected = projected_elapsed(elapsed, previous_day, marker)
    if (args.auto or args.launch) and projected < 30 - RENEW_BEFORE_DAYS:
        print(f'Not due: projected remaining days={30-projected}; no changes made.')
        if args.launch:
            launch_idm()
        return
    print(f'IDM SHA-256 matched ({"user-attested profile" if profile else "known profile"}). Target: HKCU\\{key_path}')
    print(f'Proposed: Model={marker}, Therad=0; remove MData if present.')
    if not (args.apply or args.auto or args.launch):
        print('Preview only. Exit IDM completely, then add --apply to perform the change.')
        return
    result = subprocess.run(['tasklist.exe', '/FO', 'CSV', '/NH'], capture_output=True, text=True, check=True, creationflags=0x08000000)
    if any(row and row[0].lower() == 'idman.exe' for row in csv.reader(io.StringIO(result.stdout))):
        if args.auto or args.launch:
            pid=find_idm_pid()
            if pid:
                queue_renewal(pid)
                print('Queued: renewal will run after IDM exits. No downloads interrupted.')
            else:
                print('Deferred: process changed during checking. Open the launcher again.')
            if args.launch:
                launch_idm()
            return
        raise SystemExit('IDM is running. Exit IDM completely before applying. No changes made.')
    backup_dir = BACKUP_DIR
    backup_dir.mkdir(exist_ok=True)
    backup = backup_dir / (today.strftime('%Y%m%d-%H%M%S-%f') + '.json')
    with backup.open('x', encoding='utf-8') as file:
        json.dump({'key': key_path, 'view': 'Registry64', 'time': today.isoformat(), 'idm_sha256': digest, 'values': before}, file, indent=2)
    # Re-check binary identity immediately before the write phase.
    if hashlib.sha256(EXE.read_bytes()).hexdigest() != digest:
        raise SystemExit('IDM changed during discovery. No changes made.')
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_READ | winreg.KEY_SET_VALUE | VIEW) as key:
        if snapshot(key) != before:
            raise SystemExit('Registry changed after preview. No changes made; retry after checking IDM is closed.')
        try:
            try:
                winreg.DeleteValue(key, 'MData')
            except FileNotFoundError:
                pass
            winreg.SetValueEx(key, 'Model', 0, winreg.REG_DWORD, marker)
            winreg.SetValueEx(key, 'Therad', 0, winreg.REG_DWORD, 0)
            winreg.FlushKey(key)
            if winreg.QueryValueEx(key, 'Model') != (marker, winreg.REG_DWORD) or winreg.QueryValueEx(key, 'Therad') != (0, winreg.REG_DWORD):
                raise OSError('Trial-state readback did not match the requested reset.')
            try:
                winreg.QueryValueEx(key, 'MData')
            except FileNotFoundError:
                pass
            else:
                raise OSError('MData remained after reset.')
        except OSError as error:
            try:
                restore_values(key, before)
            except OSError:
                raise SystemExit(f'Write failed and automatic rollback failed. Preserve backup: {backup}') from error
            raise SystemExit(f'Write failed; previous managed values restored. Backup: {backup}') from error
    print(f'Updated trial state. Backup: {backup}')
    if profile and profile['state'] == 'testing':
        profile.update(test_applied_at=today.isoformat(), test_backup=str(backup))
        save_settings(manual_profile=profile)
    print('Open the original IDM and verify its behavior. Future compatibility is not guaranteed.')
    if args.launch:
        launch_idm()

if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError) as error:
        raise SystemExit(f'Unable to complete operation: {error}') from error
