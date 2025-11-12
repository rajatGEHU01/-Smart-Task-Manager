import streamlit as st
import psutil
import pandas as pd
import threading
import time
import json
import os
import matplotlib.pyplot as plt
from datetime import datetime, timedelta 

# --- MODULES FROM core/monitor_engine.py ---
try:
    from sklearn.ensemble import IsolationForest
    SKLEARN_AVAILABLE = True
except Exception:
    SKLEARN_AVAILABLE = False
    import math # Placeholder for completeness

# --------- CONFIGURATION ----------
DEFAULT_CONFIG = {
    "poll_interval": 1.0,
    "cpu_threshold": 50.0,
    "mem_threshold_mb": 200.0,
    "sustained_seconds": 10,
    "auto_kill": True,
    "whitelist": ["System", "idle", "explorer.exe", "svchost.exe"],
    "log_file": "process_killer_log.csv",
    "score_file": "system_health_history.csv"
}

# Config functions rely on Streamlit's session_state passed from app.py
def get_config(session_state):
    if 'config' not in session_state:
        session_state['config'] = DEFAULT_CONFIG.copy()
    return session_state['config']

def save_config(config):
    with open('stm_config.json', 'w') as f:
        json.dump(config, f, indent=2)

def load_config(session_state, st_module):
    try:
        with open('stm_config.json') as f:
            conf = json.load(f)
        session_state['config'] = conf
        st_module.success("Configuration loaded from stm_config.json")
    except Exception:
        st_module.warning("No saved configuration found.")


# --------- MONITOR ENGINE CLASS (core/monitor_engine.py) ----------
class ProcessMonitor:
    def __init__(self, config):
        self.config = config
        self.running = False
        self.lock = threading.Lock()
        self.history = {}
        self.suggestions = {}
        self.flags = []
        self._init_log()

    def _init_log(self):
        if not os.path.exists(self.config['log_file']):
            df = pd.DataFrame(columns=["timestamp", "pid", "name", "cpu", "mem_mb", "action", "reason"])
            df.to_csv(self.config['log_file'], index=False)
        if not os.path.exists(self.config['score_file']):
            df_score = pd.DataFrame(columns=["timestamp", "score"])
            df_score.to_csv(self.config['score_file'], index=False)

    def start(self):
        if not self.running:
            self.running = True
            t = threading.Thread(target=self._run_loop, daemon=True)
            t.start()

    def stop(self):
        self.running = False
        
    def _run_loop(self):
        while self.running:
            self.poll_once()
            time.sleep(max(0.01, self.config['poll_interval']))

    def poll_once(self):
        now = datetime.utcnow()
        active_pids = set()
        for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_info', 'exe']):
            try:
                pid = proc.info['pid']
                name = proc.info['name'] or ''
                cpu = proc.cpu_percent(interval=None) 
                mem = proc.info['memory_info'].rss / (1024 * 1024)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

            active_pids.add(pid)
            
            with self.lock:
                hist = self.history.setdefault(pid, [])
                hist.append((now, cpu, mem, name))
                cutoff = now - timedelta(minutes=5)
                self.history[pid] = [h for h in hist if h[0] >= cutoff] 
                self._analyze_pid(pid)
        
        expired_pids = list(self.history.keys() - active_pids)
        for pid in expired_pids:
            with self.lock:
                del self.history[pid]

        self._update_suggestions()
    
    def _analyze_pid(self, pid):
        hist = self.history.get(pid, [])
        if not hist: return
        sustained_seconds = self.config['sustained_seconds']
        cutoff = datetime.utcnow() - timedelta(seconds=sustained_seconds)
        sustained = [h for h in hist if h[0] >= cutoff]
        if not sustained: return
        last_ts, last_cpu, last_mem, name = sustained[-1]

        cpu_flag = all(h[1] >= self.config['cpu_threshold'] for h in sustained)
        mem_flag = all(h[2] >= self.config['mem_threshold_mb'] for h in sustained)

        deadlock_flag = False
        try:
            p = psutil.Process(pid)
            num_threads = p.num_threads()
            if num_threads > 100 and last_cpu < 5 and len(sustained) >= 3:
                deadlock_flag = True
        except Exception:
            num_threads = None

        reason = None
        if cpu_flag or mem_flag or deadlock_flag:
            if cpu_flag:
                reason = f"Sustained CPU ≥ {self.config['cpu_threshold']}% for {self.config['sustained_seconds']}s"
            elif mem_flag:
                reason = f"Sustained Memory ≥ {self.config['mem_threshold_mb']} MB for {self.config['sustained_seconds']}s"
            elif deadlock_flag:
                reason = "Deadlock-like behavior detected (many threads, low CPU)"

            self._flag_process(pid, name, last_cpu, last_mem, reason)

    def _flag_process(self, pid, name, cpu, mem, reason):
        entry = {
            'timestamp': datetime.utcnow().isoformat(),
            'pid': pid,
            'name': name,
            'cpu': cpu,
            'mem_mb': mem,
            'action': 'flagged',
            'reason': reason
        }
        if any(f['pid'] == pid and f['reason'] == reason for f in self.flags):
             return
             
        self.flags.append(entry)
        self._append_log(entry)

        if self.config.get('auto_kill') and not self._is_whitelisted(name):
            killed = self._kill_process(pid, name)
            action = 'killed' if killed else 'kill_failed'
            entry2 = entry.copy()
            entry2['action'] = action
            self._append_log(entry2)

    def _append_log(self, entry):
        df = pd.DataFrame([entry])
        df.to_csv(self.config['log_file'], mode='a', header=False, index=False)

    def _kill_process(self, pid, name):
        try:
            p = psutil.Process(pid)
            p.terminate()
            gone, alive = psutil.wait_procs([p], timeout=3)
            if alive:
                for a in alive:
                    a.kill()
            return True
        except Exception as e:
            return False

    def manual_kill(self, pid):
        try:
            p = psutil.Process(pid)
            name = p.name()
            if self._is_whitelisted(name):
                return False, 'whitelisted'

            p.terminate()
            gone, alive = psutil.wait_procs([p], timeout=3)
            if alive:
                for a in alive:
                    a.kill()

            entry = {'timestamp': datetime.utcnow().isoformat(), 'pid': pid, 'name': name, 'cpu': None, 'mem_mb': None, 'action': 'manual_kill', 'reason': 'user_initiated'}
            self._append_log(entry)
            return True, 'killed'
        except psutil.NoSuchProcess:
            return True, 'killed (process already gone)'
        except Exception as e:
            return False, str(e)


    def _is_whitelisted(self, name):
        wl = [w.lower() for w in self.config.get('whitelist', [])]
        name_lower = name.lower()
        return any(w == name_lower or w in name_lower for w in wl)

    def _update_suggestions(self):
        suggestions = {}
        for pid, hist in list(self.history.items()):
            if not hist: continue
            name = hist[-1][3]
            samples = [h[1] for h in hist]
            if len(samples) < 5: continue

            mean_cpu = sum(samples) / len(samples)
            var = sum((s - mean_cpu) ** 2 for s in samples) / len(samples)

            if mean_cpu < 5 and var < 10:
                key = name.lower()
                suggestions[key] = suggestions.get(key, 0) + 1

        ranked = sorted(suggestions.items(), key=lambda x: -x[1])
        self.suggestions = [{'name': name, 'score': score} for name, score in ranked]

    def run_anomaly_detector(self):
        rows = []
        now = datetime.utcnow()
        cutoff = now - timedelta(minutes=5)
        with self.lock:
            for pid, hist in self.history.items():
                if not hist: continue
                name = hist[-1][3]
                h_recent = [h for h in hist if h[0] >= cutoff]
                if not h_recent: continue
                cpus = [h[1] for h in h_recent]
                mems = [h[2] for h in h_recent]
                rows.append({
                    'pid': pid,
                    'name': name,
                    'cpu_mean': sum(cpus) / len(cpus),
                    'cpu_max': max(cpus),
                    'mem_mean': sum(mems) / len(mems),
                    'mem_max': max(mems),
                    'samples': len(h_recent)
                })

        if not rows: return pd.DataFrame()

        df = pd.DataFrame(rows)
        features = df[['cpu_mean', 'cpu_max', 'mem_mean', 'mem_max', 'samples']].fillna(0)

        if SKLEARN_AVAILABLE and len(df) >= 3:
            model = IsolationForest(contamination=0.05, random_state=1)
            try:
                scores = model.decision_function(features)
                df['anomaly_score'] = -scores
            except Exception:
                df['anomaly_score'] = 0.0
        else:
            df['anomaly_score'] = 0.0
            for col in ['cpu_max', 'mem_max']:
                vals = features[col].values
                mean = vals.mean() if len(vals) else 0
                std = vals.std() if len(vals) else 1
                std = std if std > 0 else 1
                df['anomaly_score'] += ((vals - mean) / std).clip(min=0)

        df = df.sort_values('anomaly_score', ascending=False)
        return df


# --- UTILITY FUNCTIONS (core/utils.py) ---
def get_process_stats():
    """
    Retrieves process statistics (CPU%, Mem MB) for all running processes,
    ensuring CPU counters are polled correctly.
    """
    processes = []
    for p in psutil.process_iter(['pid', 'name', 'memory_info']):
        try:
            p.cpu_percent(None)
            processes.append(p)
        except Exception:
            continue

    time.sleep(0.5) 

    procs = []
    for p in processes:
        try:
            mem_raw = p.info['memory_info'].rss / (1024 * 1024)
            cpu_usage = p.cpu_percent(None)  
            procs.append({
                'PID': p.info['pid'],
                'Name': p.info['name'],
                'CPU (%)': f"{cpu_usage:.1f}",
                'Mem (MB)': f"{mem_raw:.1f}",
                'MEM_SORT': mem_raw
            })
        except Exception:
            continue

    df_all = pd.DataFrame(procs)
    if not df_all.empty:
        df_all = df_all.sort_values('MEM_SORT', ascending=False).drop(columns=['MEM_SORT'])
    return df_all


def compute_health_score(log_file="process_killer_log.csv"):
    """
    Computes a health score based on interventions logged in the file.
    """
    if not os.path.exists(log_file):
        return 100, [] 

    df = pd.read_csv(log_file)
    killed = df[df['action'].str.contains('kill', na=False)] 

    num_killed = len(killed)
    savings = (killed['cpu'].fillna(0).sum() * 0.1) if not killed.empty else 0 

    score = max(0, int(100 - num_killed*2 + min(50, savings)))
    
    return score, [] # Returns score and an empty list


def save_score_history(score, score_file="system_health_history.csv"):
    """
    Saves the health score to history file.
    """
    now = datetime.now().isoformat()
    df = pd.DataFrame([{"timestamp": now, "score": score}])

    if os.path.exists(score_file):
        df.to_csv(score_file, mode='a', header=False, index=False)
    else:
        df.to_csv(score_file, index=False)

# -------------------------------------------------------------
# 🌟 UI PAGE FUNCTIONS (ui_pages.py) 
# -------------------------------------------------------------

def manual_kill_from_list(monitor, pid, name):
    """
    Helper function to perform the actual termination logic for list buttons.
    """
    if monitor._is_whitelisted(name):
        st.error(f"Cannot kill PID **{pid}** ({name}): It is on the whitelist.")
        return

    try:
        p = psutil.Process(pid)
        p.terminate()
        gone, alive = psutil.wait_procs([p], timeout=3)
        if alive:
            for a in alive:
                a.kill()
        
        # Log the action
        entry = {'timestamp': datetime.utcnow().isoformat(), 'pid': pid, 'name': name, 'cpu': None, 'mem_mb': None, 'action': 'list_kill', 'reason': 'user_initiated_from_list'}
        monitor._append_log(entry)
        
        st.success(f"Successfully initiated termination for PID **{pid}** ({name}).")
        st.rerun() 
    except psutil.NoSuchProcess:
        st.info(f"PID **{pid}** ({name}) was already terminated.")
        st.rerun() 
    except Exception as e:
        st.error(f"Error killing PID **{pid}** ({name}). Reason: **{str(e)}**")
        st.rerun() 


def page_home():
    st.title("🧠 Smart Task Manager")
    st.markdown("### Intelligent Process Killer & System Health Monitor")
    st.info("""
    Welcome! This tool uses real-time monitoring, customizable thresholds,
    and machine learning to maintain system stability by automatically handling runaway processes.
    """)

    monitor = st.session_state['monitor'] 
    config = get_config(st.session_state) 

    st.markdown("#### Core Features:")
    col1, col2, col3 = st.columns(3)
    with col1:
        kill_count = len([f for f in monitor.flags if 'kill' in f['action']]) 
        st.metric("Process Interventions", kill_count, "Auto-kill, Manual Kill, List Kill")
    with col2:
        st.metric("Current CPU Usage", f"{psutil.cpu_percent():.1f}%", "")
    with col3:
        st.metric("System Health Score", f"{compute_health_score(config['log_file'])[0]}/100", "")


def page_monitor(monitor):
    st.header("⚙️ Real-time Monitoring & Auto-Kill Settings")

    config = get_config(st.session_state)

    # --- 1. THRESHOLDS & ENGINE CONTROLS ---
    st.markdown("#### Thresholds & Engine Control")
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        poll = st.slider('Poll Interval (s)', 0.1, 5.0, float(config['poll_interval']))
    with col2:
        cpu = st.slider('CPU Threshold (%)', 5.0, 100.0, float(config['cpu_threshold']))
    with col3:
        mem = st.slider('Memory Threshold (MB)', 10.0, 4096.0, float(config['mem_threshold_mb']))
    with col4:
        sustained = st.slider('Sustained Time (s)', 3, 30, int(config['sustained_seconds']))

    col_toggle, col_status = st.columns([1, 2])
    with col_toggle:
        auto = st.checkbox("🔥 **Enable Auto-Kill**", value=config['auto_kill'], help="If enabled, non-whitelisted processes exceeding thresholds for the sustained time will be terminated.")

    with col_status:
        if not monitor.running:
            if st.button("▶️ **Start Monitoring Engine**", type="primary"):
                monitor.start()
                st.success("Monitoring started.")
        else:
            if st.button("⏸️ **Stop Monitoring Engine**", type="secondary"):
                monitor.stop()
                st.warning("Monitoring stopped.")

    # Update config settings
    config['poll_interval'] = poll; config['cpu_threshold'] = cpu; config['mem_threshold_mb'] = mem
    config['sustained_seconds'] = sustained; config['auto_kill'] = auto
    st.session_state['config'] = config
    monitor.config = config 


    st.markdown("---")
    
    # --- 2. ANOMALY DETECTION SECTION ---
    st.subheader("🧠 Anomaly Detection & Scoring")
    
    if not SKLEARN_AVAILABLE:
        st.warning("⚠️ Scikit-learn not installed. Using a basic statistical scoring fallback.")

    if st.button("🔎 **Run Anomaly Detector**", type="primary", key='run_anomaly_btn'):
        with st.spinner('Analyzing process metrics for the last 5 minutes...'):
            adf = monitor.run_anomaly_detector()
            st.session_state['adf'] = adf
            if not adf.empty:
                st.success(f"**{len(adf)}** processes analyzed. Displaying top 10 anomalies.")
            else:
                st.warning("Not enough data to analyze. Ensure monitoring is running.")

    adf = st.session_state.get('adf')
    if adf is not None and not adf.empty:
        df_display = adf[['pid', 'name', 'anomaly_score', 'cpu_max', 'mem_max', 'samples']].copy()
        df_display.columns = ['PID', 'Name', 'Anomaly Score', 'Max CPU', 'Max Mem (MB)', 'Samples']
        df_display['Anomaly Score'] = df_display['Anomaly Score'].round(4)
        df_display['Max CPU'] = df_display['Max CPU'].round(1).astype(str) + '%'
        df_display['Max Mem (MB)'] = df_display['Max Mem (MB)'].round(1)

        st.dataframe(df_display.head(10), use_container_width=True, hide_index=True)

        st.markdown("---")
        csv = adf.to_csv(index=False).encode('utf-8')
        st.download_button('⬇️ Download Full Anomaly Results (CSV)', csv, file_name='anomaly_results.csv', mime='text/csv')
    else:
        st.info("Click 'Run Anomaly Detector' above to see results here.")

    st.markdown("---")
    
    # --- 3. SHOW ALL PROCESSES, SORTED BY MEMORY ---
    st.markdown("### All Running Processes (Sorted by Memory)")
    
    df_all = get_process_stats()
    st.dataframe(df_all, use_container_width=True, hide_index=True)


def page_flags(monitor):
    st.header("🚨 Intervention Logs / Flags")
    st.write("Records of processes that were flagged, auto-killed, or manually terminated.")

    config = get_config(st.session_state)
    log_file = config['log_file']
    if os.path.exists(log_file):
        df_flags_full = pd.read_csv(log_file)
        if not df_flags_full.empty:
            df_flags = df_flags_full.tail(50).iloc[::-1] # Last 50, reversed for newest first

            st.dataframe(df_flags, use_container_width=True, hide_index=True)

            st.markdown("---")
            csv = df_flags_full.to_csv(index=False).encode('utf-8')
            st.download_button("⬇️ Download Full Log (CSV)", csv, file_name='process_killer_log.csv', mime='text/csv')
        else:
            st.info("No interventions logged yet. Start monitoring to collect data.")
    else:
        st.info("No log file found. Start monitoring to generate one.")


def page_manual_kill(monitor):
    st.header("🔪 Manual Process Termination")
    st.write("Use this to manually terminate a misbehaving process by its PID or directly from the list below. **Whitelisted processes cannot be killed.**")

    # --- 1. PID Input Kill ---
    st.subheader("1. Terminate by PID")
    col_input, col_btn = st.columns([2, 1])
    with col_input:
        pid_input = st.text_input('Enter Process ID (PID) to kill', key="pid_input_manual")
    with col_btn:
        st.write("") # Spacer
        if st.button("💥 **KILL BY PID**", type="primary", key="kill_pid_btn"):
            try:
                pid_val = int(pid_input.strip())
                try:
                    name = psutil.Process(pid_val).name()
                except psutil.NoSuchProcess:
                    st.warning(f"PID {pid_val} not found.")
                    return
                except Exception:
                    name = "Unknown"
                
                ok, msg = monitor.manual_kill(pid_val)
                
                if ok:
                    st.success(f"Process PID **{pid_val}** ({name}) initiated termination.")
                else:
                    st.warning(f"Failed to initiate termination for PID {pid_val}. Reason: **{msg.capitalize()}**.")
            except ValueError:
                st.error("Please enter a valid integer for PID.")

    st.markdown("---")

    # --- 2. List Kill Interaction ---
    st.subheader("2. Terminate from Live List (All Processes, Sorted by Memory)")
    
    df_procs = get_process_stats()
    
    if df_procs.empty:
        st.info("No processes found.")
        return
        
    df_display = df_procs[['PID', 'Name', 'CPU (%)', 'Mem (MB)']].copy()

    # Render the Interactive List (Header and Rows)
    col_widths = [1, 4, 1.5, 1.5, 1.5]
    
    cols_header = st.columns(col_widths)
    with cols_header[0]: st.markdown("**PID**")
    with cols_header[1]: st.markdown("**Name**")
    with cols_header[2]: st.markdown("**CPU (%)**")
    with cols_header[3]: st.markdown("**Mem (MB)**")
    with cols_header[4]: st.markdown("**Action**")

    st.markdown("---")

    for index, row in df_display.iterrows():
        cols_row = st.columns(col_widths)
        
        with cols_row[0]: st.write(row['PID'])
        with cols_row[1]: st.write(row['Name'])
        with cols_row[2]: st.write(row['CPU (%)'])
        with cols_row[3]: st.write(row['Mem (MB)'])
        with cols_row[4]: 
            key = f"list_kill_button_{row['PID']}"
            if st.button("Kill 🔪", key=key, type="primary", help=f"Terminate {row['Name']}"):
                manual_kill_from_list(monitor, row['PID'], row['Name'])

    st.markdown("---") 


def page_whitelist(monitor):
    st.header("🛡️ Whitelist Manager")
    st.write("Protect essential system processes. Whitelisted entries **cannot** be auto-killed.")

    config = get_config(st.session_state)
    wl_str = st.text_area("Whitelist Entries (one per line, partial matching enabled)",
                          value='\n'.join(config.get('whitelist',[])),
                          height=200)

    new_whitelist = [l.strip() for l in wl_str.splitlines() if l.strip()]

    if st.button("💾 **Save Whitelist**", type="primary"):
        config['whitelist'] = new_whitelist
        st.session_state['config'] = config
        monitor.config = config 
        save_config(config)
        st.success("Whitelist saved and active!")

    st.markdown("---")

    if monitor.suggestions:
        st.subheader("💡 Dynamic Whitelist Suggestions")
        st.write("Processes with consistently low resource use that are safe to add.")

        suggest_df = pd.DataFrame(monitor.suggestions)
        suggest_df.columns = ['Process Name', 'Observation Count']
        st.table(suggest_df.head(5))

        if st.button("➕ Add Top 5 Suggestions"):
            new_entries = [s['name'] for s in monitor.suggestions[:5]]

            current_wl = set([n.lower() for n in config.get('whitelist',[])])
            for n in new_entries: current_wl.add(n)

            config['whitelist'] = list(current_wl)
            st.session_state['config'] = config
            monitor.config = config 
            save_config(config)
            st.success(f"Added {len(new_entries)} dynamic suggestions. Click 'Save Whitelist' above to finalize.")
            st.rerun() 


def page_history(monitor):
    st.header("📊 Process Usage History")
    st.write("Historical CPU/Memory usage trends for processes monitored in the last 5 minutes.")

    with monitor.lock:
        pids_with_history = sorted([pid for pid, hist in monitor.history.items() if hist])

    pid_to_name = {}
    options = []
    for pid in pids_with_history:
        try:
            name = monitor.history[pid][-1][3]
            pid_to_name[pid] = name
            options.append(f"{name} (PID: {pid})")
        except:
            continue

    sel_option = st.selectbox("Select Process", options=[None] + options)

    sel_pid = None
    if sel_option:
        try:
            sel_pid = int(sel_option.split('(PID: ')[-1].replace(')', ''))
        except:
            sel_pid = None

    if sel_pid:
        with monitor.lock:
            h = monitor.history.get(sel_pid, [])

        if h:
            st.subheader(f"History for {pid_to_name.get(sel_pid, 'Unknown')} (PID: {sel_pid})")

            dfh = pd.DataFrame([{'ts': t[0], 'cpu': t[1], 'mem_mb': t[2], 'name': t[3]} for t in h])
            dfh['ts'] = pd.to_datetime(dfh['ts'])

            col_cpu, col_mem = st.columns(2)

            with col_cpu:
                st.line_chart(dfh.set_index('ts')['cpu'], color="#8b0000", use_container_width=True, title="CPU Usage (%)")

            with col_mem:
                st.line_chart(dfh.set_index('ts')['mem_mb'], color="#1e90ff", use_container_width=True, title="Memory Usage (MB)")

            st.dataframe(dfh.tail(10).sort_values('ts', ascending=False), use_container_width=True, hide_index=True)

        else:
            st.info("No recent history for this PID.")
    else:
        st.info("Select a process to view its real-time trend.")


def page_gamification(monitor):
    st.header("❤️ System Health Score") 
    st.write("This score provides a simple metric to track your system's stability and intervention efficiency.") 

    config = get_config(st.session_state)
    score, badges = compute_health_score(config['log_file'])
    
    save_score_history(score, config['score_file'])

    st.metric("Current System Health Score", f"**{score}/100**", delta=None)

    st.markdown("---")

    score_file = config['score_file']
    if os.path.exists(score_file):
        try:
            df_score = pd.read_csv(score_file)
            if len(df_score) > 0:
                df_score['timestamp'] = pd.to_datetime(df_score['timestamp'])
                df_score.set_index('timestamp', inplace=True)
                df_resampled = df_score['score'].resample('1T').mean().dropna().reset_index()

                st.subheader("Health Score Trend")
                fig, ax = plt.subplots(figsize=(10, 5))
                ax.plot(df_resampled['timestamp'], df_resampled['score'], color='#00aaff', linewidth=2)
                ax.set_xlabel("Time")
                ax.set_ylabel("Health Score")
                ax.set_ylim(0, 105)
                ax.grid(axis='y', linestyle='--', alpha=0.6)
                plt.xticks(rotation=45, ha='right')
                plt.tight_layout()
                st.pyplot(fig)
            else:
                st.info("Score history will build up over time.")
        except Exception as e:
            st.error(f"Error loading health score history: {e}")
    else:
        st.info("No health score history yet.")


def page_config():
    st.header("⚙️ Configuration Manager")
    st.write("Load or save all current monitoring configuration settings.")

    config = get_config(st.session_state)
    st.markdown("---")

    col_load, col_save = st.columns(2)
    with col_load:
        if st.button("📥 **Load Config** from stm_config.json"):
            load_config(st.session_state, st)
            st.rerun() 
    with col_save:
        if st.button("📤 **Save Config** to stm_config.json", type="primary"):
            save_config(config)
            st.success("Config written to stm_config.json")

    st.markdown("### Current Settings (JSON)")
    st.json(config)


def page_about():
    st.header("ℹ️ About the Smart Task Manager")
    st.markdown("""
    This application is a **Project-Based Learning (PBL) / Demonstration** tool showcasing the integration of Python libraries for system monitoring and data analysis.

    * **Backend:** Python `psutil`, `pandas`, `threading`.
    * **Frontend:** `Streamlit` for a fast, interactive web UI.
    * **Intelligence:** `sklearn.ensemble.IsolationForest` or statistical fallback.
    """)

# -------------------------------------------------------------
# --- MAIN APPLICATION LOGIC ---
# -------------------------------------------------------------

PAGES = {
    "🏠 Home": page_home,
    "📈 Monitor": page_monitor,
    "🔪 Manual Kill": page_manual_kill,
    "🛡️ Whitelist": page_whitelist,
    "📊 History": page_history,
    "❤️ System Health": page_gamification,
    "🚨 Logs / Flags": page_flags, 
    "⚙️ Config": page_config,
    "ℹ️ About": page_about,
}


# --- Streamlit Setup and Custom CSS ---
st.set_page_config(page_title="Smart Task Manager", layout="wide")

st.markdown("""
<style>
/* Target the individual tab buttons for styling (Modern, Clean Tabs) */
button[data-baseweb="tab"] {
    height: 40px;
    min-width: 100px !important;
    padding: 0 15px; 
    border: none !important; 
    border-radius: 8px 8px 0 0; 
    font-size: 14px;
    text-align: center;
    transition: all 0.2s;
    background-color: #252526; 
    color: #cccccc !important; 
    margin-right: 2px; 
    box-shadow: none !important;
}

/* Hover effect */
button[data-baseweb="tab"]:hover {
    background-color: #3e3e40; 
    color: #ffffff !important;
}

/* Active tab style (The Highlight) */
button[data-baseweb="tab"][aria-selected="true"] {
    background-color: #0078d4; 
    color: white !important;
    font-weight: bold;
    border-bottom: 3px solid #0078d4 !important; 
}

/* Ensure content inside tab buttons is properly aligned (icon + text) */
button[data-baseweb="tab"] > div {
    display: flex;
    flex-direction: row; 
    align-items: center;
    justify-content: center;
    gap: 8px; 
}

/* Clean up Streamlit header/title */
h1 {
    color: #0078d4; 
    padding-top: 10px;
}

/* Force dataframe text to be readable */
.stDataFrame {
    color: #ffffff;
}
</style>
""", unsafe_allow_html=True)


# --- Session State Management ---
if 'monitor' not in st.session_state:
    # 1. Load config (uses st to display success/warning messages)
    load_config(st.session_state, st) 
    
    # 2. Initialize monitor with current config
    current_config = get_config(st.session_state)
    st.session_state['monitor'] = ProcessMonitor(current_config)

    # 3. Warm up psutil CPU counters 
    for p in psutil.process_iter(['pid']):
        try:
            p.cpu_percent(None)
        except Exception:
            pass
    psutil.cpu_percent(None)
    time.sleep(1) 


monitor = st.session_state['monitor']

# --- Horizontal Tab Logic ---
page_names = list(PAGES.keys())
tabs = st.tabs(page_names)

# Call the function corresponding to the tab
for i, (name, func) in enumerate(PAGES.items()):
    with tabs[i]:
        # Functions that require the 'monitor' object
        if name in ["📈 Monitor", "🔪 Manual Kill", "🛡️ Whitelist", "📊 History", "❤️ System Health", "🚨 Logs / Flags"]: 
            func(monitor)
        else:
            func()