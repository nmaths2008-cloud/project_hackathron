import os,socket,time,hashlib
from datetime import datetime,timezone
import psutil,requests
SERVER_URL=os.getenv('SENTINEL_SERVER_URL','http://127.0.0.1:8000').rstrip('/')
API_KEY=os.getenv('SENTINEL_API_KEY','change-me-now');INTERVAL=int(os.getenv('SENTINEL_INTERVAL','15'));HOST=socket.gethostname()
last_processes=set();last_ports=set()
def iso():return datetime.now(timezone.utc).isoformat()
def send(e):
 e.update({'host':HOST,'source':'windows-agent'})
 try:return requests.post(SERVER_URL+'/api/agent/events',json=e,headers={'X-Sentinel-API-Key':API_KEY},timeout=5).ok
 except requests.RequestException:return False
def process_snapshot():
 out=set()
 for p in psutil.process_iter(['pid','name']):
  try:out.add(f"{p.info['pid']}:{p.info['name']}")
  except (psutil.NoSuchProcess,psutil.AccessDenied):pass
 return out
def port_snapshot():
 out=set()
 try:
  for c in psutil.net_connections(kind='inet'):
   if c.status==psutil.CONN_LISTEN and c.laddr:out.add(f'{c.laddr.ip}:{c.laddr.port}')
 except (psutil.AccessDenied,PermissionError):pass
 return out
def system_changes():
 global last_processes,last_ports
 cp=process_snapshot();ct=port_snapshot(); newp=cp-last_processes if last_processes else set();newt=ct-last_ports if last_ports else set()
 for item in list(newp)[:25]:
  pid,_,name=item.partition(':');send({'timestamp':iso(),'source_ip':'127.0.0.1','username':os.getenv('USERNAME','local-user'),'action':'process_start','status':'200','endpoint':f'/process/{pid}','user_agent':'SentinelGuard-Windows-Agent','country':'LOCAL','process':name})
 for item in list(newt)[:25]:send({'timestamp':iso(),'source_ip':'127.0.0.1','username':os.getenv('USERNAME','local-user'),'action':'listener_detected','status':'200','endpoint':f'/tcp/{item}','user_agent':'SentinelGuard-Windows-Agent','country':'LOCAL'})
 last_processes,last_ports=cp,ct
def windows_logons():
    try:
        import win32evtlog
    except ImportError:
        return
    
    h = None
    try:
        h = win32evtlog.OpenEventLog('localhost', 'Security')
        flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        evs = win32evtlog.ReadEventLog(h, flags, 0) or []
        for ev in evs[:25]:
            if ev.EventID in (4624, 4625):
                send({
                    'timestamp': iso(),
                    'source_ip': '127.0.0.1',
                    'username': os.getenv('USERNAME', 'local-user'),
                    'action': 'windows_logon',
                    'status': str(ev.EventID),
                    'endpoint': '/windows/security',
                    'user_agent': 'SentinelGuard-Windows-Agent',
                    'country': 'LOCAL'
                })
    except Exception as e:
        print('Windows log collector error:', e)
    finally:
        if h:
            win32evtlog.CloseEventLog(h)
def main():
 print('SentinelGuard agent ->',SERVER_URL)
 while True:
  try:
   system_changes();windows_logons();send({'timestamp':iso(),'source_ip':'127.0.0.1','username':os.getenv('USERNAME','local-user'),'action':'heartbeat','status':'200','endpoint':'/agent/heartbeat','user_agent':'SentinelGuard-Windows-Agent','country':'LOCAL'})
  except Exception as e:print('Agent cycle:',e)
  time.sleep(INTERVAL)
if __name__=='__main__':main()
