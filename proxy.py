"""
HTTP/HTTPS Forward Proxy Server
================================

This module implements a basic forward proxy supporting:
- HTTP request forwarding
- HTTPS tunneling using the CONNECT method
- Domain-based blocklisting
- Request logging with log rotation
- Basic traffic metrics (RPM and top hosts)

Protocol Support:
- HTTP/1.1
- HTTPS via CONNECT tunneling

Limitations:
- No HTTP keep-alive (one request per connection)
- No chunked transfer decoding
- IPv4 only
- Blocking I/O per connection

Execution:
    python proxy.py

Configuration:
    Loaded from config.ini
"""


import threading as thr
import socket as sck
import argparse as agp
from concurrent.futures import ThreadPoolExecutor
import os
import time
from collections import deque,defaultdict
import signal
import sys
import configparser as cfp


# ----------------------CONFIG------------------------

"""
Configuration is read from config.ini to allow runtime changes
without modifying source code.
"""


config = cfp.ConfigParser()
config.read("config.ini")

HOST = config.get("server","host")
PORT = config.getint("server","port")
MAX_THREADS = config.getint("server","max_threads")
BLOCKLIST = config.get("filter","blocklist")
LOG_FILE = config.get("logging","log_file")
MAX_LOG_SIZE = config.getint("logging","max_log_size")
LOG_LOCK = thr.Lock()
METRICS_LOCK = thr.Lock()
REQFR = deque()
HOST_COUNT = defaultdict(int)
shutdown = False
srvr = None
binder = (HOST,PORT)
#---------------------------------------------------------


#-------------------SIGNAL HANDLER------------------------

"""
    Signal handler for graceful shutdown.

    Triggered on SIGINT / SIGTERM.
    Stops accepting new connections and closes the listening socket.
    """


def sign(signum,frame):
    global shutdown
    shutdown = True
    try : 
        if srvr:
            srvr.close()
    except:
        pass
    print("\nShutting down Gracefully")
#--------------------------------------------------------


#---------------------LOGS--------------------------------
def rotlog():
    """
    Performs log rotation when the log file exceeds MAX_LOG_SIZE.

    Old logs are renamed using incremental suffixes:
        proxy.log -> proxy.log_1.old -> proxy.log_2.old ...
    """
    try:
        if os.path.exists(LOG_FILE) and os.path.getsize(LOG_FILE) > MAX_LOG_SIZE:
            n=1
            while os.path.exists(f"{LOG_FILE}_{n}.old"):
                n+=1
            os.rename(LOG_FILE,f"{LOG_FILE}_{n}.old")
    except:
        pass

def logger(adr,host, port, req_line,action, status,size):

    """
    Writes a single structured log entry.

    Fields logged:
    - Timestamp
    - Client address
    - Target host and port
    - HTTP request line
    - Action taken (ALLOWED / BLOCKED / ERROR)
    - HTTP status code
    - Response size (bytes)
    """

    ts = time.strftime("%d-%m-%Y %H:%M", time.localtime())
    entry = f'{ts} | {adr[0]}:{adr[1]} | {host}:{port} | "{req_line}" | {action} | {status} | {size}\n'
    with LOG_LOCK:
        try:
            rotlog()
            with open(LOG_FILE, "a") as f :
                f.write(entry)
                f.flush()
        except Exception as e:
            print(f"Logging Error : {e}")
#------------------------------------------------------------


# -------------------------FILTER----------------------------
    """
    Loads blocked domains from a text file.

    Rules:
    - One domain per line
    - Case-insensitive
    """
def load_blocklist(path):
    blocked = set()
    try:
        with open(path,"r") as f:
            for line in f:
                line = line.strip().lower()
                if not line:
                    continue
                blocked.add(line)

    except FileNotFoundError:
        pass
    return blocked

BLOCKED = load_blocklist(BLOCKLIST)
#-----------------------------------------------------------


#--------------------------CLIENTS----------------------------
"""
    Handles a single client connection.

    Responsibilities:
    - Parse HTTP request headers
    - Enforce domain blocklist
    - Handle CONNECT tunneling
    - Forward HTTP requests
    - Log activity
    - Update metrics
"""
def client(conn,addr):
    server = None
    try:
        conn.settimeout(5)
        data = b""
        while b"\r\n\r\n" not in data:
            chunk = conn.recv(4096)
            if not chunk: 
                break
            data+=chunk
        if not data:
            logger(addr, "-", "-" , "-", "BAD_REQUEST", 400, 0)
            return
        
        hed_end = data.find(b"\r\n\r\n")
        hed_raw = data[:hed_end]
        extra_data = data[hed_end+4:]
        req = hed_raw.decode("latin-1")
        req_line = req.split("\r\n")[0]
        host = None
        port = 80

        pts = req_line.split()
        if not pts: 
            logger(addr, "-", "-" , "-", "BAD_REQUEST", 400, 0)
            return
        meth = pts[0]

#-------------------------HTTPS CONNECT--------------------------------------
        if meth.lower() == "connect":
            if len(pts) < 2 or ":" not in pts[1]:
               conn.sendall(b"HTTP/1.1 400 Bad Request\r\n\r\n")
               logger(addr, "-", "-" , req_line, "BAD_REQUEST", 400, 0)
               return
            host, port = pts[1].split(":",1)
            try:
               port = int(port)
            except ValueError:
               conn.sendall(b"HTTP/1.1 400 Bad Request\r\n\r\n")
               logger(addr, host , "-" , req_line, "BAD_REQUEST", 400, 0)
               return
            canon_host = host.strip().lower()
            if canon_host in BLOCKED or any(canon_host.endswith("." + b ) for b in BLOCKED):
                conn.sendall(b"HTTP/1.1 403 Forbidden\r\n\r\n")
                logger(addr,host,port,req_line,"BLOCKED",403,0)
                return
            server = sck.socket(sck.AF_INET,sck.SOCK_STREAM)
            server.settimeout(5)
            try:
                server.connect((host,port))
            except Exception:
                conn.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                logger(addr, host, port , req_line, "ERROR", 502, 0)
                return
            conn.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            now = time.time()
            with METRICS_LOCK:
              REQFR.append(now)
              HOST_COUNT[host] += 1
            logger(addr, host, port, req_line, "ALLOWED", 200, 0)
            def pipe(src, dst,other):
                try:
                    while True:
                        pdata = src.recv(4096)
                        if not pdata:
                            break
                        dst.sendall(pdata)
                except:
                  pass
                finally:
                    try: other.shutdown(sck.SHUT_RDWR)
                    except: pass
            
            t1 = thr.Thread(target=pipe, args=(conn, server, server), daemon=True)
            t2 = thr.Thread(target=pipe, args=(server, conn, conn), daemon=True)
            t1.start(); t2.start()
            t1.join(); t2.join()
            return
#---------------------------------------------------------------------------
#-------------------------------HTTP-------------------------------------
        if len(pts) < 2:
            logger(addr, "-", "-" , req_line, "BAD_REQUEST", 400, 0)
            return        
        if pts[1].startswith("http://"):
            wo_http = pts[1][7:]
            host1 = wo_http.split("/")[0]
            if ":" in host1:
                h_prt = host1.split(":")
                host = h_prt[0]
                port = int(h_prt[1])
            else : 
                host = host1
                port = 80
        if host is None :
            for line in req.split("\r\n"):
                if line.lower().startswith("host:"):
                    host1 = line.split(":",1)[1].strip()
                    if ":" in host1:
                        host,port = host1.split(":")
                        port = int(port)
                    else : host = host1
                    break
        if host is None :
            logger(addr, "-", "-" , req_line, "BAD_REQUEST", 400, 0)
            return
        
        now = time.time()
        with METRICS_LOCK:
            REQFR.append(now)
            HOST_COUNT[host]+=1

        canon_host = host.strip().lower()
        if canon_host in BLOCKED or any(canon_host.endswith("." + b ) for b in BLOCKED):
            resp = b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n"
            conn.sendall(resp)
            logger(addr, host, port, req_line, "BLOCKED", 403, 0 )
            return
#----------------------------------for POST/PUT--------------------------------#  
        con_len = 0
        for line in req.split("\r\n"):
            if line.lower().startswith("content-length"):
                strt,vlu = line.split(":",1)
                try:
                    con_len = int(vlu.strip())
                except ValueError:
                    print("Invalid Content Length")
        # bdy_dat = conn.recv(con_len) wrong bcoz .recv doesnt wait for n bytes...gives wtv available...so loop
        body = extra_data
        while len(body)<con_len:
            chunky = conn.recv(min(4096,con_len-len(body)))
            if not chunky:
                break
            body+=chunky
        full_req = hed_raw + b"\r\n\r\n" + body
        try:
            server = sck.socket(sck.AF_INET, sck.SOCK_STREAM)
            server.settimeout(5)
            server.connect((host,port))
            server.sendall(full_req)
            logger(addr, host, port, req_line, "ALLOWED", 200, 0)

        except Exception: 
            conn.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
            logger(addr, host, port, req_line, "ERROR", 502, 0)
            return
        bytes_sent = 0
        while True:
            resp = server.recv(4096)
            if not resp:
                break
            bytes_sent += len(resp)
            conn.sendall(resp)
    finally:
        try:
            if server:
                server.close()
        except:
            pass
        conn.close()
#---------------------------------------------------------------


#-----------------------Metrix---------------------------------
def getrpm():
    cutoff = time.time()-60
    with METRICS_LOCK:
        while REQFR and REQFR[0] < cutoff:
            REQFR.popleft()
        return len(REQFR)

def tophost(n=5):
    with METRICS_LOCK:
        return sorted(
            HOST_COUNT.items(),
            key=lambda x: x[1],
            reverse=True
        )[:n]

def metrix():
    while not shutdown:
        time.sleep(60)
        rpm = getrpm()
        top = tophost()
        print(f"\n ------------METRICS-----------\nRequests per Minute {rpm}\nMost Requested Hosts")
        for h,c in top:
            print(f"{h}:{c}\n------------------------------")
#------------------------------------------------------------------


#-----------------------------main-------------------------------
srvr = sck.socket(sck.AF_INET,sck.SOCK_STREAM)
srvr.bind(binder)
srvr.settimeout(1)
signal.signal(signal.SIGINT,sign)
signal.signal(signal.SIGTERM,sign)
print(f"[LISTENING] on {binder}")
srvr.listen()
thr.Thread(target=metrix, daemon=True).start()
with ThreadPoolExecutor(max_workers=50) as pool:
    while not shutdown:
        try:
            conn, addr = srvr.accept()
            pool.submit(client, conn, addr)
        except sck.timeout:
            continue
        except OSError:
            break

#--------------------------------------------------------------------

