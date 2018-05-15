import socket
import paramiko
import select
import threading
import sys
import logging
import logging.handlers
import time
import os
import configparser

rootDir="C:\\Windows"
ConfigFile = "rforward.ini"
log = None
config=None

def initLog( logfile ):
    global log
    log = logging.getLogger("LOG")
    log.setLevel(logging.DEBUG)
    handler = logging.handlers.RotatingFileHandler(filename=logfile , maxBytes=1024 * 1024 * 3, backupCount=10)
    formatter = logging.Formatter("%(asctime)s L:%(lineno)s %(levelname)s Msg: %(message)s")
    handler.setFormatter(formatter)
    log.addHandler(handler)

def initIni():
    global log, config
    config = configparser.ConfigParser()
    if not os.path.exists( ConfigFile ):
        with  open( ConfigFile , "w+") as f :
            f.write("[rforward]\r\n"
                   "server_address=172.16.39.139\r\n"
                   "server_port=22\r\n"
                   "local_port=58000\r\n"
                   "remote_address=172.16.51.138\r\n"
                   "remote_port=8000\r\n"
                   "server_username=alex\r\n"
                   "server_password=1234\r\n\r\n"
                   "[log]\r\n"
                   "logfile=logdaemon.log\r\n")
    config.read(ConfigFile)

def handler(chan, remote_address, remote_port):
    remote_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        remote_socket.connect((remote_address, remote_port))
    except:
        print(f"[!] Unable to establish tcp connection to {remote_address}:{remote_port}")
        sys.exit(1)

    print(f"[*] Established tcp connection to {remote_address}:{remote_port}")
    while True:
        r, w, x = select.select([remote_socket, chan], [], [])
        if remote_socket in r:
            data = remote_socket.recv(1024)
            if len(data) == 0:
                break
            print(f"[*] Sending {len(data)} bytes via SSH channel")
            chan.send(data)
        if chan in r:
            data = chan.recv(1024)
            if len(data) == 0:
                break
            remote_socket.send(data)
            print(f"[*] Sending {len(data)} bytes via TCP socket")
    chan.close()
    remote_socket.close()
    print("[*] Tunnel connection is closed")

#thread will be spawned to handle the forwarded connection.
def reverse_port_forward(local_port, remote_address, remote_port, client_transport):
    print("[*] Starting reverse port forwarding")
    try:
        client_transport.request_port_forward("0.0.0.0", local_port)
        client_transport.open_session()
    except paramiko.SSHException as err:
        print("[!] Unable to enable reverse port forwarding: ", str(err))
        sys.exit(1)
    print(f"[*] Started. Waiting for tcp connection on 0.0.0.0:{local_port} from SSH server")
    while True:
        try:
            chan = client_transport.accept(60)
            if not chan:
                continue
            thr = threading.Thread(target=handler, args=(chan, remote_address, remote_port))
            thr.start()
        except KeyboardInterrupt:
            client_transport.cancel_port_forward("0.0.0.0", local_port)
            client_transport.close()
            sys.exit(0)

#main
initIni()
local_port = config.getint("rforward", "local_port")
server_address = config.get("rforward", "server_address")
server_port = config.getint("rforward", "server_port")
remote_address = config.get("rforward", "remote_address")
remote_port = config.getint("rforward", "remote_port")
server_username = config.get("rforward", "server_username")
server_password = config.get("rforward", "server_password")
logfile = config.get("log", "logfile")
initLog(logfile)
log.debug("SSH Tunnel Start")

client = paramiko.SSHClient()
#client.load_host_key('/path/to/file')
client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
try:
    client.connect(server_address, port=server_port, username=server_username, password=server_password)
except (paramiko.AuthenticationException, paramiko.SSHException) as err:
    print(str(err))
    sys.exit(1)
reverse_port_forward(local_port, remote_address, remote_port, client.get_transport())