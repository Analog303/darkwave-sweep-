import socket, os, threading
os.makedirs("/var/lib/dw", exist_ok=True)
srv = socket.socket(); srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("0.0.0.0", 1389)); srv.listen(200)
def h(c):
    try:
        c.settimeout(2); d = c.recv(2048)
        txt = "".join(chr(b) if 32 <= b < 127 else "" for b in d)
        with open("/var/lib/dw/log4j.log", "a") as f:
            f.write(txt[:300] + "\n")
        c.sendall(b"0\x02\x02\x01\x00")
    except Exception: pass
    finally: c.close()
while True:
    c, _ = srv.accept(); threading.Thread(target=h, args=(c,), daemon=True).start()
