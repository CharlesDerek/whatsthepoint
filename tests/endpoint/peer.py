import socket, threading, time
for family, address in [(socket.AF_INET,'0.0.0.0'),(socket.AF_INET6,'::')]:
    for port in [53,8080,8443,853]:
        for kind in [socket.SOCK_STREAM,socket.SOCK_DGRAM]:
            sock=socket.socket(family,kind);sock.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
            if family==socket.AF_INET6:sock.setsockopt(socket.IPPROTO_IPV6,socket.IPV6_V6ONLY,1)
            sock.bind((address,port))
            def serve(s=sock,k=kind):
                if k==socket.SOCK_STREAM:
                    s.listen()
                    while True:
                        c,_=s.accept()
                        try:c.sendall(b'ok')
                        except OSError:pass
                        c.close()
                else:
                    while True:
                        data,peer=s.recvfrom(4096);s.sendto(data,peer)
            threading.Thread(target=serve,daemon=True).start()
while True:time.sleep(60)
