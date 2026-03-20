import socket

def scan_ports(host):
    open_ports = []

    # Common ports
    ports = [21, 22, 23, 80, 443, 3306]

    for port in ports:
        try:
            s = socket.socket()
            s.settimeout(1)
            s.connect((host, port))
            open_ports.append(port)
            s.close()
        except:
            pass

    return open_ports