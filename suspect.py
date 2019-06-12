class Suspect:
    def __init__(self, ip_address, mac_address, port, flags, timestamp):
        self.ip_address = ip_address
        self.mac_address = mac_address
        p = Port(port, flags, timestamp)
        self.ports = []
        self.ports.append(p)

    def update_ports(self, port, flags, timestamp):
        # testar se a porta ja existe
        for p in self.ports:
            # se existir, atualizar com o ultimo timestamp
            if p.port == port:
                p.timestamp = timestamp
                p.state = flags
                break
        else:
            # se nao existir, criar uma nova
            p = Port(port, flags, timestamp)
            self.ports.append(p)

class Port:
    def __init__(self, port, flags, time):
        self.port = port
        self.timestamp = time
        self.state = flags