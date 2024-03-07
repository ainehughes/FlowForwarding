import socket
import time
import threading

print_lock = threading.Lock()

class Router:
    def __init__(self, router_ip, router_port):
        self.router_ip = router_ip
        self.router_port = router_port
        self.routing_table = {}
        self.router_socket = None
        self.is_running = False

    def bind_router_socket(self):
        try:
            self.router_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.router_socket.bind((self.router_ip, self.router_port))
            with print_lock:
                print(f"Router is listening on {self.router_ip}:{self.router_port}")
        except OSError as e:
            with print_lock:
                print(f"Error binding the socket: {str(e)}")
            if self.router_socket:
                self.router_socket.close()
                self.router_socket = None
            return

    def receive_and_route(self):
        try:
            self.is_running = True
            while self.is_running:
                packet, source_address = self.router_socket.recvfrom(1024)
                with print_lock:
                    print(f"Received packet from {source_address}: {packet.decode('utf-8')}")

                destination_ip, label = self.extract_destination_and_label(packet)

                if destination_ip in self.routing_table:
                    next_hop = self.routing_table[destination_ip]
                    if next_hop != source_address:
                        self.router_socket.sendto(packet, next_hop)
                        with print_lock:
                            print(f"Forwarding packet to {destination_ip} via {next_hop}")

                else:
                    broadcast_message = f"Looking for {destination_ip}".encode('utf-8')
                    with print_lock:
                        print(f"Broadcasting: {broadcast_message.decode('utf-8')}")

                if packet.startswith(b"Acknowledgment"):
                    acknowledgment_source_ip = packet.decode('utf-8').split()[2]
                    with print_lock:
                        print(f"Acknowledgment received from {acknowledgment_source_ip}")

                        if acknowledgment_source_ip in self.routing_table:
                            with print_lock:
                                print(f"Forwarding information for {acknowledgment_source_ip} removed.")
                            del self.routing_table[acknowledgment_source_ip]

        except KeyboardInterrupt:
            with print_lock:
                print("Router stopped by the user.")
        except Exception as e:
            with print_lock:
                print(f"Error: {str(e)}")
        finally:
            self.close_router_socket()

    def extract_destination_and_label(self, packet):
        parts = packet.decode('utf-8').split()
        destination_ip = parts[-1]
        label = parts[0]
        return destination_ip, label

    def close_router_socket(self):
        if self.router_socket:
            self.router_socket.close()
            with print_lock:
                print("Router socket closed.")
            self.router_socket = None

    def stop_router(self):
        self.is_running = False

router1 = Router('127.0.0.1', 8080)
router2 = Router('127.0.0.1', 8081)
router3 = Router('127.0.0.1', 8082)

router1.bind_router_socket()
router2.bind_router_socket()
router3.bind_router_socket()


router1.routing_table = {'127.0.0.2': ('127.0.0.1', 8081), '127.0.0.3': ('127.0.0.1', 8082)}
router2.routing_table = {'127.0.0.1': ('127.0.0.2', 8080), '127.0.0.3': ('127.0.0.2', 8082)}
router3.routing_table = {'127.0.0.1': ('127.0.0.3', 8080), '127.0.0.2': ('127.0.0.3', 8081)}


thread1 = threading.Thread(target=router1.receive_and_route)
thread2 = threading.Thread(target=router2.receive_and_route)
thread3 = threading.Thread(target=router3.receive_and_route)

thread1.start()
thread2.start()
thread3.start()


data_packet1 = "DATA 127.0.0.2".encode('utf-8')
data_packet2 = "DATA 127.0.0.3".encode('utf-8')

router1.router_socket.sendto(data_packet1, ('127.0.0.1', 8080))
router2.router_socket.sendto(data_packet2, ('127.0.0.1', 8081))


time.sleep(1)


router1.stop_router()
router2.stop_router()
router3.stop_router()


thread1.join()
thread2.join()
thread3.join()
