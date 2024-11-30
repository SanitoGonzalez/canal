import socket
import time
import argparse
from datetime import datetime

def create_load_tester(target_host, target_port, packet_size=1024, rate_limit=1000):
    """
    Network load testing tool with built-in rate limiting and monitoring
    
    Args:
        target_host: Host to test against
        target_port: Target port number
        packet_size: Size of test packets in bytes
        rate_limit: Maximum packets per second
    """
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    packet = b'X' * packet_size
    
    packets_sent = 0
    start_time = time.time()
    
    print(f"Starting load test to {target_host}:{target_port}")
    print(f"Packet size: {packet_size} bytes")
    print(f"Rate limit: {rate_limit} packets/second")
    
    try:
        while True:
            current_time = time.time()
            elapsed = current_time - start_time
            
            if elapsed >= 1.0:
                print(f"Packets sent in last second: {packets_sent}")
                packets_sent = 0
                start_time = current_time
                
            if packets_sent < rate_limit:
                try:
                    sock.sendto(packet, (target_host, target_port))
                    packets_sent += 1
                    
                except socket.error as e:
                    print(f"Error sending packet: {e}")
                    break
                    
            # Sleep to maintain rate limit
            time.sleep(1.0 / rate_limit)
            
    except KeyboardInterrupt:
        print("\nLoad test stopped by user")
    finally:
        sock.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Network Load Testing Tool")
    parser.add_argument("host", help="Target host address")
    parser.add_argument("port", type=int, help="Target port number")
    parser.add_argument("--size", type=int, default=1024, help="Packet size in bytes")
    parser.add_argument("--rate", type=int, default=1000, help="Packets per second")
    
    args = parser.parse_args()
    
    create_load_tester(args.host, args.port, args.size, args.rate)