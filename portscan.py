#!/usr/bin/python

import re
import sys
import threading
import queue
import socket
import asyncio
import argparse
import ipaddress


class PortParser:
    def __init__(self, port_string):
        self.port_string = port_string
        self.ports = []
        self.validate_port_string()
        self.parse_ports()

    def validate_port_string(self):
        if not re.match(r'^[\d,-]+$', self.port_string):
            raise ValueError("Port string contains invalid characters.")

        for port_range in self.port_string.split(','):
            if '-' in port_range:
                start, end = map(int, port_range.split('-'))
                if start < 0 or end < 0 or start > 65535 or end > 65535 or start > end:
                    raise ValueError(f"Invalid port range : {port_range}")

    def parse_ports(self):
        port_ranges = self.port_string.split(',')
        for port_range in port_ranges:
            if '-' in port_range:
                start, end = map(int, port_range.split('-'))
                self.ports.extend(range(start, end + 1))
            else:
                self.ports.append(int(port_range))

    def get_port_iterator(self):
        return iter(self.ports)

class ThreadPool:
    def __init__(self, num_threads):
        self.tasks = queue.Queue()
        self.num_threads = num_threads
        self.threads = []
        self.enable = True
        self._init_threads()
        
    def _init_threads(self):
        for _ in range(self.num_threads):
            thread = threading.Thread(target=self._worker)
            thread.daemon = True
            self.threads.append(thread)
            thread.start()

    def _worker(self):
        while self.enable:
            task = self.tasks.get()
            try:
                task()
            finally:
                self.tasks.task_done()

    def add_task(self, task):
        self.tasks.put(task)

    def wait_completion(self):
        self.tasks.join()


class ScanPort:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        
    def check_port_status(self, host, port, timeout=0.1):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((host, port))
            sock.close()
            return 0
        except socket.gaierror:
            return 1
        except socket.error:
            return 2
        except:
            return -1

    def thread_scan(self):
        status = self.check_port_status(self.host, self.port)
        if status == 0:
            print(f"{self.host}:{self.port} up")
            return 0
        elif status == 1:
            print(f"No route to host {self.host}")
            return 1
        return -1
        
class CIDRAnalyzer:
    def __init__(self, cidr_address):
        self.cidr_address = cidr_address
        self.network = None
        try:
            self.network = ipaddress.ip_network(cidr_address, strict=False)
        except ValueError:
            pass

    def is_valid(self):
        return self.network is not None

    def get_network_address(self):
        if self.is_valid():
            return str(self.network.network_address)
        else:
            return None

    def get_ip_addresses(self):
        if self.is_valid():
            return (str(ip) for ip in self.network.hosts())
        else:
            return []

def scan_ip_range(network, ports, workers, timeout):
    pool = ThreadPool(num_threads=workers)
    for host in network.get_ip_addresses():
        for port in ports.get_port_iterator():
            sc = ScanPort(host, port)
            pool.add_task(sc.thread_scan)
    pool.wait_completion()


def main():
    parser = argparse.ArgumentParser(description="Discover network with link layer without root capabilities")

    parser.add_argument("-w", "--workers", type=int, help="number of threads",default=30)
    parser.add_argument("-n", "--network", help="network IP v4 (ex: 192.168.1.0/24)")
    parser.add_argument("-t", "--timeout", type=int, help="timeout in ms",default=234)
    parser.add_argument("-p", "--port", help="range of port (ex: '22' '22,445,80,21' '1-1000' '1-200,3306,10000')",)

    args = parser.parse_args()

    num_threads = args.workers
    timeout = float(args.timeout)/float(1000)

    try:
        port = PortParser(args.port)
    except Exception as error:
        print(error)
        exit(1)
        
    network = CIDRAnalyzer(args.network)
    if network.is_valid() is not True:
        print("Invalid IP network")
        exit(1)

    scan_ip_range(network, port, num_threads, timeout)


if __name__ == "__main__":
    main()
