#!/usr/bin/python

import os
import sys
import threading
import queue
import socket
import argparse
import ipaddress

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
    def __init__(self, host, port, timeout=0.1):
        self.host = host
        self.port = port
        self.timeout = timeout
        
    def check_port_status(self):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((self.host, self.port))
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



def scan_ip_range(network, port, threads, timeout):
    pool = ThreadPool(num_threads=threads)
    
    for host in network.get_ip_addresses():
        sc = ScanPort(host,port,timeout)
        pool.add_task(sc.check_port_status)
    pool.wait_completion()

def main():
    parser = argparse.ArgumentParser(description="Discover network with link layer without root capabilities")

    parser.add_argument("-w", "--workers", type=int, help="number of threads",default=30)
    parser.add_argument("-n", "--network", help="network IP v4 (ex: 192.168.1.0/24)")
    parser.add_argument("-t", "--timeout", type=int, help="timeout in ms",default=234)
    parser.add_argument("-p", "--port", type=int, help="timeout in ms",default=22)

    args = parser.parse_args()

    num_threads = args.workers
    network = args.network
    timeout = float(args.timeout)/float(1000)
    port = args.port
    network = CIDRAnalyzer(network)
    if network.is_valid() is not True:
        print("Invalid IP network")
        exit(1)
    
    scan_ip_range(network, port, num_threads, timeout)


if __name__ == "__main__":
    main()
    try:
        os.system("ip neigh | grep -v -P '(FAILED|INCOMPLETE)'")
    except:
        pass
  
