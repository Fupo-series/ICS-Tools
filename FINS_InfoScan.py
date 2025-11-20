import socket
import sys
from ipaddress import ip_network
import ipaddress
import time
from datetime import datetime
from prettytable import PrettyTable
import struct

GREEN = '\033[92m'
YELLOW = '\033[93m'
RESET = '\033[0m'
ORANGE = '\033[91m'


def print_result(addr, model, version, cpu_unit, system_version):
    table = PrettyTable()
    table.field_names = ["addr", "model", "version", "cpu_unit", "system_version"]
    table.add_row([addr, model, version, cpu_unit, system_version])
    print(table)


def parse_ip_range(ip_range):
    if '-' in ip_range:
        start, end = ip_range.split('-')
        start_ip = ipaddress.IPv4Address(start.strip())
        try:
            end_ip = ipaddress.IPv4Address(end.strip())
            return range(int(start_ip), int(end_ip) + 1)
        except ipaddress.AddressValueError:
            return [start]
    elif '/' in ip_range:
        return [str(ip) for ip in ipaddress.IPv4Network(ip_range, strict=False).hosts()]
    else:
        return [ip_range]


def save_result_to_file(result, filename):
    with open(filename, 'a') as f:
        f.write(result)


def print_copyright():
    print(f'''
__________________________________________
{GREEN} ____  ___  ___   ___    __    _  _ 
(_  _)/ __)/ __) / __)  /__\  ( \( )
 _)(_( (__ \__ \( (__  /(__)\  )  ( 
(____)\___)(___/ \___)(__)(__)(_)\_){RESET}

    Identify for FINS protocol (OMRON)
       ver1.0 by 01dGu0 & Novy
__________________________________________
        ''')


def print_progress_bar():
    sys.stdout.write(f'\r{YELLOW}[SCHEDULE]{RESET} ' + YELLOW + "/" + RESET)
    sys.stdout.flush()
    time.sleep(0.2)
    sys.stdout.write(f'\r{YELLOW}[SCHEDULE]{RESET} ' + YELLOW + "-" + RESET)
    sys.stdout.flush()
    time.sleep(0.2)
    sys.stdout.write(f'\r{YELLOW}[SCHEDULE]{RESET} ' + YELLOW + "\\" + RESET)
    sys.stdout.flush()
    time.sleep(0.2)
    sys.stdout.write(f'\r{YELLOW}[SCHEDULE]{RESET} ' + YELLOW + "|" + RESET)
    sys.stdout.flush()
    time.sleep(0.2)


def parse_fins_response(response):
    try:
        if len(response) < 16:
            return None, None, None, None
        
        if response[0:4] != b'FINS':
            return None, None, None, None
        
        length = struct.unpack('>I', response[4:8])[0]
        
        command = struct.unpack('>I', response[8:12])[0]
        
        error_code = struct.unpack('>I', response[12:16])[0]
        
        if error_code != 0:
            return None, None, None, None
        
        offset = 16
        
        offset += 10
        
        if len(response) > offset + 2:
            response_code = struct.unpack('>H', response[offset:offset+2])[0]
            offset += 2
            
            if response_code != 0:
                return None, None, None, None
        
        model = "OMRON PLC"
        version = "Unknown"
        cpu_unit = "Unknown"
        system_version = "Unknown"
        
        if len(response) > offset + 40:
            model_data = response[offset:offset+20]
            model_str = model_data.decode('ascii', errors='ignore').strip('\x00').strip()
            if model_str:
                model = f"OMRON {model_str}"
            offset += 20
            
            version_data = response[offset:offset+20]
            version_str = version_data.decode('ascii', errors='ignore').strip('\x00').strip()
            if version_str:
                version = version_str
            offset += 20
            
            if len(response) > offset + 4:
                sys_ver_major = response[offset]
                sys_ver_minor = response[offset+1]
                sys_ver_revision = response[offset+2]
                system_version = f"{sys_ver_major}.{sys_ver_minor}.{sys_ver_revision}"
                offset += 4
            
            if len(response) > offset + 16:
                cpu_data = response[offset:offset+16]
                cpu_str = cpu_data.decode('ascii', errors='ignore').strip('\x00').strip()
                if cpu_str:
                    cpu_unit = cpu_str
        
        return model, version, cpu_unit, system_version
        
    except Exception as e:
        return None, None, None, None


def send_fins_request(ip, port=9600, timeout=5):
    print(f'{YELLOW}[CURRENT INFO] {RESET} {ip}')

    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.settimeout(timeout)
    
    try:
        progress_bar_length = 8
        for _ in range(progress_bar_length):
            print_progress_bar()

        client.connect((ip, port))
        
        fins_node_request = bytes([
            0x46, 0x49, 0x4E, 0x53,
            0x00, 0x00, 0x00, 0x0C,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ])
        
        client.sendall(fins_node_request)
        node_response = client.recv(1024)
        
        if len(node_response) < 24:
            raise Exception("节点地址响应异常")
        
        client_node = node_response[19]
        server_node = node_response[23]
        
        fins_header = bytes([
            0x46, 0x49, 0x4E, 0x53,
            0x00, 0x00, 0x00, 0x1A,
            0x00, 0x00, 0x00, 0x02,
            0x00, 0x00, 0x00, 0x00,
        ])
        
        fins_command = bytes([
            0x80,
            0x00,
            0x02,
            0x00,
            server_node,
            0x00,
            0x00,
            client_node,
            0x00,
            0x00,
            0x05, 0x01,
        ])
        
        fins_request = fins_header + fins_command
        
        client.sendall(fins_request)
        
        response = client.recv(1024)
        
        if not response or len(response) < 16:
            print(f"\n{YELLOW}[PROMPT] {RESET}{ip}:{port}")
            addr = f"{ip}:{port}"
            print_result(addr, "未识别", "当前为工控设备但无法识别详细信息", "-", "-")
        else:
            model, version, cpu_unit, system_version = parse_fins_response(response)
            
            if model is None:
                print(f"\n{YELLOW}[PROMPT] {RESET}{ip}:{port}")
                addr = f"{ip}:{port}"
                print_result(addr, "未识别", "当前为工控设备但无法识别详细信息", "-", "-")
            else:
                print(f"\n{GREEN}[+] {RESET}{ip}:{port}")
                addr = f"{ip}:{port}"
                print_result(addr, model, version, cpu_unit, system_version)
                return f"{addr}|{model}|{version}|{cpu_unit}|{system_version}\n"
        
    except socket.timeout:
        print(f"\n{ORANGE}[ERROR] {RESET}{ip}:{port} - 响应超时，当前目标可能不是FINS协议或者目标不是工控设备")
        pass
    except ConnectionRefusedError:
        print(f"\n{ORANGE}[ERROR] {RESET}{ip}:{port} - 连接被拒绝")
        pass
    except Exception as e:
        print(f"\n{ORANGE}[ERROR] {RESET}{ip}:{port} : {e}")
        pass
    finally:
        client.close()
    
    return None


def scan_subnet(subnet, port=9600):
    for ip in ip_network(subnet):
        send_fins_request(str(ip), port)


if __name__ == "__main__":
    print_copyright()
    if len(sys.argv) < 2:
        print(f"""
{ORANGE}[ERROR] {RESET}Please enter the IP or IP segment, e.g.
python FINS_InfoScan.py 0.0.0.0 --default 9600
python FINS_InfoScan.py 0.0.0.0:9600
python FINS_InfoScan.py 0.0.0.0/24
            """)
        sys.exit(1)
    
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    filename = f"FINS_results_{timestamp}.txt"
    target = sys.argv[1]
    
    if '-' in target:
        for ipa in parse_ip_range(target):
            result = send_fins_request(str(ipaddress.IPv4Address(ipa)))
            if result:
                save_result_to_file(result, filename)
    elif '/' in target:
        for ipb in ipaddress.IPv4Network(target, strict=False):
            result = send_fins_request(str(ipb))
            if result:
                save_result_to_file(result, filename)
    else:
        if ':' in target:
            ipc, port_str = target.split(':')
            porta = int(port_str)
        else:
            ipc = target
            porta = 9600
        result = send_fins_request(ipc, porta)
        if result:
            save_result_to_file(result, filename)
    
    print(f'\n{GREEN}[FILE]{RESET}：{filename}')
