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


def print_result(addr, vendor, product_name, serial, revision):
    table = PrettyTable()
    table.field_names = ["addr", "vendor", "product_name", "serial", "revision"]
    table.add_row([addr, vendor, product_name, serial, revision])
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

    Identify for CIP/EtherNet/IP protocol
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


def parse_cip_identity(response):
    try:
        if len(response) < 63:
            return None, None, None, None
        
        offset = 24
        
        offset += 6
        
        offset += 4
        
        item2_type = struct.unpack('<H', response[offset:offset+2])[0]
        item2_length = struct.unpack('<H', response[offset+2:offset+4])[0]
        offset += 4
        
        offset += 4
        
        vendor_id = struct.unpack('<H', response[offset:offset+2])[0]
        offset += 2
        
        device_type = struct.unpack('<H', response[offset:offset+2])[0]
        offset += 2
        
        product_code = struct.unpack('<H', response[offset:offset+2])[0]
        offset += 2
        
        revision_major = response[offset]
        revision_minor = response[offset+1]
        revision = f"{revision_major}.{revision_minor}"
        offset += 2
        
        offset += 2
        
        serial_number = struct.unpack('<I', response[offset:offset+4])[0]
        offset += 4
        
        product_name_len = response[offset]
        offset += 1
        
        product_name = response[offset:offset+product_name_len].decode('ascii', errors='ignore')
        vendor_map = {
            1: "Rockwell Automation/Allen-Bradley",
            2: "Namco Controls",
            3: "Honeywell",
            5: "Keyence",
            10: "Stratus",
            12: "Phoenix Contact",
            18: "Square D/Schneider Electric",
            42: "Omron",
            52: "Parker Hannifin",
            64: "Numatics",
            73: "Belden",
            89: "Pepperl+Fuchs",
            107: "SICK AG",
            125: "Siemens",
            135: "Mitsubishi Electric",
            157: "Turck",
            186: "SMC Corporation",
            283: "Festo",
        }
        
        vendor = vendor_map.get(vendor_id, f"Unknown (ID: {vendor_id})")
        
        return vendor, product_name, f"0x{serial_number:08X}", revision
        
    except Exception as e:
        return None, None, None, None


def send_cip_request(ip, port=44818, timeout=5):
    print(f'{YELLOW}[CURRENT INFO] {RESET} {ip}')

    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.settimeout(timeout)
    
    try:
        progress_bar_length = 8
        for _ in range(progress_bar_length):
            print_progress_bar()

        client.connect((ip, port))
        
        list_identity = bytes([
            0x63, 0x00,
            0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00
        ])
        
        client.sendall(list_identity)
        
        response = client.recv(1024)
        
        if not response or len(response) < 24:
            print(f"\n{YELLOW}[PROMPT] {RESET}{ip}:{port}")
            addr = f"{ip}:{port}"
            print_result(addr, "未识别", "当前为工控设备但无法识别详细信息", "-", "-")
        else:
            vendor, product_name, serial, revision = parse_cip_identity(response)
            
            if vendor is None:
                print(f"\n{YELLOW}[PROMPT] {RESET}{ip}:{port}")
                addr = f"{ip}:{port}"
                print_result(addr, "未识别", "当前为工控设备但无法识别详细信息", "-", "-")
            else:
                print(f"\n{GREEN}[+] {RESET}{ip}:{port}")
                addr = f"{ip}:{port}"
                print_result(addr, vendor, product_name, serial, revision)
                return f"{addr}|{vendor}|{product_name}|{serial}|{revision}\n"
        
    except socket.timeout:
        print(f"\n{ORANGE}[ERROR] {RESET}{ip}:{port} - 响应超时，当前目标可能不是CIP协议或者目标不是工控设备")
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


def scan_subnet(subnet, port=44818):
    for ip in ip_network(subnet):
        send_cip_request(str(ip), port)


if __name__ == "__main__":
    print_copyright()
    if len(sys.argv) < 2:
        print(f"""
{ORANGE}[ERROR] {RESET}Please enter the IP or IP segment, e.g.
python CIP_InfoScan.py 0.0.0.0 --default 44818
python CIP_InfoScan.py 0.0.0.0:44818
python CIP_InfoScan.py 0.0.0.0/24
            """)
        sys.exit(1)
    
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    filename = f"CIP_results_{timestamp}.txt"
    target = sys.argv[1]
    
    if '-' in target:
        for ipa in parse_ip_range(target):
            result = send_cip_request(str(ipaddress.IPv4Address(ipa)))
            if result:
                save_result_to_file(result, filename)
    elif '/' in target:
        for ipb in ipaddress.IPv4Network(target, strict=False):
            result = send_cip_request(str(ipb))
            if result:
                save_result_to_file(result, filename)
    else:
        if ':' in target:
            ipc, port_str = target.split(':')
            porta = int(port_str)
        else:
            ipc = target
            porta = 44818
        result = send_cip_request(ipc, porta)
        if result:
            save_result_to_file(result, filename)
    
    print(f'\n{GREEN}[FILE]{RESET}：{filename}')
