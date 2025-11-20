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


def print_result(addr, device_type, cpu_info, rom_version, ram_size):
    table = PrettyTable()
    table.field_names = ["addr", "device_type", "cpu_info", "rom_version", "ram_size"]
    table.add_row([addr, device_type, cpu_info, rom_version, ram_size])
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

    Identify for UMAS protocol (Yokogawa)
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


def parse_umas_response(response):
    """解析UMAS协议响应"""
    try:
        if len(response) < 10:
            return None, None, None, None
        
        # UMAS协议头部验证
        if response[0] != 0x01:  # STX
            return None, None, None, None
        
        # 提取设备信息
        device_type = "Yokogawa PLC/DCS"
        
        # 解析CPU信息
        cpu_info = "Unknown"
        rom_version = "Unknown"
        ram_size = "Unknown"
        
        # 尝试解析响应数据
        try:
            # UMAS响应格式解析
            offset = 10  # 跳过头部
            
            if len(response) > offset + 20:
                # 设备型号信息通常在特定偏移位置
                model_data = response[offset:offset+16]
                model_str = model_data.decode('ascii', errors='ignore').strip('\x00').strip()
                if model_str:
                    device_type = f"Yokogawa {model_str}"
                
                # CPU型号
                offset += 16
                if len(response) > offset + 10:
                    cpu_data = response[offset:offset+10]
                    cpu_str = cpu_data.decode('ascii', errors='ignore').strip('\x00').strip()
                    if cpu_str:
                        cpu_info = cpu_str
                
                # ROM版本
                offset += 10
                if len(response) > offset + 8:
                    rom_data = response[offset:offset+8]
                    rom_str = rom_data.decode('ascii', errors='ignore').strip('\x00').strip()
                    if rom_str:
                        rom_version = rom_str
                
                # RAM大小
                offset += 8
                if len(response) > offset + 4:
                    try:
                        ram_value = struct.unpack('>I', response[offset:offset+4])[0]
                        if ram_value > 0:
                            ram_size = f"{ram_value} KB"
                    except:
                        pass
        except:
            pass
        
        return device_type, cpu_info, rom_version, ram_size
        
    except Exception as e:
        return None, None, None, None


def send_umas_request(ip, port=20171, timeout=5):
    """发送UMAS设备信息查询请求"""
    print(f'{YELLOW}[CURRENT INFO] {RESET} {ip}')

    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.settimeout(timeout)
    
    try:
        progress_bar_length = 8
        for _ in range(progress_bar_length):
            print_progress_bar()

        client.connect((ip, port))
        
        umas_request = bytes([
            0x01,  # STX
            0x30, 0x30,  # 控制字段 00
            0x46, 0x46,  # CPU号 FF (广播)
            0x30, 0x30,  # 功能码 00
            0x30, 0x31,  # 子功能 01 (读取系统信息)
            0x30, 0x30, 0x30, 0x30,  # 数据长度 0000
            0x03,  # ETX
        ])
        

        bcc = 0
        for byte in umas_request[1:-1]:
            bcc ^= byte
        
        umas_request += bytes([bcc])
        
        client.sendall(umas_request)
        
        response = client.recv(1024)
        
        if not response or len(response) < 10:
            print(f"\n{YELLOW}[PROMPT] {RESET}{ip}:{port}")
            addr = f"{ip}:{port}"
            print_result(addr, "未识别", "当前为工控设备但无法识别详细信息", "-", "-")
        else:
            device_type, cpu_info, rom_version, ram_size = parse_umas_response(response)
            
            if device_type is None:
                print(f"\n{YELLOW}[PROMPT] {RESET}{ip}:{port}")
                addr = f"{ip}:{port}"
                print_result(addr, "未识别", "当前为工控设备但无法识别详细信息", "-", "-")
            else:
                print(f"\n{GREEN}[+] {RESET}{ip}:{port}")
                addr = f"{ip}:{port}"
                print_result(addr, device_type, cpu_info, rom_version, ram_size)
                return f"{addr}|{device_type}|{cpu_info}|{rom_version}|{ram_size}\n"
        
    except socket.timeout:
        print(f"\n{ORANGE}[ERROR] {RESET}{ip}:{port} - 响应超时，当前目标可能不是UMAS协议或者目标不是工控设备")
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


def scan_subnet(subnet, port=20171):
    for ip in ip_network(subnet):
        send_umas_request(str(ip), port)


if __name__ == "__main__":
    print_copyright()
    if len(sys.argv) < 2:
        print(f"""
{ORANGE}[ERROR] {RESET}Please enter the IP or IP segment, e.g.
python UMAS_InfoScan.py 0.0.0.0 --default 20171
python UMAS_InfoScan.py 0.0.0.0:20171
python UMAS_InfoScan.py 0.0.0.0/24
            """)
        sys.exit(1)
    
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    filename = f"UMAS_results_{timestamp}.txt"
    target = sys.argv[1]
    
    if '-' in target:
        for ipa in parse_ip_range(target):
            result = send_umas_request(str(ipaddress.IPv4Address(ipa)))
            if result:
                save_result_to_file(result, filename)
    elif '/' in target:
        for ipb in ipaddress.IPv4Network(target, strict=False):
            result = send_umas_request(str(ipb))
            if result:
                save_result_to_file(result, filename)
    else:
        if ':' in target:
            ipc, port_str = target.split(':')
            porta = int(port_str)
        else:
            ipc = target
            porta = 20171
        result = send_umas_request(ipc, porta)
        if result:
            save_result_to_file(result, filename)
    
    print(f'\n{GREEN}[FILE]{RESET}：{filename}')
