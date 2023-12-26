import socket
import sys
from ipaddress import ip_network
import ipaddress
import time
from datetime import datetime
from prettytable import PrettyTable

GREEN = '\033[92m'
YELLOW = '\033[93m'
RESET = '\033[0m'
ORANGE = '\033[91m'


def print_result(addr,printable_response):
    table = PrettyTable()
    table.field_names = ["addr", "info"]
    table.add_row([addr, printable_response])
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

    Identify for Schneider PLC
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

def send_modbus_request(ip, port=502, request_data="00 00 00 00 00 05 00 2b 0e 01 00", timeout=5):
    print(f'{YELLOW}[CUTRENT INFO] {RESET} {ip}')
    # 创建 socket 对象
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.settimeout(timeout)  # 设置超时,默认五秒如果嫌长可以缩短
    
    try:
        progress_bar_length = 8
        for _ in range(progress_bar_length):
            print_progress_bar()
        # print("\n")
        # 连接到服务器
        client.connect((ip, port))
        
        # 发送请求数据
        request_bytes = bytes.fromhex(request_data)
        client.sendall(request_bytes)
        
        # 接收响应数据
        response = client.recv(1024)
        
        # 如果返回为空或者响应长度不足
        if not response or len(response) < 5:
             print(f"\n{YELLOW}[PROMPT] {RESET}{ip}:{port}")
             addr = f"{ip}:{port}"
             print_result(addr,"当前为工控设备但无法识别详细信息")
        else:
            # 将响应数据转换为ASCII字符串，忽略无法解码的部分
            ascii_response = response.decode('ascii', errors='ignore')
            printable_response = ''.join(filter(lambda x: x.isprintable(), ascii_response))
            
            # 如果转换后的信息为空或长度低于五个字符就该这么办
            if not printable_response or len(printable_response) < 5:
                print(f"\n{YELLOW}[PROMPT] {RESET}{ip}:{port}")
                addr = f"{ip}:{port}"
                print_result(addr,"当前为工控设备但无法识别详细信息")
            else:
                print(f"\n{GREEN}[+] {RESET}{ip}:{port}")
                addr = f"{ip}:{port}"
                print_result(addr,printable_response)
        
    except socket.timeout:
        print(f"\n{ORANGE}[ERROR] {RESET}{ip}:{port} - 响应超时，当前目标可能不是Modbus协议或者目标不是工控设备")
        pass
    except Exception as e:
        print(f"\n{ORANGE}[ERROR] {RESET}{ip}:{port} : {e}")
        pass
    finally:
        client.close()

def scan_subnet(subnet, port=502):
    for ip in ip_network(subnet):
        send_modbus_request(str(ip), port)

# 如何使用
if __name__ == "__main__":
    print_copyright()
    if len(sys.argv) < 2:
        print(f"""
{ORANGE}[ERROR] {RESET}Please enter the IP or IP segment, e.g.
python script.py 0.0.0.0 --default 502
python script.py 0.0.0.0:502
python script.py 0.0.0.0/24
            """)
        sys.exit(1)
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    filename = f"Schneider_results_{timestamp}.txt"
    target = sys.argv[1]
    if '-' in target:
        for ipa in parse_ip_range(target):
            scan_subnet(str(ipa))
            # if result_c is not None and result_1 is not None:
            #     save_result_to_file(result_c + result_1, filename)
    elif '/' in target:
        for ipb in ipaddress.IPv4Network(target, strict=False):
            scan_subnet(str(ipb))
            # if result_c is not None and result_1 is not None:
            #     save_result_to_file(result_c + result_1, filename)
    else:
        if ':' in target:
            ipc, port_str = target.split(':')
            porta = int(port_str)
        else:
            ipc = target
            porta = 502
        send_modbus_request(ipc, porta)
        # if result_c is not None and result_1 is not None:
        #     save_result_to_file(result_c + result_1, filename)
