import socket
import argparse
from binascii import unhexlify, hexlify
from datetime import datetime
import ipaddress
from prettytable import PrettyTable
import sys
import time

GREEN = '\033[92m'
YELLOW = '\033[93m'
RESET = '\033[0m'
ORANGE = '\033[91m'

def getSZL001c(Respons):
    result = ''
    for i in range(int(len(Respons) / 68)):
        data = Respons[i * 68 + 4:i * 68 + 68].replace("00", "")
        try:
            if unhexlify(data).decode("utf-8", "ignore") != "":
                result += unhexlify(data).decode("utf-8", "ignore") + '\n'
        except:
            pass
    return result or ''

def getSZL0011(Respons):
    result = ''
    for i in range(int(len(Respons) / 56)):
        data = Respons[i * 56 + 4:i * 56 + 56].replace("00", "")
        try:
            if unhexlify(data).decode("utf-8", "ignore") != "":
                result += unhexlify(data).decode("utf-8", "ignore") + '\n'
        except:
            pass
    return result or ''

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

    Identify for Siemens equipment
       ver1.0 by 01dGu0 & Novy
__________________________________________
        ''')

def print_result(ip_address, result_c, result_1):
    table = PrettyTable()
    table.field_names = ["ip", "product", "other"]
    table.add_row([ip_address, result_c, result_1])
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

def main(ip_address):
    try:
        print(f'{GREEN}[CUTRENT INFO] {RESET} {ip_address}')

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((ip_address, 102))

        progress_bar_length = 20
        for _ in range(progress_bar_length):
            print_progress_bar()

        print(f'\r{GREEN}[SCHEDULE]{RESET} {YELLOW}Done.{RESET}\n')

        sock.send(unhexlify("0300001611e00000000100c0010ac1020100c2020102"))
        sock.recv(1024)
        sock.send(unhexlify("0300001902f08032010000080000080000f0000001000101e0"))
        sock.recv(1024)
        sock.send(unhexlify("0300002102f080320700000a00000800080001120411440100ff090004001c0000"))
        Respons = (hexlify(sock.recv(1024)).decode())[82:]
        result_c = getSZL001c(Respons)

        sock.send(unhexlify("0300002102f080320700000a00000800080001120411440100ff09000400110000"))
        Respons = (hexlify(sock.recv(1024)).decode())[82:]
        result_1 = getSZL0011(Respons)

        print_result(ip_address, result_c, result_1)

        sock.close()
        return result_c, result_1
    except Exception as e:
        print(f'{ORANGE}[ERROR]{RESET} {e}')
        pass
    return None, None

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-f', '--file', help='Specify txt file, batch scanning, one IP per line')
    parser.add_argument('-p', '--ip', help='Specify IP or IP range (e.g., 192.168.1.1 or 192.168.1.0/24)')

    args = parser.parse_args()

    if not (args.file or args.ip):
        print_copyright()
        parser.print_help()
        print(f'\n{ORANGE}[ERROR]{RESET} Please provide at least one parameter (-f or -p).')
    else:
        print_copyright()
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        filename = f"Siemens_results_{timestamp}.txt"

        if args.file:
            print(f'{GREEN}[TARGET] {RESET}', args.file)
            with open(args.file, 'r') as file:
                for line in file:
                    ip = line.strip()
                    if '-' in ip:
                        for ip in parse_ip_range(ip):
                            result_c, result_1 = main(str(ip))
                            if result_c is not None and result_1 is not None:
                                save_result_to_file(result_c + result_1, filename)
                    elif '/' in ip:
                        for ip in ipaddress.IPv4Network(ip, strict=False):
                            result_c, result_1 = main(str(ip))
                            if result_c is not None and result_1 is not None:
                                save_result_to_file(result_c + result_1, filename)
                    else:
                        result_c, result_1 = main(ip)
                        if result_c is not None and result_1 is not None:
                            save_result_to_file(result_c + result_1, filename)
        elif args.ip:
            print(f'{GREEN}[TARGET] {RESET}', args.ip)
            if '-' in args.ip:
                for ip in parse_ip_range(args.ip):
                    result_c, result_1 = main(str(ip))
                    if result_c is not None and result_1 is not None:
                        save_result_to_file(result_c + result_1, filename)
            elif '/' in args.ip:
                for ip in ipaddress.IPv4Network(args.ip, strict=False):
                    result_c, result_1 = main(str(ip))
                    if result_c is not None and result_1 is not None:
                        save_result_to_file(result_c + result_1, filename)
            else:
                result_c, result_1 = main(args.ip)
                if result_c is not None and result_1 is not None:
                    save_result_to_file(result_c + result_1, filename)

        print(f'{GREEN}[FILE]{RESET}：{filename}')
