#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ICS设备指纹识别工具 - 统一扫描器
支持协议: Modbus, S7, CIP/EtherNet/IP, UMAS, FINS
"""

import socket
import sys
import argparse
from ipaddress import ip_network
import ipaddress
import time
from datetime import datetime
import struct
from binascii import unhexlify, hexlify

GREEN = '\033[92m'
YELLOW = '\033[93m'
RESET = '\033[0m'
ORANGE = '\033[91m'
BLUE = '\033[94m'
CYAN = '\033[96m'


def print_copyright():
    print(f'''
__________________________________________
{GREEN} ____  ___  ___   ___    __    _  _ 
(_  _)/ __)/ __) / __)  /__\  ( \( )
 _)(_( (__ \__ \( (__  /(__)\  )  ( 
(____)\___)(___/ \___)(__)(__)(_)\_){RESET}

   {CYAN}ICS Multi-Protocol Scanner{RESET}
   Modbus | S7 | CIP | UMAS | FINS
      ver2.0 by 01dGu0 & Novy
__________________________________________
        ''')


def print_progress_bar():
    sys.stdout.write(f'\r{YELLOW}[SCAN]{RESET} ' + YELLOW + "/" + RESET)
    sys.stdout.flush()
    time.sleep(0.1)
    sys.stdout.write(f'\r{YELLOW}[SCAN]{RESET} ' + YELLOW + "-" + RESET)
    sys.stdout.flush()
    time.sleep(0.1)
    sys.stdout.write(f'\r{YELLOW}[SCAN]{RESET} ' + YELLOW + "\\" + RESET)
    sys.stdout.flush()
    time.sleep(0.1)
    sys.stdout.write(f'\r{YELLOW}[SCAN]{RESET} ' + YELLOW + "|" + RESET)
    sys.stdout.flush()
    time.sleep(0.1)


def parse_ip_range(ip_range):
    """解析IP范围,返回[(ip, port)]列表"""
    results = []
    
    if ':' in ip_range and '/' not in ip_range:
        if '-' not in ip_range:
            ip_part, port_part = ip_range.rsplit(':', 1)
            try:
                port = int(port_part)
                results.append((ip_part, port))
                return results
            except ValueError:
                pass
    

    if '-' in ip_range:
        start, end = ip_range.split('-')
        start_ip = ipaddress.IPv4Address(start.strip())
        try:
            end_ip = ipaddress.IPv4Address(end.strip())
            for i in range(int(start_ip), int(end_ip) + 1):
                results.append((str(ipaddress.IPv4Address(i)), None))
        except ipaddress.AddressValueError:
            results.append((start, None))
    elif '/' in ip_range:
        for ip in ipaddress.IPv4Network(ip_range, strict=False).hosts():
            results.append((str(ip), None))
    else:
        results.append((ip_range, None))
    
    return results


def save_result_to_file(result, filename):

    with open(filename, 'a', encoding='utf-8') as f:
        f.write(result)


# ==================== Modbus协议 ====================
def scan_modbus(ip, port=None, timeout=3):

    if port is None:
        port = 502
    try:
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.settimeout(timeout)
        client.connect((ip, port))
        

        request_data = bytes.fromhex("00 00 00 00 00 05 00 2b 0e 01 00")
        client.sendall(request_data)
        response = client.recv(1024)
        client.close()
        
        if not response or len(response) < 14:
            return None, None
        

        try:
            off = 0

            if len(response) < off+7:
                return None, None
            off += 7

            if response[off] != 0x2B:
                return None, None
            off += 1
            if response[off] != 0x0E:
                return None, None
            off += 1

            if len(response) < off+5:
                return None, None
            read_dev_id_code = response[off]; off += 1
            conform = response[off]; off += 1
            more_follows = response[off]; off += 1
            next_object_id = response[off]; off += 1
            number_of_objects = response[off]; off += 1
            
            vendor = ''
            model = ''
            rev = ''
            extras = []
            
            for _ in range(number_of_objects):
                if len(response) < off+2:
                    break
                obj_id = response[off]; off += 1
                obj_len = response[off]; off += 1
                if len(response) < off+obj_len:
                    break
                val = response[off:off+obj_len].decode('ascii', errors='ignore').strip()
                off += obj_len
                if obj_id == 0x00:
                    vendor = val
                elif obj_id == 0x01:
                    model = val
                elif obj_id == 0x02:
                    rev = val
                else:
                    extras.append(val)
            
            if vendor or model or rev:
                parts = []
                if vendor: parts.append(f"VENDOR={vendor}")
                if model: parts.append(f"MODEL={model}")
                if rev: parts.append(f"REV={rev}")
                if extras: parts.append("EXTRA=" + "/".join(extras))
                return "Modbus", "|".join(parts)
            else:

                ascii_text = response.decode('ascii', errors='ignore')
                printable = ''.join(ch for ch in ascii_text if ch.isprintable())
                if printable:
                    cleaned = printable
                    if '+' in cleaned:
                        cleaned = cleaned.split('+', 1)[1]
                    return "Modbus", cleaned.strip()
                return "Modbus", "设备响应但无详细信息"
        except Exception:

            ascii_text = response.decode('ascii', errors='ignore')
            printable = ''.join(ch for ch in ascii_text if ch.isprintable())
            if printable:
                cleaned = printable
                if '+' in cleaned:
                    cleaned = cleaned.split('+', 1)[1]
                return "Modbus", cleaned.strip()
            return "Modbus", "设备响应但无详细信息"
    except:
        pass
    return None, None


# ==================== S7协议 ====================
def getSZL001c(Respons):
    result = ''
    for i in range(int(len(Respons) / 68)):
        data = Respons[i * 68 + 4:i * 68 + 68].replace("00", "")
        try:
            if unhexlify(data).decode("utf-8", "ignore") != "":
                result += unhexlify(data).decode("utf-8", "ignore") + ' '
        except:
            pass
    return result.strip()


def getSZL0011(Respons):
    result = ''
    for i in range(int(len(Respons) / 56)):
        data = Respons[i * 56 + 4:i * 56 + 56].replace("00", "")
        try:
            if unhexlify(data).decode("utf-8", "ignore") != "":
                result += unhexlify(data).decode("utf-8", "ignore") + ' '
        except:
            pass
    return result.strip()


def scan_s7(ip, port=None, timeout=3):

    if port is None:
        port = 102
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))
        
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
        
        sock.close()
        
        info = f"{result_c} {result_1}".strip()
        if info:
            return "Siemens S7", info
    except:
        pass
    return None, None


# ==================== CIP协议 ====================
def scan_cip(ip, port=None, timeout=3):

    if port is None:
        port = 44818
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        
        # RegisterSession (0x65)
        reg_header = struct.pack('<HHI I 8s I', 0x0065, 4, 0, 0, b'\x00'*8, 0)
        reg_payload = struct.pack('<HH', 1, 0)
        s.sendall(reg_header + reg_payload)
        reg_resp = s.recv(1024)
        if len(reg_resp) < 24:
            s.close()
            return None, None
        session_handle = struct.unpack('<I', reg_resp[4:8])[0]
        

        cip = bytes([0x01, 0x02, 0x20, 0x01, 0x24, 0x01])
        

        rr_body = struct.pack('<IHH', 0, 0, 2)
        rr_body += struct.pack('<HH', 0x0000, 0x0000)
        rr_body += struct.pack('<HH', 0x00B2, len(cip))
        rr_body += cip
        rr_header = struct.pack('<HHI I 8s I', 0x006F, len(rr_body), session_handle, 0, b'\x00'*8, 0)
        s.sendall(rr_header + rr_body)
        resp = s.recv(2048)
        s.close()
        
        if not resp or len(resp) < 24+8:
            return None, None
        

        off = 24
        interface_handle, timeout_val, item_count = struct.unpack('<IHH', resp[off:off+8]); off += 8

        addr_type, addr_len = struct.unpack('<HH', resp[off:off+4]); off += 4 + addr_len

        data_type, data_len = struct.unpack('<HH', resp[off:off+4]); off += 4
        cip_resp = resp[off:off+data_len]
        if len(cip_resp) < 8:
            return None, None
        

        if cip_resp[0] != 0x81:
            return None, None
        status = struct.unpack('<H', cip_resp[2:4])[0]
        if status != 0:
            return None, None
        
        pos = 4
        if len(cip_resp) < pos+13:
            return None, None
        vendor_id = struct.unpack('<H', cip_resp[pos:pos+2])[0]; pos += 2
        device_type = struct.unpack('<H', cip_resp[pos:pos+2])[0]; pos += 2
        product_code = struct.unpack('<H', cip_resp[pos:pos+2])[0]; pos += 2
        rev_major = cip_resp[pos]; rev_minor = cip_resp[pos+1]; pos += 2
        status_word = struct.unpack('<H', cip_resp[pos:pos+2])[0]; pos += 2
        serial = struct.unpack('<I', cip_resp[pos:pos+4])[0]; pos += 4
        name_len = cip_resp[pos] if len(cip_resp) > pos else 0; pos += 1
        prod_name = cip_resp[pos:pos+name_len].decode('ascii', errors='ignore') if name_len and len(cip_resp) >= pos+name_len else ''
        
        vendor_map = {1:'Rockwell/AB',18:'Schneider',42:'Omron',125:'Siemens',283:'Festo',52:'Parker'}
        vendor = vendor_map.get(vendor_id, f'VID:{vendor_id}')
        info = f"VENDOR={vendor}|MODEL={prod_name}|CODE={product_code}|REV={rev_major}.{rev_minor}|SN=0x{serial:08X}"
        return 'CIP/EtherNet/IP', info
    except Exception:
        return None, None


# ==================== UMAS协议 ====================
def scan_umas(ip, port=None, timeout=3):

    if port is None:
        port = 1152
    try:
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.settimeout(timeout)
        client.connect((ip, port))
        

        try:
            client.sendall(b"\x00\x00\x00\x00")
        except Exception:
            pass
        response = client.recv(1024)
        client.close()
        

        if response and len(response) > 0:
            return "UMAS", "VENDOR=Schneider Electric|PRODUCT=Modicon|PROTOCOL=UMAS"
    except:
        pass
    return None, None


# ==================== FINS协议 ====================
def scan_fins(ip, port=None, timeout=3, debug=False):

    if port is None:
        port = 9600
    

    try:
        client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        client.settimeout(timeout)
        

        fins_request = bytes([
            0x80, 0x00, 0x02,  
            0x00, 0x00, 0x00,  
            0x00, 0x01, 0x00,  
            0x00,              
            0x05, 0x01         
        ])
        
        client.sendto(fins_request, (ip, port))
        response, _ = client.recvfrom(1024)
        client.close()
        
        if debug:
            print(f'{CYAN}[FINS调试]{RESET} UDP响应长度: {len(response)}')
            print(f'{CYAN}[FINS调试]{RESET} 响应hex: {response.hex()[:100]}...')
            print(f'{CYAN}[FINS调试]{RESET} 响应首字节: 0x{response[0]:02X}')
        
        if response and len(response) > 10:

            if response[0] == 0xC0:
                info = "OMRON PLC"
                

                found_model = False
                for offset in [14, 12, 16, 20]:
                    if len(response) > offset + 20:
                        try:
                            model_data = response[offset:offset+20].decode('ascii', errors='ignore').strip('\x00').strip()
                            if model_data and len(model_data) > 2:
                                info = f"OMRON {model_data}"
                                found_model = True
                                if debug:
                                    print(f'{CYAN}[FINS调试]{RESET} 在偏移{offset}找到型号: {model_data}')
                                break
                        except:
                            pass
                

                if not found_model and len(response) > 20:
                    try:
                        full_data = response[10:].decode('ascii', errors='ignore').strip('\x00').strip()
                        if full_data and len(full_data) > 3:
                            info = f"OMRON {full_data[:40]}"
                            if debug:
                                print(f'{CYAN}[FINS调试]{RESET} 完整数据: {full_data[:60]}')
                    except:
                        pass
                

                try:
                    payload_ascii = response.decode('ascii', errors='ignore')
                except:
                    payload_ascii = ''
                ver_match = None
                fields = {}
                if payload_ascii:
                    import re
                    m = re.search(r'\b\d{2}\.\d{2}\b', payload_ascii)
                    if m:
                        ver_match = m.group(0)

                    def get_field(label, text):
                        m2 = re.search(label + r'\s*:\s*(.*)', text)
                        return m2.group(1).strip() if m2 else None
                    mapping = [
                        ('MODE', r'Controller Mode'),
                        ('VERSION', r'Controller Version'),
                        ('PROGRAM_AREA', r'Program Area Size'),
                        ('IOM', r'IOM Size'),
                        ('DM_WORDS', r'No\. of DM Words'),
                        ('TIMER_COUNTER', r'Timer/Counter Size'),
                        ('EXP_DM', r'Expansion DM Size'),
                        ('STEPS', r'No\. of steps/transitions'),
                        ('MEMCARD', r'Kind of Memory Card'),
                        ('MEMCARD_SIZE', r'Memory Card Size'),
                    ]
                    for key, label in mapping:
                        val = get_field(label, payload_ascii)
                        if val:
                            fields[key] = val
                return "FINS", info
    except Exception as e:
        if debug:
            print(f'{CYAN}[FINS调试]{RESET} UDP失败: {e}')
        pass
    

    try:
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.settimeout(timeout)
        client.connect((ip, port))
        

        fins_node_request = bytes([
            0x46, 0x49, 0x4E, 0x53,  # Magic: 'FINS'
            0x00, 0x00, 0x00, 0x0C,  # Length: 12
            0x00, 0x00, 0x00, 0x01,  # Command: 1 (Node Address Request)
            0x00, 0x00, 0x00, 0x00,  # Error Code: 0
            0x00, 0x00, 0x00, 0x00,  # Client Node Address (auto)
        ])
        
        client.sendall(fins_node_request)
        node_response = client.recv(1024)
        
        if debug:
            print(f'{CYAN}[FINS调试]{RESET} 节点地址响应长度: {len(node_response)}')
            print(f'{CYAN}[FINS调试]{RESET} 节点地址响应hex: {node_response.hex()}')
        

        if node_response[:4] == b'FINS':
            minimal_info = 'OMRON FINS/TCP'
        else:
            minimal_info = None
        
        if len(node_response) >= 24:

            client_node = node_response[19]
            server_node = node_response[23]
            
            if debug:
                print(f'{CYAN}[FINS调试]{RESET} 客户端节点: 0x{client_node:02X}, 服务器节点: 0x{server_node:02X}')
            

            fins_header = bytes([
                0x46, 0x49, 0x4E, 0x53,  # Magic: 'FINS'
                0x00, 0x00, 0x00, 0x1A,  # Length: 26
                0x00, 0x00, 0x00, 0x02,  # Command: 2 (FINS Frame Send)
                0x00, 0x00, 0x00, 0x00,  # Error Code: 0
            ])
            
            fins_command = bytes([
                0x80, 0x00, 0x02,        # ICF, RSV, GCT
                0x00, server_node, 0x00,  # DNA, DA1, DA2
                0x00, client_node, 0x00,  # SNA, SA1, SA2
                0x00,                     # SID
                0x05, 0x01                # Command: 读取控制器数据
            ])
            
            client.sendall(fins_header + fins_command)
            response = client.recv(1024)
            client.close()
            
            if debug:
                print(f'{CYAN}[FINS调试]{RESET} 控制器数据响应长度: {len(response)}')
                print(f'{CYAN}[FINS调试]{RESET} 控制器数据响应hex: {response.hex()[:200]}...')
            
            if response and len(response) > 30:
                offset = 26
                
                if len(response) > offset + 2:
                    resp_code = struct.unpack('>H', response[offset:offset+2])[0]
                    if debug:
                        print(f'{CYAN}[FINS调试]{RESET} 响应码: 0x{resp_code:04X}')
                    
                    offset += 2
                    
                    info_base = 'OMRON PLC'
                    model_data = ''
                    if len(response) > offset + 20:
                        try:
                            model_data = response[offset:offset+20].decode('ascii', errors='ignore').strip('\x00').strip()
                            if model_data and len(model_data) > 2:
                                info_base = f'OMRON {model_data}'
                                if debug:
                                    print(f'{CYAN}[FINS调试]{RESET} 找到型号: {model_data}')
                        except:
                            pass
                    
                    enc_err = struct.unpack('>I', response[12:16])[0] if len(response) >= 16 else 0
                    
                    try:
                        payload_ascii = response[offset+2:].decode('ascii', errors='ignore') if len(response) > offset+2 else ''
                    except:
                        payload_ascii = ''
                    ver_match = None
                    if payload_ascii:
                        import re
                        m = re.search(r'\b\d{2}\.\d{2}\b', payload_ascii)
                        if m:
                            ver_match = m.group(0)
                    
                    return 'FINS', info_base
            else:
                if minimal_info:
                    return 'FINS', minimal_info
    except Exception as e:
        if debug:
            print(f'{CYAN}[FINS调试]{RESET} TCP失败: {e}')
        pass
    return None, None


# ==================== 主扫描函数 ====================
def scan_target(ip, port=None, protocols='all', verbose=False, debug=False):

    results = []
    
    if verbose:
        port_info = f":{port}" if port else ""
        print(f'\n{BLUE}[TARGET]{RESET} {ip}{port_info}')
    
    protocol_scanners = {
        'modbus': (scan_modbus, 502),
        's7': (scan_s7, 102),
        'cip': (scan_cip, 44818),
        'umas': (scan_umas, 1152),
        'fins': (scan_fins, 9600)
    }
    
    if protocols == 'all':
        selected_protocols = list(protocol_scanners.keys())
    else:
        selected_protocols = [p.lower() for p in protocols.split(',')]
    
    if port:
        port_to_protocol = {v[1]: k for k, v in protocol_scanners.items()}
        priority_protocol = port_to_protocol.get(port, None)
        if priority_protocol and priority_protocol in selected_protocols:
            selected_protocols.remove(priority_protocol)
            selected_protocols.insert(0, priority_protocol)
        

        for proto_name in selected_protocols:
            if proto_name not in protocol_scanners:
                continue
                
            scanner_func, default_port = protocol_scanners[proto_name]
            target_port = port if (priority_protocol and proto_name == priority_protocol) else None
            
            if verbose:
                for _ in range(2):
                    print_progress_bar()
            
            used_port = target_port if target_port else default_port
            if proto_name == 'fins':
                protocol, info = scanner_func(ip, used_port, debug=debug)
            else:
                protocol, info = scanner_func(ip, used_port)
            
            if protocol and info:
                results.append({
                    'ip': f"{ip}:{used_port}",
                    'protocol': protocol,
                    'info': info
                })
                
                if verbose:
                    print(f'\r{GREEN}[+] {protocol:20s}{RESET} {info[:60]}')
    else:
        for proto_name in selected_protocols:
            if proto_name not in protocol_scanners:
                continue
                
            scanner_func, default_port = protocol_scanners[proto_name]
            
            if verbose:
                for _ in range(2):
                    print_progress_bar()
            
            if proto_name == 'fins':
                protocol, info = scanner_func(ip, None, debug=debug)
            else:
                protocol, info = scanner_func(ip, None)
            
            if protocol and info:
                results.append({
                    'ip': ip,
                    'protocol': protocol,
                    'info': info
                })
                
                if verbose:
                    print(f'\r{GREEN}[+] {protocol:20s}{RESET} {info[:60]}')
    
    return results


def print_results_table(all_results):

    if not all_results:
        print(f'\n{YELLOW}[INFO]{RESET} 未发现工控设备')
        return
    
    host_header = 'Host'
    proto_header = 'Protocol'
    info_header = 'Info'
    host_width = max(len(host_header), max(len(r['ip']) for r in all_results))
    proto_width = max(len(proto_header), max(len(r['protocol']) for r in all_results))
    host_width = min(host_width, 21)
    proto_width = min(proto_width, 18)
    info_width = 80
    
    def trunc(s, width):
        s = str(s).replace('\n', ' ').replace('\r', ' ').strip()
        if len(s) <= width:
            return s.ljust(width)
        return (s[:width-3] + '...').ljust(width)
    
    border = '+' + '-' * (host_width + 2) + '+' + '-' * (proto_width + 2) + '+' + '-' * (info_width + 2) + '+'
    print(f'\n{GREEN}[扫描结果]{RESET}')
    print(border)
    header_row = f"| {host_header.ljust(host_width)} | {proto_header.ljust(proto_width)} | {info_header.ljust(info_width)} |"
    print(header_row)
    print('+' + '-' * (host_width + 2) + '+' + '-' * (proto_width + 2) + '+' + '-' * (info_width + 2) + '+')
    
    for r in all_results:
        host = trunc(r['ip'], host_width)
        proto = trunc(r['protocol'], proto_width)
        info = trunc(r['info'], info_width)
        print(f"| {host} | {proto} | {info} |")
    
    print(border)


def export_results(all_results, filename):
    """导出结果到文件"""
    if not all_results:
        return
    
    with open(filename, 'w', encoding='utf-8') as f:
        for result in all_results:
            line = f"{result['ip']}|{result['protocol']}|{result['info']}\n"
            f.write(line)
    
    print(f'\n{GREEN}[文件]{RESET} 结果已保存至: {filename}')


def main():
    parser = argparse.ArgumentParser(
        description='ICS工控设备多协议指纹识别工具',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f'''
使用示例:
  {sys.argv[0]} -t 192.168.1.100                    # 扫描单个IP(所有协议默认端口)
  {sys.argv[0]} -t 192.168.1.100:502                # 扫描单个IP的502端口
  {sys.argv[0]} -t 192.168.1.0/24                   # 扫描IP段
  {sys.argv[0]} -t 192.168.1.1-192.168.1.254        # 扫描IP范围
  {sys.argv[0]} -t 192.168.1.100 -p modbus,s7       # 仅扫描指定协议
  {sys.argv[0]} -f targets.txt                      # 批量扫描(每行一个IP或IP:端口)
  {sys.argv[0]} -t 192.168.1.0/24 -o result.txt     # 保存结果到文件
  {sys.argv[0]} -t 192.168.1.100 -v                 # 详细输出模式

支持的协议:
  modbus  - Modbus TCP (默认端口502)
  s7      - Siemens S7 (默认端口102)
  cip     - CIP/EtherNet/IP (默认端口44818)
  umas    - UMAS/Yokogawa (默认端口20171)
  fins    - FINS/OMRON (默认端口9600)
        '''
    )
    
    parser.add_argument('-t', '--target', help='目标IP、IP段或IP:端口(如192.168.1.100:502)')
    parser.add_argument('-f', '--file', help='目标文件(每行一个IP)')
    parser.add_argument('-p', '--protocols', default='all', 
                        help='指定扫描协议(逗号分隔,默认all): modbus,s7,cip,umas,fins')
    parser.add_argument('-o', '--output', help='输出文件名')
    parser.add_argument('-v', '--verbose', action='store_true', help='详细输出模式')
    parser.add_argument('-d', '--debug', action='store_true', help='FINS协议调试模式')
    parser.add_argument('--timeout', type=int, default=3, help='连接超时时间(秒,默认3)')
    
    args = parser.parse_args()
    
    print_copyright()
    
    if not (args.target or args.file):
        parser.print_help()
        sys.exit(1)
    
    targets = []
    if args.target:
        targets.extend(parse_ip_range(args.target))
    
    if args.file:
        try:
            with open(args.file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        targets.extend(parse_ip_range(line))
        except FileNotFoundError:
            print(f'{ORANGE}[ERROR]{RESET} 文件不存在: {args.file}')
            sys.exit(1)
    
    if not targets:
        print(f'{ORANGE}[ERROR]{RESET} 没有有效的扫描目标')
        sys.exit(1)
    
    # 去重
    targets = list(set(targets))
    
    print(f'{CYAN}[INFO]{RESET} 目标数量: {len(targets)}')
    print(f'{CYAN}[INFO]{RESET} 扫描协议: {args.protocols}')
    print(f'{CYAN}[INFO]{RESET} 开始扫描...\n')
    
    # 执行扫描
    all_results = []
    start_time = time.time()
    
    for idx, target in enumerate(targets, 1):
        ip, port = target
        if not args.verbose:
            port_info = f":{port}" if port else ""
            print(f'\r{YELLOW}[进度]{RESET} {idx}/{len(targets)} - {ip}{port_info}', end='', flush=True)
        
        # 调试输出
        if args.debug and port:
            print(f'\n{CYAN}[调试]{RESET} 开始扫描 {ip}:{port} 的所有协议...')
        
        results = scan_target(ip, port, args.protocols, args.verbose, args.debug)
        
        # 调试输出
        if args.debug:
            print(f'{CYAN}[调试]{RESET} 扫描完成,发现 {len(results)} 个结果')
            for r in results:
                print(f'{CYAN}[调试]{RESET} - {r["protocol"]}: {r["info"][:50]}...')
        
        all_results.extend(results)
    
    elapsed_time = time.time() - start_time
    
    if not args.verbose:
        print()  # 换行
    
    # 显示结果
    print_results_table(all_results)
    
    print(f'\n{CYAN}[统计]{RESET} 扫描目标: {len(targets)} | 发现设备: {len(all_results)} | 耗时: {elapsed_time:.2f}秒')
    
    # 导出结果
    if args.output:
        export_results(all_results, args.output)


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print(f'\n\n{YELLOW}[INFO]{RESET} 用户中断扫描')
        sys.exit(0)
