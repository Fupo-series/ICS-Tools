# ICS Tools
工控设备信息识别工具箱，旨在快速识别攻防演练中轨道交通、燃气、水利等行业内网场景、传统工业内网中的工业控制设备型号与指纹。工具相比ISF和NMAP等更简单易用且体积更小，支持多协议统一扫描与精准识别。

注意:识别和显示上可能会有点Bug,但是我并没有进行全面的测试,如果遇到bug和错误请务必提Issues告知我,当然如果你希望添加新功能也可以告诉我！！！！！

## 🚀 快速开始 - 推荐使用统一扫描器
```bash
python3 ICS_Scanner.py -t 192.168.1.100

python3 ICS_Scanner.py -t 192.168.1.0/24

python3 ICS_Scanner.py -t 192.168.1.100:9600

python3 ICS_Scanner.py -t 192.168.1.100 -p modbus,s7,cip

python3 ICS_Scanner.py -f targets.txt

python3 ICS_Scanner.py -t 192.168.1.0/24 -v -o result.txt
```

## 支持的协议
- ✅ **Modbus TCP** - 施耐德、罗克韦尔、华为等（端口502）
- ✅ **Siemens S7** - 西门子PLC（端口102）
- ✅ **CIP/EtherNet/IP** - 罗克韦尔AB、施耐德、欧姆龙、西门子等（端口44818）
- ✅ **UMAS** - 施耐德Modicon（端口1152）
- ✅ **FINS** - 欧姆龙PLC（端口9600，支持UDP/TCP）

## 核心特性
- 🎯 **多协议统一扫描**：一次性扫描Modbus、S7、CIP、UMAS、FINS五大协议，无需切换工具
- 🔍 **指纹识别精准**：提取厂商、型号、版本、序列号等关键设备信息
- 📊 **结果清晰直观**：表格化输出，Host:Port | 协议 | 设备信息，一目了然
- ⚡ **批量高效扫描**：支持单IP、IP:端口、CIDR段、IP范围、批量文件扫描
- 💾 **灵活结果保存**：可选保存到文件（-o 参数），管道分隔便于后处理
- 🛡️ **稳定容错**：超时保护、异常处理，避免扫描中断

## 注意事项
- 推荐使用 **ICS_Scanner.py** 统一扫描器，一次性覆盖所有协议
- 支持自定义端口识别（如 -t IP:端口），优先匹配该端口协议
- 部分设备信息可能返回为空或存在编码字符，后续持续优化
- 使用过程中如遇bug或识别异常请联系作者反馈

## 🔮 后续规划
- 🚧 **深度识别与解析**：扩展字段提取，增强设备详细信息（内存、I/O、配置等）
- 🚧 **工控设备连接**：支持会话建立、状态查询、参数读取
- 🚧 **指令执行**：安全模式下的读写测试与控制指令交互
- 🚧 **协议扩展**：增加DNP3、IEC-60870、BACnet、OPC UA等协议支持

以上功能正在考虑与测试中，后期将逐步添加。

---

# 统一扫描器使用说明
## ICS_Scanner.py - 多协议统一扫描工具
```bash
python3 ICS_Scanner.py -h

__________________________________________
 ____  ___  ___   ___    __    _  _
(_  _)/ __)/ __) / __)  /__\  ( \( )
 _)(_( (__ \__ \( (__  /(__)\  )  (
(____)\___)(___)\___)(__)(__)()\_)

   ICS Multi-Protocol Scanner
   Modbus | S7 | CIP | UMAS | FINS
      ver2.0 by 01dGu0 & Novy
__________________________________________

usage: ICS_Scanner.py [-h] [-t TARGET] [-f FILE] [-p PROTOCOLS] [-o OUTPUT] [-v] [-d] [--timeout TIMEOUT]

optional arguments:
  -h, --help            帮助信息
  -t TARGET, --target TARGET
                        目标IP或IP段（支持IP、IP:端口、CIDR、范围）
  -f FILE, --file FILE  目标文件（每行一个IP或IP:端口）
  -p PROTOCOLS, --protocols PROTOCOLS
                        指定扫描协议（逗号分隔：modbus,s7,cip,umas,fins；默认all）
  -o OUTPUT, --output OUTPUT
                        输出文件名（仅在指定时保存）
  -v, --verbose         详细输出模式
  -d, --debug           调试模式（显示FINS等协议的详细响应）
  --timeout TIMEOUT     连接超时时间（秒，默认3）
```

### 使用示例
```bash
python3 ICS_Scanner.py -t 192.168.1.100

python3 ICS_Scanner.py -t 192.168.1.100:9600

python3 ICS_Scanner.py -t 192.168.1.0/24

python3 ICS_Scanner.py -t 192.168.1.1-192.168.1.254

python3 ICS_Scanner.py -t 192.168.1.100 -p modbus,s7

python3 ICS_Scanner.py -f targets.txt

python3 ICS_Scanner.py -t 192.168.1.0/24 -v -o result.txt

python3 ICS_Scanner.py -t 192.168.1.100:9600 -p fins -d
```

### 输出格式
扫描结果以表格形式展示，每条记录包含：
- **Host**: 主机地址:端口
- **Protocol**: 识别协议（Modbus、Siemens S7、CIP/EtherNet/IP、UMAS、FINS）
- **Info**: 设备指纹信息（厂商|型号|版本|序列号等）

示例：
```
+---------------------+-----------------+----------------------------------------------------------------------------------+
| Host                | Protocol        | Info                                                                             |
+---------------------+-----------------+----------------------------------------------------------------------------------+
| 192.168.1.100:502   | Modbus          | VENDOR=Schneider Electric|MODEL=BMX P34 2020|REV=v3.01                          |
| 192.168.1.100:44818 | CIP/EtherNet/IP | VENDOR=Rockwell/AB|MODEL=1756-EN2T/D|CODE=166|REV=10.6|SN=0x00A7E2C6           |
| 192.168.1.100:9600  | FINS            | OMRON CJ2M-CPU31                                                                 |
+---------------------+-----------------+----------------------------------------------------------------------------------+
```

---

# 单独协议扫描器（可选）
当前工具箱同时提供单协议扫描器，适用于特定场景下的专项识别。推荐优先使用统一扫描器 ICS_Scanner.py。
## CIP/EtherNet/IP协议识别(罗克韦尔AB、施耐德等):
```bash
$ python3 CIP_InfoScan.py

__________________________________________
 ____  ___  ___   ___    __    _  _
(_  _)/ __)/ __) / __)  /__\  ( \( )
 _)(_( (__ \__ \( (__  /(__)\  )  (
(____)\___)(___/ \___)(__)(__)(_)\_)

    Identify for CIP/EtherNet/IP protocol
       ver1.0 by 01dGu0 & Novy
__________________________________________

[ERROR] Please enter the IP or IP segment, e.g.
python CIP_InfoScan.py 0.0.0.0 --default 44818
python CIP_InfoScan.py 0.0.0.0:44818
python CIP_InfoScan.py 0.0.0.0/24
```

## UMAS协议识别:
```bash
$ python3 UMAS_InfoScan.py

__________________________________________
 ____  ___  ___   ___    __    _  _
(_  _)/ __)/ __) / __)  /__\  ( \( )
 _)(_( (__ \__ \( (__  /(__)\  )  (
(____)\___)(___/ \___)(__)(__)(_)\_)

    Identify for UMAS protocol (Yokogawa)
       ver1.0 by 01dGu0 & Novy
__________________________________________

[ERROR] Please enter the IP or IP segment, e.g.
python UMAS_InfoScan.py 0.0.0.0 --default 20171
python UMAS_InfoScan.py 0.0.0.0:20171
python UMAS_InfoScan.py 0.0.0.0/24
```

## FINS协议识别:
```bash
$ python3 FINS_InfoScan.py

__________________________________________
 ____  ___  ___   ___    __    _  _
(_  _)/ __)/ __) / __)  /__\  ( \( )
 _)(_( (__ \__ \( (__  /(__)\  )  (
(____)\___)(___/ \___)(__)(__)(_)\_)

    Identify for FINS protocol (OMRON)
       ver1.0 by 01dGu0 & Novy
__________________________________________

[ERROR] Please enter the IP or IP segment, e.g.
python FINS_InfoScan.py 0.0.0.0 --default 9600
python FINS_InfoScan.py 0.0.0.0:9600
python FINS_InfoScan.py 0.0.0.0/24
```

## 西门子S7协议识别：
```bash
$ python3 SiemensPLC_InfoScan.py

__________________________________________
 ____  ___  ___   ___    __    _  _
(_  _)/ __)/ __) / __)  /__\  ( \( )
 _)(_( (__ \__ \( (__  /(__)\  )  (
(____)\___)(___/ \___)(__)(__)(_)\_)

    Identify for Siemens equipment
       ver1.0 by 01dGu0 & Novy
__________________________________________

usage: SiemensPLC_InfoScan.py [-h] [-f FILE] [-p IP]

optional arguments:
  -h, --help            show this help message and exit
  -f FILE, --file FILE  Specify txt file, batch scanning, one IP per line
  -p IP, --ip IP        Specify IP or IP range (e.g., 192.168.1.1 or 192.168.1.0/24)

[ERROR] Please provide at least one parameter (-f or -p).
```
## Modbus协议识别
```bash
$ python3 ModbusPLC_InfoScan.py

__________________________________________
 ____  ___  ___   ___    __    _  _
(_  _)/ __)/ __) / __)  /__\  ( \( )
 _)(_( (__ \__ \( (__  /(__)\  )  (
(____)\___)(___/ \___)(__)(__)(_)\_)

    Identify for Modbus protocol
       ver1.0 by 01dGu0 & Novy
__________________________________________


[ERROR] Please enter the IP or IP segment, e.g.
python script.py 0.0.0.0 --default 502
python script.py 0.0.0.0:502
python script.py 0.0.0.0/24
```
## 示例输出
以下为工具扫描真实工控设备的输出示例：
<img width="1690" height="760" alt="274ef3499d5ccdd2764b5572c29a43fc" src="https://github.com/user-attachments/assets/bbc3995b-4ac2-4e1a-bc85-5d07d0065f42" />
<img width="1636" height="758" alt="4495702fd4a03bbd1ca457e7e658d8c7" src="https://github.com/user-attachments/assets/d98c71d5-944a-4f86-912a-cb32ed3ff99e" />
<img width="1682" height="760" alt="e9f56a869479bd96d7aa128e5c9b4880" src="https://github.com/user-attachments/assets/64380dcb-167d-42dc-9a68-1ac53963fbeb" />
<img width="1686" height="756" alt="b93127378e859c8f5234086a1f539ffa" src="https://github.com/user-attachments/assets/aae08772-622b-4620-b003-389f43bc3b2c" />
<img width="1774" height="784" alt="54b11a3b672ec0925b7053d4032bfbc7" src="https://github.com/user-attachments/assets/81590894-32b0-4f85-a3a9-319081772b82" />








