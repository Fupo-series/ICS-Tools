# ICS Tools
工控设备信息识别工具箱,旨在快速识别攻防演练中轨道交通、燃气、水利等行业内网场景、传统工业内网中的工业控制设备型号,工具相比ISF和NMAP等工具更简单易用且体积更小。
## 注:当前已支持Modbus协议设备和西门子设备的识别,使用过程中如遇bug或其他错误请联系作者或进行反馈,如果你有好的建议也可告诉我们
## 说明:目前modbus协议识别支持常见的施耐德、罗克韦尔等品牌,modbus默认端口为502,你可根据实际情况指定端口;部分modbus协议设备信息可能返回为空,在设备识别的数据处理上存在部分问题,例如返回的设备信息中存在无关字符,后续将优化
# 协议识别
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
## modbus协议识别
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
# 扫描
## 单IP扫描
![image](https://github.com/Fupo-series/ICS-Tools/assets/45167857/81aea0c2-4ff9-4b07-9623-41067071edc2)
## IP段扫描
![image](https://github.com/Fupo-series/ICS-Tools/assets/45167857/b135bfcd-0494-4931-8d98-c2b5206fe520)
## 批量扫描
![image](https://github.com/Fupo-series/ICS-Tools/assets/45167857/5fe98798-a605-42db-8fb6-560638ea4fa5)
## modbus协议识别(以罗克韦尔和施耐德为例)
<img width="951" alt="image" src="https://github.com/Fupo-series/ICS-Tools/assets/48084662/65e5fd84-440e-4c9d-b806-f0719bb9cd68">
<img width="924" alt="image" src="https://github.com/Fupo-series/ICS-Tools/assets/48084662/7c95274e-014f-4912-b911-b1d9e7478827">


