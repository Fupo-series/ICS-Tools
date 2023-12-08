# ICS Tools
工控设备信息识别工具箱,旨在快速识别攻防演练中轨道交通、燃气、水利等行业内网场景、传统工业内网中的工业控制设备型号,工具相比ISF和NMAP等工具更简单易用且体积更小。
注:当前脚本仅支持西门子S7系列设备识别,包括但不局限于S7-300、S7-500、S7-1200、S7-1500等,后续将会增加例如三菱、施耐德、罗克韦尔、欧姆龙等品牌及modbus等相关工控协议的识别
## 西门子识别：
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
**单IP扫描**
![image](https://github.com/novysodope/ICscan/assets/45167857/b212686f-3c3a-4b20-a65d-3da1e447ee21)

**IP段扫描**
![image](https://github.com/novysodope/ICscan/assets/45167857/389b8dcc-591c-4427-944a-740b127ac856)

**批量扫描**
![image](https://github.com/novysodope/ICscan/assets/45167857/6ed95e72-80d6-436d-b981-8198219a128a)
