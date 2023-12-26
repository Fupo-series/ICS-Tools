# ICS Tools
工控设备信息识别工具箱,旨在快速识别攻防演练中轨道交通、燃气、水利等行业内网场景、传统工业内网中的工业控制设备型号,工具相比ISF和NMAP等工具更简单易用且体积更小。
## 注:当前已支持Modbus协议设备和西门子设备的识别,使用过程中如遇bug或其他错误请联系作者或进行反馈,如果你有好的建议也可留言
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
**单IP扫描**
![image](https://github.com/Fupo-series/ICS-Tools/assets/45167857/81aea0c2-4ff9-4b07-9623-41067071edc2)


**IP段扫描**
![image](https://github.com/Fupo-series/ICS-Tools/assets/45167857/b135bfcd-0494-4931-8d98-c2b5206fe520)


**批量扫描**
![image](https://github.com/Fupo-series/ICS-Tools/assets/45167857/5fe98798-a605-42db-8fb6-560638ea4fa5)

