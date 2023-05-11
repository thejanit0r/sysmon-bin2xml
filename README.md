# Sysmon Bin2XML

This utility converts a SysInternals' Sysmon binary configuration blob back to XML.

In order to configure Sysmon, an XML configuration file is passed as an argument to Sysmon, which in turn will compile the XML configuration to a binary format and store it, typically, in `HKLM\SYSTEM\CurrentControlSet\Services\SysmonDrv\Parameters\Rules`. Unfortunately, when an XML configuration file is lost, due to e.g. bad backup practices, there is no officially documented way to rebuild it from the currently active configuration; in such situations this script may be of help.

It has been tested on popular public Sysmon configuration files, i.e. from https://github.com/Neo23x0/sysmon-config and from https://github.com/SwiftOnSecurity/sysmon-config, in conjunction with Sysmon 14.16. It may or may not work on older XML schemas and binary versions; if it doesn't, you may try your luck with https://github.com/mattifestation/PSSysmonTools. Pull requests are welcome.

**What is Sysmon?**

_System Monitor (Sysmon) is a Windows system service and device driver that, once installed on a system, remains resident across system reboots to monitor and log system activity to the Windows event log. It provides detailed information about process creations, network connections, and changes to file creation time._

https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon

**How do I dump the contents of the registry key?**

E.g. with Powershell:

```powershell
$Path = Join-Path (Get-Location).Path "sysmon_cfg.bin"

Add-Content -Path $Path -Encoding Byte -Value `
	(Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\SysmonDrv\Parameters").Rules
```

# Installation & Usage

```bash
pip install -r requirements.txt

python3 sysmon_bin2xml.py -i "sysmon_cfg.bin" -o "sysmon_cfg.xml" 
```

