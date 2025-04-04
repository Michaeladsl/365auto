# 365auto
Automation for Microsoft 365 foundations benchmarks 4.0.0

### Notes
The script opens any links that are required for manual checks. It is recommended to open your default browser and signing to admin.microsoft.com and leaving that browser open while the script runs to ensure links can open successfully

_The script will have an initial 'four' popup login sequences for all of the required powershell modules!_

### Installs

```
Install-Module Microsoft.Graph.Identity.DirectoryManagement
Install-Module Microsoft.Graph.Identity.SignIns
Install-Module Microsoft.Graph.Beta
Install-Module Microsoft.Graph
Install-Module Microsoft.Graph.Beta.Security
Install-Module Microsoft.Graph.Authentication
Install-Module ExchangePowerShell
Install-Module MicrosoftTeams
```

### Usage

```
.\365auto.ps1
```

### Examples

_Report Example_
![365ato report](https://github.com/user-attachments/assets/28e9763b-5862-48ae-bd0b-0cdfa9e4662b)

_PowerShell Output_
![365auto powershell output](https://github.com/user-attachments/assets/9d8486df-d89d-4daf-83f5-1d92ab13e008)

_Manual Check Example_
![365auto manual example](https://github.com/user-attachments/assets/b0840ab5-baef-46ef-b3cc-50e21a30e124)

_Failed Check Example_
![365auto fail example](https://github.com/user-attachments/assets/80a1125c-223c-427d-b2a6-22749efa2526)

_Passed Check Example_
![365ato pass example](https://github.com/user-attachments/assets/bbd5805a-5663-4656-976a-732f3ad1a85d)
