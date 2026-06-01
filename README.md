<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage

- [Scenario Creation](https://github.com/JMitchell2417/threat-hunting-scenario-tor/blob/main/threat-hunting-scenario-tor-event-creation.md)

## Platforms and Languages Leveraged

- Windows 11 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

## Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched for any file that had the string "tor" in it and discovered what looks like the user "ponyboy" downloaded a TOR installer, did something that resulted in many TOR-related files being copied to the desktop, and the creation of a file called `tor-shopping-list.txt` on the desktop at `2026-05-30T23:23:08.1142364Z`. These events began at `2026-05-30T22:57:08.4918101Z`.

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "jd-target-vm-1"
| where FileName contains "tor"
| where InitiatingProcessAccountName == "ponyboy"
| where Timestamp >= datetime(2026-05-30T22:57:08.4918101Z)
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName

```

<img width="1212" alt="image" src="./images/tor-download.jpg">

---

### 2. Searched the `DeviceProcessEvents` Table

Searched for any `ProcessCommandLine` that contained the string "tor-browser-windows-x86_64-portable-14.0.1.exe". Based on the logs returned, at `2026-05-30T23:04:45.0708165Z`, an employee "ponyboy" on the "jd-target-vm-1" device ran the file `tor-browser-windows-x86_64-portable-14.0.1.exe` from their Downloads folder, using a command that triggered a silent installation.

**Query used to locate event:**

```kql

DeviceProcessEvents
| where DeviceName == "jd-target-vm-1"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-15.0.14.exe"
| project Timestamp, DeviceName, AccountName, ActionType, FileName, SHA256, ProcessCommandLine

```

<img width="1212" alt="image" src="./images/tor-install.jpg">

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched for any indication that user "employee" actually opened the TOR browser. There was evidence that they did open it at `2026-05-30T23:05:38.8933816Z`. There were several other instances of `firefox.exe` (TOR) as well as `tor.exe` spawned afterwards.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "jd-target-vm-1"
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe", "start-tor-browser.exe", "tor-browser-windows-x86_64-portable-*.exe")
| order by Timestamp desc
| project Timestamp, DeviceName, AccountName, ActionType, FileName, SHA256, ProcessCommandLine

```

<img width="1212" alt="image" src="./images/tor-process-creation.jpg">

---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched for any indication the TOR browser was used to establish a connection using any of the known TOR ports. At `2026-05-30T23:05:51.6543673Z`, an employee "ponyboy" on the "jd-target-vm-1" device successfully established a connection to the remote IP address `185.80.30.102` on port `9001`. The connection was initiated by the process `tor.exe`, located in the folder `C:\Users\ponyboy\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`. There were a couple of other connections to sites over port `9150`.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "jd-target-vm-1"
| where InitiatingProcessAccountName == "ponyboy"
| where RemotePort in ("9001", "9030", "9050", "9051", "9150")
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath

```

<img width="1212" alt="image" src="./images/tor-usage.jpg">

---

## Chronological Event Timeline

### 1. File Download - TOR Installer

- **Timestamp:** `2026-05-30T22:57:08.4918101Z`
- **Event:** The user "employee" downloaded a file named `tor-browser-windows-x86_64-portable-14.0.1.exe` to the Downloads folder.
- **Action:** File download detected.
- **File Path:** `C:\Users\ponyboy\Downloads\tor-browser-windows-x86_64-portable-14.0.1.exe`

### 2. Process Execution - TOR Browser Installation

- **Timestamp:** `2026-05-30T23:04:45.0708165Z`
- **Event:** The user "employee" executed the file `tor-browser-windows-x86_64-portable-14.0.1.exe` in silent mode, initiating a background installation of the TOR Browser.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-14.0.1.exe /S`
- **File Path:** `C:\Users\ponyboy\Downloads\tor-browser-windows-x86_64-portable-14.0.1.exe`

### 3. Process Execution - TOR Browser Launch

- **Timestamp:** ` 2026-05-30T23:05:38.8933816Z`
- **Event:** User "employee" opened the TOR browser. Subsequent processes associated with TOR browser, such as `firefox.exe` and `tor.exe`, were also created, indicating that the browser launched successfully.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** `C:\Users\ponyboy\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

### 4. Network Connection - TOR Network

- **Timestamp:** `2026-05-30T23:05:51.6543673Z`
- **Event:** A network connection to IP `185.80.30.102` on port `9001` by user "ponyboy" was established using `tor.exe`, confirming TOR browser network activity.
- **Action:** Connection success.
- **Process:** `tor.exe`
- **File Path:** `c:\users\ponyboy\desktop\tor browser\browser\torbrowser\tor\tor.exe`

### 5. Additional Network Connections - TOR Browser Activity

- **Timestamps:**
  - `2026-05-30T23:05:51.6543673Z` - Connected to `127.0.0.1` on port `9150`.
  - `2026-05-30T23:06:19.7259964Z` - Connected to `178.254.20.235` on port `9001`.
- **Event:** Additional TOR network connections were established, indicating ongoing activity by user "ponyboy" through the TOR browser.
- **Action:** Multiple successful connections detected.

### 6. File Creation - TOR Shopping List

- **Timestamp:** `2026-05-30T23:23:08.1142364Z`
- **Event:** The user "ponyboy" created a file named `tor-shopping-list.txt` on the desktop, potentially indicating a list or notes related to their TOR browser activities.
- **Action:** File creation detected.
- **File Path:** `C:\Users\ponyboy\Desktop\tor-shopping-list.txt`

---

## Summary

The user "ponyboy" on the "jd-target-vm-1" device initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and created various files related to TOR on their desktop, including a file named `tor-shopping-list.txt`. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of the "shopping list" file.

---

## Response Taken

TOR usage was confirmed on the endpoint `jd-target-vm-1` by the user `ponyboy`. The device was isolated, and the user's direct manager was notified.

---
