![LSBanner](https://github.com/user-attachments/assets/49dccf6b-4cf2-47ca-bb1d-cc335a0e4cc4)


## Overview
This project is a Python-based LAN Scanner with a graphical user interface (GUI) built using PyQt6. The tool allows users to scan a specified IP range, retrieve information about connected devices, and display details such as IP addresses, MAC addresses, and hostnames. The application also includes functionality to ping devices and display their latency.

## Features
- **LAN Scanning**: Scan a specified IP range to discover connected devices.
- **Device Information Display**: Show detailed information about each device, including IP address, MAC address, and hostname.
- **Ping Utility**: Ping a selected device to check its availability and latency.
- **Graphical User Interface**: User-friendly GUI built with PyQt6 for easy interaction.

## Installation

### Prerequisites
- Python 3.x

### Installation Steps
1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/lan-scanner-tool.git
   cd lan-scanner-tool
   ```
2. Install the required Python libraries:
   ```bash
   pip install -r requirements.txt
   ```
   
   or:
   ```bash
   pip3 install PyQt6 scapy pythonping
   ```

3. Run the application:
   ```bash
   sudo python3 main.py
   ```
## Information about stability and compatibility
This software is only tested on linux, so Lan Scanner may be unstable on Windows and MacOs.

## Contributions
Contributions are welcome! Please feel free to submit a pull request or open an issue for any suggestions or improvements.

## License
This project is licensed under the MIT License. See the LICENSE file for more details.
