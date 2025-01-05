import getpass
import os
import sys
import socket
import subprocess
import scapy.all as scapy
from PyQt6 import QtWidgets, uic, QtCore, QtGui
from PyQt6.QtWidgets import QLineEdit, QDialog, QFileDialog, QApplication, QPushButton, QSplashScreen, QLabel, QDialogButtonBox, QColorDialog, \
    QVBoxLayout, QMessageBox
from PyQt6.QtCore import Qt
from pythonping import ping

from LS_MainWindow import Ui_MainWindow
from OBJWidget import Ui_Form


class MainWindow(QtWidgets.QMainWindow, Ui_MainWindow):
    def __init__(self, *args, obj=None, **kwargs):
        super(MainWindow, self).__init__(*args, **kwargs)
        self.setupUi(self)
        self.SetupApp()
        self.CheckRoot()

        self.LanScanButton.clicked.connect(self.DoLanScan)
        self.SDT_CloseTab.clicked.connect(self.CloseServerDetailsTab)
        self.SDT_ReloadButton.clicked.connect(self.updatePingDisplay)



    def CheckRoot(self):
        if os.geteuid() != 0:
            password = getpass.getpass("Enter root password: ")
            try:
                subprocess.run(['sudo', '-S', 'python3'] + sys.argv, input=f"{password}\n", text=True, check=True)
            except subprocess.CalledProcessError as e:
                print(f"Erreur : Impossible de relancer avec sudo. {e}")
            sys.exit(1)

    def SetupApp(self):
        self.ClearServerList()
        self.CloseServerDetailsTab()

    def CloseServerDetailsTab(self):
        self.ServerDetailsTab.setVisible(False)

    def ClearServerList(self):
        layout = self.scrollAreaWidgetContents.layout()
        if layout:
            while layout.count():
                item = layout.takeAt(0)
                widget = item.widget()
                if widget:
                    widget.setParent(None)
                    widget.deleteLater()

    def Pingsever(self, server):
        pingResult = ping(target=server, count=5, timeout=2)
        return {
            'host': server,
            'avg_latency': pingResult.rtt_avg_ms,
            'min_latency': pingResult.rtt_min_ms,
            'max_latency': pingResult.rtt_max_ms,
            'packet_loss': pingResult.packet_loss
        }

    def updatePingDisplay(self):
        pingResult = self.Pingsever(self.SDT_IpAdress.text())["avg_latency"]
        if pingResult == 2000:
            self.SDT_PingResult.setText("Server unreachable")
            self.SDT_PingResult.setStyleSheet("color: red;")
        else:
            self.SDT_PingResult.setText(f"Online ({pingResult}ms)")
            self.SDT_PingResult.setStyleSheet("color: green;")


    def displayServerInfo(self, objectIP, objectMAC, objectHOSTNAME):
        print(f"Openned object: {objectIP}")
        self.SDT_IpAdress.setText(objectIP)
        self.SDT_Hostname.setText(objectHOSTNAME)
        self.SDT_MacAdress.setText(objectMAC)
        self.updatePingDisplay()

        self.ServerDetailsTab.setVisible(True)



    def display_devices(self,devices):
        if devices:
            print("\nIP\t\t\tMAC Address")
            print("-----------------------------------------")
            for device in devices:
                print(f"{device['ip']}\t\t{device['mac']}")

                OBJWidget = QtWidgets.QWidget()
                objWidget = Ui_Form()
                objWidget.setupUi(OBJWidget)
                objWidget.IpAdressLabel.setText(device["ip"])
                objWidget.MacAdressLabel.setText(device["mac"])
                objWidget.ServerNameLabel.setText(device["hostname"])
                objWidget.MoreInfoButton.clicked.connect(lambda checked, ObjectIP = (device["ip"]), ObjectMAC = (device["mac"]), ObjectHOSTNAME = (device["hostname"]): self.displayServerInfo(ObjectIP, ObjectMAC, ObjectHOSTNAME))
                self.scrollAreaWidgetContents.layout().addWidget(OBJWidget)
        else:
            print("No devices found.")



    def scan(self,ip_range):
        print(f"Scanning IP range: {ip_range}")

        arp_request = scapy.ARP(pdst=ip_range)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request

        print("Sending ARP requests...")
        answered_list = scapy.srp(arp_request_broadcast, timeout=5, verbose=True)[0]

        if not answered_list:
            print("No responses received.")
        else:
            print("Responses received.")

        devices = []
        for element in answered_list:
            print(element[1].psrc)
            try:
                hostname = socket.gethostbyaddr(element[1].psrc)[0]
            except:
                print(socket.getfqdn(element[1].psrc))
                print("Unknown Host")
                hostname = str("Unknown Host")

            device = {'ip': element[1].psrc, 'mac': element[1].hwsrc, 'hostname': hostname}
            devices.append(device)
            print(f"Device found: IP = {device['ip']}, MAC = {device['mac']}, HOSTNAME = {device['hostname']}")

        return devices


    def DoLanScan(self):
        self.ClearServerList()
        ip_range = str(self.IPRangeEditor.text())
        devices = self.scan(ip_range)
        self.display_devices(devices)
        self.LanScanButton.setText("Lan Scan")


app = QtWidgets.QApplication(sys.argv)
window = MainWindow()
window.show()
app.exec()