# Form implementation generated from reading ui file 'LS_MainWindow.ui'
#
# Created by: PyQt6 UI code generator 6.4.2
#
# WARNING: Any manual changes made to this file will be lost when pyuic6 is
# run again.  Do not edit this file unless you know what you are doing.


from PyQt6 import QtCore, QtGui, QtWidgets


class Ui_MainWindow(object):
    def setupUi(self, MainWindow):
        MainWindow.setObjectName("MainWindow")
        MainWindow.resize(1000, 600)
        icon = QtGui.QIcon()
        icon.addPixmap(QtGui.QPixmap("LSIcon.png"), QtGui.QIcon.Mode.Normal, QtGui.QIcon.State.Off)
        MainWindow.setWindowIcon(icon)
        MainWindow.setStyleSheet("QMainWindow{\n"
"\n"
"color: #2E3436;\n"
"background-color: #101010;\n"
"}")
        self.centralwidget = QtWidgets.QWidget(parent=MainWindow)
        self.centralwidget.setStyleSheet("QWidget{\n"
"\n"
"color: #2E3436;\n"
"background-color: #101010;\n"
"}")
        self.centralwidget.setObjectName("centralwidget")
        self.horizontalLayout_2 = QtWidgets.QHBoxLayout(self.centralwidget)
        self.horizontalLayout_2.setObjectName("horizontalLayout_2")
        self.horizontalLayout = QtWidgets.QHBoxLayout()
        self.horizontalLayout.setObjectName("horizontalLayout")
        self.verticalLayout_2 = QtWidgets.QVBoxLayout()
        self.verticalLayout_2.setObjectName("verticalLayout_2")
        self.horizontalFrame_2 = QtWidgets.QFrame(parent=self.centralwidget)
        self.horizontalFrame_2.setMinimumSize(QtCore.QSize(0, 100))
        self.horizontalFrame_2.setObjectName("horizontalFrame_2")
        self.horizontalLayout_3 = QtWidgets.QHBoxLayout(self.horizontalFrame_2)
        self.horizontalLayout_3.setObjectName("horizontalLayout_3")
        self.label_2 = QtWidgets.QLabel(parent=self.horizontalFrame_2)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Policy.Fixed, QtWidgets.QSizePolicy.Policy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.label_2.sizePolicy().hasHeightForWidth())
        self.label_2.setSizePolicy(sizePolicy)
        self.label_2.setMinimumSize(QtCore.QSize(50, 50))
        self.label_2.setMaximumSize(QtCore.QSize(50, 50))
        self.label_2.setText("")
        self.label_2.setPixmap(QtGui.QPixmap("LSIcon.png"))
        self.label_2.setScaledContents(True)
        self.label_2.setObjectName("label_2")
        self.horizontalLayout_3.addWidget(self.label_2)
        self.label_3 = QtWidgets.QLabel(parent=self.horizontalFrame_2)
        font = QtGui.QFont()
        font.setFamily("Rubik Mono One")
        font.setPointSize(20)
        self.label_3.setFont(font)
        self.label_3.setStyleSheet("color: white;")
        self.label_3.setObjectName("label_3")
        self.horizontalLayout_3.addWidget(self.label_3)
        spacerItem = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Policy.Expanding, QtWidgets.QSizePolicy.Policy.Minimum)
        self.horizontalLayout_3.addItem(spacerItem)
        self.verticalLayout_2.addWidget(self.horizontalFrame_2)
        self.ServerDetailsTab = QtWidgets.QWidget(parent=self.centralwidget)
        self.ServerDetailsTab.setMinimumSize(QtCore.QSize(0, 60))
        self.ServerDetailsTab.setStyleSheet("color: white;")
        self.ServerDetailsTab.setObjectName("ServerDetailsTab")
        self.gridLayout = QtWidgets.QGridLayout(self.ServerDetailsTab)
        self.gridLayout.setObjectName("gridLayout")
        self.SDT_CloseTab = QtWidgets.QPushButton(parent=self.ServerDetailsTab)
        self.SDT_CloseTab.setStyleSheet("QPushButton{\n"
"\n"
"color: #EEEEEC;\n"
"    background-color: #A40000;\n"
"    padding: 7px 20px;\n"
"    text-align: center;\n"
"    text-decoration: none;\n"
"    border-color: grey;\n"
"    border-style:solid;\n"
"    border-width: 1px;\n"
"    border-radius: 5px;\n"
"    margin: 0px;\n"
"    margin-top: 0px;\n"
"}\n"
"\n"
":hover{\n"
"background-color:black;\n"
"color: #A40000;\n"
"}")
        self.SDT_CloseTab.setObjectName("SDT_CloseTab")
        self.gridLayout.addWidget(self.SDT_CloseTab, 6, 2, 1, 1)
        self.SDT_Hostname = QtWidgets.QLabel(parent=self.ServerDetailsTab)
        font = QtGui.QFont()
        font.setPointSize(12)
        self.SDT_Hostname.setFont(font)
        self.SDT_Hostname.setObjectName("SDT_Hostname")
        self.gridLayout.addWidget(self.SDT_Hostname, 1, 2, 1, 1)
        self.SDT_IpAdress = QtWidgets.QLabel(parent=self.ServerDetailsTab)
        font = QtGui.QFont()
        font.setPointSize(12)
        self.SDT_IpAdress.setFont(font)
        self.SDT_IpAdress.setObjectName("SDT_IpAdress")
        self.gridLayout.addWidget(self.SDT_IpAdress, 2, 2, 1, 1)
        self.label_9 = QtWidgets.QLabel(parent=self.ServerDetailsTab)
        font = QtGui.QFont()
        font.setPointSize(12)
        self.label_9.setFont(font)
        self.label_9.setObjectName("label_9")
        self.gridLayout.addWidget(self.label_9, 3, 1, 1, 1)
        self.label_6 = QtWidgets.QLabel(parent=self.ServerDetailsTab)
        font = QtGui.QFont()
        font.setPointSize(12)
        self.label_6.setFont(font)
        self.label_6.setObjectName("label_6")
        self.gridLayout.addWidget(self.label_6, 4, 1, 1, 1)
        self.SDT_PingResult = QtWidgets.QLabel(parent=self.ServerDetailsTab)
        font = QtGui.QFont()
        font.setPointSize(12)
        self.SDT_PingResult.setFont(font)
        self.SDT_PingResult.setStyleSheet("color: green;")
        self.SDT_PingResult.setObjectName("SDT_PingResult")
        self.gridLayout.addWidget(self.SDT_PingResult, 4, 2, 1, 1)
        self.label_5 = QtWidgets.QLabel(parent=self.ServerDetailsTab)
        font = QtGui.QFont()
        font.setPointSize(12)
        self.label_5.setFont(font)
        self.label_5.setObjectName("label_5")
        self.gridLayout.addWidget(self.label_5, 1, 1, 1, 1)
        self.label_4 = QtWidgets.QLabel(parent=self.ServerDetailsTab)
        font = QtGui.QFont()
        font.setFamily("Comfortaa")
        font.setPointSize(18)
        self.label_4.setFont(font)
        self.label_4.setStyleSheet("")
        self.label_4.setObjectName("label_4")
        self.gridLayout.addWidget(self.label_4, 0, 1, 1, 1)
        self.SDT_ReloadButton = QtWidgets.QPushButton(parent=self.ServerDetailsTab)
        self.SDT_ReloadButton.setStyleSheet("QPushButton{\n"
"\n"
"color: #2E3436;\n"
"    background-color: #FFBB00;\n"
"    padding: 7px 20px;\n"
"    text-align: center;\n"
"    text-decoration: none;\n"
"    border-color: #2E3436;\n"
"    border-style:solid;\n"
"    border-width: 1px;\n"
"    border-radius: 5px;\n"
"    margin: 0px;\n"
"    margin-top: 0px;\n"
"}\n"
"\n"
":hover{\n"
"background-color:black;\n"
"color: #FFBB00;\n"
"}")
        self.SDT_ReloadButton.setObjectName("SDT_ReloadButton")
        self.gridLayout.addWidget(self.SDT_ReloadButton, 6, 1, 1, 1)
        self.SDT_MacAdress = QtWidgets.QLabel(parent=self.ServerDetailsTab)
        font = QtGui.QFont()
        font.setPointSize(12)
        self.SDT_MacAdress.setFont(font)
        self.SDT_MacAdress.setObjectName("SDT_MacAdress")
        self.gridLayout.addWidget(self.SDT_MacAdress, 3, 2, 1, 1)
        self.label_7 = QtWidgets.QLabel(parent=self.ServerDetailsTab)
        font = QtGui.QFont()
        font.setPointSize(12)
        self.label_7.setFont(font)
        self.label_7.setObjectName("label_7")
        self.gridLayout.addWidget(self.label_7, 2, 1, 1, 1)
        spacerItem1 = QtWidgets.QSpacerItem(20, 20, QtWidgets.QSizePolicy.Policy.Minimum, QtWidgets.QSizePolicy.Policy.Fixed)
        self.gridLayout.addItem(spacerItem1, 5, 1, 1, 1)
        self.verticalLayout_2.addWidget(self.ServerDetailsTab)
        spacerItem2 = QtWidgets.QSpacerItem(20, 40, QtWidgets.QSizePolicy.Policy.Minimum, QtWidgets.QSizePolicy.Policy.Expanding)
        self.verticalLayout_2.addItem(spacerItem2)
        self.label = QtWidgets.QLabel(parent=self.centralwidget)
        font = QtGui.QFont()
        font.setFamily("Comfortaa")
        font.setPointSize(15)
        self.label.setFont(font)
        self.label.setStyleSheet("color: white;\n"
"margin-left: 20px;")
        self.label.setObjectName("label")
        self.verticalLayout_2.addWidget(self.label)
        self.IPRangeEditor = QtWidgets.QLineEdit(parent=self.centralwidget)
        self.IPRangeEditor.setStyleSheet("QLineEdit{\n"
"\n"
"background-color:black;\n"
"color: #FFBB00;\n"
"    padding: 7px 20px;\n"
"    text-align: center;\n"
"    text-decoration: none;\n"
"    border-color: #2E3436;\n"
"    border-style:solid;\n"
"    border-width: 1px;\n"
"    border-radius: 5px;\n"
"    margin: 10px;\n"
"    margin-top: 0px;\n"
"}\n"
"\n"
":hover{\n"
"background-color:black;\n"
"color: white;\n"
"}")
        self.IPRangeEditor.setObjectName("IPRangeEditor")
        self.verticalLayout_2.addWidget(self.IPRangeEditor)
        self.LanScanButton = QtWidgets.QPushButton(parent=self.centralwidget)
        self.LanScanButton.setMinimumSize(QtCore.QSize(0, 60))
        font = QtGui.QFont()
        font.setFamily("Comfortaa")
        font.setPointSize(15)
        font.setBold(False)
        font.setUnderline(False)
        font.setStrikeOut(False)
        self.LanScanButton.setFont(font)
        self.LanScanButton.setStyleSheet("QPushButton{\n"
"\n"
"color: #2E3436;\n"
"    background-color: #FFBB00;\n"
"    padding: 7px 20px;\n"
"    text-align: center;\n"
"    text-decoration: none;\n"
"    border-color: #2E3436;\n"
"    border-style:solid;\n"
"    border-width: 1px;\n"
"    border-radius: 5px;\n"
"    margin: 10px;\n"
"    margin-top: 0px;\n"
"}\n"
"\n"
":hover{\n"
"background-color:black;\n"
"color: #FFBB00;\n"
"}")
        self.LanScanButton.setObjectName("LanScanButton")
        self.verticalLayout_2.addWidget(self.LanScanButton)
        self.horizontalLayout.addLayout(self.verticalLayout_2)
        self.verticalLayout = QtWidgets.QVBoxLayout()
        self.verticalLayout.setObjectName("verticalLayout")
        self.scrollArea = QtWidgets.QScrollArea(parent=self.centralwidget)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Policy.Fixed, QtWidgets.QSizePolicy.Policy.Expanding)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.scrollArea.sizePolicy().hasHeightForWidth())
        self.scrollArea.setSizePolicy(sizePolicy)
        self.scrollArea.setMinimumSize(QtCore.QSize(600, 0))
        self.scrollArea.setWidgetResizable(True)
        self.scrollArea.setObjectName("scrollArea")
        self.scrollAreaWidgetContents = QtWidgets.QWidget()
        self.scrollAreaWidgetContents.setGeometry(QtCore.QRect(0, 0, 598, 534))
        self.scrollAreaWidgetContents.setObjectName("scrollAreaWidgetContents")
        self.verticalLayout_3 = QtWidgets.QVBoxLayout(self.scrollAreaWidgetContents)
        self.verticalLayout_3.setObjectName("verticalLayout_3")
        self.scrollArea.setWidget(self.scrollAreaWidgetContents)
        self.verticalLayout.addWidget(self.scrollArea)
        self.horizontalLayout.addLayout(self.verticalLayout)
        self.horizontalLayout_2.addLayout(self.horizontalLayout)
        MainWindow.setCentralWidget(self.centralwidget)
        self.menubar = QtWidgets.QMenuBar(parent=MainWindow)
        self.menubar.setGeometry(QtCore.QRect(0, 0, 1000, 20))
        self.menubar.setObjectName("menubar")
        MainWindow.setMenuBar(self.menubar)
        self.statusbar = QtWidgets.QStatusBar(parent=MainWindow)
        self.statusbar.setObjectName("statusbar")
        MainWindow.setStatusBar(self.statusbar)

        self.retranslateUi(MainWindow)
        QtCore.QMetaObject.connectSlotsByName(MainWindow)

    def retranslateUi(self, MainWindow):
        _translate = QtCore.QCoreApplication.translate
        MainWindow.setWindowTitle(_translate("MainWindow", "Lan Scanner"))
        self.label_3.setText(_translate("MainWindow", "Lan Scanner"))
        self.SDT_CloseTab.setText(_translate("MainWindow", "Close tab"))
        self.SDT_Hostname.setText(_translate("MainWindow", "HOSTNAME"))
        self.SDT_IpAdress.setText(_translate("MainWindow", "IPADRESS"))
        self.label_9.setText(_translate("MainWindow", "MAC Adress:"))
        self.label_6.setText(_translate("MainWindow", "Ping:"))
        self.SDT_PingResult.setText(_translate("MainWindow", "PINGRESULT"))
        self.label_5.setText(_translate("MainWindow", "Name:"))
        self.label_4.setText(_translate("MainWindow", "Server details:"))
        self.SDT_ReloadButton.setText(_translate("MainWindow", "Reload"))
        self.SDT_MacAdress.setText(_translate("MainWindow", "MACADRESS"))
        self.label_7.setText(_translate("MainWindow", "IP Adress:"))
        self.label.setText(_translate("MainWindow", "IP Range:"))
        self.IPRangeEditor.setText(_translate("MainWindow", "192.168.0.1/24"))
        self.LanScanButton.setText(_translate("MainWindow", "Lan Scan"))
