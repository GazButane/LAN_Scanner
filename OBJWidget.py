# Form implementation generated from reading ui file 'OBJWidget.ui'
#
# Created by: PyQt6 UI code generator 6.4.2
#
# WARNING: Any manual changes made to this file will be lost when pyuic6 is
# run again.  Do not edit this file unless you know what you are doing.


from PyQt6 import QtCore, QtGui, QtWidgets


class Ui_Form(object):
    def setupUi(self, Form):
        Form.setObjectName("Form")
        Form.resize(611, 168)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Policy.Expanding, QtWidgets.QSizePolicy.Policy.Preferred)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(Form.sizePolicy().hasHeightForWidth())
        Form.setSizePolicy(sizePolicy)
        Form.setStyleSheet("QWidget{\n"
"\n"
"color: #F3F3F3;\n"
"background-color: #00171F;\n"
"border-radius: 15px;\n"
"\n"
"}")
        self.horizontalLayout_2 = QtWidgets.QHBoxLayout(Form)
        self.horizontalLayout_2.setObjectName("horizontalLayout_2")
        self.label_2 = QtWidgets.QLabel(parent=Form)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Policy.Fixed, QtWidgets.QSizePolicy.Policy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.label_2.sizePolicy().hasHeightForWidth())
        self.label_2.setSizePolicy(sizePolicy)
        self.label_2.setMinimumSize(QtCore.QSize(150, 150))
        self.label_2.setMaximumSize(QtCore.QSize(150, 150))
        self.label_2.setText("")
        self.label_2.setPixmap(QtGui.QPixmap("DefaultSever.png"))
        self.label_2.setScaledContents(True)
        self.label_2.setObjectName("label_2")
        self.horizontalLayout_2.addWidget(self.label_2)
        self.horizontalLayout = QtWidgets.QHBoxLayout()
        self.horizontalLayout.setObjectName("horizontalLayout")
        self.verticalLayout_2 = QtWidgets.QVBoxLayout()
        self.verticalLayout_2.setObjectName("verticalLayout_2")
        self.ServerNameLabel = QtWidgets.QLabel(parent=Form)
        font = QtGui.QFont()
        font.setFamily("Rubik Mono One")
        font.setPointSize(20)
        self.ServerNameLabel.setFont(font)
        self.ServerNameLabel.setStyleSheet("color: #FFBB00;")
        self.ServerNameLabel.setObjectName("ServerNameLabel")
        self.verticalLayout_2.addWidget(self.ServerNameLabel)
        spacerItem = QtWidgets.QSpacerItem(20, 40, QtWidgets.QSizePolicy.Policy.Minimum, QtWidgets.QSizePolicy.Policy.Expanding)
        self.verticalLayout_2.addItem(spacerItem)
        self.IpAdressLabel = QtWidgets.QLabel(parent=Form)
        font = QtGui.QFont()
        font.setFamily("Comfortaa")
        font.setPointSize(15)
        font.setBold(True)
        self.IpAdressLabel.setFont(font)
        self.IpAdressLabel.setObjectName("IpAdressLabel")
        self.verticalLayout_2.addWidget(self.IpAdressLabel)
        self.MacAdressLabel = QtWidgets.QLabel(parent=Form)
        font = QtGui.QFont()
        font.setFamily("Comfortaa")
        font.setPointSize(15)
        font.setBold(False)
        self.MacAdressLabel.setFont(font)
        self.MacAdressLabel.setObjectName("MacAdressLabel")
        self.verticalLayout_2.addWidget(self.MacAdressLabel)
        self.horizontalLayout.addLayout(self.verticalLayout_2)
        self.verticalLayout = QtWidgets.QVBoxLayout()
        self.verticalLayout.setObjectName("verticalLayout")
        spacerItem1 = QtWidgets.QSpacerItem(20, 40, QtWidgets.QSizePolicy.Policy.Minimum, QtWidgets.QSizePolicy.Policy.Expanding)
        self.verticalLayout.addItem(spacerItem1)
        self.MoreInfoButton = QtWidgets.QPushButton(parent=Form)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Policy.Maximum, QtWidgets.QSizePolicy.Policy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.MoreInfoButton.sizePolicy().hasHeightForWidth())
        self.MoreInfoButton.setSizePolicy(sizePolicy)
        self.MoreInfoButton.setMinimumSize(QtCore.QSize(0, 50))
        self.MoreInfoButton.setStyleSheet("QPushButton{\n"
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
        self.MoreInfoButton.setObjectName("MoreInfoButton")
        self.verticalLayout.addWidget(self.MoreInfoButton)
        self.horizontalLayout.addLayout(self.verticalLayout)
        self.horizontalLayout_2.addLayout(self.horizontalLayout)

        self.retranslateUi(Form)
        QtCore.QMetaObject.connectSlotsByName(Form)

    def retranslateUi(self, Form):
        _translate = QtCore.QCoreApplication.translate
        Form.setWindowTitle(_translate("Form", "Form"))
        self.ServerNameLabel.setText(_translate("Form", "Default Server"))
        self.IpAdressLabel.setText(_translate("Form", "IP_ADRESS"))
        self.MacAdressLabel.setText(_translate("Form", "MAC_ADRESS"))
        self.MoreInfoButton.setText(_translate("Form", "More..."))
