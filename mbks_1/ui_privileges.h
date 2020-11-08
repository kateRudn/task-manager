/********************************************************************************
** Form generated from reading UI file 'privileges.ui'
**
** Created by: Qt User Interface Compiler version 5.13.1
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_PRIVILEGES_H
#define UI_PRIVILEGES_H

#include <QtCore/QVariant>
#include <QtWidgets/QApplication>
#include <QtWidgets/QDialog>
#include <QtWidgets/QHeaderView>
#include <QtWidgets/QTableWidget>

QT_BEGIN_NAMESPACE

class Ui_Privileges
{
public:
    QTableWidget *tableWidget;

    void setupUi(QDialog *Privileges)
    {
        if (Privileges->objectName().isEmpty())
            Privileges->setObjectName(QString::fromUtf8("Privileges"));
        Privileges->resize(345, 306);
        tableWidget = new QTableWidget(Privileges);
        tableWidget->setObjectName(QString::fromUtf8("tableWidget"));
        tableWidget->setGeometry(QRect(20, 20, 291, 251));

        retranslateUi(Privileges);

        QMetaObject::connectSlotsByName(Privileges);
    } // setupUi

    void retranslateUi(QDialog *Privileges)
    {
        Privileges->setWindowTitle(QCoreApplication::translate("Privileges", "Dialog", nullptr));
    } // retranslateUi

};

namespace Ui {
    class Privileges: public Ui_Privileges {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_PRIVILEGES_H
