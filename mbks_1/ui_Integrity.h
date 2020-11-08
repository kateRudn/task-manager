/********************************************************************************
** Form generated from reading UI file 'Integrity.ui'
**
** Created by: Qt User Interface Compiler version 5.13.1
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_INTEGRITY_H
#define UI_INTEGRITY_H

#include <QtCore/QVariant>
#include <QtWidgets/QApplication>
#include <QtWidgets/QDialog>
#include <QtWidgets/QHeaderView>
#include <QtWidgets/QTableWidget>

QT_BEGIN_NAMESPACE

class Ui_Integrity
{
public:
    QTableWidget *tableWidget;

    void setupUi(QDialog *Integrity)
    {
        if (Integrity->objectName().isEmpty())
            Integrity->setObjectName(QString::fromUtf8("Integrity"));
        Integrity->resize(400, 300);
        tableWidget = new QTableWidget(Integrity);
        tableWidget->setObjectName(QString::fromUtf8("tableWidget"));
        tableWidget->setGeometry(QRect(20, 10, 351, 271));

        retranslateUi(Integrity);

        QMetaObject::connectSlotsByName(Integrity);
    } // setupUi

    void retranslateUi(QDialog *Integrity)
    {
        Integrity->setWindowTitle(QCoreApplication::translate("Integrity", "Dialog", nullptr));
    } // retranslateUi

};

namespace Ui {
    class Integrity: public Ui_Integrity {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_INTEGRITY_H
