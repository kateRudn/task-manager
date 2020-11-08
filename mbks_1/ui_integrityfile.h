/********************************************************************************
** Form generated from reading UI file 'integrityfile.ui'
**
** Created by: Qt User Interface Compiler version 5.13.1
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_INTEGRITYFILE_H
#define UI_INTEGRITYFILE_H

#include <QtCore/QVariant>
#include <QtWidgets/QApplication>
#include <QtWidgets/QDialog>
#include <QtWidgets/QHeaderView>
#include <QtWidgets/QTableWidget>

QT_BEGIN_NAMESPACE

class Ui_IntegrityFile
{
public:
    QTableWidget *tableWidget;

    void setupUi(QDialog *IntegrityFile)
    {
        if (IntegrityFile->objectName().isEmpty())
            IntegrityFile->setObjectName(QString::fromUtf8("IntegrityFile"));
        IntegrityFile->resize(400, 300);
        tableWidget = new QTableWidget(IntegrityFile);
        tableWidget->setObjectName(QString::fromUtf8("tableWidget"));
        tableWidget->setGeometry(QRect(30, 20, 331, 251));

        retranslateUi(IntegrityFile);

        QMetaObject::connectSlotsByName(IntegrityFile);
    } // setupUi

    void retranslateUi(QDialog *IntegrityFile)
    {
        IntegrityFile->setWindowTitle(QCoreApplication::translate("IntegrityFile", "Dialog", nullptr));
    } // retranslateUi

};

namespace Ui {
    class IntegrityFile: public Ui_IntegrityFile {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_INTEGRITYFILE_H
