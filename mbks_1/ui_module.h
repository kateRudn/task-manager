/********************************************************************************
** Form generated from reading UI file 'module.ui'
**
** Created by: Qt User Interface Compiler version 5.13.1
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_MODULE_H
#define UI_MODULE_H

#include <QtCore/QVariant>
#include <QtWidgets/QApplication>
#include <QtWidgets/QDialog>
#include <QtWidgets/QHeaderView>
#include <QtWidgets/QTableWidget>

QT_BEGIN_NAMESPACE

class Ui_Module
{
public:
    QTableWidget *tableWidget;

    void setupUi(QDialog *Module)
    {
        if (Module->objectName().isEmpty())
            Module->setObjectName(QString::fromUtf8("Module"));
        Module->resize(800, 400);
        tableWidget = new QTableWidget(Module);
        tableWidget->setObjectName(QString::fromUtf8("tableWidget"));
        tableWidget->setGeometry(QRect(10, 50, 750, 350));

        retranslateUi(Module);

        QMetaObject::connectSlotsByName(Module);
    } // setupUi

    void retranslateUi(QDialog *Module)
    {
        Module->setWindowTitle(QCoreApplication::translate("Module", "Dialog", nullptr));
    } // retranslateUi

};

namespace Ui {
    class Module: public Ui_Module {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_MODULE_H
