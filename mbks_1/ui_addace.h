/********************************************************************************
** Form generated from reading UI file 'addace.ui'
**
** Created by: Qt User Interface Compiler version 5.13.1
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_ADDACE_H
#define UI_ADDACE_H

#include <QtCore/QVariant>
#include <QtWidgets/QApplication>
#include <QtWidgets/QDialog>

QT_BEGIN_NAMESPACE

class Ui_AddAce
{
public:

    void setupUi(QDialog *AddAce)
    {
        if (AddAce->objectName().isEmpty())
            AddAce->setObjectName(QString::fromUtf8("AddAce"));
        AddAce->resize(400, 300);

        retranslateUi(AddAce);

        QMetaObject::connectSlotsByName(AddAce);
    } // setupUi

    void retranslateUi(QDialog *AddAce)
    {
        AddAce->setWindowTitle(QCoreApplication::translate("AddAce", "Dialog", nullptr));
    } // retranslateUi

};

namespace Ui {
    class AddAce: public Ui_AddAce {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_ADDACE_H
