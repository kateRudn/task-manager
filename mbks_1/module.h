#ifndef MODULE_H
#define MODULE_H

#include <QDialog>
#include <QTableWidget>
#include <QTableWidgetItem>
#include "windows.h"
#include <tlhelp32.h>
#include <winbase.h>

namespace Ui {
class Module;
}

class Module : public QDialog
{
    Q_OBJECT
void PrintModuleList (DWORD const dwProcessId, QTableWidget *tableWidget);
void AddItem(QTableWidget *tableWidget, QString QtStr, int column);
public:
    explicit Module(QWidget *parent = nullptr);
    ~Module();

private:
    Ui::Module *ui;
};

#endif // MODULE_H
