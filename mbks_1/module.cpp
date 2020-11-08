#include "module.h"
#include "ui_module.h"
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QString>
#include <QByteArray>
#include "windows.h"
#include <tlhelp32.h>
#include <winbase.h>
#include "winnt.h"
#include <psapi.h>
#include <fileapi.h>
#include <processthreadsapi.h>
#include <wow64apiset.h>
#include <sddl.h>
DWORD ID;
QString ProcName;
Module::Module(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::Module)
{
    ui->setupUi(this);
    QWidget::setWindowTitle("Modules of process "+ProcName);
    ui->tableWidget->setColumnCount(4);
    ui->tableWidget->setColumnWidth(0,285);
    QStringList name_table;
    name_table <<"File Path"<<"Address"<<"Size"<<"Library";
    ui->tableWidget->setHorizontalHeaderLabels(name_table);
    PrintModuleList(ID, ui->tableWidget);
}

void Module::AddItem(QTableWidget *tableWidget, QString QtStr, int column)
{
    tableWidget->setItem(tableWidget->rowCount()-1, column, new QTableWidgetItem(QtStr));
    QTableWidgetItem *newItem = new QTableWidgetItem();
    newItem->setText(QtStr);
    tableWidget->setItem(tableWidget->rowCount(), column, newItem);
}

void Module::PrintModuleList (DWORD const dwProcessId, QTableWidget *tableWidget)
{
  MODULEENTRY32 meModuleEntry;
  TCHAR buffer[256] = {0};
  HANDLE CONST hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwProcessId);
  if(INVALID_HANDLE_VALUE == hSnapshot) {
      return;
  }
  meModuleEntry.dwSize = sizeof(MODULEENTRY32);
  Module32First(hSnapshot, &meModuleEntry);
  int i=0;
  do {
      i++;
      ui->tableWidget->insertRow(ui->tableWidget->rowCount());
      wsprintf(buffer, L"  %s\r\n", meModuleEntry.szExePath);
      AddItem(tableWidget, QString::fromWCharArray(buffer), 0);
      memset(buffer, 0, sizeof(buffer));

      wsprintf(buffer, L"  ba: %08X", meModuleEntry.modBaseAddr);
      AddItem(tableWidget, QString::fromWCharArray(buffer), 1);
      memset(buffer, 0, sizeof(buffer));

      wsprintf(buffer, L"  bs: %08X", meModuleEntry.modBaseSize);
      AddItem(tableWidget, QString::fromWCharArray(buffer), 2);
      memset(buffer, 0, sizeof(buffer));

      wsprintf(buffer, L"  %s\r\n", meModuleEntry.szModule);
      AddItem(tableWidget, QString::fromWCharArray(buffer), 3);
      /*if (QString::fromWCharArray(buffer).indexOf("core.dll")!=-1)
      {printf("%d YES\n", i);}*/
      memset(buffer, 0, sizeof(buffer));

  } while(Module32Next(hSnapshot, &meModuleEntry));

  CloseHandle(hSnapshot);
}

Module::~Module()
{
    delete ui;
}
