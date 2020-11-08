#include "privileges.h"
#include "ui_privileges.h"
#include <QMessageBox>
#include <QString>
#include <QByteArray>
#include <QTableWidget>
#include <QEvent>
#include <QTableWidgetItem>
#include <QTime>
#include <QTimer>
#include "windows.h"
#include "winnt.h"
#include <tlhelp32.h>
#include <psapi.h>
#include <fileapi.h>
#include <processthreadsapi.h>
#include <wow64apiset.h>
#include <sddl.h>
#include <winbase.h>
#include "aclapi.h"
DWORD ProcID;

Privileges::Privileges(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::Privileges)
{
    ui->setupUi(this);
    QWidget::setWindowTitle("Privileges of process");
    ui->tableWidget->setColumnCount(2);
    QStringList name_table;
    name_table <<"Privilege"<<"Value";
    ui->tableWidget->setHorizontalHeaderLabels(name_table);
    connect(ui->tableWidget, &QTableWidget::cellDoubleClicked, this, &Privileges::cellDoubleClicked);
    timer = new QTimer();
    connect(timer, SIGNAL(timeout()), this, SLOT(slotTimer()));
    timer->start(1000);
    view();
}
void Privileges::slotTimer()
{
    ui->tableWidget->clear();
    int row=ui->tableWidget->rowCount();
    for (int i=0;i<row;i++)
    ui->tableWidget->removeRow(i);
    ui->tableWidget->setRowCount(0);
    QStringList name_table;
    name_table <<"Privilege"<<"Value";
    ui->tableWidget->setHorizontalHeaderLabels(name_table);
    view();
}
void Privileges::view()
{
    HANDLE hToken;
    DWORD dSize;
    PTOKEN_PRIVILEGES Priv;
    DWORD dwPrivilegeNameSize;
    TCHAR ucPrivilegeName[256];
    HANDLE curHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, ProcID);
    BOOL t=OpenProcessToken(curHandle, TOKEN_QUERY, &hToken);
    if (t==FALSE){return;}

    if (!GetTokenInformation(hToken, TokenPrivileges, NULL, 0, &dSize))
     {if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
        {
            printf("1PRIVGetTokenInformation Error %u\n", GetLastError());}
    }
     Priv= (PTOKEN_PRIVILEGES)GlobalAlloc(GPTR, dSize);
     if (!GetTokenInformation(hToken, TokenPrivileges, Priv,
         dSize, &dSize))
     {
         printf("2PRIV:GetTokenInformation Error %u\n", GetLastError());
     }
     for (DWORD i = 0; i < Priv->PrivilegeCount; i++)
     {
         dwPrivilegeNameSize = sizeof(ucPrivilegeName);
         LookupPrivilegeName(NULL, &Priv->Privileges[i].Luid,ucPrivilegeName, &dwPrivilegeNameSize);
         ui->tableWidget->insertRow(ui->tableWidget->rowCount());
        AddItem(ui->tableWidget, QString::fromWCharArray(ucPrivilegeName), 0);
        if (Priv->Privileges[i].Attributes == SE_PRIVILEGE_USED_FOR_ACCESS)
        {
            AddItem(ui->tableWidget, "USED_FOR_ACCESS", 1);
        }
        else if (Priv->Privileges[i].Attributes == SE_PRIVILEGE_ENABLED_BY_DEFAULT)
        {
            AddItem(ui->tableWidget,"ENABLED_BY_DEFAULT", 1);
        }
        else if (Priv->Privileges[i].Attributes == SE_PRIVILEGE_ENABLED)
        {
            AddItem(ui->tableWidget, "ENABLED", 1);
        }
        else if (Priv->Privileges[i].Attributes == SE_PRIVILEGE_REMOVED)
        {
            AddItem(ui->tableWidget, "REMOVED", 1);
        }
        else if (Priv->Privileges[i].Attributes == 0x00000003L)
        {
            AddItem(ui->tableWidget, "DEFAULT_ENABLED", 1);
        }
        else {
            AddItem(ui->tableWidget, "DISABLED", 1);
        }

     }
     if (Priv) GlobalFree(Priv);
     if (hToken){CloseHandle(hToken);}
     CloseHandle(curHandle);
}
void Privileges::change()
{
   HANDLE curHandle, hToken;
   int row=ui->tableWidget->currentRow();
   QTableWidgetItem *tmp = ui->tableWidget->item(row, 0);
   QString modifPril= tmp->text();//privil_name
   QString modP = QString("%1").arg(modifPril);
   LPCWSTR my_Priv = reinterpret_cast<LPCWSTR>(modP.utf16());

QTableWidgetItem *currentPriv = ui->tableWidget->item(row, 1);
QString curPriv= currentPriv->text();//privil_of_on
BOOL on_off;
if (curPriv=="ENABLED"){on_off=FALSE;}
else if (curPriv=="DISABLED"){on_off=TRUE;}
else {return;}
curHandle = OpenProcess(PROCESS_ALL_ACCESS, false, ProcID);
OpenProcessToken(curHandle, TOKEN_QUERY|TOKEN_ADJUST_PRIVILEGES, &hToken);
SetPrivilege(hToken, my_Priv, on_off);
CloseHandle(hToken);
CloseHandle(curHandle);
}

BOOL Privileges:: SetPrivilege(
    HANDLE hToken,          // access token handle
    LPCTSTR lpszPrivilege,  // name of privilege to enable/disable
    BOOL bEnablePrivilege   // to enable or disable privilege
)
{
    TOKEN_PRIVILEGES tp;
    LUID luid;
    if (!LookupPrivilegeValue(
        NULL,            // lookup privilege on local system
        lpszPrivilege,   // privilege to lookup
        &luid))        // receives LUID of privilege
    {
        printf("LookupPrivilegeValue error: %u\n", GetLastError());
        return FALSE;
    }
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    if (bEnablePrivilege)
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    else
        tp.Privileges[0].Attributes = 0;

    // Enable the privilege or disable all privileges.
    if (!AdjustTokenPrivileges(
        hToken,
        FALSE,
        &tp,
        sizeof(TOKEN_PRIVILEGES),
        (PTOKEN_PRIVILEGES)NULL,
        (PDWORD)NULL))
    {
        printf("AdjustTokenPrivileges error: %u\n", GetLastError());
        return FALSE;
    }

    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)
    {
       printf("The token does not have the specified privilege. \n");
        return FALSE;
    }
    return TRUE;
}
void Privileges::AddItem(QTableWidget *tableWidget, QString QtStr, int column)
{
    tableWidget->setItem(tableWidget->rowCount()-1, column, new QTableWidgetItem(QtStr));
    QTableWidgetItem *newItem = new QTableWidgetItem();
    newItem->setText(QtStr);
    tableWidget->setItem(tableWidget->rowCount(), column, newItem);
}
void Privileges::cellDoubleClicked()
{
    change();

}

Privileges::~Privileges()
{
    delete ui;
}

