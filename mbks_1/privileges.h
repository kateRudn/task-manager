#ifndef PRIVILEGES_H
#define PRIVILEGES_H
#include <QDialog>
#include <QMessageBox>
#include <QString>
#include <QByteArray>
#include <QTableWidget>
#include <QEvent>
#include <QTableWidgetItem>
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
namespace Ui {
class Privileges;
}

class Privileges : public QDialog
{
    Q_OBJECT
  void change();
  BOOL SetPrivilege(
      HANDLE hToken,          // access token handle
      LPCTSTR lpszPrivilege,  // name of privilege to enable/disable
      BOOL bEnablePrivilege   // to enable or disable privilege
  );
  void view();
  void AddItem(QTableWidget *tableWidget, QString QtStr, int column);
  void cellDoubleClicked();
public:
    explicit Privileges(QWidget *parent = nullptr);
    ~Privileges();

private slots:
  void slotTimer();
private:
    Ui::Privileges *ui;
    QTimer *timer;
};

#endif // PRIVILEGES_H
