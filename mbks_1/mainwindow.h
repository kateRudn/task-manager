#ifndef MAINWINDOW_H
#define MAINWINDOW_H
#include <QMainWindow>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QTimer>
#include <QTime>
#include "windows.h"
#include <tlhelp32.h>
#include <winbase.h>
#include "dialog.h"
#include "module.h"
#include "privileges.h"
#include <processthreadsapi.h>
#include "integrity.h"
#include "integrityfile.h"
extern DWORD ID;
extern DWORD ProcID;
extern QString ProcName;
extern DWORD IDProc;
extern QString str;
extern QString level;
extern QString globalFilePath;
extern QString FileNameGlobal;
QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
	Q_OBJECT
	void PrintProcessList();
	void SetSettings();
	void AddItem(QTableWidget *tableWidget, QString QtStr, int column);
	bool IsWow64(HANDLE hProcess, BOOL &isWow64);
	
	void IntegrLev(DWORD ID);
	int ModuleList(DWORD const dwProcessId);
public:
	MainWindow(QWidget *parent = nullptr);
	~MainWindow();
	void cellDoubleClicked();

private slots:
	void slotTimer();
	void on_pushButton_clicked();

private:
	Ui::MainWindow *ui;
	Module *mod;
	QTimer *timer;
};


#endif // MAINWINDOW_H

