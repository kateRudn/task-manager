#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <QMessageBox>
#include <QString>
#include <QByteArray>
#include <QTableWidget>
#include <QEvent>
#include <QTableWidgetItem>
#include <QTimer>
#include <QTime>
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
#include "dialog.h"
#include "privileges.h"
#include "integrity.h"
#include "integrityfile.h"
#pragma comment(lib, "advapi32.lib")

MainWindow::MainWindow(QWidget *parent)
	: QMainWindow(parent)
	, ui(new Ui::MainWindow)
{
	ui->setupUi(this);
	QWidget::setWindowTitle("Processes");
	timer = new QTimer();
	connect(timer, SIGNAL(timeout()), this, SLOT(slotTimer()));
	timer->start(1000);
	connect(ui->tableWidget, &QTableWidget::cellDoubleClicked, this, &MainWindow::cellDoubleClicked);
	PrintProcessList();
}

void MainWindow::slotTimer()
{
	ui->tableWidget->clear();
	int row = ui->tableWidget->rowCount();
	for (int i = 0; i < row; i++)
		ui->tableWidget->removeRow(i);
	ui->tableWidget->setRowCount(0);
	PrintProcessList();
}
int MainWindow::ModuleList(DWORD const dwProcessId)
{
	int res = 0;
	MODULEENTRY32 meModuleEntry;
	TCHAR buffer[256] = { 0 };
	HANDLE CONST hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwProcessId);
	if (INVALID_HANDLE_VALUE == hSnapshot) {
		return -1;
	}
	meModuleEntry.dwSize = sizeof(MODULEENTRY32);
	Module32First(hSnapshot, &meModuleEntry);
	do {
		wsprintf(buffer, L"  %s\r\n", meModuleEntry.szModule);
		if (QString::fromWCharArray(buffer).indexOf("mscore.dll") != -1 || QString::fromWCharArray(buffer).indexOf("shcore.dll") != -1)
		{
			res = 1;
		}

	} while (Module32Next(hSnapshot, &meModuleEntry));
	CloseHandle(hSnapshot);
	return res;
}
void MainWindow::PrintProcessList()
{
	SetSettings();
	PROCESSENTRY32 peProcessEntry;
	HANDLE hToken;
	HANDLE curHandle;
	DWORD dSize = 0;
	PTOKEN_PRIVILEGES Priv;
	struct StructProcParam
	{
		LPSTR UserName;
		PTOKEN_USER pUser;
		DWORD uSize = 0;
		SID_NAME_USE SidType;
		TCHAR lpName[256];
		TCHAR lpDomain[256];

		PROCESS_MITIGATION_DEP_POLICY dep;
		PROCESS_MITIGATION_ASLR_POLICY aslr;
		PSECURITY_DESCRIPTOR pSD;
		PSID pSID;
		PACL pacl, pdacl;
		LPWSTR SIDParam;
		PROCESS_MEMORY_COUNTERS procMem;
		BOOL is = FALSE;
		TCHAR ProcPath[256] = { 0 };
		TCHAR buffer[256] = { 0 };
		TCHAR NameFile[256] = { 0 };
		DWORD sizeName;
	}Proc;
	HANDLE CONST hSnapshotPr = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (INVALID_HANDLE_VALUE == hSnapshotPr) {
		printf("Error: no process\n");
		return;
	}
	peProcessEntry.dwSize = sizeof(PROCESSENTRY32);
	Process32First(hSnapshotPr, &peProcessEntry);
	do {
		ui->tableWidget->insertRow(ui->tableWidget->rowCount());
		curHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, peProcessEntry.th32ProcessID);
		GetProcessMemoryInfo(curHandle, &Proc.procMem, sizeof(Proc.procMem));
		GetModuleFileNameExW(curHandle, NULL, Proc.ProcPath, sizeof(Proc.ProcPath));
		//GetProcessImageFileNameW(curHandle, Proc.NameFile, sizeof(Proc.NameFile));
		//AddItem(ui->tableWidget, QString::fromWCharArray(Proc.NameFile), 2);
		 //memset(Proc.buffer,0,sizeof(Proc.NameFile));
	  // GetExitCodeProcess(curHandle,&ProcessExCode);
	 //  wsprintf(ProcDescr, L"%08X", curHandle);
	 //  wsprintf(ProcPrior, L"%d\r\n",  peProcessEntry.cntThreads);//количество потоков
		wsprintf(Proc.buffer, L"%08X", peProcessEntry.th32ProcessID);
		AddItem(ui->tableWidget, QString::fromWCharArray(Proc.buffer), 0);
		memset(Proc.buffer, 0, sizeof(Proc.buffer));

		wsprintf(Proc.buffer, L"%08X", peProcessEntry.th32ParentProcessID);
		AddItem(ui->tableWidget, QString::fromWCharArray(Proc.buffer), 1);
		memset(Proc.buffer, 0, sizeof(Proc.buffer));

		wsprintf(Proc.buffer, L"%s\r\n", peProcessEntry.szExeFile);
		AddItem(ui->tableWidget, QString::fromWCharArray(Proc.buffer), 2);
		//printf("%s ", QString::fromWCharArray(Proc.buffer).toStdString().data());
		memset(Proc.buffer, 0, sizeof(Proc.buffer));

		wsprintf(Proc.buffer, L"%d\r\n", peProcessEntry.pcPriClassBase);
		AddItem(ui->tableWidget, QString::fromWCharArray(Proc.buffer), 3);
		memset(Proc.buffer, 0, sizeof(Proc.buffer));

		wsprintf(Proc.buffer, L"%d\r\n", Proc.procMem.WorkingSetSize);
		AddItem(ui->tableWidget, QString::fromWCharArray(Proc.buffer), 4);
		memset(Proc.buffer, 0, sizeof(Proc.buffer));

		IsWow64(curHandle, Proc.is);
		if (Proc.is) { AddItem(ui->tableWidget, "x64", 5); }
		else { AddItem(ui->tableWidget, "x32", 5); }
		AddItem(ui->tableWidget, QString::fromWCharArray(Proc.ProcPath), 7);
		if (ModuleList(peProcessEntry.th32ProcessID)) { AddItem(ui->tableWidget, "Yes", 14); }
		else { AddItem(ui->tableWidget, "No", 13); }
		bool true_dep=GetProcessMitigationPolicy(curHandle,ProcessDEPPolicy, &Proc.dep, sizeof(Proc.dep));
		 if (true_dep)
		 {
			 if (Proc.dep.Enable|| Proc.dep.Permanent) {
				 AddItem(ui->tableWidget, "DEP", 10);
			 }
			// if (Proc.dep.Permanent) { AddItem(ui->tableWidget, "DEP (permanent)", 10); }
		 else {AddItem(ui->tableWidget, "NOT DEP", 10);}
		 }
		 bool true_aslr=GetProcessMitigationPolicy(curHandle,ProcessASLRPolicy, &Proc.aslr, sizeof(Proc.aslr));
			   if (true_aslr)
			   {
			   if (Proc.aslr.DisallowStrippedImages|| Proc.aslr.EnableBottomUpRandomization|| Proc.aslr.EnableForceRelocateImages
				   || Proc.aslr.EnableHighEntropy|| Proc.aslr.Flags|| Proc.aslr.ReservedFlags)
			   AddItem(ui->tableWidget, "ASLR", 11);
			   else { AddItem(ui->tableWidget, "NOT ASLR", 11); }
			   }
		BOOL t = OpenProcessToken(curHandle, TOKEN_QUERY, &hToken);
		if (t == FALSE) { continue; }

		if (!GetTokenInformation(hToken, TokenPrivileges, NULL, 0, &dSize))
		{
			if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
			{
				printf("1PRIVGetTokenInformation Error %u\n", GetLastError());
			}
		}
		Priv = (PTOKEN_PRIVILEGES)GlobalAlloc(GPTR, dSize);
		if (!GetTokenInformation(hToken, TokenPrivileges, Priv,
			dSize, &dSize))
		{
			printf("2PRIV:GetTokenInformation Error %u\n", GetLastError());
		}
		wsprintf(Proc.buffer, L"%d", Priv->PrivilegeCount);
		AddItem(ui->tableWidget, QString::fromWCharArray(Proc.buffer), 9);
		memset(Proc.buffer, 0, sizeof(Proc.buffer));
		IntegrLev(peProcessEntry.th32ProcessID);
		if (!GetTokenInformation(hToken, (TOKEN_INFORMATION_CLASS)1, NULL, 0, &Proc.uSize))
		{
			if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
				printf("1USGetTokenInformation Error %u\n", GetLastError());
			}
		}
		Proc.pUser = (PTOKEN_USER)GlobalAlloc(GPTR, Proc.uSize);
		//ConvertSidToStringSid(Proc.pUserInfo->User.Sid, &Proc.SIDParam);
	   // AddItem(ui->tableWidget, QString::fromWCharArray(Proc.SIDParam),6);

		if (!GetTokenInformation(hToken, (TOKEN_INFORMATION_CLASS)1, Proc.pUser, Proc.uSize, &Proc.uSize))
		{
			printf("2USE:GetTokenInformation Error %u\n", GetLastError());
		}

		if (!LookupAccountSid(NULL, Proc.pUser->User.Sid, Proc.lpName, &Proc.uSize, Proc.lpDomain, &Proc.uSize, &Proc.SidType))
		{
			DWORD dwResult = GetLastError();
			if (dwResult == ERROR_NONE_MAPPED)
			{
				AddItem(ui->tableWidget, "NONE_MAPPED", 12);
				AddItem(ui->tableWidget, "NONE_MAPPED", 13);
			}
			else
			{
				printf("LookupAccountSid Error %u\n", GetLastError());
			}
		}
		else
		{
			/*printf( "Current user is  %s\\%s\n",
					Proc.lpDomain, Proc.lpName );*/
			AddItem(ui->tableWidget, QString::fromWCharArray(Proc.lpDomain), 12);
			AddItem(ui->tableWidget, QString::fromWCharArray(Proc.lpName), 13);

		}
		ULONG Error = GetSecurityInfo(curHandle,
			SE_FILE_OBJECT,
			OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
			&Proc.pSID,
			NULL,
			&Proc.pdacl, &Proc.pacl,
			&Proc.pSD
		);
		if (Error != ERROR_SUCCESS)
		{
			AddItem(ui->tableWidget, "unknown", 6);
		}
		else {
			ConvertSidToStringSid(Proc.pSID, &Proc.SIDParam);
			AddItem(ui->tableWidget, QString::fromWCharArray(Proc.SIDParam), 6);
		}
		if (Proc.pUser) GlobalFree(Proc.pUser);
		if (Priv)GlobalFree(Priv);
		Proc = {};
		if (hToken) { CloseHandle(hToken); }
		CloseHandle(curHandle);
	} while (Process32Next(hSnapshotPr, &peProcessEntry));
	CloseHandle(hSnapshotPr);
}

void MainWindow::AddItem(QTableWidget *tableWidget, QString QtStr, int column)
{
	tableWidget->setItem(tableWidget->rowCount() - 1, column, new QTableWidgetItem(QtStr));
	QTableWidgetItem *newItem = new QTableWidgetItem();
	newItem->setText(QtStr);
	tableWidget->setItem(tableWidget->rowCount(), column, newItem);
}


void MainWindow::SetSettings()
{
	ui->tableWidget->setColumnCount(15);
	//ui->tableWidget->setColumnWidth(7,800);
	QStringList name_table;
	name_table << "PID" << "PPID" << "Name" << "Priority" << "Memory" << "Type" << "SID" << "File Path" << "Integrity level" << "Privileges" << "DEP" << "ASLR" << "Domain" << "User" << "Native";
	ui->tableWidget->setHorizontalHeaderLabels(name_table);
}
bool MainWindow::IsWow64(HANDLE hProcess, BOOL &isWow64)
{

	typedef BOOL(WINAPI *LPFN_ISWOW64PROCESS) (HANDLE, PBOOL);
	LPFN_ISWOW64PROCESS fnIsWow64Process;
	fnIsWow64Process = (LPFN_ISWOW64PROCESS)GetProcAddress(GetModuleHandle(TEXT("kernel32")), "IsWow64Process");
	bool res = fnIsWow64Process != NULL && fnIsWow64Process(hProcess, &isWow64);
	return res;
}

void MainWindow::cellDoubleClicked()
{
	char *end;
	QString check = ui->tableWidget->item(ui->tableWidget->currentRow(), 0)->text();
	QByteArray text = check.toStdString().data();
	const char *chStr = text.constData();
	ID = strtol(chStr, &end, 16);
	ProcID = strtol(chStr, &end, 16);
	IDProc = strtol(chStr, &end, 16);
	ProcName = ui->tableWidget->item(ui->tableWidget->currentRow(), 2)->text();
	if (ui->tableWidget->currentColumn() == 9)
	{
		Privileges window;
		window.setModal(true);
		window.exec();
	}
	else if (ui->tableWidget->currentColumn() == 8)
	{
		QTableWidgetItem *tmp = ui->tableWidget->item(ui->tableWidget->currentRow(), 8);
		if (tmp != NULL)
		{
			str = ui->tableWidget->item(ui->tableWidget->currentRow(), 8)->text();
			Integrity window;
			window.setModal(true);
			window.exec();
		}
	}
	else
	{
		mod = new Module(this);
		mod->show();
	}
}


void MainWindow::IntegrLev(DWORD ID)
{
	PTOKEN_MANDATORY_LABEL IntPrivil = NULL;
	DWORD IntSize = 0;
	HANDLE hToken;
	HANDLE curHandle;
	DWORD dwIntegrityLevel;
	curHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, ID);
	BOOL t = OpenProcessToken(curHandle, TOKEN_QUERY, &hToken);
	if (t == FALSE) { return; }

	if (!GetTokenInformation(hToken, (TOKEN_INFORMATION_CLASS)25, NULL, 0, &IntSize))
	{
		if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
			printf("1INTGetTokenInformation Error %u\n", GetLastError());
		}
	}

	IntPrivil = (PTOKEN_MANDATORY_LABEL)GlobalAlloc(GPTR, IntSize);

	if (!GetTokenInformation(hToken, (TOKEN_INFORMATION_CLASS)25, IntPrivil, IntSize, &IntSize))
	{
		printf("2INT:GetTokenInformation Error %u\n", GetLastError());
	}
	dwIntegrityLevel = *GetSidSubAuthority(IntPrivil->Label.Sid, (DWORD)(UCHAR)(*GetSidSubAuthorityCount(IntPrivil->Label.Sid) - 1));
	//if (dwIntegrityLevel != NULL)
	{
		if (dwIntegrityLevel <= SECURITY_MANDATORY_UNTRUSTED_RID)
		{
			// Low Integrity
			AddItem(ui->tableWidget, "Untrusted Process", 8);
		}
		else if (dwIntegrityLevel == SECURITY_MANDATORY_LOW_RID)
		{
			// Low Integrity
			AddItem(ui->tableWidget, "Low Process", 8);
		}
		else if (dwIntegrityLevel >= SECURITY_MANDATORY_MEDIUM_RID &&
			dwIntegrityLevel < SECURITY_MANDATORY_HIGH_RID)
		{
			// Medium Integrity
			AddItem(ui->tableWidget, "Medium Process", 8);
		}
		else if (dwIntegrityLevel >= SECURITY_MANDATORY_HIGH_RID &&
			dwIntegrityLevel < SECURITY_MANDATORY_SYSTEM_RID)
		{
			// High Integrity
			AddItem(ui->tableWidget, "High Process", 8);

		}
		else if (dwIntegrityLevel >= SECURITY_MANDATORY_SYSTEM_RID &&
			dwIntegrityLevel < SECURITY_MANDATORY_PROTECTED_PROCESS_RID)
		{
			// System Integrity
			AddItem(ui->tableWidget, "System Process", 8);
		}
		else if (dwIntegrityLevel >= SECURITY_MANDATORY_PROTECTED_PROCESS_RID)
		{
			// High Integrity
			AddItem(ui->tableWidget, "Protected Process", 8);
		}
	}
	if (IntPrivil) GlobalFree(IntPrivil);
	if (hToken) { CloseHandle(hToken); }
	CloseHandle(curHandle);
}

MainWindow::~MainWindow()
{
	delete ui;
}

void MainWindow::on_pushButton_clicked()
{
	Dialog window;
	window.setModal(true);
	window.exec();
}



