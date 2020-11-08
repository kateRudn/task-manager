#include "integrity.h"
#include "ui_integrity.h"
#include "mainwindow.h"
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
DWORD IDProc;
QString str;
Integrity::Integrity(QWidget *parent) :
	QDialog(parent),
	ui(new Ui::Integrity)
{
	ui->setupUi(this);
	QWidget::setWindowTitle("Integrity level of process");
	ui->tableWidget->setColumnCount(2);
	QStringList name_table;
	name_table << "Integrity level" << "Value";
	ui->tableWidget->setHorizontalHeaderLabels(name_table);
	connect(ui->tableWidget, &QTableWidget::cellDoubleClicked, this, &Integrity::cellDoubleClicked);
	// ui->tableWidget_2->setFont(QFont(0, 0, 200, 1));
	timer = new QTimer();
	connect(timer, SIGNAL(timeout()), this, SLOT(slotTimer()));
	timer->start(1000);
	Integrity_level();
}
void Integrity::slotTimer()
{
	ui->tableWidget->clear();
	int row = ui->tableWidget->rowCount();
	for (int i = 0; i < row; i++)
		ui->tableWidget->removeRow(i);
	ui->tableWidget->setRowCount(0);
	QStringList name_table;
	name_table << "Integrity level" << "Value";
	ui->tableWidget->setHorizontalHeaderLabels(name_table);
	Integrity_level();
}
void Integrity::Integrity_level()
{

	for (int i = 0; i < 6; i++)
	{
		ui->tableWidget->insertRow(ui->tableWidget->rowCount());
		switch (i)
		{
		case 0: {AddItem(ui->tableWidget, "Protected Process", 0);
			if (str == "High Process") { AddItem(ui->tableWidget, "+", 1); }
			break; }
		case 1: { AddItem(ui->tableWidget, "System Process", 0);
			if (str == "System Process") { AddItem(ui->tableWidget, "+", 1); }
			break; }
		case 2: {AddItem(ui->tableWidget, "High Process", 0);
			if (str == "High Process") { AddItem(ui->tableWidget, "+", 1); }
			break; }
		case 3: {AddItem(ui->tableWidget, "Medium Process", 0);
			if (str == "Medium Process") { AddItem(ui->tableWidget, "+", 1); }
			break; }
		case 4: AddItem(ui->tableWidget, "Low Process", 0);
			if (str == "Low Process") { AddItem(ui->tableWidget, "+", 1); }
			break;
		case 5: AddItem(ui->tableWidget, "Untrusted Process", 0);
			if (str == "Untrusted Process") { AddItem(ui->tableWidget, "+", 1); }
			break;
		}

	}
}
bool Integrity::SetIntegrityLevel(int privilegeLevel, DWORD PrID)
{
	std::string sidLevel;
	if (privilegeLevel == 0)
		sidLevel = "S-1-16-0";
	else if (privilegeLevel == 1)
		sidLevel = "S-1-16-4096";
	else if (privilegeLevel == 2)
		sidLevel = "S-1-16-8192";
	else if (privilegeLevel == 3)
		sidLevel = "S-1-16-12288";
	else if (privilegeLevel == 4)
		sidLevel = " S-1-16-16384";
	else {
		return false;
	}

	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PrID);
	if (hProcess != INVALID_HANDLE_VALUE) {
		if (OpenProcessToken(hProcess, TOKEN_QUERY | TOKEN_ADJUST_DEFAULT, &hProcess)) {
			DWORD dwSize = 0;
			if (GetTokenInformation(hProcess, TokenIntegrityLevel, NULL, 0, &dwSize) || GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
				PTOKEN_MANDATORY_LABEL pTokenLevel = (PTOKEN_MANDATORY_LABEL)LocalAlloc(0, dwSize);
				if (pTokenLevel != NULL) {
					if (GetTokenInformation(hProcess, TokenIntegrityLevel, pTokenLevel, dwSize, &dwSize)) {
						PSID pSID = NULL;
						memset(pTokenLevel, 0, sizeof(pTokenLevel));
						ConvertStringSidToSidA(sidLevel.c_str(), &pSID);
						pTokenLevel->Label.Attributes = SE_GROUP_INTEGRITY;
						pTokenLevel->Label.Sid = pSID;
						SetTokenInformation(hProcess, TokenIntegrityLevel, pTokenLevel, dwSize);
						CloseHandle(hProcess);
						LocalFree(pTokenLevel);
						return true;
					}
					LocalFree(pTokenLevel);
				}
			}
		}
	}
	CloseHandle(hProcess);
	return false;
}

void Integrity::AddItem(QTableWidget *tableWidget, QString QtStr, int column)
{
	tableWidget->setItem(tableWidget->rowCount() - 1, column, new QTableWidgetItem(QtStr));
	QTableWidgetItem *newItem = new QTableWidgetItem();
	newItem->setText(QtStr);
	tableWidget->setItem(tableWidget->rowCount(), column, newItem);
}
void Integrity::cellDoubleClicked()
{
	int change;
	if (str == "Untrusted Process" || str == "Low Process"&&ui->tableWidget->currentRow() <= 4
		|| str == "Medium Process"&&ui->tableWidget->currentRow() <= 3
		|| str == "High Process"&&ui->tableWidget->currentRow() <= 2
		|| str == "System Process"&&ui->tableWidget->currentRow() <= 1)
	{
		QMessageBox *msg = new QMessageBox;
		msg->setText("NO!");
		msg->exec();
		return;
	}
	switch (ui->tableWidget->currentRow())
	{
	case 0: { QMessageBox *msg = new QMessageBox;
		msg->setText("NO!");
		msg->exec();
		return; }
	case 1: change = 4; str = "System Process"; break;
	case 2: change = 3; str = "High Process"; break;
	case 3: change = 2; str = "Medium Process"; break;
	case 4: change = 1; str = "Low Process"; break;
	case 5: change = 0; str = "Untrusted Process"; break;
	}
	SetIntegrityLevel(change, IDProc);
}
Integrity::~Integrity()
{
	delete ui;
}
