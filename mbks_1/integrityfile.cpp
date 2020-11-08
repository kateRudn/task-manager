#include "integrityfile.h"
#include "ui_integrityfile.h"
#include <QMessageBox>
#include <QString>
#include <QTableWidget>
#include <QEvent>
#include <QTableWidgetItem>
#include <QTimer>
#include <QTime>
#include "windows.h"
#include <tlhelp32.h>
#include <psapi.h>
#include <fileapi.h>
#include <processthreadsapi.h>
#include <wow64apiset.h>
#include <sddl.h>
#include <QFile>
#include <QFileInfo>
#include <QLine>
#include <QLineEdit>
#include <winbase.h>
#include <aclapi.h>
#include "dialog.h"
QString level;
QString FileNameGlobal;
IntegrityFile::IntegrityFile(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::IntegrityFile)
{
    ui->setupUi(this);
	QWidget::setWindowTitle("Integrity level of file");
	connect(ui->tableWidget, &QTableWidget::cellDoubleClicked, this, &IntegrityFile::cellDoubleClicked);
	InegrityLevelFile();
}
void IntegrityFile::AddItem(QTableWidget *tableWidget, QString QtStr, int column)
{
	tableWidget->setItem(tableWidget->rowCount() - 1, column, new QTableWidgetItem(QtStr));
	QTableWidgetItem *newItem = new QTableWidgetItem();
	newItem->setText(QtStr);
	tableWidget->setItem(tableWidget->rowCount(), column, newItem);
}
void IntegrityFile::InegrityLevelFile()
{
	ui->tableWidget->setColumnCount(2);
	QStringList name_table;
	name_table << "Integrity level" << "Value";
	ui->tableWidget->setHorizontalHeaderLabels(name_table);
	ui->tableWidget->insertRow(ui->tableWidget->rowCount());
	AddItem(ui->tableWidget, "High level", 0);
	if (level== "High level"){ AddItem(ui->tableWidget, "+", 1); }
	ui->tableWidget->insertRow(ui->tableWidget->rowCount());
	AddItem(ui->tableWidget, "Medium level", 0);
	if (level == "Medium level") { AddItem(ui->tableWidget, "+", 1); }
	ui->tableWidget->insertRow(ui->tableWidget->rowCount());
	AddItem(ui->tableWidget, "Low level", 0);
	if (level == "Low level") { AddItem(ui->tableWidget, "+", 1); }
	ui->tableWidget->insertRow(ui->tableWidget->rowCount());
	AddItem(ui->tableWidget, "Untrusted", 0);
	if (level == "Untrusted") { AddItem(ui->tableWidget, "+", 1); }
}
void IntegrityFile::ChangeIntegrityLevel(int lev)
{
	QString newLevelStr;
	QString newLevelValue;
	if (lev == 3) { return; }
	else if (lev == 2) { level = QString("%1").arg("Low level");    newLevelValue = "S:(ML;;NR;;;LW)"; }
	else if (lev == 1) { level = QString("%1").arg("Medium level");  newLevelValue = "S:(ML;;NR;;;ME)"; }
	else if (lev == 0) { level = QString("%1").arg("High level");    newLevelValue = "S:(ML;;NR;;;HI)"; }
	//else { newLevelStr = QString("%1").arg("High Integrity Process");    newLevelValue = "S:(ML;;NR;;;HI)"; }
//	ui->tableWidget->setItem(row, column, new QTableWidgetItem("+"));

	PSECURITY_DESCRIPTOR pSD = NULL;
	PSID lpSid = 0;
	PACL pSACL = NULL;
	BOOL lpbSaclPresent = FALSE;
	BOOL lpbSaclDefaulted = FALSE;
	LPCWSTR FileName = reinterpret_cast<LPCWSTR>(FileNameGlobal.utf16());
	LPCWSTR newLevel = reinterpret_cast<LPCWSTR>(newLevelValue.utf16());
	if (ConvertStringSecurityDescriptorToSecurityDescriptorW(newLevel, SDDL_REVISION_1, &pSD, NULL))
	{
		if (GetSecurityDescriptorSacl(pSD, &lpbSaclPresent, &pSACL, &lpbSaclDefaulted))
		{
			if (!SetNamedSecurityInfoW((LPWSTR)FileName, SE_FILE_OBJECT, LABEL_SECURITY_INFORMATION, &lpSid, 0, 0, pSACL))
				printf("Security Info Error %u\n", GetLastError());
		}
		else printf("Security Descriptor Error %u\n", GetLastError());
		LocalFree(pSD);
	}
	else printf("Get Security Descriptor Error %u\n", GetLastError());
	CleanTable();
	InegrityLevelFile();
}
void IntegrityFile::cellDoubleClicked()
{
	ChangeIntegrityLevel(ui->tableWidget->currentRow());
}
void IntegrityFile::CleanTable()
{
	ui->tableWidget->clear();
	int row = ui->tableWidget->rowCount();
	for (int i = 0; i < row; i++)
	ui->tableWidget->removeRow(i);
	ui->tableWidget->setRowCount(0);
}

IntegrityFile::~IntegrityFile()
{
    delete ui;
}
