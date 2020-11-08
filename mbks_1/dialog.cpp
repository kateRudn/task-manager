#include "dialog.h"
#include "ui_dialog.h"
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
#include <securitybaseapi.h>
#include <accctrl.h>
#include <aclapi.h>
#include <Sddl.h>
#include "integrityfile.h"
// trycatch

// C:\Users\Anna\Downloads\2.txt
// C:\Users\Anna\Downloads\putty-64bit-0.72-installer.msi
// C:\Windows\bcastdvr\broadcastpause720.h264
// C:\Windows\PFRO.log

QString globalFilePath;

void Dialog::AddItem(QTableWidget *tableWidget, QString QtStr, int column)
{
	tableWidget->setItem(tableWidget->rowCount() - 1, column, new QTableWidgetItem(QtStr));
	QTableWidgetItem *newItem = new QTableWidgetItem();
	newItem->setText(QtStr);
	tableWidget->setItem(tableWidget->rowCount(), column, newItem);
}

/*void Dialog::ChangeIntegrityLevel()
{
	int row = ui->tableFile->currentRow();
	int column = ui->tableFile->currentColumn();
	QString oldLevel = ui->tableFile->item(row, column)->text();
	QString newLevelStr;
	QString newLevelValue;
	if (oldLevel == "Untrusted Process") return;
	else if (oldLevel == "Medium Process") { newLevelStr = QString("%1").arg("Low Process");              newLevelValue = "S:(ML;;NR;;;LW)"; }
	else if (oldLevel == "High Integrity Process") { newLevelStr = QString("%1").arg("Medium Process");            newLevelValue = "S:(ML;;NR;;;ME)"; }
	else if (oldLevel == "System Integrity Process") { newLevelStr = QString("%1").arg("High Integrity Process");    newLevelValue = "S:(ML;;NR;;;HI)"; }
	else  return;
	ui->tableFile->setItem(row, column, new QTableWidgetItem(newLevelStr));

	PSECURITY_DESCRIPTOR pSD = 0;
	PSID lpSid = 0;
	PACL pSACL = 0;
	BOOL lpbSaclPresent = FALSE;
	BOOL lpbSaclDefaulted = FALSE;
	LPCWSTR FileName = reinterpret_cast<LPCWSTR>(ui->tableFile->item(row, 6)->text().utf16());
	LPCWSTR newLevel = reinterpret_cast<LPCWSTR>(newLevelValue.utf16());
	if (ConvertStringSecurityDescriptorToSecurityDescriptorW(newLevel, SDDL_REVISION_1, &pSD, 0))
	{
		if (GetSecurityDescriptorSacl(pSD, &lpbSaclPresent, &pSACL, &lpbSaclDefaulted))
		{
			if (!SetNamedSecurityInfoW((LPWSTR)FileName, SE_FILE_OBJECT, LABEL_SECURITY_INFORMATION, &lpSid, 0, 0, pSACL))
				printf("Security Info Error %u\n", GetLastError());
		}
		else printf("Security Descriptor Error %u\n", GetLastError());
		//LocalFree(pSD);
	}
	else printf("Get Security Descriptor Error %u\n", GetLastError());
	LocalFree(pSD);
}*/

void Dialog::DeleteAceFunc()
{
	int row = ui->tableFile->currentRow();
	int column = ui->tableFile->currentColumn();

	PACL pAcl = 0;
	PSID aceSid;
	ACCESS_ALLOWED_ACE* pAce;
	ACL_REVISION_INFORMATION FileAcl;
	LPCWSTR FileNameLPC = reinterpret_cast<LPCWSTR>(globalFilePath.utf16());
	perror("Delete Success\n");
	DWORD Error = GetNamedSecurityInfo(FileNameLPC, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
		0, 0, &pAcl, 0, 0);
	if (Error != ERROR_SUCCESS)
	{
		perror("oops");
		return;
	}
	GetAclInformation(pAcl, &FileAcl, sizeof(FileAcl), AclRevisionInformation);
	perror("Delete Success\n");
	//GetAce(pAcl, 0, (LPVOID *)&pAce);
	//aceSid = &pAce->SidStart;
	if (!DeleteAce(pAcl, row))
	{
		perror("DeleteAce");
		return;
	}
	perror("Delete Success\n");
	if (!SetNamedSecurityInfoW((LPWSTR)FileNameLPC, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, 0, 0, pAcl, 0))
	{
		printf("Set securite error %u\n", GetLastError());
		//return;
	}
	CleanTable();
	PrintTable();
}

void Dialog::ChangeStatus()
{
	int row = ui->tableFile->currentRow();
	int column = ui->tableFile->currentColumn();
	QString actualStatus = QString("%1").arg(ui->tableFile->item(row, column)->text());
	//if (actualStatus == "denied") return;

	LPCWSTR FileNameLPC = reinterpret_cast<LPCWSTR>(globalFilePath.utf16());
	PACL pOldDACL = 0, pNewDACL = 0;
	// Get a pointer to the existing DACL.
	DWORD Error = GetNamedSecurityInfo(FileNameLPC, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
		0, 0, &pOldDACL, 0, 0);
	if (Error != ERROR_SUCCESS)
	{
		printf("ChangeStatus SecurityInfo Error %u\n", GetLastError());
		return;
	}

	// Initialize an EXPLICIT_ACCESS structure for the new ACE.
	DWORD dwAccessRight;
	QString rightStr = QString("%1").arg(ui->tableFile->item(row, column - 1)->text());
	QString userNameStr = QString("%1").arg(ui->tableFile->item(row, column - 2)->text());
	LPCWSTR userNameLPC = reinterpret_cast<LPCWSTR>(userNameStr.utf16());
	ACCESS_ALLOWED_ACE *pAce;
	EXPLICIT_ACCESS ea;
	PSID pEveryoneSID = 0;
	SID_IDENTIFIER_AUTHORITY SIDAuthWorld = SECURITY_WORLD_SID_AUTHORITY;
	if (rightStr == "delete")                       dwAccessRight = DELETE;
	else if (rightStr == "write owner")             dwAccessRight = WRITE_OWNER;
	else if (rightStr == "write DAC")               dwAccessRight = WRITE_DAC;
	else if (rightStr == "read")                    dwAccessRight = FILE_GENERIC_READ;
	else if (rightStr == "write")                   dwAccessRight = FILE_GENERIC_WRITE;
	else if (rightStr == "execute")                 dwAccessRight = FILE_GENERIC_EXECUTE;
	else if (rightStr == "synchronize")             dwAccessRight = SYNCHRONIZE;
	else if (rightStr == "read control")            dwAccessRight = READ_CONTROL;
	else
	{
		perror("ChangeStatus Right Error");
		if (pEveryoneSID != 0)
			LocalFree(pEveryoneSID);
		return;
	}
	if (!GetAce(pOldDACL, row, (LPVOID *)&pAce))
	{
		perror("ChangeStatus GetAce Error");
		return;
	}
	if (!AllocateAndInitializeSid(&SIDAuthWorld, 1, SECURITY_WORLD_RID, 0, 0, 0, 0, 0, 0, 0, &pEveryoneSID))
	{
		printf("ChangeStatus InitializeSid Error %u\n", GetLastError());
		if (pEveryoneSID != 0)
			LocalFree(pEveryoneSID);
		return;
	}
	ZeroMemory(&ea, sizeof(EXPLICIT_ACCESS));
	/*ea.grfAccessPermissions = dwAccessRight;
	ea.grfAccessMode = DENY_ACCESS;
	ea.grfInheritance = NO_INHERITANCE;
	ea.Trustee.TrusteeForm = TRUSTEE_IS_SID;
	ea.Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
	ea.Trustee.ptstrName = (LPTSTR)&pEveryoneSID;*/

	// Create a new ACL that merges the new ACE into the existing DACL.
	//ZeroMemory(&pNewDACL, );
	if (actualStatus=="allowed")
	BuildExplicitAccessWithNameW(&ea, (LPWSTR)userNameLPC, dwAccessRight, DENY_ACCESS, NO_INHERITANCE);
	else if (actualStatus == "denied")
		BuildExplicitAccessWithNameW(&ea, (LPWSTR)userNameLPC, dwAccessRight, GRANT_ACCESS, NO_INHERITANCE);
	Error = SetEntriesInAcl(1, &ea, pOldDACL, &pNewDACL);
	if (ERROR_SUCCESS != Error)
	{
		printf("ChangeStatus SetEntries Error %u\n", GetLastError());
		if (pNewDACL != 0)
			LocalFree((HLOCAL)pNewDACL);
		if (pEveryoneSID != 0)
			LocalFree(pEveryoneSID);
		return;
	}

	// Attach the new ACL as the object's DACL.
	Error = SetNamedSecurityInfo((LPWSTR)FileNameLPC, SE_FILE_OBJECT,
		DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
		0, 0, pNewDACL, 0);
	if (ERROR_SUCCESS != Error)
	{
		printf("ChangeStatus SetSecurity Error %u\n", GetLastError());
		if (pNewDACL != 0)
			LocalFree((HLOCAL)pNewDACL);
		if (pEveryoneSID != 0)
			LocalFree(pEveryoneSID);
		return;
	}

	if (pNewDACL != 0)
		LocalFree((HLOCAL)pNewDACL);
	if (pEveryoneSID != 0)
		LocalFree(pEveryoneSID);

	CleanTable();
	perror("ChangeStatus SetEntries Success");
	PrintTable();
	perror("ChangeStatus SetEntries Success!");
}

void Dialog::CleanTable()
{
	ui->tableFile->clear();
	int row = ui->tableFile->rowCount();
	for (int i = 0; i < row; i++)
		ui->tableFile->removeRow(i);
	ui->tableFile->setRowCount(0);
}

void Dialog::PrintTable()
{
	// создаем таблицу
	ui->tableFile->setColumnCount(7);
	ui->tableFile->setColumnWidth(0, 300);
	QStringList name_table;
	name_table << "File owner SID" << "File owner name" << "Integrity level" << "Users' names" << "Users' rights" << "Users' access" << "File path";
	ui->tableFile->setHorizontalHeaderLabels(name_table);

	ui->tableFile->insertRow(ui->tableFile->rowCount());
	QFileInfo FileInfo(globalFilePath);
	QString FileNameTemp = QString("%1").arg(globalFilePath);
	LPCWSTR FileNameLPC = reinterpret_cast<LPCWSTR>(FileNameTemp.utf16());

	// записываем в таблицу путь к файлу
	AddItem(ui->tableFile, globalFilePath, 6);

	// ищем уровень целостности
	PSID lpSid = 0;
	PACL pDACL = 0, pSACL = 0;
	PSECURITY_DESCRIPTOR pSD = 0;
	LPWSTR SIDParam;
	SYSTEM_MANDATORY_LABEL_ACE *sAce;
	DWORD dwIntegrityLevel;
	if (ERROR_SUCCESS != GetNamedSecurityInfo(FileNameLPC, SE_FILE_OBJECT, LABEL_SECURITY_INFORMATION,
		&lpSid,                 // Sid владельца
		0,                  // Sid группы
		0, &pSACL,   // списки прав доступа
		&pSD))
	{
		printf("Sacl info error %u\n", GetLastError());
	}
	else
	{
		if (0 != pSACL && pSACL->AceCount > 0)
		{
			GetAce(pSACL, 0, reinterpret_cast<void**>(&sAce));
			SID* sid = reinterpret_cast<SID*>(&sAce->SidStart);
			dwIntegrityLevel = sid->SubAuthority[0];
			printf("int_level %x\n", dwIntegrityLevel);
			//if (dwIntegrityLevel!=0)
			{
				if (dwIntegrityLevel == 0x0000)       AddItem(ui->tableFile, "Untrusted", 2); // Low Integrity
				else if (dwIntegrityLevel == 0x1000)        AddItem(ui->tableFile, "Low level", 2);       // Low Integrity
				else if (dwIntegrityLevel == 0x2000)        AddItem(ui->tableFile, "Medium level", 2);    // Medium Integrity
				else if (dwIntegrityLevel == 0x3000)        AddItem(ui->tableFile, "High level", 2); // High Integrity
				else if (dwIntegrityLevel == 0x4000)        AddItem(ui->tableFile, "System level", 2); // System Integrity
				else if (dwIntegrityLevel == 0x5000)        AddItem(ui->tableFile, "Protected level", 2); // High Integrity
				else                                        AddItem(ui->tableFile, "Untrusted", 2);
			}
		}
		else
		{
			//printf("0 sacl %u\n", GetLastError());
			AddItem(ui->tableFile, "Untrusted", 2);
		}
	}
	PWSTR stringSD;
	ULONG stringSDLen = 0;
	ConvertSecurityDescriptorToStringSecurityDescriptor(pSD, SDDL_REVISION_1, LABEL_SECURITY_INFORMATION, &stringSD, &stringSDLen);

	lpSid = 0;
	if (pSD) LocalFree(pSD);

	// ищем SID владельца файла
	DWORD Error = GetNamedSecurityInfo(FileNameLPC, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
		&lpSid,                 // Sid владельца
		0,                  // Sid группы
		&pDACL, 0,   // списки прав доступа
		&pSD);
	if (Error != ERROR_SUCCESS)
	{
		AddItem(ui->tableFile, "unknown", 0);
	}
	else
	{
		ConvertSidToStringSid(lpSid, &SIDParam);
		AddItem(ui->tableFile, QString::fromWCharArray(SIDParam), 0);
	}

	// ищем имя владельца файла
	TCHAR lpName[256];
	TCHAR lpDomain[256];
	DWORD lpNameBuf = 256;
	SID_NAME_USE SidType;
	memset(lpName, 0, sizeof(lpName));
	memset(lpDomain, 0, sizeof(lpDomain));
	if (!LookupAccountSid(0, lpSid, lpName, &lpNameBuf, lpDomain, &lpNameBuf, &SidType))
		printf("Account Name Error: %d\n", GetLastError());
	else
		AddItem(ui->tableFile, QString::fromWCharArray(lpName), 1);

	// ищем список ACL
	ACL_REVISION_INFORMATION FileAcl;
	ACCESS_ALLOWED_ACE *pAce;
	PSID pAceSid;
	BYTE AType;
	QString newLpName;

	GetAclInformation(pDACL, &FileAcl, sizeof(FileAcl), AclRevisionInformation);
	if (pDACL->AceCount == 0)
	{
		if (pSD) LocalFree(pSD);
		printf("Empty DACL %u\n", GetLastError());
		return;
	}
	if (!GetAce(pDACL, 0, (LPVOID *)&pAce))
	{
		printf("First Ace Error %u\n", GetLastError());
		CleanTable();
		return;
	}
	//AddItem(ui->tableFile, QString::number(pAce->SidStart), 3);
	memset(lpName, 0, sizeof(lpName));
	memset(lpDomain, 0, sizeof(lpDomain));
	lpNameBuf = 256;
	pAceSid = &pAce->SidStart;
	if (!LookupAccountSid(0, pAceSid, lpName, &lpNameBuf, lpDomain, &lpNameBuf, &SidType))
		printf("Account Name Error(2): %d\n", GetLastError());
	newLpName = QString("%1\\%2").arg(QString::fromWCharArray(lpDomain)).arg(QString::fromWCharArray(lpName));
	AddItem(ui->tableFile, newLpName, 3);
	AType = pAce->Header.AceType;
	if (AType == ACCESS_DENIED_ACE_TYPE)        AddItem(ui->tableFile, "denied", 5);
	else if (AType == ACCESS_ALLOWED_ACE_TYPE)  AddItem(ui->tableFile, "allowed", 5);
	else if (AType == SYSTEM_AUDIT_ACE_TYPE)    AddItem(ui->tableFile, "system audit", 5);
	else                                        AddItem(ui->tableFile, "else", 5);
	if ((pAce->Mask & WRITE_OWNER) == WRITE_OWNER)                          AddItem(ui->tableFile, "write owner", 4);
	else if ((pAce->Mask & WRITE_DAC) == WRITE_DAC)                         AddItem(ui->tableFile, "write DAC", 4);
	else if ((pAce->Mask & DELETE) == DELETE)                               AddItem(ui->tableFile, "delete", 4);
	else if ((pAce->Mask & FILE_GENERIC_READ) == FILE_GENERIC_READ)         AddItem(ui->tableFile, "read", 4);
	else if ((pAce->Mask & FILE_GENERIC_WRITE) == FILE_GENERIC_WRITE)       AddItem(ui->tableFile, "write", 4);
	else if ((pAce->Mask & FILE_GENERIC_EXECUTE) == FILE_GENERIC_EXECUTE)   AddItem(ui->tableFile, "execute", 4);
	else if ((pAce->Mask & SYNCHRONIZE) == SYNCHRONIZE)                     AddItem(ui->tableFile, "synchronize", 4);
	else if ((pAce->Mask & READ_CONTROL) == READ_CONTROL)                   AddItem(ui->tableFile, "read control", 4);
	else                                                                    AddItem(ui->tableFile, "else", 4);

	for (int i = 1; i < pDACL->AceCount; i++)
	{
		ui->tableFile->insertRow(ui->tableFile->rowCount());

		GetAce(pDACL, i, (LPVOID *)&pAce);
		memset(lpName, 0, sizeof(lpName));
		memset(lpDomain, 0, sizeof(lpDomain));
		lpNameBuf = 256;
		pAceSid = &pAce->SidStart;
		if (!LookupAccountSid(0, pAceSid, lpName, &lpNameBuf, lpDomain, &lpNameBuf, &SidType))
			printf("Account Name Error(2): %d\n", GetLastError());
		newLpName = QString("%1\\%2").arg(QString::fromWCharArray(lpDomain)).arg(QString::fromWCharArray(lpName));
		AddItem(ui->tableFile, newLpName, 3);

		AType = pAce->Header.AceType;
		if (AType == ACCESS_DENIED_ACE_TYPE)        AddItem(ui->tableFile, "denied", 5);
		else if (AType == ACCESS_ALLOWED_ACE_TYPE)  AddItem(ui->tableFile, "allowed", 5);
		else if (AType == SYSTEM_AUDIT_ACE_TYPE)    AddItem(ui->tableFile, "system audit", 5);
		else                                        AddItem(ui->tableFile, "else", 5);
		if ((pAce->Mask & WRITE_OWNER) == WRITE_OWNER)                          AddItem(ui->tableFile, "write owner", 4);
		else if ((pAce->Mask & WRITE_DAC) == WRITE_DAC)                         AddItem(ui->tableFile, "write DAC", 4);
		else if ((pAce->Mask & DELETE) == DELETE)                               AddItem(ui->tableFile, "delete", 4);
		else if ((pAce->Mask & FILE_GENERIC_READ) == FILE_GENERIC_READ)         AddItem(ui->tableFile, "read", 4);
		else if ((pAce->Mask & FILE_GENERIC_WRITE) == FILE_GENERIC_WRITE)       AddItem(ui->tableFile, "write", 4);
		else if ((pAce->Mask & FILE_GENERIC_EXECUTE) == FILE_GENERIC_EXECUTE)   AddItem(ui->tableFile, "execute", 4);
		else if ((pAce->Mask & SYNCHRONIZE) == SYNCHRONIZE)                     AddItem(ui->tableFile, "synchronize", 4);
		else if ((pAce->Mask & READ_CONTROL) == READ_CONTROL)                   AddItem(ui->tableFile, "read control", 4);
		else                                                                    AddItem(ui->tableFile, "else", 4);
	}

	if (pSD) LocalFree(pSD);
}

void Dialog::cellDoubleClicked()
{
	int column = ui->tableFile->currentColumn();
	if (column == 2)
	{
	FileNameGlobal = globalFilePath;
	level = ui->tableFile->item(ui->tableFile->currentRow(), 2)->text();
	IntegrityFile window;
	window.setModal(true);
	window.exec();
	CleanTable();
	PrintTable();
	}
	else if (column == 3 || column == 4) DeleteAceFunc();
	else if (column == 5) ChangeStatus();
}

void Dialog::on_ReadFileName_clicked()
{
	CleanTable();

	// считываем путь к файлу
	QString FileName(ui->lineEdit->text());
	//return;
	QFile file(FileName);
	if (!file.exists())
	{
		perror("File does not exist.\n");
		printf("The last error code: %u\n", GetLastError());
		QMessageBox *msg = new QMessageBox;
		msg->setText("EROR: file not found!");
		msg->exec();
		return;
	}
	globalFilePath = QString("%1").arg(FileName);
	//FileNameGlobal= QString("%1").arg(FileName);

	PrintTable();
}

Dialog::Dialog(QWidget *parent)
	: QDialog(parent)
	, ui(new Ui::Dialog)
{
	ui->setupUi(this);
	QWidget::setWindowTitle("Files");
	connect(ui->tableFile, &QTableWidget::cellDoubleClicked, this, &Dialog::cellDoubleClicked);
}

Dialog::~Dialog()
{
	delete ui;
}

