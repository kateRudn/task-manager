#ifndef INTEGRITY_H
#define INTEGRITY_H

#include <QDialog>
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
namespace Ui {
	class Integrity;
}

class Integrity : public QDialog
{
	Q_OBJECT
		void AddItem(QTableWidget *tableWidget, QString QtStr, int column);
	void Integrity_level();
	bool SetIntegrityLevel(int privilegeLevel, DWORD PrID);
	void cellDoubleClicked();
public:
	explicit Integrity(QWidget *parent = nullptr);
	~Integrity();
private slots:
	void slotTimer();
private:
	Ui::Integrity *ui;
	QTimer *timer;
};

#endif // INTEGRITY_H
