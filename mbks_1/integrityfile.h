#ifndef INTEGRITYFILE_H
#define INTEGRITYFILE_H

#include <QDialog>
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
namespace Ui {
class IntegrityFile;
}

class IntegrityFile : public QDialog
{
	Q_OBJECT
	void AddItem(QTableWidget *tableWidget, QString QtStr, int column);
	void ChangeIntegrityLevel(int lev);
	void InegrityLevelFile();
	void cellDoubleClicked();
	void CleanTable();
public:
    explicit IntegrityFile(QWidget *parent = nullptr);
    ~IntegrityFile();

private:
    Ui::IntegrityFile *ui;
};

#endif // INTEGRITYFILE_H
