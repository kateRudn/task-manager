#ifndef DIALOG_H
#define DIALOG_H

#include <QDialog>
#include <QTableWidget>
#include <QTableWidgetItem>
#include "windows.h"
#include <tlhelp32.h>
#include "integrityfile.h"
extern QString level;
extern QString FileNameGlobal;

QT_BEGIN_NAMESPACE
namespace Ui { class Dialog; }
QT_END_NAMESPACE

class Dialog : public QDialog
{
	Q_OBJECT
		void AddItem(QTableWidget *tableWidget, QString QtStr, int column);

public:
	Dialog(QWidget *parent = nullptr);
	~Dialog();

private slots:
	void cellDoubleClicked();
	//void ChangeIntegrityLevel();
	void DeleteAceFunc();
	void ChangeStatus();
	void CleanTable();
	void PrintTable();
	void on_ReadFileName_clicked();

private:
	Ui::Dialog *ui;
};
#endif // DIALOG_H
