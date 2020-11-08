#include "addace.h"
#include "ui_addace.h"

AddAce::AddAce(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::AddAce)
{
    ui->setupUi(this);
}

AddAce::~AddAce()
{
    delete ui;
}
