#ifndef ADDACE_H
#define ADDACE_H

#include <QDialog>

namespace Ui {
class AddAce;
}

class AddAce : public QDialog
{
    Q_OBJECT

public:
    explicit AddAce(QWidget *parent = nullptr);
    ~AddAce();

private:
    Ui::AddAce *ui;
};

#endif // ADDACE_H
