#pragma once

#include "explainbin/ui/AppSettings.hpp"

#include <QWidget>

class QCheckBox;
class QComboBox;
class QLabel;
class QSpinBox;

namespace explainbin::ui {

class SettingsView : public QWidget {
    Q_OBJECT
public:
    explicit SettingsView(QWidget* parent = nullptr);

    void reload();

signals:
    void settingsChanged();

private:
    void persist();

    QCheckBox* m_verifySignature = nullptr;
    QCheckBox* m_computeMd5 = nullptr;
    QSpinBox* m_maxSize = nullptr;
    QComboBox* m_theme = nullptr;
    QLabel* m_saved = nullptr;
    bool m_loading = false;
};

} // namespace explainbin::ui
