#pragma once

#include <QSettings>
#include <QString>

namespace explainbin::ui {

struct AppSettings {
    bool verifySignature = true;
    bool computeMd5 = true;
    int maxSizeMb = 256;
    bool darkTheme = true;

    static AppSettings load() {
        QSettings settings(QStringLiteral("ExplainBin"), QStringLiteral("ExplainBin"));
        AppSettings value;
        value.verifySignature =
            settings.value(QStringLiteral("analysis/verifySignature"), true).toBool();
        value.computeMd5 = settings.value(QStringLiteral("analysis/computeMd5"), true).toBool();
        value.maxSizeMb = settings.value(QStringLiteral("analysis/maxSizeMb"), 256).toInt();
        value.darkTheme = settings.value(QStringLiteral("ui/darkTheme"), true).toBool();
        if (value.maxSizeMb < 1 || value.maxSizeMb > 4096) {
            value.maxSizeMb = 256;
        }
        return value;
    }

    void save() const {
        QSettings settings(QStringLiteral("ExplainBin"), QStringLiteral("ExplainBin"));
        settings.setValue(QStringLiteral("analysis/verifySignature"), verifySignature);
        settings.setValue(QStringLiteral("analysis/computeMd5"), computeMd5);
        settings.setValue(QStringLiteral("analysis/maxSizeMb"), maxSizeMb);
        settings.setValue(QStringLiteral("ui/darkTheme"), darkTheme);
    }
};

} // namespace explainbin::ui
