#include "explainbin/core/Types.hpp"
#include "explainbin/ui/AppSettings.hpp"
#include "explainbin/ui/MainWindow.hpp"
#include "explainbin/ui/Theme.hpp"

#include <QApplication>
#include <QFileInfo>
#include <QStringList>

int main(int argc, char* argv[]) {
    QApplication application(argc, argv);
    QApplication::setOrganizationName(QStringLiteral("ExplainBin"));
    QApplication::setApplicationName(QStringLiteral("ExplainBin"));
    QApplication::setApplicationDisplayName(QStringLiteral("ExplainBin"));
    QApplication::setApplicationVersion(
        QString::fromUtf8(explainbin::kToolVersion));

    const explainbin::ui::AppSettings settings = explainbin::ui::AppSettings::load();
    explainbin::ui::applyTheme(application, settings.darkTheme);

    explainbin::ui::MainWindow window;
    window.show();

    const QStringList arguments = application.arguments();
    if (arguments.size() > 1) {
        const QFileInfo candidate(arguments.at(1));
        if (candidate.exists() && candidate.isFile()) {
            window.openFile(candidate.absoluteFilePath());
        }
    }

    return application.exec();
}
