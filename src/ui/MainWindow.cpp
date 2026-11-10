#include "explainbin/ui/MainWindow.hpp"

#include "explainbin/core/Analyzer.hpp"
#include "explainbin/ui/Animations.hpp"
#include "explainbin/ui/AppSettings.hpp"
#include "explainbin/ui/Dashboard.hpp"
#include "explainbin/ui/FileAnalysisView.hpp"
#include "explainbin/ui/FindingsView.hpp"
#include "explainbin/ui/ImportsExportsView.hpp"
#include "explainbin/ui/PEStructureView.hpp"
#include "explainbin/ui/ReportView.hpp"
#include "explainbin/ui/SettingsView.hpp"
#include "explainbin/ui/SignatureView.hpp"
#include "explainbin/ui/Theme.hpp"

#include <QAction>
#include <QApplication>
#include <QCloseEvent>
#include <QDragEnterEvent>
#include <QDropEvent>
#include <QFileDialog>
#include <QFileInfo>
#include <QFrame>
#include <QHBoxLayout>
#include <QIcon>
#include <QLabel>
#include <QListWidget>
#include <QMenuBar>
#include <QMessageBox>
#include <QMimeData>
#include <QProgressBar>
#include <QPropertyAnimation>
#include <QPushButton>
#include <QScrollBar>
#include <QShowEvent>
#include <QSignalBlocker>
#include <QStackedWidget>
#include <QStatusBar>
#include <QTimer>
#include <QUrl>
#include <QVBoxLayout>

#include <QtConcurrent/QtConcurrentRun>

#include <algorithm>
#include <exception>
#include <filesystem>

namespace explainbin::ui {
namespace {

constexpr int kNavigationCount = 8;

QString normalisedPath(const QString& path) {
    return QFileInfo(path).absoluteFilePath();
}

} // namespace

MainWindow::MainWindow(QWidget* parent) : QMainWindow(parent) {
    setWindowTitle(QStringLiteral("ExplainBin \u2014 PE Security Analyzer"));
    setWindowIcon(QIcon(QStringLiteral(":/icons/appicon.svg")));
    resize(1360, 880);
    setMinimumSize(1080, 720);
    setAcceptDrops(true);
    if (anim::enabled()) {
        setWindowOpacity(0.0);
    }

    buildInterface();

    connect(&m_watcher, &QFutureWatcher<AnalysisResult>::finished, this,
            &MainWindow::onAnalysisFinished);
}

MainWindow::~MainWindow() {
    if (m_watcher.isRunning()) {
        m_watcher.waitForFinished();
    }
}

void MainWindow::buildInterface() {
    auto* central = new QWidget(this);
    central->setObjectName(QStringLiteral("centralRoot"));
    auto* centralLayout = new QHBoxLayout(central);
    centralLayout->setContentsMargins(0, 0, 0, 0);
    centralLayout->setSpacing(0);

    auto* sidebar = new QWidget(central);
    sidebar->setObjectName(QStringLiteral("sidebar"));
    sidebar->setFixedWidth(238);
    auto* sidebarLayout = new QVBoxLayout(sidebar);
    sidebarLayout->setContentsMargins(14, 20, 14, 16);
    sidebarLayout->setSpacing(4);

    auto* brandRow = new QWidget(sidebar);
    auto* brandLayout = new QHBoxLayout(brandRow);
    brandLayout->setContentsMargins(6, 0, 0, 0);
    brandLayout->setSpacing(10);

    auto* brandIcon = new QLabel(brandRow);
    brandIcon->setPixmap(QIcon(QStringLiteral(":/icons/appicon.svg")).pixmap(32, 32));
    brandIcon->setFixedSize(32, 32);

    auto* brandText = new QWidget(brandRow);
    auto* brandTextLayout = new QVBoxLayout(brandText);
    brandTextLayout->setContentsMargins(0, 0, 0, 0);
    brandTextLayout->setSpacing(0);
    auto* appName = new QLabel(QStringLiteral("ExplainBin"), brandText);
    appName->setObjectName(QStringLiteral("appName"));
    auto* tagline = new QLabel(QStringLiteral("Explainable PE analysis"), brandText);
    tagline->setObjectName(QStringLiteral("appTagline"));
    brandTextLayout->addWidget(appName);
    brandTextLayout->addWidget(tagline);

    brandLayout->addWidget(brandIcon);
    brandLayout->addWidget(brandText, 1);
    sidebarLayout->addWidget(brandRow);
    sidebarLayout->addSpacing(18);

    auto* navSection = new QLabel(QStringLiteral("NAVIGATION"), sidebar);
    navSection->setObjectName(QStringLiteral("navSection"));
    navSection->setContentsMargins(14, 0, 0, 4);
    sidebarLayout->addWidget(navSection);

    m_navigation = new QListWidget(sidebar);
    m_navigation->setObjectName(QStringLiteral("navList"));
    m_navigation->setFocusPolicy(Qt::NoFocus);
    m_navigation->setIconSize(QSize(18, 18));
    m_navigation->setSpacing(0);
    const QStringList sections = {
        QStringLiteral("Dashboard"),
        QStringLiteral("File Analysis"),
        QStringLiteral("PE Structure"),
        QStringLiteral("Imports & Exports"),
        QStringLiteral("Digital Signature"),
        QStringLiteral("Security Findings"),
        QStringLiteral("Reports"),
        QStringLiteral("Settings"),
    };
    const QStringList sectionIcons = {
        QStringLiteral(":/icons/nav_dashboard.svg"),
        QStringLiteral(":/icons/nav_file.svg"),
        QStringLiteral(":/icons/nav_structure.svg"),
        QStringLiteral(":/icons/nav_imports.svg"),
        QStringLiteral(":/icons/nav_signature.svg"),
        QStringLiteral(":/icons/nav_findings.svg"),
        QStringLiteral(":/icons/nav_reports.svg"),
        QStringLiteral(":/icons/nav_settings.svg"),
    };
    for (int index = 0; index < sections.size(); ++index) {
        new QListWidgetItem(QIcon(sectionIcons.at(index)), sections.at(index), m_navigation);
    }
    sidebarLayout->addWidget(m_navigation, 1);

    m_navIndicator = new QWidget(m_navigation->viewport());
    m_navIndicator->setObjectName(QStringLiteral("navIndicator"));
    m_navIndicator->setAttribute(Qt::WA_TransparentForMouseEvents);
    m_navIndicator->hide();
    m_navIndicatorAnimation = new QPropertyAnimation(m_navIndicator, "geometry", this);
    m_navIndicatorAnimation->setDuration(220);
    m_navIndicatorAnimation->setEasingCurve(QEasingCurve::OutCubic);

    auto* separator = new QFrame(sidebar);
    separator->setObjectName(QStringLiteral("sidebarSeparator"));
    separator->setFrameShape(QFrame::HLine);
    sidebarLayout->addWidget(separator);

    auto* footer = new QLabel(sidebar);
    footer->setObjectName(QStringLiteral("footerStatus"));
    footer->setTextFormat(Qt::RichText);
    footer->setText(QStringLiteral(
                        "<span style=\"color:#5fd18b;\">&#9679;</span>&nbsp; v%1"
                        "<br/><span>offline &middot; static only</span>")
                        .arg(fromUtf8(kToolVersion)));
    footer->setContentsMargins(6, 2, 0, 0);
    sidebarLayout->addWidget(footer);

    centralLayout->addWidget(sidebar);

    auto* mainArea = new QWidget(central);
    auto* mainLayout = new QVBoxLayout(mainArea);
    mainLayout->setContentsMargins(0, 0, 0, 0);
    mainLayout->setSpacing(0);

    auto* headerBar = new QWidget(mainArea);
    headerBar->setObjectName(QStringLiteral("headerBar"));
    auto* headerLayout = new QHBoxLayout(headerBar);
    headerLayout->setContentsMargins(20, 12, 20, 12);
    headerLayout->setSpacing(10);

    m_fileChip = new QLabel(QStringLiteral("No file selected"), headerBar);
    m_fileChip->setObjectName(QStringLiteral("fileChip"));
    m_fileChip->setTextInteractionFlags(Qt::TextSelectableByMouse);
    headerLayout->addWidget(m_fileChip, 1);

    m_openButton = new QPushButton(QStringLiteral("Open file\u2026"), headerBar);
    m_analyzeButton = new QPushButton(QStringLiteral("Analyze"), headerBar);
    m_analyzeButton->setObjectName(QStringLiteral("primary"));
    m_analyzeButton->setEnabled(false);
    headerLayout->addWidget(m_openButton);
    headerLayout->addWidget(m_analyzeButton);

    mainLayout->addWidget(headerBar);

    auto* progressRow = new QWidget(mainArea);
    progressRow->setObjectName(QStringLiteral("progressRow"));
    auto* progressLayout = new QHBoxLayout(progressRow);
    progressLayout->setContentsMargins(20, 8, 20, 8);
    progressLayout->setSpacing(12);
    m_stage = new QLabel(QStringLiteral("Ready. Open a Windows executable, DLL or driver."),
                         progressRow);
    m_stage->setObjectName(QStringLiteral("stageLabel"));
    m_progress = new QProgressBar(progressRow);
    m_progress->setTextVisible(false);
    m_progress->setRange(0, 100);
    m_progress->setValue(0);
    m_progress->setFixedWidth(190);
    m_progress->hide();
    progressLayout->addWidget(m_stage, 1);
    progressLayout->addWidget(m_progress);
    mainLayout->addWidget(progressRow);

    m_stack = new QStackedWidget(mainArea);
    m_dashboard = new Dashboard(m_stack);
    m_fileAnalysis = new FileAnalysisView(m_stack);
    m_structure = new PEStructureView(m_stack);
    m_imports = new ImportsExportsView(m_stack);
    m_signature = new SignatureView(m_stack);
    m_findings = new FindingsView(m_stack);
    m_reports = new ReportView(m_stack);
    m_settings = new SettingsView(m_stack);

    m_stack->addWidget(m_dashboard);
    m_stack->addWidget(m_fileAnalysis);
    m_stack->addWidget(m_structure);
    m_stack->addWidget(m_imports);
    m_stack->addWidget(m_signature);
    m_stack->addWidget(m_findings);
    m_stack->addWidget(m_reports);
    m_stack->addWidget(m_settings);

    mainLayout->addWidget(m_stack, 1);
    centralLayout->addWidget(mainArea, 1);

    setCentralWidget(central);

    auto* fileMenu = menuBar()->addMenu(QStringLiteral("&File"));
    auto* openAction = fileMenu->addAction(QStringLiteral("&Open file\u2026"));
    openAction->setShortcut(QKeySequence::Open);
    connect(openAction, &QAction::triggered, this, [this] {
        const QString path = QFileDialog::getOpenFileName(
            this, QStringLiteral("Open a Windows binary"), QString(),
            QStringLiteral("Windows binaries (*.exe *.dll *.sys *.ocx *.cpl *.scr *.efi *.mui);;"
                           "All files (*)"));
        if (!path.isEmpty()) {
            openFile(path);
        }
    });
    fileMenu->addSeparator();
    auto* exitAction = fileMenu->addAction(QStringLiteral("E&xit"));
    exitAction->setShortcut(QKeySequence::Quit);
    connect(exitAction, &QAction::triggered, this, &QWidget::close);

    auto* helpMenu = menuBar()->addMenu(QStringLiteral("&Help"));
    auto* aboutAction = helpMenu->addAction(QStringLiteral("&About ExplainBin"));
    connect(aboutAction, &QAction::triggered, this, [this] {
        QMessageBox::about(
            this, QStringLiteral("About ExplainBin"),
            QStringLiteral("<b>ExplainBin %1</b><br><br>%2<br><br>"
                           "ExplainBin is open source. Every finding includes technical "
                           "evidence, a plain-language explanation, legitimate alternatives and "
                           "suggested next steps.")
                .arg(fromUtf8(kToolVersion), fromUtf8(kStaticAnalysisDisclaimer)));
    });

    connect(m_openButton, &QPushButton::clicked, this, [this] {
        const QString path = QFileDialog::getOpenFileName(
            this, QStringLiteral("Open a Windows binary"), QString(),
            QStringLiteral("Windows binaries (*.exe *.dll *.sys *.ocx *.cpl *.scr *.efi *.mui);;"
                           "All files (*)"));
        if (!path.isEmpty()) {
            openFile(path);
        }
    });
    connect(m_analyzeButton, &QPushButton::clicked, this, &MainWindow::startAnalysis);
    connect(m_navigation, &QListWidget::currentRowChanged, this, &MainWindow::navigate);
    connect(m_navigation->verticalScrollBar(), &QScrollBar::valueChanged, this,
            [this] { updateNavIndicator(false); });
    connect(m_settings, &SettingsView::settingsChanged, this, &MainWindow::onSettingsChanged);

    m_stack->setCurrentIndex(0);
    m_navigation->setCurrentRow(0);
    updateNavIndicator(false);

    statusBar()->setSizeGripEnabled(false);
    statusBar()->showMessage(fromUtf8(kStaticAnalysisDisclaimer));
}

void MainWindow::openFile(const QString& path) {
    if (path.isEmpty()) {
        return;
    }
    if (m_watcher.isRunning()) {
        QMessageBox::information(this, QStringLiteral("Analysis running"),
                                 QStringLiteral("Please wait for the current analysis to finish."));
        return;
    }

    const QFileInfo info(path);
    if (!info.exists() || !info.isFile()) {
        QMessageBox::warning(this, QStringLiteral("File not found"),
                             QStringLiteral("The selected path is not an existing file:\n") + path);
        return;
    }

    m_path = normalisedPath(path);
    m_fileChip->setText(info.fileName() + QStringLiteral("  \u00b7  ") +
                        displayBytes(static_cast<std::uint64_t>(info.size())));
    m_fileChip->setToolTip(m_path);
    m_analyzeButton->setEnabled(true);
    startAnalysis();
}

void MainWindow::startAnalysis() {
    if (m_path.isEmpty() || m_watcher.isRunning()) {
        return;
    }
    const QFileInfo info(m_path);
    if (!info.exists() || !info.isFile()) {
        QMessageBox::warning(this, QStringLiteral("File not found"),
                             QStringLiteral("The selected file is no longer available:\n") + m_path);
        return;
    }

    const AppSettings settings = AppSettings::load();
    AnalysisOptions options;
    options.maxFileSizeBytes =
        static_cast<std::uint64_t>(settings.maxSizeMb) * 1024ULL * 1024ULL;
    options.verifySignature = settings.verifySignature;
    options.computeMd5 = settings.computeMd5;

    m_hasResult = false;
    m_result = AnalysisResult{};
    updateViews();

    setBusy(true);
    m_progress->setRange(0, 0);
    m_progress->setValue(0);
    anim::fadeIn(m_progress, 180);
    m_stage->setText(QStringLiteral("Analyzing ") + info.fileName() +
                     QStringLiteral(" \u2014 reading, hashing, parsing and verifying\u2026"));

    const std::filesystem::path path(m_path.toStdWString());
    m_watcher.setFuture(QtConcurrent::run([path, options]() -> AnalysisResult {
        try {
            Analyzer analyzer;
            return analyzer.analyze(path, options);
        } catch (const std::exception& exception) {
            AnalysisResult result;
            result.success = false;
            result.errorMessage =
                std::string("Unexpected analysis failure: ") + exception.what();
            return result;
        } catch (...) {
            AnalysisResult result;
            result.success = false;
            result.errorMessage = "Unexpected unknown analysis failure.";
            return result;
        }
    }));
}

void MainWindow::onAnalysisFinished() {
    m_result = m_watcher.result();
    m_hasResult = true;
    setBusy(false);
    m_progress->setRange(0, 100);
    m_progress->setValue(100);
    QTimer::singleShot(650, this, [this] { anim::fadeOut(m_progress, 180); });

    if (m_result.success) {
        m_stage->setText(QStringLiteral("Analysis complete in %1 ms.").arg(m_result.durationMs));
    } else {
        m_stage->setText(QStringLiteral("Analysis failed: ") + fromUtf8(m_result.errorMessage));
    }

    setResult(m_result);
    navigate(0);

    if (m_closing) {
        close();
    }
}

void MainWindow::onSettingsChanged() {
    applyTheme(*qApp, AppSettings::load().darkTheme);
    m_stage->setText(QStringLiteral("Settings saved. They apply to the next analysis."));
}

void MainWindow::setBusy(bool busy) {
    m_openButton->setEnabled(!busy);
    m_analyzeButton->setEnabled(!busy && !m_path.isEmpty());
}

void MainWindow::navigate(int index) {
    if (index < 0 || index >= kNavigationCount) {
        return;
    }
    if (m_stack->currentIndex() != index) {
        m_stack->setCurrentIndex(index);
        anim::fadeIn(m_stack->currentWidget(), 210);
    }
    if (m_navigation->currentRow() != index) {
        const QSignalBlocker blocker(m_navigation);
        m_navigation->setCurrentRow(index);
    }
    updateNavIndicator(true);
}

void MainWindow::updateNavIndicator(bool animate) {
    if (!m_navigation || !m_navIndicator) {
        return;
    }
    const int row = m_navigation->currentRow();
    if (row < 0) {
        m_navIndicator->hide();
        return;
    }
    const QRect itemRect = m_navigation->visualItemRect(m_navigation->item(row));
    if (!itemRect.isValid() || itemRect.height() <= 0) {
        return;
    }
    const QRect target(10, itemRect.top() + 8, 3, std::max(14, itemRect.height() - 16));
    m_navIndicator->show();
    m_navIndicator->raise();
    if (!animate || !anim::enabled() || !m_navIndicatorAnimation) {
        m_navIndicator->setGeometry(target);
        return;
    }
    m_navIndicatorAnimation->stop();
    m_navIndicatorAnimation->setStartValue(m_navIndicator->geometry());
    m_navIndicatorAnimation->setEndValue(target);
    m_navIndicatorAnimation->start();
}

void MainWindow::updateViews() {
    if (m_hasResult) {
        setResult(m_result);
        return;
    }
    m_dashboard->clear();
    m_fileAnalysis->clear();
    m_structure->clear();
    m_imports->clear();
    m_signature->clear();
    m_findings->clear();
    m_reports->clear();
}

void MainWindow::setResult(const AnalysisResult& result) {
    m_dashboard->setResult(result);
    m_fileAnalysis->setResult(result);
    m_structure->setResult(result);
    m_imports->setResult(result);
    m_signature->setResult(result);
    m_findings->setResult(result);
    m_reports->setResult(result);

    if (!result.file.fileName.empty()) {
        m_fileChip->setText(fromUtf8(result.file.fileName) + QStringLiteral("  \u00b7  ") +
                            displayBytes(result.file.size));
        m_fileChip->setToolTip(fromUtf8(result.file.path));
    }
}

void MainWindow::dragEnterEvent(QDragEnterEvent* event) {
    if (event->mimeData()->hasUrls()) {
        for (const QUrl& url : event->mimeData()->urls()) {
            if (url.isLocalFile()) {
                event->acceptProposedAction();
                return;
            }
        }
    }
}

void MainWindow::dropEvent(QDropEvent* event) {
    for (const QUrl& url : event->mimeData()->urls()) {
        if (url.isLocalFile()) {
            event->acceptProposedAction();
            openFile(url.toLocalFile());
            return;
        }
    }
}

void MainWindow::closeEvent(QCloseEvent* event) {
    if (m_watcher.isRunning()) {
        m_closing = true;
        m_stage->setText(QStringLiteral("Finishing the current analysis before closing\u2026"));
        event->ignore();
        return;
    }
    event->accept();
}

void MainWindow::showEvent(QShowEvent* event) {
    QMainWindow::showEvent(event);
    if (!m_firstShow) {
        return;
    }
    m_firstShow = false;
    updateNavIndicator(false);
    anim::revealWindow(this, 260);
}

} // namespace explainbin::ui
