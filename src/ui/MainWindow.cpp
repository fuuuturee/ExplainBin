#include "explainbin/ui/MainWindow.hpp"

#include "explainbin/core/Analyzer.hpp"
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
#include <QHBoxLayout>
#include <QLabel>
#include <QListWidget>
#include <QMenuBar>
#include <QMessageBox>
#include <QMimeData>
#include <QProgressBar>
#include <QPushButton>
#include <QStackedWidget>
#include <QStatusBar>
#include <QUrl>
#include <QVBoxLayout>

#include <QtConcurrent/QtConcurrentRun>

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
    sidebar->setFixedWidth(232);
    auto* sidebarLayout = new QVBoxLayout(sidebar);
    sidebarLayout->setContentsMargins(14, 20, 14, 16);
    sidebarLayout->setSpacing(6);

    auto* appName = new QLabel(QStringLiteral("ExplainBin"), sidebar);
    appName->setObjectName(QStringLiteral("appName"));
    auto* tagline = new QLabel(QStringLiteral("Explainable PE analysis"), sidebar);
    tagline->setObjectName(QStringLiteral("appTagline"));
    sidebarLayout->addWidget(appName);
    sidebarLayout->addWidget(tagline);
    sidebarLayout->addSpacing(14);

    m_navigation = new QListWidget(sidebar);
    m_navigation->setObjectName(QStringLiteral("navList"));
    m_navigation->setFocusPolicy(Qt::NoFocus);
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
    m_navigation->addItems(sections);
    sidebarLayout->addWidget(m_navigation, 1);

    auto* footer = new QLabel(
        QStringLiteral("v%1 \u00b7 offline \u00b7 static only").arg(fromUtf8(kToolVersion)),
        sidebar);
    footer->setObjectName(QStringLiteral("appTagline"));
    footer->setWordWrap(true);
    sidebarLayout->addWidget(footer);

    centralLayout->addWidget(sidebar);

    auto* mainArea = new QWidget(central);
    auto* mainLayout = new QVBoxLayout(mainArea);
    mainLayout->setContentsMargins(0, 0, 0, 0);
    mainLayout->setSpacing(0);

    auto* headerBar = new QWidget(mainArea);
    headerBar->setObjectName(QStringLiteral("headerBar"));
    auto* headerLayout = new QHBoxLayout(headerBar);
    headerLayout->setContentsMargins(18, 12, 18, 12);
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
    auto* progressLayout = new QHBoxLayout(progressRow);
    progressLayout->setContentsMargins(18, 8, 18, 8);
    progressLayout->setSpacing(12);
    m_stage = new QLabel(QStringLiteral("Ready. Open a Windows executable, DLL or driver."),
                         progressRow);
    m_stage->setObjectName(QStringLiteral("stageLabel"));
    m_progress = new QProgressBar(progressRow);
    m_progress->setTextVisible(false);
    m_progress->setRange(0, 100);
    m_progress->setValue(0);
    m_progress->setFixedWidth(200);
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
    connect(m_settings, &SettingsView::settingsChanged, this, &MainWindow::onSettingsChanged);

    m_navigation->setCurrentRow(0);
    m_stack->setCurrentIndex(0);

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
    if (busy) {
        m_progress->setRange(0, 0);
    }
}

void MainWindow::navigate(int index) {
    if (index < 0 || index >= kNavigationCount) {
        return;
    }
    m_stack->setCurrentIndex(index);
    if (m_navigation->currentRow() != index) {
        m_navigation->setCurrentRow(index);
    }
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

} // namespace explainbin::ui
