#include "explainbin/ui/SettingsView.hpp"

#include <QCheckBox>
#include <QComboBox>
#include <QFormLayout>
#include <QLabel>
#include <QSpinBox>
#include <QTimer>
#include <QVBoxLayout>

namespace explainbin::ui {

SettingsView::SettingsView(QWidget* parent) : QWidget(parent) {
    auto* root = new QVBoxLayout(this);
    root->setContentsMargins(26, 22, 26, 22);
    root->setSpacing(14);

    auto* title = new QLabel(QStringLiteral("Settings"), this);
    title->setObjectName(QStringLiteral("sectionTitle"));
    auto* hint = new QLabel(
        QStringLiteral("Preferences are stored locally for the current Windows user. They affect "
                       "new analyses only; the analyzed file is never uploaded or executed."),
        this);
    hint->setObjectName(QStringLiteral("pageHint"));
    hint->setWordWrap(true);
    root->addWidget(title);
    root->addWidget(hint);

    auto* form = new QWidget(this);
    auto* formLayout = new QFormLayout(form);
    formLayout->setContentsMargins(0, 0, 0, 0);
    formLayout->setSpacing(14);
    formLayout->setLabelAlignment(Qt::AlignLeft);

    m_verifySignature = new QCheckBox(
        QStringLiteral("Verify the embedded Authenticode signature"), form);
    m_verifySignature->setToolTip(
        QStringLiteral("Uses the Windows trust engine with cache-only revocation."));
    formLayout->addRow(m_verifySignature);

    m_computeMd5 = new QCheckBox(QStringLiteral("Also compute an MD5 hash"), form);
    m_computeMd5->setToolTip(
        QStringLiteral("MD5 is provided for compatibility with existing tooling only."));
    formLayout->addRow(m_computeMd5);

    m_maxSize = new QSpinBox(form);
    m_maxSize->setRange(1, 4096);
    m_maxSize->setSuffix(QStringLiteral(" MiB"));
    m_maxSize->setToolTip(
        QStringLiteral("Files larger than this are rejected before any parsing."));
    formLayout->addRow(QStringLiteral("Maximum input size"), m_maxSize);

    m_theme = new QComboBox(form);
    m_theme->addItem(QStringLiteral("Dark"));
    m_theme->addItem(QStringLiteral("Light"));
    formLayout->addRow(QStringLiteral("Theme"), m_theme);

    root->addWidget(form);

    m_saved = new QLabel(this);
    m_saved->setObjectName(QStringLiteral("muted"));
    root->addWidget(m_saved);

    auto* spacer = new QWidget(this);
    spacer->setSizePolicy(QSizePolicy::Preferred, QSizePolicy::Expanding);
    root->addWidget(spacer);

    connect(m_verifySignature, &QCheckBox::toggled, this, &SettingsView::persist);
    connect(m_computeMd5, &QCheckBox::toggled, this, &SettingsView::persist);
    connect(m_maxSize, QOverload<int>::of(&QSpinBox::valueChanged), this, &SettingsView::persist);
    connect(m_theme, QOverload<int>::of(&QComboBox::currentIndexChanged), this,
            &SettingsView::persist);

    reload();
}

void SettingsView::reload() {
    const AppSettings settings = AppSettings::load();
    m_loading = true;
    m_verifySignature->setChecked(settings.verifySignature);
    m_computeMd5->setChecked(settings.computeMd5);
    m_maxSize->setValue(settings.maxSizeMb);
    m_theme->setCurrentIndex(settings.darkTheme ? 0 : 1);
    m_loading = false;
    m_saved->clear();
}

void SettingsView::persist() {
    if (m_loading) {
        return;
    }

    AppSettings settings;
    settings.verifySignature = m_verifySignature->isChecked();
    settings.computeMd5 = m_computeMd5->isChecked();
    settings.maxSizeMb = m_maxSize->value();
    settings.darkTheme = m_theme->currentIndex() == 0;
    settings.save();

    m_saved->setText(QStringLiteral("Settings saved."));
    QTimer::singleShot(2500, this, [this] { m_saved->clear(); });

    emit settingsChanged();
}

} // namespace explainbin::ui
