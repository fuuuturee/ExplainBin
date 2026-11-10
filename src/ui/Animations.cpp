#include "explainbin/ui/Animations.hpp"

#include <QApplication>
#include <QGraphicsOpacityEffect>
#include <QPointer>
#include <QPropertyAnimation>
#include <QTimer>
#include <QVariant>

#include <functional>

namespace explainbin::ui::anim {
namespace {

QGraphicsOpacityEffect* installEffect(QWidget* widget) {
    auto* effect = new QGraphicsOpacityEffect(widget);
    effect->setOpacity(0.0);
    widget->setGraphicsEffect(effect);
    return effect;
}

void animateOpacity(QWidget* widget, QGraphicsOpacityEffect* effect, double from, double to,
                    int durationMs, const std::function<void()>& finished) {
    const QPointer<QWidget> guard(widget);
    auto* animation = new QPropertyAnimation(effect, "opacity", effect);
    animation->setDuration(durationMs);
    animation->setStartValue(from);
    animation->setEndValue(to);
    animation->setEasingCurve(QEasingCurve::OutCubic);
    QObject::connect(animation, &QPropertyAnimation::finished, widget, [guard, effect, finished] {
        if (!guard) {
            return;
        }
        if (finished) {
            finished();
        }
        // Deleting the effect also deletes this animation, which is currently
        // emitting finished(). Defer the teardown to the next event-loop turn.
        const QPointer<QGraphicsOpacityEffect> effectGuard(effect);
        QTimer::singleShot(0, guard.data(), [guard, effectGuard] {
            if (guard && effectGuard && guard->graphicsEffect() == effectGuard) {
                guard->setGraphicsEffect(nullptr);
            }
        });
    });
    animation->start(QAbstractAnimation::DeleteWhenStopped);
}

} // namespace

bool enabled() {
    if (!qApp) {
        return false;
    }
    const QVariant value = qApp->property("explainbin.animations");
    return value.isValid() ? value.toBool() : true;
}

void fadeIn(QWidget* widget, int durationMs, int delayMs) {
    if (!widget) {
        return;
    }
    widget->setGraphicsEffect(nullptr);
    widget->show();
    if (!enabled()) {
        return;
    }

    auto start = [widget, durationMs] {
        if (!widget->isVisible()) {
            return;
        }
        auto* effect = installEffect(widget);
        animateOpacity(widget, effect, 0.0, 1.0, durationMs, {});
    };

    if (delayMs > 0) {
        QTimer::singleShot(delayMs, widget, start);
    } else {
        start();
    }
}

void fadeOut(QWidget* widget, int durationMs, bool hideWhenFinished) {
    if (!widget) {
        return;
    }
    widget->setGraphicsEffect(nullptr);
    if (!enabled()) {
        if (hideWhenFinished) {
            widget->hide();
        }
        return;
    }

    auto* effect = installEffect(widget);
    effect->setOpacity(1.0);
    animateOpacity(widget, effect, 1.0, 0.0, durationMs, [widget, hideWhenFinished] {
        if (hideWhenFinished) {
            widget->hide();
        }
    });
}

void revealWindow(QWidget* window, int durationMs) {
    if (!window || !enabled()) {
        return;
    }
    window->setWindowOpacity(0.0);
    const QPointer<QWidget> guard(window);
    auto* animation = new QPropertyAnimation(window, "windowOpacity", window);
    animation->setDuration(durationMs);
    animation->setStartValue(0.0);
    animation->setEndValue(1.0);
    animation->setEasingCurve(QEasingCurve::OutCubic);
    QObject::connect(animation, &QPropertyAnimation::finished, window, [guard] {
        if (guard) {
            guard->setWindowOpacity(1.0);
        }
    });
    animation->start(QAbstractAnimation::DeleteWhenStopped);
}

} // namespace explainbin::ui::anim
