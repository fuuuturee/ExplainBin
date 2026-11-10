#pragma once

#include <QWidget>

namespace explainbin::ui::anim {

// Animations can be disabled in the settings. Callers must not assume that a
// widget was actually animated: the helpers always leave it in the final state.
[[nodiscard]] bool enabled();

// Fades a widget in, optionally after a short delay. The drop-in effect is
// removed when the animation finishes so painting returns to the native path.
void fadeIn(QWidget* widget, int durationMs = 220, int delayMs = 0);

// Fades a widget out and hides it afterwards.
void fadeOut(QWidget* widget, int durationMs = 170, bool hideWhenFinished = true);

// Fades from fully transparent to fully visible without touching visibility,
// used for the initial window reveal.
void revealWindow(QWidget* window, int durationMs = 260);

} // namespace explainbin::ui::anim
