package log

import (
	"fmt"

	"golang.org/x/exp/slog"
)

func Infof(format string, args ...any) {
    slog.Default().Info(fmt.Sprintf(format, args...))
}

func Errorf(format string, args ...any) {
    slog.Default().Error(fmt.Sprintf(format, args...))
}

func Warnf(format string, args ...any) {
    slog.Default().Warn(fmt.Sprintf(format, args...))
}

func Debugf(format string, args ...any) {
    slog.Default().Debug(fmt.Sprintf(format, args...))
}
