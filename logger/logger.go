package logger

import (
	"github.com/go-logr/logr"
	"github.com/go-logr/zapr"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

type Logger struct {
	LogLevel   int8
	Encoding   string
	EncodeTime zapcore.TimeEncoder
}

func NewLogger(logLevel int8, encoding string, encodeTime zapcore.TimeEncoder) *Logger {

	return &Logger{
		LogLevel:   logLevel,
		Encoding:   encoding,
		EncodeTime: encodeTime,
	}
}

func (l *Logger) Build() logr.Logger {
	zp := zap.NewProductionConfig()
	zp.Encoding = l.Encoding
	zp.EncoderConfig.StacktraceKey = ""
	zp.EncoderConfig.EncodeTime = l.EncodeTime

	if l.LogLevel > 0 {
		l.LogLevel = 0 - l.LogLevel
	}
	zp.Level = zap.NewAtomicLevelAt(zapcore.Level(l.LogLevel))

	z, err := zp.Build()
	if err != nil {
		panic(err)
	}

	return zapr.NewLogger(z)
}
