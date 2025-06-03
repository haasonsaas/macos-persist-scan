package output

import (
	"github.com/haasonsaas/macos-persist-scan/pkg/scanner"
)

type Formatter interface {
	Format(result *scanner.ScanResult) ([]byte, error)
}

type FormatterType string

const (
	FormatterTable FormatterType = "table"
	FormatterJSON  FormatterType = "json"
	FormatterSARIF FormatterType = "sarif"
)

func GetFormatter(formatType FormatterType) Formatter {
	switch formatType {
	case FormatterJSON:
		return &JSONFormatter{}
	case FormatterSARIF:
		return &SARIFFormatter{}
	case FormatterTable:
		fallthrough
	default:
		return &TableFormatter{}
	}
}