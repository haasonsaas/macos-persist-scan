package output

import (
	"encoding/json"

	"github.com/haasonsaas/macos-persist-scan/pkg/scanner"
)

type JSONFormatter struct {
	Pretty bool
}

func (f *JSONFormatter) Format(result *scanner.ScanResult) ([]byte, error) {
	if f.Pretty {
		return json.MarshalIndent(result, "", "  ")
	}
	return json.Marshal(result)
}