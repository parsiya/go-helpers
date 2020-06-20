package jsonhelper

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
)

// JSON utils.

// StructToJSONString converts a struct into a JSON string. If escape is set to
// false, then the HTML inside the string will not be escaped.
func StructToJSONString(v interface{}, indent bool, escape bool) (string, error) {
	var sb strings.Builder
	enc := json.NewEncoder(&sb)
	if indent {
		enc.SetIndent("", "    ")
	}
	// Do not escape < > & in HTML.
	enc.SetEscapeHTML(escape)
	err := enc.Encode(v)
	return sb.String(), err
}

// PrettyPrintJSON gets a string and pretty prints it to io.Writer.
func PrettyPrintJSON(in string, w io.Writer) error {
	var content bytes.Buffer
	if err := json.Indent(&content, []byte(in), "", "\t"); err != nil {
		return err
	}
	_, err := w.Write(content.Bytes())
	if err != nil {
		return err
	}
	return nil
}
