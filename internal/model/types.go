package model

import (
	"encoding/json"
	"io"
)

type EncodingKind string

const (
	EncodingNone   EncodingKind = "none"
	EncodingURL    EncodingKind = "url"
	EncodingBase64 EncodingKind = "base64"
)

type Parameter struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type ReflectionContext string

type AttributeType string

const (
	ContextHTML      ReflectionContext = "html"
	ContextAttribute ReflectionContext = "attribute"
	ContextScript    ReflectionContext = "script"
	ContextComment   ReflectionContext = "comment"
)

const (
	AttributeTypeUnknown AttributeType = "unknown"
	AttributeTypeName    AttributeType = "name"
	AttributeTypeValue   AttributeType = "value"
)

type Reflection struct {
	Marker        string            `json:"marker"`
	Context       ReflectionContext `json:"context"`
	Tag           string            `json:"tag,omitempty"`
	Attribute     string            `json:"attribute,omitempty"`
	AttributeType AttributeType     `json:"attribute_type,omitempty"`
	Quote         string            `json:"quote,omitempty"`
	ScriptURL     bool              `json:"script_url,omitempty"`
	Snippet       string            `json:"snippet,omitempty"`
}

type Finding struct {
	URL         string       `json:"url"`
	Method      string       `json:"method"`
	Parameter   string       `json:"parameter"`
	Payload     string       `json:"payload,omitempty"`
	Confidence  int          `json:"confidence"`
	Reflections []Reflection `json:"reflections,omitempty"`
	Notes       []string     `json:"notes,omitempty"`
}

type DOMIssue struct {
	URL      string `json:"url"`
	Line     int    `json:"line"`
	Kind     string `json:"kind"`
	Source   string `json:"source,omitempty"`
	Sink     string `json:"sink,omitempty"`
	CodeLine string `json:"code_line"`
}

type BlindXSSPayload struct {
	URL       string `json:"url"`
	Method    string `json:"method"`
	Parameter string `json:"parameter"`
	Payload   string `json:"payload"`
	Sent      bool   `json:"sent"`
}

type JSLibrary struct {
	Name     string `json:"name"`
	Version  string `json:"version,omitempty"`
	URL      string `json:"url,omitempty"`
	Source   string `json:"source,omitempty"`
	Outdated bool   `json:"outdated"`
	Severity string `json:"severity,omitempty"`
	Notes    string `json:"notes,omitempty"`
}

type WAFResult struct {
	URL       string  `json:"url"`
	Detected  bool    `json:"detected"`
	Name      string  `json:"name,omitempty"`
	Score     float64 `json:"score,omitempty"`
	Status    int     `json:"status"`
	Evidence  string  `json:"evidence,omitempty"`
	Signature string  `json:"signature,omitempty"`
}

type Form struct {
	Action string      `json:"action"`
	Method string      `json:"method"`
	Inputs []Parameter `json:"inputs"`
	Source string      `json:"source"`
}

type CrawlResult struct {
	Seed        string      `json:"seed"`
	Pages       []string    `json:"pages"`
	Links       []string    `json:"links"`
	Forms       []Form      `json:"forms"`
	Scripts     []string    `json:"scripts,omitempty"`
	JSLibraries []JSLibrary `json:"js_libraries,omitempty"`
}

func PrintJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}
