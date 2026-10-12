package api

type ClefResponse struct {
	Result   Result   `json:"result"`
	Success  bool     `json:"success"`
	Errors   []string `json:"errors"`
	Messages []string `json:"messages"`
}

type Result struct {
	Model   string         `json:"model"`
	Answers FullDatapoints `json:"answers"`
	Usage   UsageData      `json:"usage"`
}

type FullDatapoints struct {
	Malice   NoulDatapoint `json:"malicious"`
	Severity NoulDatapoint `json:"severe"`
}

type NoulDatapoint struct {
	Type string  `json:"type"`
	Noul float64 `json:"noul"`
}

type UsageData struct {
	InputTokens  int `json:"input_tokens"`
	OutputTokens int `json:"output_tokens"`
}

type ClefQuestion struct {
	Type         string            `json:"type"` // "noul", "choice", or "score"
	Instructions string            `json:"instructions"`
	Criteria     map[string]string `json:"criteria,omitempty"` // options for choice/score
}

type ClefRequest struct {
	Model     string                  `json:"model"` // "clef" or "clef-flash"
	State     string                  `json:"state"`
	Questions map[string]ClefQuestion `json:"questions"`
}

type ProcessDetails struct {
	User    string `json:"user"`
	Parent  string `json:"parent"`
	Path    string `json:"path"`
	Cmdline string `json:"cmdline"`
}
