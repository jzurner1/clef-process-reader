package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mini-soc/utils"
	"net/http"
	"time"
)

func GetClefOpinion(ctx context.Context, details ProcessDetails, auth utils.AuthDetails) (float64, error) {
	state := fmt.Sprintf("This process was just started on a Windows device - parent: \"%s\", path: \"%s\", command line: \"%s\", user: \"%s\"",
		details.Parent, details.Path, details.Cmdline, details.User)

	questions := map[string]ClefQuestion{
		"malicious": {
			Type:         "noul",
			Instructions: "Is this process malicious?",
			Criteria:     nil,
		},
	}

	httpClient := &http.Client{Timeout: 30 * time.Second}
	req := ClefRequest{
		Model:     "clef",
		State:     state,
		Questions: questions,
	}

	res, err := SendClefRequest(ctx, auth, req, httpClient)
	if err != nil {
		return 0, fmt.Errorf("failed to send request: %w", err)
	}

	return res.Result.Answers.Malice.Noul, nil
}

func SendClefRequest(ctx context.Context, auth utils.AuthDetails, req ClefRequest, client *http.Client) (*ClefResponse, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	url := fmt.Sprintf("https://api.cloudflare.com/client/v4/accounts/%s/ai/run/@cf/cloudflare/%s", auth.AccountID, req.Model)

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to build request: %w", err)
	}
	httpReq.Header.Set("Authorization", "Bearer "+auth.APIToken)
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("clef API error code %d: %s", resp.StatusCode, resp.Status)
	}

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	var env ClefResponse
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	return &env, nil
}
