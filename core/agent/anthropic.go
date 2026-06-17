// Package agent holds the SECURITY-CRITICAL pre-LLM floor for finding
// resolution plus the minimal anthropic.Client interface the agent loop (built
// in a later wave) consumes.
//
// The single most important invariant in this package: a finding that matches a
// hard-constraint family (secrets-exposure, priv-escalation, injection-probe,
// boundary-violation, or a tripped volume circuit-breaker) is force-escalated by
// checkHardConstraints BEFORE any path that could call the model. The model
// never sees these findings. This is enforced three ways:
//
//  1. ResolveFinding calls checkHardConstraints first and returns immediately on
//     a hard constraint — the Client is never touched.
//  2. agent_test.go drives a spy Client whose Messages() calls t.Fatal; the
//     REJECT/BYPASS/SANITIZE tests prove the spy's call-count stays 0.
//  3. imports_test.go forbids any non-test source in this package from importing
//     a network/inference family, so the gate path cannot reach inference at all
//     except through the Client interface threaded in by the caller.
package agent

import "context"

// Client is the single inference seam for the agent loop. The agent loop in the
// NEXT wave consumes exactly this interface; the inference DirectClient (also a
// later wave) implements it. Keeping the surface to one method keeps the pre-LLM
// floor honest: the only way to reach the model is Messages, and a spy that
// implements Client can prove, by call-count, that the floor never reached it.
type Client interface {
	// Messages performs one Anthropic-style messages exchange. ctx carries
	// cancellation/deadline; req is the request; the response or an error is
	// returned. Implementations MUST NOT be invoked for hard-constrained
	// findings — the floor in this package guarantees that.
	Messages(ctx context.Context, req MessagesRequest) (MessagesResponse, error)
}

// MessagesRequest is the minimal Anthropic-compatible request shape the agent
// loop builds. It intentionally mirrors only the fields the loop needs; the
// inference client maps it onto the wire format. Kept here (not in the inference
// package) so the floor + interface compile and test with zero inference deps.
type MessagesRequest struct {
	Model     string    `json:"model"`
	MaxTokens int       `json:"max_tokens"`
	System    string    `json:"system,omitempty"`
	Messages  []Message `json:"messages"`
	Tools     []Tool    `json:"tools,omitempty"`
}

// Message is one turn in the conversation.
type Message struct {
	Role    string         `json:"role"` // "user" | "assistant"
	Content []ContentBlock `json:"content"`
}

// ContentBlock is one block within a message (text or tool use/result). Only the
// fields the agent loop needs are modeled.
type ContentBlock struct {
	Type string `json:"type"` // "text" | "tool_use" | "tool_result"
	Text string `json:"text,omitempty"`

	// tool_use
	ID    string `json:"id,omitempty"`
	Name  string `json:"name,omitempty"`
	Input any    `json:"input,omitempty"`

	// tool_result
	ToolUseID string `json:"tool_use_id,omitempty"`
	Content   any    `json:"content,omitempty"`
}

// Tool is a tool definition advertised to the model.
type Tool struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	InputSchema any    `json:"input_schema,omitempty"`
}

// MessagesResponse is the minimal Anthropic-compatible response shape.
type MessagesResponse struct {
	StopReason string         `json:"stop_reason"`
	Content    []ContentBlock `json:"content"`
}
