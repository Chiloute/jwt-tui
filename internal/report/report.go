package report

import (
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/chiloute/jwt-tui/internal/jwt"
)

type Result struct {
	Info     *jwt.JWTInfo
	Verify   jwt.VerifyResult
	Findings []jwt.Finding
}

func Analyze(token, keySpec string) Result {
	info, _ := jwt.ParseJWT(token)
	res := jwt.VerifyToken(token, keySpec)
	return Result{
		Info:     info,
		Verify:   res,
		Findings: jwt.Analyze(token, keySpec, res, time.Now()),
	}
}

func ExitCode(r Result) int {
	if r.Info == nil {
		return 2
	}
	if r.Verify.Sig == jwt.SigValid {
		return 0
	}
	return 1
}

func Text(w io.Writer, r Result) error {
	if r.Info == nil {
		return fmt.Errorf("could not decode the token")
	}

	fmt.Fprintln(w, "Header")
	fmt.Fprintln(w, jwt.PrettyJSON(mustJSON(r.Info.Header)))
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Payload")
	fmt.Fprintln(w, jwt.PrettyJSON(mustJSON(r.Info.Payload)))
	fmt.Fprintln(w)

	fmt.Fprintf(w, "Signature: %s", r.Verify.Sig)
	if r.Verify.SigError != "" {
		fmt.Fprintf(w, " (%s)", r.Verify.SigError)
	}
	fmt.Fprintln(w)
	if t := r.Verify.Temporal.String(); t != "" {
		fmt.Fprintf(w, "Temporal:  %s\n", t)
	}

	if len(r.Findings) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "Analysis")
		for _, f := range r.Findings {
			fmt.Fprintf(w, "  [%s] %s (%s)\n", f.Sev, f.Title, f.Code)
		}
	}
	return nil
}

func JSON(w io.Writer, r Result) error {
	if r.Info == nil {
		return fmt.Errorf("could not decode the token")
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(toOutput(r))
}

type output struct {
	Header    map[string]interface{} `json:"header"`
	Payload   map[string]interface{} `json:"payload"`
	Signature sigOutput              `json:"signature"`
	Temporal  temporalOutput         `json:"temporal"`
	Key       keyOutput              `json:"key"`
	Findings  []findingOutput        `json:"findings"`
}

type sigOutput struct {
	State string `json:"state"`
	Alg   string `json:"alg"`
	Error string `json:"error"`
}

type temporalOutput struct {
	State     string     `json:"state"`
	ExpiresAt *time.Time `json:"exp"`
	NotBefore *time.Time `json:"nbf"`
	IssuedAt  *time.Time `json:"iat"`
}

type keyOutput struct {
	Encoding string `json:"encoding"`
	Origin   string `json:"origin"`
	Private  bool   `json:"private"`
	Bytes    int    `json:"bytes"`
}

type findingOutput struct {
	Severity string `json:"severity"`
	Code     string `json:"code"`
	Title    string `json:"title"`
	Detail   string `json:"detail"`
}

func toOutput(r Result) output {
	v := r.Verify
	findings := make([]findingOutput, 0, len(r.Findings))
	for _, f := range r.Findings {
		findings = append(findings, findingOutput{f.Sev.String(), f.Code, f.Title, f.Detail})
	}
	return output{
		Header:    r.Info.Header,
		Payload:   r.Info.Payload,
		Signature: sigOutput{v.Sig.String(), v.Alg, v.SigError},
		Temporal:  temporalOutput{temporalState(v.Temporal), v.ExpiresAt, v.NotBefore, v.IssuedAt},
		Key:       keyOutput{v.KeyEncoding.String(), v.KeyOrigin, v.KeyPrivate, v.KeyBytes},
		Findings:  findings,
	}
}

func temporalState(t jwt.TemporalState) string {
	if s := t.String(); s != "" {
		return s
	}
	return "none"
}

func mustJSON(v map[string]interface{}) string {
	b, err := json.Marshal(v)
	if err != nil {
		return "{}"
	}
	return string(b)
}
