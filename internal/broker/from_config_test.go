package broker_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"github.com/mmartinez/postern/internal/broker"
	"github.com/mmartinez/postern/internal/config"
)

func TestFromConfigRules_TranslatesHeaderAndPlaceholder(t *testing.T) {
	t.Parallel()

	in := []config.Rule{
		{
			Host:      "api.anthropic.com",
			SecretRef: "op://Agents/Anthropic/api_key",
			Inject: config.Inject{
				Type:     config.InjectTypeHeader,
				Name:     "x-api-key",
				Template: "{{ CREDENTIAL }}",
			},
		},
		{
			Host:      "api.example.com",
			SecretRef: "op://V/I/f",
			Inject: config.Inject{
				Type:     config.InjectTypePlaceholder,
				Name:     "__placeholder__",
				Template: "Bearer {{ CREDENTIAL }}",
			},
		},
	}

	got, err := broker.FromConfigRules(in)
	if err != nil {
		t.Fatalf("FromConfigRules: %v", err)
	}

	want := []broker.Rule{
		{
			Host:      "api.anthropic.com",
			SecretRef: "op://Agents/Anthropic/api_key",
			Injection: broker.InjectSpec{Type: broker.InjectHeader, Name: "x-api-key", Template: "{{ CREDENTIAL }}"},
		},
		{
			Host:      "api.example.com",
			SecretRef: "op://V/I/f",
			Injection: broker.InjectSpec{Type: broker.InjectPlaceholder, Name: "__placeholder__", Template: "Bearer {{ CREDENTIAL }}"},
		},
	}
	if diff := cmp.Diff(want, got, cmpopts.EquateEmpty()); diff != "" {
		t.Fatalf("rules diff (-want +got):\n%s", diff)
	}
}

func TestFromConfigRules_RejectsUnknownInjectType(t *testing.T) {
	t.Parallel()

	_, err := broker.FromConfigRules([]config.Rule{{
		Host:      "api.example.com",
		SecretRef: "op://V/I/f",
		Inject:    config.Inject{Type: "made-up", Template: "x"},
	}})
	if err == nil {
		t.Fatalf("FromConfigRules with unknown inject type: want error, got nil")
	}
}

func TestFromConfigRules_EmptyInputReturnsEmpty(t *testing.T) {
	t.Parallel()

	got, err := broker.FromConfigRules(nil)
	if err != nil {
		t.Fatalf("FromConfigRules(nil): %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("FromConfigRules(nil) = %d rules, want 0", len(got))
	}
}
