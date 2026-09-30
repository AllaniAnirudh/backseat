package main

import (
	"reflect"
	"testing"
)

func TestSplitFlags(t *testing.T) {
	cases := []struct {
		name  string
		argv  []string
		wantF []string
		wantP []string
	}{
		{"code first", []string{"CODE", "--name", "bob"}, []string{"--name", "bob"}, []string{"CODE"}},
		{"flags first", []string{"--name", "bob", "CODE"}, []string{"--name", "bob"}, []string{"CODE"}},
		{"equals form", []string{"CODE", "--name=bob"}, []string{"--name=bob"}, []string{"CODE"}},
		{"flag value that looks positional stays with flag",
			[]string{"--relay-ws", "ws://x/y", "CODE"},
			[]string{"--relay-ws", "ws://x/y"}, []string{"CODE"}},
		{"bare dash is positional", []string{"-", "--name", "bob"},
			[]string{"--name", "bob"}, []string{"-"}},
		{"no args", nil, nil, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			gotF, gotP := splitFlags(c.argv)
			if !reflect.DeepEqual(gotF, c.wantF) {
				t.Errorf("flagArgs = %q, want %q", gotF, c.wantF)
			}
			if !reflect.DeepEqual(gotP, c.wantP) {
				t.Errorf("posArgs = %q, want %q", gotP, c.wantP)
			}
		})
	}
}
