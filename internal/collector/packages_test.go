package collector

import (
	"reflect"
	"testing"
)

func TestParseDPKGOutput(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		want   []Package
	}{
		{
			name:  "empty output",
			input: "",
			want:  nil,
		},
		{
			name:  "single package with source",
			input: "bash\t5.1-6\tamd64\tbash\n",
			want: []Package{
				{Name: "bash", Version: "5.1-6", Arch: "amd64", Source: "bash"},
			},
		},
		{
			name:  "package with different source",
			input: "libssl3\t3.0.2-0ubuntu1\tamd64\topenssl\n",
			want: []Package{
				{Name: "libssl3", Version: "3.0.2-0ubuntu1", Arch: "amd64", Source: "openssl"},
			},
		},
		{
			name:  "package without source falls back to name",
			input: "mypkg\t1.0\tamd64\t\n",
			want: []Package{
				{Name: "mypkg", Version: "1.0", Arch: "amd64", Source: "mypkg"},
			},
		},
		{
			name:  "multiple packages",
			input: "bash\t5.1-6\tamd64\tbash\ncurl\t7.81.0-1\tamd64\tcurl\n",
			want: []Package{
				{Name: "bash", Version: "5.1-6", Arch: "amd64", Source: "bash"},
				{Name: "curl", Version: "7.81.0-1", Arch: "amd64", Source: "curl"},
			},
		},
		{
			name:  "skips lines with fewer than 3 fields",
			input: "bash\t5.1-6\tamd64\tbash\nbadline\ncurl\t7.81.0-1\tamd64\tcurl\n",
			want: []Package{
				{Name: "bash", Version: "5.1-6", Arch: "amd64", Source: "bash"},
				{Name: "curl", Version: "7.81.0-1", Arch: "amd64", Source: "curl"},
			},
		},
		{
			name:  "trims whitespace",
			input: "  bash\t5.1-6\tamd64\tbash  \n",
			want: []Package{
				{Name: "bash", Version: "5.1-6", Arch: "amd64", Source: "bash"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseDPKGOutput(tt.input)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("parseDPKGOutput() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseRPMOutput(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  []Package
	}{
		{
			name:  "empty output",
			input: "",
			want:  nil,
		},
		{
			name:  "single package with source",
			input: "bash\t5.1.8-6.el9\tx86_64\tbash\n",
			want: []Package{
				{Name: "bash", Version: "5.1.8-6.el9", Arch: "x86_64", Source: "bash"},
			},
		},
		{
			name:  "package with (none) source falls back to name",
			input: "gpg-pubkey\t8483c65d-5ccc5b19\t(none)\t(none)\n",
			want: []Package{
				{Name: "gpg-pubkey", Version: "8483c65d-5ccc5b19", Arch: "(none)", Source: "gpg-pubkey"},
			},
		},
		{
			name:  "package with empty source falls back to name",
			input: "mypkg\t1.0-1\tx86_64\t\n",
			want: []Package{
				{Name: "mypkg", Version: "1.0-1", Arch: "x86_64", Source: "mypkg"},
			},
		},
		{
			name:  "package with different source",
			input: "openssl-libs\t3.0.7-18.el9\tx86_64\topenssl\n",
			want: []Package{
				{Name: "openssl-libs", Version: "3.0.7-18.el9", Arch: "x86_64", Source: "openssl"},
			},
		},
		{
			name:  "multiple packages",
			input: "bash\t5.1.8-6.el9\tx86_64\tbash\ncurl\t7.76.1-26.el9\tx86_64\tcurl\n",
			want: []Package{
				{Name: "bash", Version: "5.1.8-6.el9", Arch: "x86_64", Source: "bash"},
				{Name: "curl", Version: "7.76.1-26.el9", Arch: "x86_64", Source: "curl"},
			},
		},
		{
			name:  "skips lines with fewer than 3 fields",
			input: "bash\t5.1.8-6.el9\tx86_64\tbash\nbadline\ncurl\t7.76.1-26.el9\tx86_64\tcurl\n",
			want: []Package{
				{Name: "bash", Version: "5.1.8-6.el9", Arch: "x86_64", Source: "bash"},
				{Name: "curl", Version: "7.76.1-26.el9", Arch: "x86_64", Source: "curl"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseRPMOutput(tt.input)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("parseRPMOutput() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCollectPackages_UnsupportedManager(t *testing.T) {
	_, err := CollectPackages("apt")
	if err == nil {
		t.Error("expected error for unsupported package manager")
	}
}
