package collector

import "testing"

func TestNormalizeOSFamily(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"ubuntu", "ubuntu"},
		{"Ubuntu", "ubuntu"},
		{"UBUNTU", "ubuntu"},
		{"debian", "debian"},
		{"Debian", "debian"},
		{"rhel", "rhel"},
		{"centos", "centos"},
		{"rocky", "rocky"},
		{"alma", "alma"},
		{"almalinux", "alma"},
		{"AlmaLinux", "alma"},
		// substring matches
		{"ubuntu-minimal", "ubuntu"},
		{"debian-slim", "debian"},
		{"redhat-enterprise", "rhel"},
		{"centos-stream", "centos"},
		{"rocky-linux", "rocky"},
		{"almalinux-9", "alma"},
		// unsupported
		{"archlinux", ""},
		{"opensuse", ""},
		{"alpine", ""},
		{"", ""},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := normalizeOSFamily(tt.input)
			if got != tt.want {
				t.Errorf("normalizeOSFamily(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}
