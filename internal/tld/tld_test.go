package tld

import "testing"

func TestClassify(t *testing.T) {
	tests := []struct {
		tld    string
		want   Type
		policy string
	}{
		{"com", Generic, "yes"},
		{"ninja", Generic, "yes"},
		{"COM.", Generic, "yes"},
		{"nl", CountryCode, "no"},
		{"uk", CountryCode, "no"},
		{"edu", Sponsored, "partly"},
		{"museum", Sponsored, "partly"},
		{"biz", GenericRestricted, "yes"},
		{"arpa", Infrastructure, "no"},
		{"xn--p1ai", IDN, "unknown"},
	}
	for _, tt := range tests {
		got := Classify(tt.tld)
		if got.Type != tt.want || got.ICANNPolicy != tt.policy || got.Description == "" {
			t.Errorf("Classify(%q) = %s/%s, want %s/%s", tt.tld, got.Type, got.ICANNPolicy, tt.want, tt.policy)
		}
	}
}
