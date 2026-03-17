package analyze

import "testing"

func TestDetectJSLibrariesFromScriptURLs(t *testing.T) {
	body := []byte(`<html><head>
	<script src="/static/jquery-1.12.4.min.js"></script>
	<script src="/static/vue-3.5.0.js"></script>
	</head></html>`)
	libs := DetectJSLibraries("https://example.com", body)
	if len(libs) < 2 {
		t.Fatalf("expected at least 2 libraries, got %#v", libs)
	}
	foundJQ := false
	for _, lib := range libs {
		if lib.Name == "jquery" {
			foundJQ = true
			if lib.Version != "1.12.4" {
				t.Fatalf("expected jquery version 1.12.4, got %q", lib.Version)
			}
			if !lib.Outdated {
				t.Fatalf("expected jquery 1.12.4 to be marked outdated")
			}
		}
	}
	if !foundJQ {
		t.Fatalf("expected jquery detection in %#v", libs)
	}
}

func TestDetectJSLibrariesFromInlineBanner(t *testing.T) {
	body := []byte(`<html><head><script>/*! jQuery v3.7.1 | (c) */</script></head></html>`)
	libs := DetectJSLibraries("https://example.com", body)
	if len(libs) == 0 {
		t.Fatalf("expected inline detection")
	}
	if libs[0].Name != "jquery" || libs[0].Version != "3.7.1" {
		t.Fatalf("unexpected library detection: %#v", libs[0])
	}
}
