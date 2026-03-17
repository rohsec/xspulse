package crawl

import (
	"reflect"
	"testing"
)

func TestParsePageDedupesLinksAndCanonicalizesQueryOrder(t *testing.T) {
	html := []byte(`
	<html><body>
	  <a href="/search?b=2&a=1#frag">one</a>
	  <a href="/search?a=1&b=2">two</a>
	  <a href="/search?a=1&b=2">three</a>
	</body></html>`)

	links, _, _ := parsePage("https://example.com/root", html)
	want := []string{"https://example.com/search?a=1&b=2"}
	if !reflect.DeepEqual(links, want) {
		t.Fatalf("unexpected links\nwant: %#v\ngot:  %#v", want, links)
	}
}

func TestParsePageDedupesEquivalentFormsByActionMethodAndInputs(t *testing.T) {
	html := []byte(`
	<html><body>
	  <form action="/login?b=2&a=1" method="post">
	    <input name="user" value="alice">
	    <input name="pass" value="secret">
	  </form>
	  <form action="/login?a=1&b=2" method="POST">
	    <input name="pass" value="secret">
	    <input name="user" value="alice">
	  </form>
	</body></html>`)

	_, forms, _ := parsePage("https://example.com", html)
	if len(forms) != 1 {
		t.Fatalf("expected one deduped form, got %d: %#v", len(forms), forms)
	}
	if forms[0].Action != "https://example.com/login?a=1&b=2" {
		t.Fatalf("unexpected canonical action: %s", forms[0].Action)
	}
}

func TestParsePageExtractsSyntheticGetFormFromQueryPage(t *testing.T) {
	html := []byte(`<html><body>No forms here</body></html>`)
	_, forms, _ := parsePage("https://example.com/search?b=2&a=1", html)
	if len(forms) != 1 {
		t.Fatalf("expected synthetic GET form for query page, got %d", len(forms))
	}
	if forms[0].Method != "GET" {
		t.Fatalf("expected GET method, got %s", forms[0].Method)
	}
	if len(forms[0].Inputs) != 2 || forms[0].Inputs[0].Name != "a" || forms[0].Inputs[1].Name != "b" {
		t.Fatalf("unexpected synthetic inputs: %#v", forms[0].Inputs)
	}
}
