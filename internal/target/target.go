package target

import (
	"fmt"
	"net/url"
	"sort"
	"strings"

	"github.com/rynosec/xspulse/internal/model"
)

type ParsedTarget struct {
	URL        *url.URL
	Method     string
	Parameters []model.Parameter
	RawData    string
}

func Parse(rawURL, method, data string) (*ParsedTarget, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}
	if u.Scheme == "" {
		u, err = url.Parse("https://" + rawURL)
		if err != nil {
			return nil, err
		}
	}
	m := strings.ToUpper(strings.TrimSpace(method))
	if m == "" {
		if data != "" {
			m = "POST"
		} else {
			m = "GET"
		}
	}

	params := []model.Parameter{}
	if m == "GET" {
		q := u.Query()
		if len(q) == 0 && data != "" {
			parsed, err := url.ParseQuery(data)
			if err != nil {
				return nil, fmt.Errorf("parse GET data: %w", err)
			}
			q = parsed
		}
		keys := make([]string, 0, len(q))
		for k := range q {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			vals := q[k]
			if len(vals) == 0 {
				params = append(params, model.Parameter{Name: k, Value: ""})
				continue
			}
			params = append(params, model.Parameter{Name: k, Value: vals[0]})
		}
	} else if data != "" {
		vals, err := url.ParseQuery(data)
		if err != nil {
			return nil, fmt.Errorf("parse --data: %w", err)
		}
		keys := make([]string, 0, len(vals))
		for k := range vals {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			v := vals.Get(k)
			params = append(params, model.Parameter{Name: k, Value: v})
		}
	}
	return &ParsedTarget{URL: u, Method: m, Parameters: params, RawData: data}, nil
}

func (p *ParsedTarget) CloneWith(name, value string) (string, string, error) {
	cp := *p.URL
	if p.Method == "GET" {
		q := cp.Query()
		q.Set(name, value)
		cp.RawQuery = q.Encode()
		return cp.String(), "", nil
	}
	vals := url.Values{}
	for _, param := range p.Parameters {
		if param.Name == name {
			vals.Set(param.Name, value)
		} else {
			vals.Set(param.Name, param.Value)
		}
	}
	return cp.String(), vals.Encode(), nil
}
