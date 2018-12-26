package vestigo

import "net/http"

type route struct {
	method  string
	path    string
	handler http.HandlerFunc
}

func (r *route) String() string {
	return r.method + "  " + r.path
}
