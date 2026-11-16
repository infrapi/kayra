package discovery

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestRegister(t *testing.T) {
	gin.SetMode(gin.TestMode)
	doc := New("infrapi.io", Groups{
		System: "system.infrapi.io", Catalog: "catalog.infrapi.io", Authorization: "authorization.infrapi.io",
	}, "/oauth2/userinfo", "/oauth2/discovery/keys", "/apis")
	engine := gin.New()
	Register(engine, doc)

	w := httptest.NewRecorder()
	engine.ServeHTTP(w, httptest.NewRequest(http.MethodGet, Path, nil))
	if w.Code != http.StatusOK {
		t.Fatalf("GET %s: %d", Path, w.Code)
	}
	if cc := w.Header().Get("Cache-Control"); !strings.Contains(cc, "max-age") {
		t.Errorf("Cache-Control %q: want a max-age", cc)
	}

	var got Document
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	want := Document{
		Domain: "infrapi.io",
		APIs: map[string]string{
			"system":        "/apis/system.infrapi.io/v1",
			"catalog":       "/apis/catalog.infrapi.io/v1",
			"authorization": "/apis/authorization.infrapi.io/v1",
		},
		Endpoints: Endpoints{
			Userinfo: "/oauth2/userinfo",
			Check:    "/apis/authorization.infrapi.io/v1/check",
			JWKS:     "/oauth2/discovery/keys",
			APIs:     "/apis",
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("document:\n got %+v\nwant %+v", got, want)
	}
}
