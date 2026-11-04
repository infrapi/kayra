package oidc

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// SelfBaseURL is used to build the issuer, jwks_uri and userinfo_endpoint
// members of Kayra's own discovery document.
type SelfBaseURL string

// RegisterRoutes mounts Kayra's own OIDC discovery document and the
// aggregated JWKS endpoint.
func RegisterRoutes(r gin.IRouter, m *Manager, baseURL string) {
	r.GET("/.well-known/openid-configuration", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"issuer":                   baseURL,
			"jwks_uri":                 baseURL + "/oauth2/discovery/keys",
			"userinfo_endpoint":        baseURL + "/oauth2/userinfo",
			"response_types_supported": []string{"token"},
		})
	})

	r.GET("/oauth2/discovery/keys", func(c *gin.Context) {
		c.JSON(http.StatusOK, JWKSet{Keys: m.AllKeys()})
	})
}
