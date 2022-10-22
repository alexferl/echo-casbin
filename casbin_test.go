package casbin

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/casbin/casbin/v2"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
)

var enforcer *casbin.Enforcer

func init() {
	e, err := casbin.NewEnforcer("./fixtures/model.conf", "./fixtures/policy.csv")
	if err != nil {
		panic(err)
	}

	enforcer = e
}

func TestJWT(t *testing.T) {
	e := echo.New()

	e.GET("/", func(c echo.Context) error {
		return c.JSON(http.StatusOK, "ok")
	})

	e.Use(Casbin(enforcer))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	resp := httptest.NewRecorder()

	e.ServeHTTP(resp, req)

	assert.Equal(t, http.StatusOK, resp.Code)
}

type Response struct {
	Message string `json:"message"`
}

func TestJWT_Defaults_ForbiddenMessage(t *testing.T) {
	e := echo.New()

	e.GET("/user", func(c echo.Context) error {
		return c.JSON(http.StatusOK, "ok")
	})

	config := Config{
		Enforcer:         enforcer,
		ForbiddenMessage: "nope",
	}

	e.Use(CasbinWithConfig(config))

	req := httptest.NewRequest(http.MethodGet, "/user", nil)
	resp := httptest.NewRecorder()

	e.ServeHTTP(resp, req)

	r := &Response{}
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		assert.NoError(t, err)
	}

	err = json.Unmarshal(b, r)
	if err != nil {
		assert.NoError(t, err)
	}

	assert.Equal(t, &Response{Message: "nope"}, r)
}

func TestJWTWithConfig_ForbiddenMessage(t *testing.T) {
	e := echo.New()

	e.GET("/user", func(c echo.Context) error {
		return c.JSON(http.StatusOK, "ok")
	})

	e.Use(Casbin(enforcer))

	req := httptest.NewRequest(http.MethodGet, "/user", nil)
	resp := httptest.NewRecorder()

	e.ServeHTTP(resp, req)

	r := &Response{}
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		assert.NoError(t, err)
	}

	err = json.Unmarshal(b, r)
	if err != nil {
		assert.NoError(t, err)
	}

	assert.Equal(t, &Response{Message: DefaultConfig.ForbiddenMessage}, r)
}

func TestJWTWithConfig_RolesFunc(t *testing.T) {
	testCases := []struct {
		name       string
		roles      []string
		statusCode int
		err        error
	}{
		{"no role", []string{}, http.StatusForbidden, nil},
		{"any", []string{"any"}, http.StatusForbidden, nil},
		{"user", []string{"user"}, http.StatusOK, nil},
		{"any user", []string{"any", "user"}, http.StatusOK, nil},
		{"error", []string{""}, http.StatusForbidden, echo.NewHTTPError(http.StatusForbidden)},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			e := echo.New()

			e.GET("/user", func(c echo.Context) error {
				return c.JSON(http.StatusOK, "ok")
			})

			config := Config{
				Enforcer: enforcer,
				RolesFunc: func(c echo.Context) ([]string, error) {
					return tc.roles, tc.err
				},
			}

			e.Use(CasbinWithConfig(config))

			req := httptest.NewRequest(http.MethodGet, "/user", nil)
			resp := httptest.NewRecorder()

			e.ServeHTTP(resp, req)

			assert.Equal(t, tc.statusCode, resp.Code)
		})
	}
}

func TestJWTWithConfig_Return_Codes(t *testing.T) {
	testCases := []struct {
		name       string
		roles      string
		endpoint   string
		method     string
		statusCode int
	}{
		{"root no role", "", "/", http.MethodGet, http.StatusOK},
		{"root any", "any", "/", http.MethodGet, http.StatusOK},
		{"root user", "user", "/", http.MethodGet, http.StatusOK},
		{"root admin", "admin", "/", http.MethodGet, http.StatusOK},
		{"root user admin", "user,admin", "/", http.MethodGet, http.StatusOK},
		{"user no role", "", "/user", http.MethodGet, http.StatusForbidden},
		{"user any", "any", "/user", http.MethodPost, http.StatusForbidden},
		{"user user", "any,user", "/user", http.MethodDelete, http.StatusOK},
		{"user admin", "admin", "/user", http.MethodPut, http.StatusOK},
		{"user invalid", "invalid", "/user", http.MethodPost, http.StatusForbidden},
		{"admin no role", "", "/admin", http.MethodGet, http.StatusForbidden},
		{"admin any", "any", "/admin", http.MethodGet, http.StatusForbidden},
		{"admin user", "user", "/admin", http.MethodGet, http.StatusForbidden},
		{"admin admin", "user,admin", "/admin", http.MethodGet, http.StatusOK},
		{"admin admin", "admin", "/admin", http.MethodGet, http.StatusOK},
		{"admin invalid", "invalid", "/admin", http.MethodGet, http.StatusForbidden},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			e := echo.New()

			e.Any(tc.endpoint, func(c echo.Context) error {
				return c.JSON(http.StatusOK, "ok")
			})

			config := Config{
				Enforcer:          enforcer,
				EnableRolesHeader: true,
			}
			e.Use(CasbinWithConfig(config))

			req := httptest.NewRequest(tc.method, tc.endpoint, nil)
			req.Header.Add("X-Roles", tc.roles)
			resp := httptest.NewRecorder()

			e.ServeHTTP(resp, req)

			assert.Equal(t, tc.statusCode, resp.Code)
		})
	}
}

func rolesHeader(s string) ([]string, error) {
	var roles []string
	for _, role := range strings.Split(s, ",") {
		role = strings.TrimSpace(role)
		roles = append(roles, role)
	}

	return roles, nil
}

func rolesHeaderErr(s string) ([]string, error) {
	return nil, echo.NewHTTPError(http.StatusForbidden, "nope")
}

func TestJWTWithConfig_RolesHeaderFunc(t *testing.T) {
	testCases := []struct {
		name       string
		fn         func(string) ([]string, error)
		roles      string
		endpoint   string
		method     string
		statusCode int
	}{
		{"root no role", rolesHeader, "", "/", http.MethodGet, http.StatusOK},
		{"admin admin", rolesHeader, "user,admin", "/admin", http.MethodGet, http.StatusOK},
		{"error", rolesHeaderErr, "", "/", http.MethodGet, http.StatusForbidden},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			e := echo.New()

			e.Any(tc.endpoint, func(c echo.Context) error {
				return c.JSON(http.StatusOK, "ok")
			})

			config := Config{
				Enforcer:          enforcer,
				EnableRolesHeader: true,
				RolesHeaderFunc:   tc.fn,
			}
			e.Use(CasbinWithConfig(config))

			req := httptest.NewRequest(tc.method, tc.endpoint, nil)
			req.Header.Add("X-Roles", tc.roles)
			resp := httptest.NewRecorder()

			e.ServeHTTP(resp, req)

			assert.Equal(t, tc.statusCode, resp.Code)
		})
	}
}

func TestJWTWithConfig_Skipper(t *testing.T) {
	e := echo.New()

	e.GET("/", func(c echo.Context) error {
		return c.JSON(http.StatusOK, "ok")
	})

	config := Config{
		Enforcer: enforcer,
		Skipper:  func(c echo.Context) bool { return true },
	}
	e.Use(CasbinWithConfig(config))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	resp := httptest.NewRecorder()

	e.ServeHTTP(resp, req)

	assert.Equal(t, http.StatusOK, resp.Code)
}

func TestJWTWithConfig_Enforcer_Panic(t *testing.T) {
	e := echo.New()

	assert.Panics(t, func() { e.Use(CasbinWithConfig(Config{})) })
}

func TestJWTWithConfig_Functions(t *testing.T) {
	testCases := []struct {
		name       string
		endpoint   string
		statusCode int
	}{
		{"success", "/", http.StatusOK},
		{"failure", "/admin", http.StatusForbidden},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			e := echo.New()

			e.GET("/", func(c echo.Context) error {
				return c.JSON(http.StatusOK, "ok")
			})

			config := Config{
				Enforcer:    enforcer,
				SuccessFunc: func(string, string, string) {},
				FailureFunc: func([]string, string, string) {},
			}
			e.Use(CasbinWithConfig(config))

			req := httptest.NewRequest(http.MethodGet, tc.endpoint, nil)
			resp := httptest.NewRecorder()

			e.ServeHTTP(resp, req)

			assert.Equal(t, tc.statusCode, resp.Code)
		})
	}
}
