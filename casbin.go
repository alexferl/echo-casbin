package casbin

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/casbin/casbin/v2"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

type (
	Config struct {
		// Skipper defines a function to skip middleware.
		Skipper middleware.Skipper

		Enforcer          *casbin.Enforcer
		ContextKey        string
		DefaultRole       string
		EnableRolesHeader bool
		RolesHeader       string
		ForbiddenMessage  string
		SuccessFunc       func(string, string, string)
		FailureFunc       func([]string, string, string)
	}
)

var DefaultConfig = Config{
	Skipper:          middleware.DefaultSkipper,
	ContextKey:       "roles",
	DefaultRole:      "any",
	RolesHeader:      "X-Roles",
	ForbiddenMessage: "Access to this resource has been restricted",
}

func Casbin(ce *casbin.Enforcer) echo.MiddlewareFunc {
	c := DefaultConfig
	c.Enforcer = ce
	return CasbinWithConfig(c)
}

func CasbinWithConfig(config Config) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			if config.Skipper(c) {
				return next(c)
			}

			roles, ok := c.Get(config.ContextKey).([]string)
			if !ok {
				roles = []string{}
			}

			if len(roles) < 1 && config.EnableRolesHeader {
				rolesHeader := c.Request().Header.Get(config.RolesHeader)
				if rolesHeader == "" {
					rolesHeader = config.DefaultRole
				}

				for _, role := range strings.Split(rolesHeader, ",") {
					role = strings.TrimSpace(role)
					roles = append(roles, role)
				}
			}

			obj := c.Request().URL.Path
			act := c.Request().Method

			var authorized bool
			for _, role := range roles {
				pass, err := config.Enforcer.Enforce(role, obj, act)
				if err != nil {
					c.Logger().Errorf("error enforcing: %w", err)
					text := http.StatusText(http.StatusInternalServerError)
					err := echo.NewHTTPError(http.StatusInternalServerError, text)
					err.Internal = fmt.Errorf("error enforcing: %w", err)
					return err
				}

				if pass {
					authorized = true
				}

				if config.SuccessFunc != nil {
					config.SuccessFunc(role, obj, act)
				}
				break
			}

			if !authorized {
				if config.FailureFunc != nil {
					config.FailureFunc(roles, obj, act)
					err := echo.NewHTTPError(http.StatusForbidden, errors.New(config.ForbiddenMessage))
					return err
				}
			}

			return next(c)
		}
	}
}
