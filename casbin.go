package casbin

import (
	"errors"
	"net/http"
	"strings"

	"github.com/casbin/casbin/v2"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

type Config struct {
	// Skipper defines a function to skip middleware.
	Skipper middleware.Skipper

	// Enforce defines the enforcer used for
	// authorization enforcement and policy management.
	// Required.
	Enforcer *casbin.Enforcer

	// ContextKey defines the key that will be used to
	// read the roles on the echo.Context for enforcing.
	// Optional. Defaults to "roles".
	ContextKey string

	// DefaultRoles defines
	// Optional. Defaults to "any".
	DefaultRole string

	// EnableRolesHeader enables the RolesHeader.
	// Optional. Defaults to false.
	EnableRolesHeader bool

	// RolesHeader defines the header that will be used to
	// read in the roles if EnableRolesHeader is set to true.
	// Roles should be separated by commas. E.g. "role1,role2".
	// Optional. Defaults to false.
	RolesHeader string

	// RolesFunc defines the function that will retrieve the roles
	// to be passed to the Enforcer.
	// Takes precedence over ContextKey and RolesHeader if they're defined.
	// Optional.
	RolesFunc func(c echo.Context) ([]string, error)

	// ForbiddenMessage defines the message that will be
	// returned when authorization fails.
	// Optional. Defaults to "Access to this resource has been restricted".
	ForbiddenMessage string

	// SuccessFunc defines the function that will run
	// when authorization succeeds.
	// Optional.
	SuccessFunc func(string, string, string)

	// FailureFunc defines the function that will run
	// when authorization fails.
	// Optional.
	FailureFunc func([]string, string, string)
}

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
	if config.Skipper == nil {
		config.Skipper = DefaultConfig.Skipper
	}

	if config.Enforcer == nil {
		panic("enforcer is required")
	}

	if config.ContextKey == "" {
		config.ContextKey = DefaultConfig.ContextKey
	}

	if config.DefaultRole == "" {
		config.DefaultRole = DefaultConfig.DefaultRole
	}

	if config.RolesHeader == "" {
		config.RolesHeader = DefaultConfig.RolesHeader
	}

	if config.ForbiddenMessage == "" {
		config.ForbiddenMessage = DefaultConfig.ForbiddenMessage
	}

	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			if config.Skipper(c) {
				return next(c)
			}

			var roles []string
			if config.RolesFunc != nil {
				var err error
				roles, err = config.RolesFunc(c)
				if err != nil {
					return err
				}
			} else {
				var ok bool
				roles, ok = c.Get(config.ContextKey).([]string)
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
			}

			if len(roles) < 1 {
				roles = append(roles, config.DefaultRole)
			}

			obj := c.Path()
			act := c.Request().Method

			var authorized bool
			for _, role := range roles {
				pass, err := config.Enforcer.Enforce(role, obj, act)
				if err != nil {
					c.Logger().Errorf("failed enforcing: %v", err)
					text := http.StatusText(http.StatusInternalServerError)
					err := echo.NewHTTPError(http.StatusInternalServerError, text)
					return err
				}

				if pass {
					authorized = true
					if config.SuccessFunc != nil {
						config.SuccessFunc(role, obj, act)
					}
					break
				}
			}

			if !authorized {
				if config.FailureFunc != nil {
					config.FailureFunc(roles, obj, act)
				}
				err := echo.NewHTTPError(http.StatusForbidden, errors.New(config.ForbiddenMessage))
				return err
			}

			return next(c)
		}
	}
}
