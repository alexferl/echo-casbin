# echo-casbin [![Go Report Card](https://goreportcard.com/badge/github.com/alexferl/echo-casbin)](https://goreportcard.com/report/github.com/alexferl/echo-casbin) [![codecov](https://codecov.io/gh/alexferl/echo-casbin/branch/master/graph/badge.svg)](https://codecov.io/gh/alexferl/echo-casbin)

A [Casbin](https://casbin.io/) middleware for the [Echo](https://github.com/labstack/echo) framework.

## Installing
```shell
go get github.com/alexferl/echo-casbin
```

## Motivation
You might wonder why not use the Casbin middleware in the [echo-contrib](https://github.com/labstack/echo-contrib/tree/master/casbin) repo?
The main reason is that it doesn't provide any built-in methods for retrieving roles other than the default
Basic Authorization header. You can pass your own function in place of it, but I wanted to have built-in methods
that I will use in most of my projects. You can still define your own function to retrieve roles, so it's still flexible.

## Using
You need to have a model and policy before you can use the middleware. You can use the ones in [here](fixtures) to get
started.

### Code example
This example expects the roles to be passed in the `X-Roles` header. There is **no** validation done to make sure the
client doing the request is allowed to use these roles, this is beyond the scope of this middleware. A function can be
defined with the `RolesHeaderFunc` config to do the validation.

The default way the middleware gets the roles is from the key `roles` on the `echo.Context`. In a real application,
another middleware running before this one would validate the client's identity and set their roles on the context so
this middleware can access them.

```go
package main

import (
	"net/http"

	mw "github.com/alexferl/echo-casbin"
	"github.com/casbin/casbin/v2"
	"github.com/labstack/echo/v4"
)

func main() {
	e := echo.New()

	e.GET("/", func(c echo.Context) error {
		return c.JSON(http.StatusOK, "ok")
	})

	e.GET("/user", func(c echo.Context) error {
		return c.JSON(http.StatusOK, "user")
	})

	enforcer, err := casbin.NewEnforcer("/path/to/model.conf", "/path/to/policy.csv")
	if err != nil {
		panic(err)
	}

	config := mw.Config{
		Enforcer:          enforcer,
		EnableRolesHeader: true,
	}
	e.Use(mw.CasbinWithConfig(config))

	e.Logger.Fatal(e.Start("localhost:1323"))
}
```

Making a request to non-protected endpoint:
```shell
curl http://localhost:1323
"ok"
```

Making a request to a protected endpoint:
```shell
curl http://localhost:1323/user
{"message":"Access to this resource has been restricted"}
```

Making a request to a protected endpoint with the right role:
```shell
curl http://localhost:1323/user -H 'X-Roles: user'
"user"
```

### Configuration
```go
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

	// RolesHeaderFunc defines the function that will validate that
	// a client is allowed to the use roles they passed via the RolesHeader.
	// The RolesHeader value will be passed unmodified, so you will need
	// to parse it in this function yourself. The DefaultRole will be passed
	// if the RolesHeader is empty. The roles that you want to have
	// enforced will need to be returned in a slice: []string{"role1, "role2"}.
	// Optional.
	RolesHeaderFunc func(string) ([]string, error)

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
```
