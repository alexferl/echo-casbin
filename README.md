# echo-casbin [![Go Report Card](https://goreportcard.com/badge/github.com/alexferl/echo-casbin)](https://goreportcard.com/report/github.com/alexferl/echo-casbin) [![codecov](https://codecov.io/gh/alexferl/echo-casbin/branch/master/graph/badge.svg)](https://codecov.io/gh/alexferl/echo-casbin)

A [Casbin](https://casbin.io/) middleware for the [Echo](https://github.com/labstack/echo) framework.

## Installing
```shell
go get github.com/alexferl/echo-casbin
```

## Motivation
You might wonder why not use the Casbin middleware in the [echo-contrib](https://github.com/labstack/echo-contrib/tree/master/casbin) repo?
The main reason is that it doesn't provide any built-in methods for retrieving roles other than the default
Basic Authorization header. You can write use your own function in place of it, but I wanted to have built-in methods
I will use in most of my projects. You can still define your function to retrieve roles, so it's still flexible.

## Using

### Code example
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
		return c.JSON(http.StatusOK, "ok")
	})

	enforcer, err := casbin.NewEnforcer("/path/to/model.conf", "/path/to/policy.csv")
	if err != nil {
		panic(err)
	}

	e.Use(mw.Casbin(enforcer))

	e.Logger.Fatal(e.Start("localhost:1323"))
}
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
