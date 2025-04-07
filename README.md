[![Go Reference](https://pkg.go.dev/badge/github.com/jackc/pgx/v5.svg)](https://pkg.go.dev/github.com/jackc/pgx/v5)
[![Build Status](https://github.com/jackc/pgx/actions/workflows/ci.yml/badge.svg)](https://github.com/jackc/pgx/actions/workflows/ci.yml)

# pgx - PostgreSQL Driver and Toolkit

pgx is a PostgreSQL Driver fork from [pgx](https://github.com/jackc/pgx), and add opengauss sha256 sasl support.

## Example Usage

```go
package main

import (
	"context"
	"fmt"
	"os"

	"github.com/Kseleven/pgx/v5"
)

func main() {
	// urlExample := "postgres://username:password@localhost:5432/database_name"
	conn, err := pgx.Connect(context.Background(), os.Getenv("DATABASE_URL"))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to connect to database: %v\n", err)
		os.Exit(1)
	}
	defer conn.Close(context.Background())

	var name string
	var weight int64
	err = conn.QueryRow(context.Background(), "select name, weight from widgets where id=$1", 42).Scan(&name, &weight)
	if err != nil {
		fmt.Fprintf(os.Stderr, "QueryRow failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Println(name, weight)
}
```

See the [getting started guide](https://github.com/jackc/pgx/wiki/Getting-started-with-pgx) for more information.

## Features

* Same as pgx Features, See the [pgx Features](https://github.com/jackc/pgx?tab=readme-ov-file#features) for more information.
* Support opengauss `password_encryption_type=2` sha256 algorithm, See the [opengauss](https://docs.opengauss.org/zh/docs/5.0.0/docs/DatabaseAdministrationGuide/%E8%AE%BE%E7%BD%AE%E5%AF%86%E7%A0%81%E5%AE%89%E5%85%A8%E7%AD%96%E7%95%A5.html) for more information.

