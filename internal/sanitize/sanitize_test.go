package sanitize_test

import (
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/Kseleven/pgx/v5/internal/sanitize"
)

func TestNewQuery(t *testing.T) {
	successTests := []struct {
		sql      string
		expected sanitize.Query
	}{
		{
			sql:      "select 42",
			expected: sanitize.Query{Parts: []sanitize.Part{"select 42"}},
		},
		{
			sql:      "select $1",
			expected: sanitize.Query{Parts: []sanitize.Part{"select ", 1}},
		},
		{
			sql:      "select 'quoted $42', $1",
			expected: sanitize.Query{Parts: []sanitize.Part{"select 'quoted $42', ", 1}},
		},
		{
			sql:      `select "doubled quoted $42", $1`,
			expected: sanitize.Query{Parts: []sanitize.Part{`select "doubled quoted $42", `, 1}},
		},
		{
			sql:      "select 'foo''bar', $1",
			expected: sanitize.Query{Parts: []sanitize.Part{"select 'foo''bar', ", 1}},
		},
		{
			sql:      `select "foo""bar", $1`,
			expected: sanitize.Query{Parts: []sanitize.Part{`select "foo""bar", `, 1}},
		},
		{
			sql:      "select '''', $1",
			expected: sanitize.Query{Parts: []sanitize.Part{"select '''', ", 1}},
		},
		{
			sql:      `select """", $1`,
			expected: sanitize.Query{Parts: []sanitize.Part{`select """", `, 1}},
		},
		{
			sql:      "select $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11",
			expected: sanitize.Query{Parts: []sanitize.Part{"select ", 1, ", ", 2, ", ", 3, ", ", 4, ", ", 5, ", ", 6, ", ", 7, ", ", 8, ", ", 9, ", ", 10, ", ", 11}},
		},
		{
			sql:      `select "adsf""$1""adsf", $1, 'foo''$$12bar', $2, '$3'`,
			expected: sanitize.Query{Parts: []sanitize.Part{`select "adsf""$1""adsf", `, 1, `, 'foo''$$12bar', `, 2, `, '$3'`}},
		},
		{
			sql:      `select E'escape string\' $42', $1`,
			expected: sanitize.Query{Parts: []sanitize.Part{`select E'escape string\' $42', `, 1}},
		},
		{
			sql:      `select e'escape string\' $42', $1`,
			expected: sanitize.Query{Parts: []sanitize.Part{`select e'escape string\' $42', `, 1}},
		},
		{
			sql:      `select /* a baby's toy */ 'barbie', $1`,
			expected: sanitize.Query{Parts: []sanitize.Part{`select /* a baby's toy */ 'barbie', `, 1}},
		},
		{
			sql:      `select /* *_* */ $1`,
			expected: sanitize.Query{Parts: []sanitize.Part{`select /* *_* */ `, 1}},
		},
		{
			sql:      `select 42 /* /* /* 42 */ */ */, $1`,
			expected: sanitize.Query{Parts: []sanitize.Part{`select 42 /* /* /* 42 */ */ */, `, 1}},
		},
		{
			sql:      "select -- a baby's toy\n'barbie', $1",
			expected: sanitize.Query{Parts: []sanitize.Part{"select -- a baby's toy\n'barbie', ", 1}},
		},
		{
			sql:      "select 42 -- is a Deep Thought's favorite number",
			expected: sanitize.Query{Parts: []sanitize.Part{"select 42 -- is a Deep Thought's favorite number"}},
		},
		{
			sql:      "select 42, -- \\nis a Deep Thought's favorite number\n$1",
			expected: sanitize.Query{Parts: []sanitize.Part{"select 42, -- \\nis a Deep Thought's favorite number\n", 1}},
		},
		{
			sql:      "select 42, -- \\nis a Deep Thought's favorite number\r$1",
			expected: sanitize.Query{Parts: []sanitize.Part{"select 42, -- \\nis a Deep Thought's favorite number\r", 1}},
		},
		{
			// https://github.com/Kseleven/pgx/issues/1380
			sql:      "select 'hello w�rld'",
			expected: sanitize.Query{Parts: []sanitize.Part{"select 'hello w�rld'"}},
		},
		{
			// Unterminated quoted string
			sql:      "select 'hello world",
			expected: sanitize.Query{Parts: []sanitize.Part{"select 'hello world"}},
		},
	}

	for i, tt := range successTests {
		query, err := sanitize.NewQuery(tt.sql)
		if err != nil {
			t.Errorf("%d. %v", i, err)
		}

		if len(query.Parts) == len(tt.expected.Parts) {
			for j := range query.Parts {
				if query.Parts[j] != tt.expected.Parts[j] {
					t.Errorf("%d. expected part %d to be %v but it was %v", i, j, tt.expected.Parts[j], query.Parts[j])
				}
			}
		} else {
			t.Errorf("%d. expected query parts to be %v but it was %v", i, tt.expected.Parts, query.Parts)
		}
	}
}

func TestQuerySanitize(t *testing.T) {
	successfulTests := []struct {
		query    sanitize.Query
		args     []any
		expected string
	}{
		{
			query:    sanitize.Query{Parts: []sanitize.Part{"select 42"}},
			args:     []any{},
			expected: `select 42`,
		},
		{
			query:    sanitize.Query{Parts: []sanitize.Part{"select ", 1}},
			args:     []any{int64(42)},
			expected: `select  42 `,
		},
		{
			query:    sanitize.Query{Parts: []sanitize.Part{"select ", 1}},
			args:     []any{float64(1.23)},
			expected: `select  1.23 `,
		},
		{
			query:    sanitize.Query{Parts: []sanitize.Part{"select ", 1}},
			args:     []any{true},
			expected: `select  true `,
		},
		{
			query:    sanitize.Query{Parts: []sanitize.Part{"select ", 1}},
			args:     []any{[]byte{0, 1, 2, 3, 255}},
			expected: `select  '\x00010203ff' `,
		},
		{
			query:    sanitize.Query{Parts: []sanitize.Part{"select ", 1}},
			args:     []any{nil},
			expected: `select  null `,
		},
		{
			query:    sanitize.Query{Parts: []sanitize.Part{"select ", 1}},
			args:     []any{"foobar"},
			expected: `select  'foobar' `,
		},
		{
			query:    sanitize.Query{Parts: []sanitize.Part{"select ", 1}},
			args:     []any{"foo'bar"},
			expected: `select  'foo''bar' `,
		},
		{
			query:    sanitize.Query{Parts: []sanitize.Part{"select ", 1}},
			args:     []any{`foo\'bar`},
			expected: `select  'foo\''bar' `,
		},
		{
			query:    sanitize.Query{Parts: []sanitize.Part{"insert ", 1}},
			args:     []any{time.Date(2020, time.March, 1, 23, 59, 59, 999999999, time.UTC)},
			expected: `insert  '2020-03-01 23:59:59.999999Z' `,
		},
		{
			query:    sanitize.Query{Parts: []sanitize.Part{"select 1-", 1}},
			args:     []any{int64(-1)},
			expected: `select 1- -1 `,
		},
		{
			query:    sanitize.Query{Parts: []sanitize.Part{"select 1-", 1}},
			args:     []any{float64(-1)},
			expected: `select 1- -1 `,
		},
	}

	for i, tt := range successfulTests {
		actual, err := tt.query.Sanitize(tt.args...)
		if err != nil {
			t.Errorf("%d. %v", i, err)
			continue
		}

		if tt.expected != actual {
			t.Errorf("%d. expected %s, but got %s", i, tt.expected, actual)
		}
	}

	errorTests := []struct {
		query    sanitize.Query
		args     []any
		expected string
	}{
		{
			query:    sanitize.Query{Parts: []sanitize.Part{"select ", 1, ", ", 2}},
			args:     []any{int64(42)},
			expected: `insufficient arguments`,
		},
		{
			query:    sanitize.Query{Parts: []sanitize.Part{"select 'foo'"}},
			args:     []any{int64(42)},
			expected: `unused argument: 0`,
		},
		{
			query:    sanitize.Query{Parts: []sanitize.Part{"select ", 1}},
			args:     []any{42},
			expected: `invalid arg type: int`,
		},
	}

	for i, tt := range errorTests {
		_, err := tt.query.Sanitize(tt.args...)
		if err == nil || err.Error() != tt.expected {
			t.Errorf("%d. expected error %v, got %v", i, tt.expected, err)
		}
	}
}

func TestQuoteString(t *testing.T) {
	tc := func(name, input string) {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			got := string(sanitize.QuoteString(nil, input))
			want := oldQuoteString(input)

			if got != want {
				t.Errorf("got:  %s", got)
				t.Fatalf("want: %s", want)
			}
		})
	}

	tc("empty", "")
	tc("text", "abcd")
	tc("with quotes", `one's hat is always a cat`)
}

// This function was used before optimizations.
// You should keep for testing purposes - we want to ensure there are no breaking changes.
func oldQuoteString(str string) string {
	return "'" + strings.ReplaceAll(str, "'", "''") + "'"
}

func TestQuoteBytes(t *testing.T) {
	tc := func(name string, input []byte) {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			got := string(sanitize.QuoteBytes(nil, input))
			want := oldQuoteBytes(input)

			if got != want {
				t.Errorf("got:  %s", got)
				t.Fatalf("want: %s", want)
			}
		})
	}

	tc("nil", nil)
	tc("empty", []byte{})
	tc("text", []byte("abcd"))
}

// This function was used before optimizations.
// You should keep for testing purposes - we want to ensure there are no breaking changes.
func oldQuoteBytes(buf []byte) string {
	return `'\x` + hex.EncodeToString(buf) + "'"
}
