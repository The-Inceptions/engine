module github.com/owasp-amass/engine

go 1.21

toolchain go1.21.4

require (
	github.com/99designs/gqlgen v0.17.47
	github.com/PuerkitoBio/goquery v1.9.2
	github.com/caffix/pipeline v0.2.3
	github.com/caffix/queue v0.1.5 // direct
	github.com/caffix/stringset v0.1.2
	github.com/cheggaaa/pb/v3 v3.1.5
	github.com/geziyor/geziyor v0.0.0-20230315135110-a242b58aaa65
	github.com/glebarez/sqlite v1.11.0
	github.com/google/uuid v1.6.0 // direct
	github.com/gorilla/websocket v1.5.1
	github.com/hashicorp/go-multierror v1.1.1
	github.com/miekg/dns v1.1.59
	github.com/owasp-amass/asset-db v0.3.6-0.20240118034832-9f35c5a2dea6
	github.com/owasp-amass/config v0.2.1
	github.com/owasp-amass/open-asset-model v0.2.1-0.20240113165517-79f7a07407c7
	github.com/owasp-amass/resolve v0.7.3
	github.com/rubenv/sql-migrate v1.6.1
	github.com/tylertreat/BoomFilters v0.0.0-20210315201527-1a82519a3e43
	github.com/vektah/gqlparser/v2 v2.5.12
	golang.org/x/net v0.25.0
	gorm.io/driver/postgres v1.5.7
	gorm.io/gorm v1.25.10
)

require (
	github.com/samber/slog-common v0.16.0
	github.com/samber/slog-syslog/v2 v2.3.0
	go.uber.org/ratelimit v0.3.1
)

require (
	filippo.io/edwards25519 v1.1.0 // indirect
	github.com/AndreasBriese/bbloom v0.0.0-20190825152654-46b345b51c96 // indirect
	github.com/VividCortex/ewma v1.2.0 // indirect
	github.com/VividCortex/gohistogram v1.0.0 // indirect
	github.com/agnivade/levenshtein v1.1.1 // indirect
	github.com/andybalholm/cascadia v1.3.2 // indirect
	github.com/benbjohnson/clock v1.3.5 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/chromedp/cdproto v0.0.0-20240519224452-66462be74baa // indirect
	github.com/chromedp/chromedp v0.9.5 // indirect
	github.com/chromedp/sysutil v1.0.0 // indirect
	github.com/dgraph-io/badger v1.6.2 // indirect
	github.com/dgraph-io/ristretto v0.1.1 // indirect
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/fatih/color v1.17.0 // indirect
	github.com/glebarez/go-sqlite v1.22.0 // indirect
	github.com/go-gorp/gorp/v3 v3.1.0 // indirect
	github.com/go-kit/kit v0.13.0 // indirect
	github.com/go-sql-driver/mysql v1.8.1 // indirect
	github.com/gobwas/httphead v0.1.0 // indirect
	github.com/gobwas/pool v0.2.1 // indirect
	github.com/gobwas/ws v1.4.0 // indirect
	github.com/golang/glog v1.2.1 // indirect
	github.com/golang/protobuf v1.5.4 // indirect
	github.com/hashicorp/errwrap v1.1.0 // indirect
	github.com/hashicorp/golang-lru/v2 v2.0.7 // indirect
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20231201235250-de7065d80cb9 // indirect
	github.com/jackc/pgx/v5 v5.5.5 // indirect
	github.com/jackc/puddle/v2 v2.2.1 // indirect
	github.com/jinzhu/inflection v1.0.0 // indirect
	github.com/jinzhu/now v1.1.5 // indirect
	github.com/josharian/intern v1.0.0 // indirect
	github.com/mailru/easyjson v0.7.7 // indirect
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/mattn/go-runewidth v0.0.15 // indirect
	github.com/mitchellh/mapstructure v1.5.0 // indirect
	github.com/ncruces/go-strftime v0.1.9 // indirect
	github.com/owasp-amass/amass/v4 v4.2.0 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/prometheus/client_golang v1.19.1 // indirect
	github.com/prometheus/client_model v0.6.1 // indirect
	github.com/prometheus/common v0.53.0 // indirect
	github.com/prometheus/procfs v0.15.0 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	github.com/rivo/uniseg v0.4.7 // indirect
	github.com/samber/lo v1.39.0 // indirect
	github.com/sosodev/duration v1.3.1 // indirect
	github.com/temoto/robotstxt v1.1.2 // indirect
	golang.org/x/crypto v0.23.0 // indirect
	golang.org/x/exp v0.0.0-20240506185415-9bf2ced13842 // indirect
	golang.org/x/mod v0.17.0 // indirect
	golang.org/x/sync v0.7.0 // indirect
	golang.org/x/sys v0.20.0 // indirect
	golang.org/x/text v0.15.0 // indirect
	golang.org/x/time v0.5.0 // indirect
	golang.org/x/tools v0.21.0 // indirect
	google.golang.org/protobuf v1.34.1 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
	gorm.io/datatypes v1.2.0 // indirect
	gorm.io/driver/mysql v1.5.6 // indirect
	modernc.org/libc v1.50.8 // indirect
	modernc.org/mathutil v1.6.0 // indirect
	modernc.org/memory v1.8.0 // indirect
	modernc.org/sqlite v1.29.10 // indirect
)
