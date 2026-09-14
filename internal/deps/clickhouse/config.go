package clickhouse

type Config struct {
	URL                string `env:"CLICKHOUSE_URL,required"`
	Environment        string `env:"PUG_ENVIRONMENT,default=development"`
	RawEventsRetention string `env:"PUG_RAW_EVENTS_RETENTION"`
}
