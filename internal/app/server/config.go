package server

type config struct {
	Port                     string `env:"PUG_SERVER_PORT,default=3000"`
	Environment              string `env:"PUG_ENVIRONMENT,default=development"`
	JWTKey                   string `env:"PUG_JWT_SECRET_KEY"`
	JWTKeyringFile           string `env:"PUG_JWT_KEYRING_FILE"`
	CORSOrigins              string `env:"PUG_CORS_ORIGINS,default=*"`
	TrustProxyHeaders        bool   `env:"PUG_TRUST_PROXY_HEADERS,default=false"`
	IngestProjectRate        int    `env:"PUG_INGEST_PROJECT_RATE,default=200"`
	IngestProjectBurst       int    `env:"PUG_INGEST_PROJECT_BURST,default=400"`
	IngestIPRate             int    `env:"PUG_INGEST_IP_RATE,default=50"`
	IngestIPBurst            int    `env:"PUG_INGEST_IP_BURST,default=100"`
	IngestProjectConcurrency int    `env:"PUG_INGEST_PROJECT_CONCURRENCY,default=32"`
	IngestIPConcurrency      int    `env:"PUG_INGEST_IP_CONCURRENCY,default=8"`
	// DemoEnabled mirrors the demo worker's PUG_DEMO_ENABLED switch: when true,
	// the server exposes the credential-less AuthService.DemoSignIn viewer login.
	// Off everywhere else so the demo login can't be minted on a real deployment.
	DemoEnabled bool `env:"PUG_DEMO_ENABLED,default=false"`
}
