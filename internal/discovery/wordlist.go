package discovery

import "strings"

var standardReconWords = []string{
	"account", "accounts", "admin", "administracao", "analytics", "android", "api", "api-gateway",
	"app", "apps", "assets", "auth", "autodiscover", "backup", "backups", "beta", "billing", "blog",
	"cdn", "chat", "ci", "client", "clientes", "cloud", "cms", "console", "crm", "dashboard", "data",
	"database", "db", "demo", "deploy", "developer", "developers", "devops", "docs", "download", "edge",
	"email", "erp", "external", "files", "finance", "ftp", "gateway", "git", "gitlab", "grafana", "graphql",
	"help", "helpdesk", "homolog", "homologacao", "id", "identity", "img", "images", "imap", "internal",
	"intranet", "ios", "jenkins", "jira", "kibana", "labs", "legacy", "login", "logs", "mail", "manage",
	"management", "metrics", "mfa", "mobile", "monitor", "monitoring", "mx", "new", "ns", "ns1", "ns2",
	"oauth", "office", "old", "origin", "owa", "partners", "payments", "portal", "preview", "private", "prod",
	"production", "prometheus", "proxy", "qa", "remote", "reports", "s3", "sandbox", "secure", "security",
	"service", "services", "sftp", "shop", "signin", "smtp", "sso", "stage", "staging", "static", "status",
	"storage", "store", "support", "test", "testing", "tickets", "training", "uat", "upload", "uploads", "vpn",
	"web", "webmail", "wiki", "www", "www1", "www2",
}

var exhaustiveReconWords = []string{
	"access", "ad", "ads", "agent", "alerts", "alpha", "archive", "artifacts", "audit", "automation", "b2b",
	"b2c", "backend", "batch", "bastion", "bi", "build", "cache", "canary", "catalog", "central", "checkout",
	"click", "cluster", "collector", "community", "config", "connect", "consumer", "content", "control", "core",
	"corp", "corporate", "customer", "customers", "devportal", "directory", "discovery", "dns", "docker", "ecom",
	"elastic", "events", "export", "feature", "fileserver", "forum", "frontend", "geo", "global", "graph", "health",
	"hooks", "host", "hr", "hub", "import", "infra", "integration", "inventory", "invoice", "k8s", "kafka",
	"kubernetes", "ldap", "links", "load", "m", "master", "media", "member", "members", "message", "messaging",
	"microservice", "mirror", "mq", "net", "network", "node", "notifications", "ops", "panel", "partner",
	"password", "pay", "poc", "postgres", "preprod", "profile", "public", "rabbitmq", "redis", "registry", "repo",
	"repository", "research", "rest", "sales", "scheduler", "search", "server", "session", "share", "source",
	"sql", "ssh", "staff", "stream", "telemetry", "temp", "tools", "tracking", "translate", "user", "users",
	"vault", "video", "webhook", "webhooks", "worker", "workspace", "ws",
}

var environmentWords = []string{
	"dev", "development", "test", "testing", "qa", "uat", "stage", "staging", "homolog", "sandbox", "demo",
	"preview", "preprod", "prod", "production", "canary", "blue", "green", "old", "new", "legacy",
}

var serviceWords = []string{
	"api", "app", "auth", "admin", "backend", "cdn", "console", "dashboard", "gateway", "internal", "login",
	"mobile", "portal", "service", "static", "web", "www",
}

var regionWords = []string{
	"br", "br1", "br2", "us", "us1", "us2", "eu", "eu1", "sa", "sa1", "east", "west", "north", "south",
	"us-east", "us-west", "eu-west", "eu-central", "sa-east", "us-east-1", "us-west-1", "us-west-2",
	"eu-west-1", "eu-central-1", "sa-east-1",
}

func DefaultWords(mode Mode) []string {
	words := append([]string(nil), standardReconWords...)
	if mode != ModeExhaustive {
		return cleanWords(words)
	}
	words = append(words, exhaustiveReconWords...)
	for _, service := range serviceWords {
		for _, environment := range environmentWords {
			words = append(words, service+"-"+environment, environment+"-"+service)
		}
	}
	for _, service := range serviceWords {
		for _, region := range regionWords {
			words = append(words, service+"-"+region)
		}
	}
	return cleanWords(words)
}

func wordsForAlteration(words []string, learned []string) []string {
	seen := make(map[string]struct{})
	result := make([]string, 0, 96)
	for _, pool := range [][]string{environmentWords, regionWords, learned, words} {
		for _, word := range pool {
			word = strings.ToLower(strings.TrimSpace(word))
			if !validWord(word) {
				continue
			}
			if _, found := seen[word]; found {
				continue
			}
			seen[word] = struct{}{}
			result = append(result, word)
			if len(result) == 96 {
				return result
			}
		}
	}
	return result
}
