package config

import (
	"log"
	"strings"

	"github.com/spf13/viper"
)

type Config struct {
	Server     ServerConfig     `mapstructure:"server"`
	DB         DBConfig         `mapstructure:"db"`
	RabbitMQ   RabbitMQConfig   `mapstructure:"rabbitmq"`
	Enrichment EnrichmentConfig `mapstructure:"enrichment"`
	Logging    LoggingConfig    `mapstructure:"logging"`
}

type ServerConfig struct {
	Port     int    `mapstructure:"port"`
	GRPCPort int    `mapstructure:"grpc_port"`
	Env      string `mapstructure:"env"`
}

type DBConfig struct {
	Postgres      PostgresConfig      `mapstructure:"postgres"`
	Elasticsearch ElasticsearchConfig `mapstructure:"elasticsearch"`
	Redis         RedisConfig         `mapstructure:"redis"`
}

type PostgresConfig struct {
	Host     string `mapstructure:"host"`
	Port     int    `mapstructure:"port"`
	User     string `mapstructure:"user"`
	Password string `mapstructure:"password"`
	DBName   string `mapstructure:"dbname"`
	SSLMode  string `mapstructure:"sslmode"`
}

type ElasticsearchConfig struct {
	Addresses []string `mapstructure:"addresses"`
}

type RedisConfig struct {
	Host     string `mapstructure:"host"`
	Port     int    `mapstructure:"port"`
	Password string `mapstructure:"password"`
	DB       int    `mapstructure:"db"`
}

type RabbitMQConfig struct {
	URL string `mapstructure:"url"`
}

type EnrichmentConfig struct {
	Shodan     ShodanConfig     `mapstructure:"shodan"`
	VirusTotal VirusTotalConfig `mapstructure:"virustotal"`
}

type ShodanConfig struct {
	APIKey string `mapstructure:"api_key"`
}

type VirusTotalConfig struct {
	APIKey string `mapstructure:"api_key"`
}

type LoggingConfig struct {
	Level string `mapstructure:"level"`
}

// LoadConfig reads configuration from file or environment variables
func LoadConfig(configPath string) (*Config, error) {
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	viper.AutomaticEnv()

	if configPath != "" {
		viper.SetConfigFile(configPath)
	} else {
		viper.AddConfigPath("configs")
		viper.AddConfigPath(".")
		viper.SetConfigName("config")
		viper.SetConfigType("yaml")
	}

	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, err
		}
		log.Println("No config file found. Using environment variables.")
	}

	var config Config
	if err := viper.Unmarshal(&config); err != nil {
		return nil, err
	}

	return &config, nil
}
