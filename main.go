// EgoBGP is a minimal BGP announcer that dynamically announces or withdraws
// prefixes based on HTTP health checks.
package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	api "github.com/osrg/gobgp/v3/api"
	"github.com/osrg/gobgp/v3/pkg/server"
	log "github.com/sirupsen/logrus"
	"google.golang.org/protobuf/types/known/anypb"
)

const (
	// Version information
	Version = "1.2.0"

	// Default values
	defaultHealthCheckInterval = 10
	defaultSuccessThreshold   = 1
	defaultFailureThreshold   = 4 // 4 failures before withdrawing
	defaultBGPPort           = 179
	bgpTimeout               = 5 * time.Second
	healthCheckTimeout       = 5 * time.Second

	// BGP constants
	asPathType = 2 // AS_SEQUENCE
	originIGP  = 0
	medValue   = 100
)

// Config holds the application configuration
type Config struct {
	LocalASN            uint32
	RouterID            string
	LocalPort           int
	LocalAddress        string
	PeerIP              string
	PeerPort            int
	PeerASN             uint32
	NextHopIPv4         string
	NextHopIPv6         string
	PrefixesToAnnounce  []string
	HealthCheckURL      string
	HealthCheckInterval int
	SuccessThreshold    int
	FailureThreshold    int
}

// validate performs basic validation of the configuration
func (c *Config) validate() error {
	// Validate ASNs
	if c.LocalASN == 0 || c.LocalASN > 4294967295 {
		return fmt.Errorf("invalid LOCAL_ASN: must be between 1 and 4294967295")
	}
	if c.PeerASN == 0 || c.PeerASN > 4294967295 {
		return fmt.Errorf("invalid PEER_ASN: must be between 1 and 4294967295")
	}

	// Validate IP addresses
	if ip := net.ParseIP(c.RouterID); ip == nil {
		return fmt.Errorf("invalid ROUTER_ID: not a valid IP address")
	}
	if ip := net.ParseIP(c.PeerIP); ip == nil {
		return fmt.Errorf("invalid PEER_IP: not a valid IP address")
	}
	
	// Validate next-hop addresses
	if c.NextHopIPv4 != "" {
		if ip := net.ParseIP(c.NextHopIPv4); ip == nil || ip.To4() == nil {
			return fmt.Errorf("invalid NEXT_HOP_IPV4: must be a valid IPv4 address")
		}
	}
	if c.NextHopIPv6 != "" {
		if ip := net.ParseIP(c.NextHopIPv6); ip == nil || ip.To4() != nil {
			return fmt.Errorf("invalid NEXT_HOP_IPV6: must be a valid IPv6 address")
		}
	}

	// Validate local address if specified
	if c.LocalAddress != "" {
		if ip := net.ParseIP(c.LocalAddress); ip == nil {
			return fmt.Errorf("invalid LOCAL_ADDRESS: not a valid IP address")
		}
	}

	// Validate prefixes and ensure appropriate next-hop addresses are provided
	if len(c.PrefixesToAnnounce) == 0 {
		return fmt.Errorf("ANNOUNCED_PREFIXES: at least one prefix is required")
	}
	
	hasIPv4Prefix := false
	hasIPv6Prefix := false
	
	for i, prefix := range c.PrefixesToAnnounce {
		if _, _, err := net.ParseCIDR(strings.TrimSpace(prefix)); err != nil {
			return fmt.Errorf("invalid ANNOUNCED_PREFIXES[%d]: %v", i, err)
		}
		
		// Check if this is an IPv4 or IPv6 prefix
		if ip, _, err := net.ParseCIDR(strings.TrimSpace(prefix)); err == nil {
			if ip.To4() != nil {
				hasIPv4Prefix = true
			} else {
				hasIPv6Prefix = true
			}
		}
	}
	
	// Ensure appropriate next-hop addresses are provided
	if hasIPv4Prefix && c.NextHopIPv4 == "" {
		return fmt.Errorf("NEXT_HOP_IPV4 is required when announcing IPv4 prefixes")
	}
	if hasIPv6Prefix && c.NextHopIPv6 == "" {
		return fmt.Errorf("NEXT_HOP_IPV6 is required when announcing IPv6 prefixes")
	}

	// Validate URL
	if _, err := http.NewRequest("GET", c.HealthCheckURL, nil); err != nil {
		return fmt.Errorf("invalid HEALTH_CHECK_URL: %v", err)
	}

	// Validate ports
	if c.LocalPort < 1 || c.LocalPort > 65535 {
		return fmt.Errorf("invalid LOCAL_PORT: must be between 1 and 65535")
	}
	if c.PeerPort < 1 || c.PeerPort > 65535 {
		return fmt.Errorf("invalid PEER_PORT: must be between 1 and 65535")
	}

	// Validate thresholds
	if c.HealthCheckInterval < 1 {
		return fmt.Errorf("invalid HEALTH_CHECK_INTERVAL: must be greater than 0")
	}
	if c.SuccessThreshold < 1 {
		return fmt.Errorf("invalid SUCCESS_THRESHOLD: must be greater than 0")
	}
	if c.FailureThreshold < 1 {
		return fmt.Errorf("invalid FAILURE_THRESHOLD: must be greater than 0")
	}

	return nil
}

// LoadConfig loads and validates configuration from environment variables
func LoadConfig() (*Config, error) {
	// Required fields
	localASNStr := os.Getenv("LOCAL_ASN")
	if localASNStr == "" {
		return nil, fmt.Errorf("LOCAL_ASN is required")
	}
	localASN, err := strconv.ParseUint(localASNStr, 10, 32)
	if err != nil {
		return nil, fmt.Errorf("invalid LOCAL_ASN: %v", err)
	}

	routerID := os.Getenv("ROUTER_ID")
	if routerID == "" {
		return nil, fmt.Errorf("ROUTER_ID is required")
	}

	peerIP := os.Getenv("PEER_IP")
	if peerIP == "" {
		return nil, fmt.Errorf("PEER_IP is required")
	}

	peerASNStr := os.Getenv("PEER_ASN")
	if peerASNStr == "" {
		return nil, fmt.Errorf("PEER_ASN is required")
	}
	peerASN, err := strconv.ParseUint(peerASNStr, 10, 32)
	if err != nil {
		return nil, fmt.Errorf("invalid PEER_ASN: %v", err)
	}

	// Load separate IPv4 and IPv6 next-hop addresses (optional)
	nextHopIPv4 := os.Getenv("NEXT_HOP_IPV4")
	nextHopIPv6 := os.Getenv("NEXT_HOP_IPV6")

	prefixesToAnnounce := os.Getenv("ANNOUNCED_PREFIXES")
	if prefixesToAnnounce == "" {
		return nil, fmt.Errorf("ANNOUNCED_PREFIXES is required")
	}

	// Split and trim prefixes
	prefixList := strings.Split(prefixesToAnnounce, ",")
	var trimmedPrefixes []string
	for _, prefix := range prefixList {
		trimmed := strings.TrimSpace(prefix)
		if trimmed != "" {
			trimmedPrefixes = append(trimmedPrefixes, trimmed)
		}
	}

	healthCheckURL := os.Getenv("HEALTH_CHECK_URL")
	if healthCheckURL == "" {
		return nil, fmt.Errorf("HEALTH_CHECK_URL is required")
	}

	// Optional fields with defaults
	healthCheckInterval := getEnvInt("HEALTH_CHECK_INTERVAL", defaultHealthCheckInterval)
	successThreshold := getEnvInt("SUCCESS_THRESHOLD", defaultSuccessThreshold)
	failureThreshold := getEnvInt("FAILURE_THRESHOLD", defaultFailureThreshold)
	localPort := getEnvInt("LOCAL_PORT", defaultBGPPort)
	peerPort := getEnvInt("PEER_PORT", defaultBGPPort)
	localAddress := os.Getenv("LOCAL_ADDRESS") // Optional, defaults to wildcard if not set

	cfg := &Config{
		LocalASN:            uint32(localASN),
		RouterID:            routerID,
		LocalPort:           localPort,
		LocalAddress:        localAddress,
		PeerIP:              peerIP,
		PeerPort:            peerPort,
		PeerASN:             uint32(peerASN),
		NextHopIPv4:         nextHopIPv4,
		NextHopIPv6:         nextHopIPv6,
		PrefixesToAnnounce:  trimmedPrefixes,
		HealthCheckURL:      healthCheckURL,
		HealthCheckInterval: healthCheckInterval,
		SuccessThreshold:    successThreshold,
		FailureThreshold:    failureThreshold,
	}

	// Validate the complete configuration
	if err := cfg.validate(); err != nil {
		return nil, err
	}

	return cfg, nil
}

// getEnvInt gets an environment variable as int with a default value
func getEnvInt(key string, defaultVal int) int {
	if value, exists := os.LookupEnv(key); exists {
		if intVal, err := strconv.Atoi(value); err == nil {
			return intVal
		}
		log.Warnf("Invalid value for %s, using default: %d", key, defaultVal)
	}
	return defaultVal
}

// BGPServer represents the BGP server instance
type BGPServer struct {
	s            *server.BgpServer
	config       *Config
	announcedSet map[string]bool
}

// NewBGPServer creates and configures a new BGP server instance
func NewBGPServer(cfg *Config) (*BGPServer, error) {
	s := server.NewBgpServer()
	go s.Serve()

	ctx, cancel := context.WithTimeout(context.Background(), bgpTimeout)
	defer cancel()

	global := &api.Global{
		Asn:        cfg.LocalASN,
		RouterId:   cfg.RouterID,
		ListenPort: int32(cfg.LocalPort),
	}
	
	if cfg.LocalAddress != "" {
		global.ListenAddresses = []string{cfg.LocalAddress}
	}

	if err := s.StartBgp(ctx, &api.StartBgpRequest{
		Global: global,
	}); err != nil {
		return nil, fmt.Errorf("failed to start BGP server: %v", err)
	}

	// Configure IPv4 and IPv6 families
	families := []api.Family{
		{Afi: api.Family_AFI_IP, Safi: api.Family_SAFI_UNICAST},
		{Afi: api.Family_AFI_IP6, Safi: api.Family_SAFI_UNICAST},
	}

	if err := s.AddPeer(ctx, &api.AddPeerRequest{
		Peer: &api.Peer{
			Conf: &api.PeerConf{
				NeighborAddress: cfg.PeerIP,
				PeerAsn:         cfg.PeerASN,
				LocalAsn:        cfg.LocalASN,
			},
			Transport: &api.Transport{
				PassiveMode: false,
				RemotePort: uint32(cfg.PeerPort),
				LocalPort:  uint32(cfg.LocalPort),
			},
			AfiSafis: func() []*api.AfiSafi {
				afiSafis := make([]*api.AfiSafi, 0, len(families))
				for _, f := range families {
					afiSafis = append(afiSafis, &api.AfiSafi{
						Config: &api.AfiSafiConfig{
							Family:  &f,
							Enabled: true,
						},
					})
				}
				return afiSafis
			}(),
		},
	}); err != nil {
		return nil, fmt.Errorf("failed to add peer: %v", err)
	}

	log.Infof("BGP server started (AS%d, Router ID: %s, Port: %d)", cfg.LocalASN, cfg.RouterID, cfg.LocalPort)
	if cfg.LocalAddress != "" {
		log.Infof("BGP server bound to address: %s", cfg.LocalAddress)
	}
	log.Infof("Configured peer: %s:%d (AS%d)", cfg.PeerIP, cfg.PeerPort, cfg.PeerASN)

	return &BGPServer{
		s:            s,
		config:       cfg,
		announcedSet: make(map[string]bool),
	}, nil
}

// AnnouncePrefixes announces all configured prefixes
func (s *BGPServer) AnnouncePrefixes(ctx context.Context) error {
	var announcedCount int
	var errors []string

	for _, prefixStr := range s.config.PrefixesToAnnounce {
		if s.announcedSet[prefixStr] {
			continue // Already announced
		}

		ip, prefix, err := net.ParseCIDR(prefixStr)
		if err != nil {
			errors = append(errors, fmt.Sprintf("invalid prefix format '%s': %v", prefixStr, err))
			continue
		}

		prefixLen, _ := prefix.Mask.Size()

		// Determine address family and next-hop
		family := &api.Family{
			Afi:  api.Family_AFI_IP,
			Safi: api.Family_SAFI_UNICAST,
		}
		var nextHop string
		if ip.To4() == nil {
			family.Afi = api.Family_AFI_IP6
			nextHop = s.config.NextHopIPv6
		} else {
			nextHop = s.config.NextHopIPv4
		}

		// Validate that we have a next-hop for this address family
		if nextHop == "" {
			if family.Afi == api.Family_AFI_IP {
				errors = append(errors, fmt.Sprintf("NEXT_HOP_IPV4 is required for IPv4 prefix '%s'", prefixStr))
			} else {
				errors = append(errors, fmt.Sprintf("NEXT_HOP_IPV6 is required for IPv6 prefix '%s'", prefixStr))
			}
			continue
		}

		nlri, _ := anypb.New(&api.IPAddressPrefix{
			Prefix:    prefix.IP.String(),
			PrefixLen: uint32(prefixLen),
		})

		// Create path attributes
		attrs := []*anypb.Any{}

		originAttr, _ := anypb.New(&api.OriginAttribute{
			Origin: originIGP,
		})
		attrs = append(attrs, originAttr)

		asPathAttr, _ := anypb.New(&api.AsPathAttribute{
			Segments: []*api.AsSegment{
				{
					Type:    asPathType,
					Numbers: []uint32{s.config.LocalASN},
				},
			},
		})
		attrs = append(attrs, asPathAttr)

		nextHopAttr, _ := anypb.New(&api.NextHopAttribute{
			NextHop: nextHop,
		})
		attrs = append(attrs, nextHopAttr)

		medAttr, _ := anypb.New(&api.MultiExitDiscAttribute{
			Med: medValue,
		})
		attrs = append(attrs, medAttr)

		_, err = s.s.AddPath(ctx, &api.AddPathRequest{
			TableType: api.TableType_GLOBAL,
			Path: &api.Path{
				Family: family,
				Nlri:   nlri,
				Pattrs: attrs,
			},
		})

		if err != nil {
			errors = append(errors, fmt.Sprintf("failed to announce prefix '%s': %v", prefixStr, err))
			continue
		}

		s.announcedSet[prefixStr] = true
		announcedCount++
		log.WithFields(log.Fields{
			"prefix":   prefixStr,
			"next-hop": nextHop,
		}).Info("Announced prefix")
	}

	if len(errors) > 0 {
		return fmt.Errorf("some prefixes failed to announce: %s", strings.Join(errors, "; "))
	}

	if announcedCount > 0 {
		log.WithField("count", announcedCount).Info("Successfully announced prefixes")
	}
	return nil
}

// WithdrawPrefixes withdraws all configured prefixes
func (s *BGPServer) WithdrawPrefixes(ctx context.Context) error {
	var withdrawnCount int
	var errors []string

	for _, prefixStr := range s.config.PrefixesToAnnounce {
		if !s.announcedSet[prefixStr] {
			continue // Not announced
		}

		ip, prefix, err := net.ParseCIDR(prefixStr)
		if err != nil {
			errors = append(errors, fmt.Sprintf("invalid prefix format '%s': %v", prefixStr, err))
			continue
		}

		prefixLen, _ := prefix.Mask.Size()

		// Determine address family and next-hop
		family := &api.Family{
			Afi:  api.Family_AFI_IP,
			Safi: api.Family_SAFI_UNICAST,
		}
		var nextHop string
		if ip.To4() == nil {
			family.Afi = api.Family_AFI_IP6
			nextHop = s.config.NextHopIPv6
		} else {
			nextHop = s.config.NextHopIPv4
		}

		// Validate that we have a next-hop for this address family
		if nextHop == "" {
			if family.Afi == api.Family_AFI_IP {
				errors = append(errors, fmt.Sprintf("NEXT_HOP_IPV4 is required for IPv4 prefix '%s'", prefixStr))
			} else {
				errors = append(errors, fmt.Sprintf("NEXT_HOP_IPV6 is required for IPv6 prefix '%s'", prefixStr))
			}
			continue
		}

		nlri, _ := anypb.New(&api.IPAddressPrefix{
			Prefix:    prefix.IP.String(),
			PrefixLen: uint32(prefixLen),
		})

		// Create path attributes (must match announcement)
		attrs := []*anypb.Any{}

		originAttr, _ := anypb.New(&api.OriginAttribute{
			Origin: originIGP,
		})
		attrs = append(attrs, originAttr)

		asPathAttr, _ := anypb.New(&api.AsPathAttribute{
			Segments: []*api.AsSegment{
				{
					Type:    asPathType,
					Numbers: []uint32{s.config.LocalASN},
				},
			},
		})
		attrs = append(attrs, asPathAttr)

		nextHopAttr, _ := anypb.New(&api.NextHopAttribute{
			NextHop: nextHop,
		})
		attrs = append(attrs, nextHopAttr)

		err = s.s.DeletePath(ctx, &api.DeletePathRequest{
			TableType: api.TableType_GLOBAL,
			Path: &api.Path{
				Family: family,
				Nlri:   nlri,
				Pattrs: attrs,
			},
		})

		if err != nil {
			errors = append(errors, fmt.Sprintf("failed to withdraw prefix '%s': %v", prefixStr, err))
			continue
		}

		delete(s.announcedSet, prefixStr)
		withdrawnCount++
		log.WithFields(log.Fields{
			"prefix": prefixStr,
		}).Info("Withdrawn prefix")
	}

	if len(errors) > 0 {
		return fmt.Errorf("some prefixes failed to withdraw: %s", strings.Join(errors, "; "))
	}

	if withdrawnCount > 0 {
		log.WithField("count", withdrawnCount).Info("Successfully withdrawn prefixes")
	}
	return nil
}

// Stop gracefully stops the BGP server
func (s *BGPServer) Stop() error {
	ctx, cancel := context.WithTimeout(context.Background(), bgpTimeout)
	defer cancel()

	if err := s.s.StopBgp(ctx, &api.StopBgpRequest{}); err != nil {
		return fmt.Errorf("failed to stop BGP server: %v", err)
	}
	log.Info("BGP server stopped")
	return nil
}

// HealthChecker performs periodic health checks
type HealthChecker struct {
	client            *http.Client
	config            *Config
	handler           func(bool) error
	successCount      int
	failureCount      int
	lastCheckSucceeded bool
}

// NewHealthChecker creates a new health checker instance
func NewHealthChecker(cfg *Config, handler func(bool) error) *HealthChecker {
	return &HealthChecker{
		client: &http.Client{
			Timeout: healthCheckTimeout,
		},
		config:  cfg,
		handler: handler,
	}
}

// Start begins the periodic health checking
func (c *HealthChecker) Start(ctx context.Context) error {
	log.WithFields(log.Fields{
		"url":      c.config.HealthCheckURL,
		"interval": c.config.HealthCheckInterval,
	}).Info("Starting health checker")

	ticker := time.NewTicker(time.Duration(c.config.HealthCheckInterval) * time.Second)
	defer ticker.Stop()

	// Perform initial health check
	if err := c.check(ctx); err != nil {
		log.WithError(err).Warn("Initial health check failed")
	}

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if err := c.check(ctx); err != nil {
				log.WithError(err).Debug("Health check failed")
			}
		}
	}
}

func (c *HealthChecker) check(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, "GET", c.config.HealthCheckURL, nil)
	if err != nil {
		return c.handleHealthStatus(false, fmt.Errorf("failed to create request: %v", err))
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return c.handleHealthStatus(false, fmt.Errorf("health check request failed: %v", err))
	}
	defer resp.Body.Close()

	healthy := resp.StatusCode == http.StatusOK
	var checkErr error
	if !healthy {
		checkErr = fmt.Errorf("health check returned non-200 status: %d", resp.StatusCode)
	}
	return c.handleHealthStatus(healthy, checkErr)
}

func (c *HealthChecker) handleHealthStatus(healthy bool, checkErr error) error {
	if healthy {
		c.successCount++
		c.failureCount = 0
		log.WithFields(log.Fields{
			"success_count": c.successCount,
			"threshold":     c.config.SuccessThreshold,
		}).Debug("Health check succeeded")
	} else {
		c.failureCount++
		c.successCount = 0
		log.WithFields(log.Fields{
			"failure_count": c.failureCount,
			"threshold":     c.config.FailureThreshold,
		}).Debug("Health check failed")
	}

	// Handle state changes
	if healthy && c.successCount >= c.config.SuccessThreshold && !c.lastCheckSucceeded {
		if err := c.handler(true); err != nil {
			log.WithError(err).Error("Failed to handle health check success")
		}
		c.lastCheckSucceeded = true
	}

	if !healthy && c.failureCount >= c.config.FailureThreshold && c.lastCheckSucceeded {
		if err := c.handler(false); err != nil {
			log.WithError(err).Error("Failed to handle health check failure")
		}
		c.lastCheckSucceeded = false
	}

	return checkErr
}

func main() {
	log.SetFormatter(&log.TextFormatter{
		FullTimestamp:   true,
		TimestampFormat: "2006-01-02T15:04:05.000Z07:00",
	})

	logLevel := os.Getenv("LOG_LEVEL")
	if logLevel != "" {
		level, err := log.ParseLevel(logLevel)
		if err != nil {
			log.Warnf("Invalid LOG_LEVEL '%s', defaulting to 'info'", logLevel)
		} else {
			log.SetLevel(level)
		}
	}

	log.Infof("Starting EgoBGP version %s", Version)

	// Load configuration
	cfg, err := LoadConfig()
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// Create context with cancellation
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Set up signal handling
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Create and start BGP server
	server, err := NewBGPServer(cfg)
	if err != nil {
		log.Fatalf("Failed to create BGP server: %v", err)
	}

	// Create health checker
	checker := NewHealthChecker(cfg, func(healthy bool) error {
		if healthy {
			return server.AnnouncePrefixes(ctx)
		}
		return server.WithdrawPrefixes(ctx)
	})

	// Start health checker in a goroutine
	go func() {
		if err := checker.Start(ctx); err != nil {
			log.WithError(err).Error("Health checker error")
			cancel()
		}
	}()

	sig := <-sigChan
	log.Infof("Received signal %v, shutting down...", sig)

	if err := server.Stop(); err != nil {
		log.WithError(err).Error("Error stopping BGP server")
		os.Exit(1)
	}

	os.Exit(0)
} 