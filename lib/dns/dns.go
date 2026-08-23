package dns

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/dn-11/wg-quick-op/conf"
	"github.com/miekg/dns"
	"github.com/rs/zerolog/log"
)

var (
	publicDNS          []netip.AddrPort
	defaultDNSClient   dnsQueryClient = dnsClientAdapter{client: &dns.Client{Timeout: 500 * time.Millisecond}}
	ResolveUDPAddrImpl                = net.ResolveUDPAddr
)

// dnsQueryClient 是 DNS resolver 发送查询并接收响应所需的最小接口。
// 生产环境由 dnsClientAdapter 调用 miekg/dns.Client，测试时替换为 fake client，
// 以便控制响应、错误、延迟和查询顺序。
type dnsQueryClient interface {
	QueryDNS(context.Context, *dns.Msg, string) (*dns.Msg, time.Duration, error)
}

type dnsClientAdapter struct {
	client *dns.Client
}

func (c dnsClientAdapter) QueryDNS(ctx context.Context, msg *dns.Msg, server string) (*dns.Msg, time.Duration, error) {
	return c.client.ExchangeContext(ctx, msg, server)
}

func Init() {
	if !conf.EnhancedDNS.DirectResolver.Enabled {
		log.Trace().Msg("Direct DNS resolver disabled")
		return
	}

	publicDNS = nil

	// 1. load from config
	for _, server := range conf.EnhancedDNS.DirectResolver.ROAFinder {
		if addrPort, ok := parseDNSServer(server, "53", "ROAFinder config"); ok {
			publicDNS = append(publicDNS, addrPort)
		}
	}

	// 2. load from /etc/resolv.conf
	if len(publicDNS) == 0 {
		log.Debug().Msg("No available DNS servers from config, try to query /etc/resolv.conf")
		config, err := dns.ClientConfigFromFile("/etc/resolv.conf")
		if err != nil {
			log.Err(err).Msg("Failed to load config from /etc/resolv.conf")
		} else {
			for _, server := range config.Servers {
				if addrPort, ok := parseDNSServer(server, "53", "/etc/resolv.conf"); ok {
					publicDNS = append(publicDNS, addrPort)
				}
			}
		}
	}

	// 3. fallback default dns server
	if len(publicDNS) == 0 {
		log.Warn().Msg("No available DNS servers from config, use default DNS servers")
		publicDNS = []netip.AddrPort{
			netip.MustParseAddrPort("223.5.5.5:53"),
			netip.MustParseAddrPort("119.29.29.29:53"),
		}
	}

	ResolveUDPAddrImpl = ResolveUDPAddrDirect
	log.Trace().
		Strs("public_dns", addrPortStrings(publicDNS)).
		Bool("ipv4_only", conf.EnhancedDNS.DirectResolver.IPv4Only).
		Msg("direct DNS resolver initialized")
}

// parseDNSServer 将不同来源的 DNS 地址统一补全为 AddrPort，并执行地址过滤。
// 配置项允许显式指定端口，系统 resolv.conf 通常只提供主机地址。
func parseDNSServer(server, defaultPort, source string) (netip.AddrPort, bool) {
	address := server
	if _, _, err := net.SplitHostPort(address); err != nil {
		address = net.JoinHostPort(server, defaultPort)
	}

	addrPort, err := netip.ParseAddrPort(address)
	if err != nil {
		log.Error().Err(err).Str("addr", server).Str("source", source).Msg("Cannot parse DNS server address")
		return netip.AddrPort{}, false
	}
	if conf.EnhancedDNS.DirectResolver.IPv4Only && addrPort.Addr().Is6() {
		log.Debug().Str("addr", address).Str("source", source).Msg("Skip IPv6 resolver in ipv4_only mode")
		return netip.AddrPort{}, false
	}
	return addrPort, true
}

// 接受域名/IP + 端口，返回 UDPAddr
func ResolveUDPAddrDirect(_ string, addr string) (*net.UDPAddr, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("Split host port failed: %w", err)
	}

	numPort, err := strconv.Atoi(port)
	if err != nil {
		return nil, fmt.Errorf("Parse port failed: %w", err)
	}

	// 字面量 IP 不需要 DNS；域名交给独立的域名解析流程。
	ip, err := netip.ParseAddr(host)
	if err == nil {
		log.Trace().Str("host", host).Msg("Input hostname is already an IP address, skipping DNS resolution")
	} else {
		ip, err = resolveDomainDirect(host)
		if err != nil {
			return nil, fmt.Errorf("Resolve host direct failed: %w", err)
		}
	}

	return &net.UDPAddr{IP: net.IP(ip.AsSlice()).To16(), Port: numPort}, nil
}

// 只接受不带端口的域名输入，返回 netip.Addr
func resolveDomainDirect(host string) (netip.Addr, error) {
	maxCnameDepth := conf.EnhancedDNS.DirectResolver.MaxCnameDepth
	if maxCnameDepth <= 0 {
		log.Warn().Int("max_cname_depth", maxCnameDepth).Msg("Invalid MaxCnameDepth, using default value 5")
		maxCnameDepth = 5
	}
	requestedDomain := dns.Fqdn(host)
	domain, err := unfoldCNAME(requestedDomain, maxCnameDepth)
	if err != nil {
		return netip.Addr{}, err
	}
	if resolved := resolveFromAuthoritativeServers(domain); resolved.IsValid() {
		log.Info().Str("domain", requestedDomain).Str("resolved_ip", resolved.String()).Str("source", "authoritative").Msg("DNS resolution succeeded")
		return resolved, nil
	}

	log.Debug().Str("domain", domain).Strs("resolvers", addrPortStrings(publicDNS)).Msg("Authoritative resolution unavailable; using public DNS")
	for resolved := range queryAAndAAAAAddrIter(domain, publicDNS) {
		log.Info().Str("domain", requestedDomain).Str("resolved_ip", resolved.String()).Str("source", "public_fallback").Msg("DNS resolution succeeded")
		return resolved, nil
	}
	return netip.Addr{}, errors.New("no address found")
}

func resolveFromAuthoritativeServers(domain string) netip.Addr {
	nsIter := nsAddrIter(domain)
	if nsIter == nil {
		log.Trace().Str("domain", domain).Msg("authoritative NS discovery failed; public resolver fallback required")
		return netip.Addr{}
	}

	nsIndex := 0
	for ns := range nsIter {
		for resolved := range queryAAndAAAAAddrIter(domain, []netip.AddrPort{netip.AddrPortFrom(ns, 53)}) {
			return resolved
		}
		log.Debug().Str("domain", domain).Str("nameserver_addr", ns.String()).Int("nameserver_addr_index", nsIndex).Msg("Authoritative nameserver returned no usable address")
		nsIndex++
	}
	return netip.Addr{}
}

func unfoldCNAME(domain string, depth int) (string, error) {
	if depth == 0 {
		return "", errors.New("CNAME is too deep")
	}
	rec, err := queryWithRetryWithList(context.Background(), domain, dns.TypeA, publicDNS)
	if err != nil {
		return "", err
	}
	for _, ans := range rec.Answer {
		if ans.Header().Rrtype == dns.TypeCNAME {
			target := ans.(*dns.CNAME).Target
			log.Trace().Str("domain", domain).Str("cname_target", target).Int("remaining_depth", depth).Msg("CNAME record followed")
			return unfoldCNAME(target, depth-1)
		}
	}
	return domain, nil
}

// 找到负责该域名解析的权威 NS，并逐个找出这些 NS 的 IP 地址
func nsAddrIter(domain string) func(yield func(addr netip.Addr) bool) {
	var nsRec *dns.Msg
	requestedDomain := domain

	// 第一阶段：找到 NS 记录
DomainTrim:
	for domain != "" {
		rec, err := queryWithRetryWithList(context.Background(), domain, dns.TypeNS, publicDNS)
		if err != nil {
			log.Trace().Str("requested_domain", requestedDomain).Str("query_domain", domain).Err(err).Msg("Authoritative NS discovery query failed")
			return nil
		}

		// SOA 的名称指示当前所属 zone 的顶点，直接跳到该名称继续查询 NS
		for _, rr := range rec.Ns {
			soaRR, ok := rr.(*dns.SOA)
			if ok && len(soaRR.Hdr.Name) < len(domain) { // 启发式判断：SOA 名称更短时，将其视为当前域名所属的上级 zone
				log.Trace().Str("requested_domain", requestedDomain).Str("from_domain", domain).Str("to_domain", soaRR.Hdr.Name).Msg("Authoritative NS discovery follows SOA authority")
				domain = soaRR.Hdr.Name
				continue DomainTrim
			}
		}

		// 如果当前查询名称存在 NS 记录，就结束查找
		for _, rr := range rec.Answer {
			if rr.Header().Rrtype == dns.TypeNS {
				nsRec = rec
				break DomainTrim
			}
		}

		// 如果没有可用于跳转到上级 zone 的 SOA，且 Answer 中没有 NS，则逐级查询父域名
		_, after, found := strings.Cut(domain, ".")
		if !found {
			log.Trace().Str("requested_domain", requestedDomain).Str("from_domain", domain).Msg("Authoritative NS discovery cannot find NS server")
			return nil
		}

		log.Trace().Str("requested_domain", requestedDomain).Str("from_domain", domain).Str("to_domain", after).Msg("Authoritative NS discovery trims domain label")
		domain = after
	}

	if domain == "" { // 已逐级查询到根域名，仍然没有找到 NS。
		return nil
	}

	// 第二阶段：对找到的 NS 记录进行 IP 地址解析
	rand.Shuffle(len(nsRec.Answer), func(i, j int) {
		nsRec.Answer[i], nsRec.Answer[j] = nsRec.Answer[j], nsRec.Answer[i]
	})

	return func(yield func(addr netip.Addr) bool) {
		for nsIndex, rr := range nsRec.Answer {
			ns, ok := rr.(*dns.NS)
			if !ok {
				log.Warn().Str("name", rr.Header().Name).Msgf("%s is not a NS Record", rr.Header().Name)
				continue
			}
			log.Trace().Str("requested_domain", requestedDomain).Str("nameserver", ns.Ns).Int("nameserver_index", nsIndex).Msg("Authoritative NS selected")

			// 先处理 Extra 中随响应附带的 NS 地址，再通过公共 DNS 补查缺失的地址族
			seen := make(map[netip.Addr]struct{}) // 对当前 NS 的地址去重，避免重复产出同一个 IP
			var hasA, hasAAAA bool

			for _, rr := range nsRec.Extra {
				if rr.Header().Name != ns.Ns {
					continue
				}
				switch rr := rr.(type) {
				case *dns.A:
					addr, ok := netip.AddrFromSlice(rr.A)
					if !ok {
						log.Warn().Str("rr", rr.String()).Msgf("Cannot convert dns response to netip")
						continue
					}
					if _, ok := seen[addr]; ok {
						continue
					}
					hasA = true
					seen[addr] = struct{}{}

					if !yield(addr) { // 消费者不需要更多地址了，停止迭代
						return
					}
				case *dns.AAAA:
					if conf.EnhancedDNS.DirectResolver.IPv4Only { // 如果配置了 IPv4Only，则忽略 AAAA 记录
						continue
					}
					addr, ok := netip.AddrFromSlice(rr.AAAA)
					if !ok {
						log.Warn().Str("rr", rr.String()).Msgf("Cannot convert dns response to netip")
						continue
					}
					if _, ok := seen[addr]; ok {
						continue
					}
					hasAAAA = true
					seen[addr] = struct{}{}

					if !yield(addr) {
						return
					}
				}
			}

			if hasA && (hasAAAA || conf.EnhancedDNS.DirectResolver.IPv4Only) {
				// Extra 已覆盖当前配置启用的全部地址族，无需再用公共 DNS 解析 NS 主机名
				continue
			}

			missingTypes := make([]uint16, 0, 2)
			if !hasA {
				missingTypes = append(missingTypes, dns.TypeA)
			}
			if !hasAAAA && !conf.EnhancedDNS.DirectResolver.IPv4Only {
				missingTypes = append(missingTypes, dns.TypeAAAA)
			}
			queryTypeNames := make([]string, 0, len(missingTypes))
			for _, queryType := range missingTypes {
				queryTypeNames = append(queryTypeNames, dnsTypeName(queryType))
			}
			log.Trace().Str("requested_domain", requestedDomain).Str("nameserver", ns.Ns).Strs("query_types", queryTypeNames).Msg("Resolving nameserver address")

			// 通过公共 DNS 解析 NS 的主机名，获取缺失的地址族
			for addr := range queryAddrIter(ns.Ns, publicDNS, missingTypes...) {
				if (addr.Is4() && hasA) || (addr.Is6() && (hasAAAA || conf.EnhancedDNS.DirectResolver.IPv4Only)) {
					continue // Extra 已经提供该地址族时跳过，避免重复补充
				}
				if _, ok := seen[addr]; ok { // 已经处理过该地址，跳过
					continue
				}

				seen[addr] = struct{}{}
				if !yield(addr) {
					return
				}
			}
		}
	}
}
