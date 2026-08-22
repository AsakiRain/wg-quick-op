package dns

import (
	"context"
	"errors"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"github.com/dn-11/wg-quick-op/conf"
	"github.com/dn-11/wg-quick-op/utils"
	"github.com/miekg/dns"
	"github.com/rs/zerolog/log"
	"golang.org/x/time/rate"
)

var globalRateLimiter = rate.NewLimiter(rate.Every(time.Millisecond*20), 1)

type dnsQueryResult struct {
	queryType uint16
	msg       *dns.Msg
}

type dnsRcodeError struct {
	domain    string
	queryType uint16
	server    netip.AddrPort
	rcode     int
}

func (e *dnsRcodeError) Error() string {
	name := dns.RcodeToString[e.rcode]
	if name == "" {
		name = strconv.Itoa(e.rcode)
	}
	return "DNS query " + e.domain + " type " + dnsTypeName(e.queryType) + " from " + e.server.String() + " returned " + name
}

func dnsTypeName(queryType uint16) string {
	if name, ok := dns.TypeToString[queryType]; ok {
		return name
	}
	return strconv.Itoa(int(queryType))
}

func addrPortStrings(addrs []netip.AddrPort) []string {
	result := make([]string, 0, len(addrs))
	for _, addr := range addrs {
		result = append(result, addr.String())
	}
	return result
}

func rrStrings(records []dns.RR) []string {
	result := make([]string, 0, len(records))
	for _, record := range records {
		result = append(result, record.String())
	}
	return result
}

// queryWithRetry 向单个 DNS 服务器发送一次查询，并在传输失败时重试。
//
// ctx 控制限速等待和 DNS 请求的取消；domain 和 qType 指定 DNS 问题；
// server 必须是包含端口的 DNS 服务器地址。函数返回解析后的 DNS 响应，
// 或返回发送 DNS 请求失败、context 错误以及由 DNS 响应码转换而来的 dnsRcodeError。
// 同一服务器最多尝试 3 次，只有限速等待失败或 QueryDNS 失败会触发重试；
// DNS 服务器已经返回的 NXDOMAIN、SERVFAIL 等响应不会在此处重复请求。
func queryWithRetry(ctx context.Context, domain string, qType uint16, server netip.AddrPort) (*dns.Msg, error) {
	// 请求报文可以在重试间复用，因为 QueryDNS 不会改变问题部分。
	msg := new(dns.Msg)
	msg.SetQuestion(domain, qType)
	var rec *dns.Msg
	var responseErr error
	attempt := 0

	// 最多执行 3 次尝试，首次出错等待 50ms 后重试，后续等待时间翻倍
	err := <-utils.GoRetryCtx(ctx, 3, 50*time.Millisecond, func(ctx context.Context) (err error) {
		attempt++
		if err := globalRateLimiter.Wait(ctx); err != nil { // ctx 被取消，等待立刻失败返回
			return err
		}

		var rtt time.Duration
		rec, rtt, err = defaultDNSClient.QueryDNS(ctx, msg, server.String())
		if err != nil { // 发送 DNS 请求失败，交给 GoRetryCtx 重试。
			log.Warn().Str("domain", domain).Err(err).Str("server", server.String()).Msg("DNS lookup failed")
			return err
		}

		log.Trace().
			Str("domain", domain).
			Str("query_type", dnsTypeName(qType)).
			Str("server", server.String()).
			Int("attempt", attempt).
			Dur("rtt", rtt).
			Str("rcode", dns.RcodeToString[rec.Rcode]).
			Bool("truncated", rec.Truncated).
			Strs("answer", rrStrings(rec.Answer)).
			Strs("authority", rrStrings(rec.Ns)).
			Strs("additional", rrStrings(rec.Extra)).
			Msg("DNS query response")

		if rec.Rcode != dns.RcodeSuccess { // DNS 服务器返回了非成功响应码（例如 NXDOMAIN），封装为 dnsRcodeError，并不再重试
			responseErr = &dnsRcodeError{domain: domain, queryType: qType, server: server, rcode: rec.Rcode}
			log.Warn().Err(responseErr).Msg("DNS server returned failure response")
		}
		return nil // 正常完成DNS请求，不再重试
	})
	if err != nil { // GoRetryCtx 超过重试次数仍然失败，返回最后一次的错误。
		return nil, err
	}
	if responseErr != nil { // DNS 请求成功，但服务器返回非成功响应码，返回封装的 dnsRcodeError。
		return nil, responseErr
	}
	return rec, nil // 返回成功的 DNS 响应
}

// queryWithRetryWithList 按顺序尝试 dnsList 中的 DNS 服务器。
// 每个服务器内部由 queryWithRetry 负责传输失败重试；普通错误会继续尝试下一个服务器，
func queryWithRetryWithList(ctx context.Context, domain string, qType uint16, dnsList []netip.AddrPort) (*dns.Msg, error) {
	for _, s := range dnsList {
		msg, err := queryWithRetry(ctx, domain, qType, s)
		if err != nil {
			if errors.Is(err, context.Canceled) { // 对于上下文取消，立即返回，不再尝试其他服务器
				log.Trace().Err(err).Str("domain", domain).Str("query_type", dnsTypeName(qType)).Str("server", s.String()).Msg("DNS query canceled; stop server iteration")
				return nil, err
			}
			var rcodeErr *dnsRcodeError
			if errors.As(err, &rcodeErr) && rcodeErr.rcode == dns.RcodeNameError { // 对于 NXDomain 终止服务器遍历查询
				log.Trace().Err(err).Str("domain", domain).Str("query_type", dnsTypeName(qType)).Str("server", s.String()).Msg("Response NXDOMAIN; stop server iteration")
				return nil, err
			}
			log.Debug().Err(err).Str("domain", domain).Str("server", s.String()).Msg("Failed to resolve")
			continue
		}
		return msg, nil
	}
	return nil, errors.New("Failed to resolve with all server")
}

func queryAAndAAAAAddrIter(domain string, dnsList []netip.AddrPort) func(yield func(addr netip.Addr) bool) {
	queryTypes := []uint16{dns.TypeA}
	if !conf.EnhancedDNS.DirectResolver.IPv4Only {
		queryTypes = append(queryTypes, dns.TypeAAAA)
	}
	return queryAddrIter(domain, dnsList, queryTypes...)
}

// queryAddrIter 并发查询指定的 DNS 记录类型，并按响应到达顺序产出可用 IP 地址。
// 调用方通过 yield 返回 false 可以停止消费；停止后会取消其他仍在进行的查询。
func queryAddrIter(domain string, dnsList []netip.AddrPort, queryTypes ...uint16) func(yield func(addr netip.Addr) bool) {
	return func(yield func(addr netip.Addr) bool) {
		var (
			wg         sync.WaitGroup
			resultChan = make(chan dnsQueryResult, len(queryTypes))
		)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		for _, queryType := range queryTypes {
			wg.Go(func() {
				rec, err := queryWithRetryWithList(ctx, domain, queryType, dnsList)
				if err != nil {
					if !errors.Is(err, context.Canceled) {
						log.Error().Err(err).Str("domain", domain).Str("query_type", dnsTypeName(queryType)).Strs("servers", addrPortStrings(dnsList)).Msg("DNS query failed")
					}
					return
				}
				select {
				case resultChan <- dnsQueryResult{queryType: queryType, msg: rec}:
				case <-ctx.Done():
				}
			})
		}
		go func() {
			wg.Wait()
			close(resultChan)
		}()

		responseCount := 0
		addressCount := 0
		for result := range resultChan {
			log.Trace().
				Str("domain", domain).
				Str("query_type", dnsTypeName(result.queryType)).
				Int("answer_count", len(result.msg.Answer)).
				Msg("DNS address iterator processing completed response")

			responseCount++
			for _, rr := range result.msg.Answer {
				switch rr := rr.(type) {
				case *dns.A:
					addr, ok := netip.AddrFromSlice(rr.A)
					if !ok {
						log.Warn().Str("rr", rr.String()).Msgf("Cannot convert dns response to netip")
						continue
					}
					addressCount++
					log.Trace().Str("domain", domain).Str("query_type", "A").Str("addr", addr.String()).Msg("DNS address iterator yield")
					if !yield(addr) {
						log.Trace().Str("domain", domain).Str("addr", addr.String()).Msg("DNS address iterator stopped by consumer")
						return
					}
				case *dns.AAAA:
					addr, ok := netip.AddrFromSlice(rr.AAAA)
					if !ok {
						log.Warn().Str("rr", rr.String()).Msgf("Cannot convert dns response to netip")
						continue
					}
					addressCount++
					log.Trace().Str("domain", domain).Str("query_type", "AAAA").Str("addr", addr.String()).Msg("DNS address iterator yield")
					if !yield(addr) {
						log.Trace().Str("domain", domain).Str("addr", addr.String()).Msg("DNS address iterator stopped by consumer")
						return
					}
				}
			}
		}
		log.Trace().
			Str("domain", domain).
			Int("response_count", responseCount).
			Int("address_count", addressCount).
			Msg("DNS address iterator completed")
	}
}
