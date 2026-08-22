package dns

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dn-11/wg-quick-op/conf"
	miekgdns "github.com/miekg/dns"
	"golang.org/x/time/rate"
)

type dnsQueryKey struct {
	server    string
	domain    string
	queryType uint16
}

type fakeDNSResult struct {
	msg   *miekgdns.Msg
	err   error
	delay time.Duration
}

type fakeDNSClient struct {
	mu        sync.Mutex
	responses map[dnsQueryKey]fakeDNSResult
	calls     []dnsQueryKey
}

// 实现 fakeDNSClient 的 QueryDNS 方法，该方法从实例化时传入的 responses map 中返回预设的 DNS 响应，并记录查询调用的参数到 calls 切片中
func (f *fakeDNSClient) QueryDNS(ctx context.Context, msg *miekgdns.Msg, server string) (*miekgdns.Msg, time.Duration, error) {
	question := msg.Question[0]
	key := dnsQueryKey{server: server, domain: question.Name, queryType: question.Qtype}
	f.mu.Lock()
	f.calls = append(f.calls, key)
	result, ok := f.responses[key]
	f.mu.Unlock()
	if !ok {
		return nil, 0, errors.New("unexpected DNS query")
	}

	timer := time.NewTimer(result.delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return nil, 0, ctx.Err()
	case <-timer.C:
	}
	if result.err != nil {
		return nil, result.delay, result.err
	}
	return result.msg.Copy(), result.delay, nil
}

// 工具函数，插桩替换全局 DNS 依赖、关闭限速并重置 IPv4-only，测试结束后恢复原值
func useFakeDNS(t *testing.T, responses map[dnsQueryKey]fakeDNSResult) *fakeDNSClient {
	t.Helper()
	oldClient := defaultDNSClient
	oldPublicDNS := publicDNS
	oldIPv4Only := conf.EnhancedDNS.DirectResolver.IPv4Only
	oldRateLimiter := globalRateLimiter
	fake := &fakeDNSClient{responses: responses}
	defaultDNSClient = fake
	publicDNS = []netip.AddrPort{netip.MustParseAddrPort("192.0.2.53:53")}
	conf.EnhancedDNS.DirectResolver.IPv4Only = false
	globalRateLimiter = rate.NewLimiter(rate.Inf, 1)
	t.Cleanup(func() {
		defaultDNSClient = oldClient
		publicDNS = oldPublicDNS
		conf.EnhancedDNS.DirectResolver.IPv4Only = oldIPv4Only
		globalRateLimiter = oldRateLimiter
	})
	return fake
}

// 工具函数，解析指定的 host:51820，并返回规范化后的 IP 地址
func resolveTestEndpoint(t *testing.T, host string) netip.Addr {
	t.Helper()
	addr, err := ResolveUDPAddrDirect("", net.JoinHostPort(host, "51820"))
	if err != nil {
		t.Fatalf("ResolveUDPAddrDirect returned an error: %v", err)
	}
	resolved, ok := netip.AddrFromSlice(addr.IP)
	if !ok {
		t.Fatalf("ResolveUDPAddrDirect returned invalid IP %v", addr.IP)
	}
	return resolved.Unmap()
}

// 工具函数，构造包含指定问题和 Answer 记录的 NOERROR 响应
func dnsResponse(domain string, queryType uint16, answers ...miekgdns.RR) *miekgdns.Msg {
	request := new(miekgdns.Msg)
	request.SetQuestion(domain, queryType)
	response := new(miekgdns.Msg)
	response.SetReply(request)
	response.Answer = answers
	return response
}

// 工具函数，构造带有指定 RCODE 的 DNS 响应
func dnsErrorResponse(domain string, queryType uint16, rcode int) *miekgdns.Msg {
	response := dnsResponse(domain, queryType)
	response.Rcode = rcode
	return response
}

// 工具函数，构造 A 记录
func aRecord(name, addr string) miekgdns.RR {
	return &miekgdns.A{Hdr: rrHeader(name, miekgdns.TypeA), A: net.ParseIP(addr).To4()}
}

// 工具函数，构造 AAAA 记录
func aaaaRecord(name, addr string) miekgdns.RR {
	return &miekgdns.AAAA{Hdr: rrHeader(name, miekgdns.TypeAAAA), AAAA: net.ParseIP(addr)}
}

// 工具函数，构造 NS 记录
func nsRecord(name, target string) miekgdns.RR {
	return &miekgdns.NS{Hdr: rrHeader(name, miekgdns.TypeNS), Ns: target}
}

// 工具函数，构造测试记录共用的资源记录头
func rrHeader(name string, recordType uint16) miekgdns.RR_Header {
	return miekgdns.RR_Header{Name: name, Rrtype: recordType, Class: miekgdns.ClassINET, Ttl: 60}
}

// 工具函数，将地址迭代器的输出收集为切片
func collectAddresses(iter func(func(netip.Addr) bool)) []netip.Addr {
	var result []netip.Addr
	for addr := range iter {
		result = append(result, addr)
	}
	return result
}

// 工具函数，断言两个地址切片的内容相同且顺序一致
func assertAddresses(t *testing.T, got []netip.Addr, want ...string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("got addresses %v, want %v", got, want)
	}
	for i, addr := range got {
		if addr.String() != want[i] {
			t.Fatalf("got address %s at index %d, want %s", addr, i, want[i])
		}
	}
}

// 工具函数，断言两个地址切片的内容相同但顺序可以不同
func assertAddressSet(t *testing.T, got []netip.Addr, want ...string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("got addresses %v, want %v", got, want)
	}
	gotSet := make(map[string]bool, len(got))
	for _, addr := range got {
		gotSet[addr.String()] = true
	}
	if len(gotSet) != len(want) {
		t.Fatalf("got addresses %v, want %v", got, want)
	}
	for _, addr := range want {
		if !gotSet[addr] {
			t.Fatalf("got addresses %v, missing %s", got, addr)
		}
	}
}

// 工具函数，断言指定的域名和查询类型没有被查询过
func assertNotQueried(t *testing.T, fake *fakeDNSClient, domain string, queryType uint16) {
	t.Helper()
	fake.mu.Lock()
	defer fake.mu.Unlock()
	for _, call := range fake.calls {
		if call.domain == domain && call.queryType == queryType {
			t.Fatalf("unexpected query for %s type %s; calls: %v", domain, dnsTypeName(queryType), fake.calls)
		}
	}
}

// 工具函数，断言指定的域名和查询类型已经被查询过
func assertQueried(t *testing.T, fake *fakeDNSClient, domain string, queryType uint16) {
	t.Helper()
	fake.mu.Lock()
	defer fake.mu.Unlock()
	for _, call := range fake.calls {
		if call.domain == domain && call.queryType == queryType {
			return
		}
	}
	t.Fatalf("query for %s type %s was not made; calls: %v", domain, dnsTypeName(queryType), fake.calls)
}

// 工具函数，断言指定的 DNS 服务器已经被查询过
func assertQueriedServer(t *testing.T, fake *fakeDNSClient, server string) {
	t.Helper()
	fake.mu.Lock()
	defer fake.mu.Unlock()
	for _, call := range fake.calls {
		if call.server == server {
			return
		}
	}
	t.Fatalf("server %s was not queried; calls: %v", server, fake.calls)
}

// 验证空 AAAA 响应先完成时不会提前结束迭代，随后返回的 A 记录仍会被返回
func TestAddressIteratorWaitsAfterEmptyAAAA(t *testing.T) {
	resolver := netip.MustParseAddrPort("192.0.2.53:53")
	fake := useFakeDNS(t, map[dnsQueryKey]fakeDNSResult{
		{server: resolver.String(), domain: "endpoint.example.", queryType: miekgdns.TypeA}: {
			msg:   dnsResponse("endpoint.example.", miekgdns.TypeA, aRecord("endpoint.example.", "198.51.100.8")),
			delay: 20 * time.Millisecond,
		},
		{server: resolver.String(), domain: "endpoint.example.", queryType: miekgdns.TypeAAAA}: {
			msg: dnsResponse("endpoint.example.", miekgdns.TypeAAAA),
		},
	})

	got := collectAddresses(queryAAndAAAAAddrIter("endpoint.example.", []netip.AddrPort{resolver}))
	assertAddresses(t, got, "198.51.100.8")
	assertQueried(t, fake, "endpoint.example.", miekgdns.TypeA)
	assertQueried(t, fake, "endpoint.example.", miekgdns.TypeAAAA)
}

// 验证 NS 响应的附加区只有 AAAA glue 时，只补查缺失的 A 记录而不重复查询 AAAA
func TestNameserverIteratorSupplementsMissingGlueFamily(t *testing.T) {
	publicResolver := netip.MustParseAddrPort("192.0.2.53:53")
	nsResponse := dnsResponse("endpoint.example.", miekgdns.TypeNS, nsRecord("endpoint.example.", "ns1.example."))
	nsResponse.Extra = []miekgdns.RR{aaaaRecord("ns1.example.", "2001:db8::53")}
	fake := useFakeDNS(t, map[dnsQueryKey]fakeDNSResult{
		{server: publicResolver.String(), domain: "endpoint.example.", queryType: miekgdns.TypeNS}: {
			msg: nsResponse,
		},
		{server: publicResolver.String(), domain: "ns1.example.", queryType: miekgdns.TypeA}: {
			msg: dnsResponse("ns1.example.", miekgdns.TypeA, aRecord("ns1.example.", "192.0.2.54")),
		},
		{server: publicResolver.String(), domain: "ns1.example.", queryType: miekgdns.TypeAAAA}: {
			msg: dnsResponse("ns1.example.", miekgdns.TypeAAAA, aaaaRecord("ns1.example.", "2001:db8::53")),
		},
	})

	got := collectAddresses(nsAddrIter("endpoint.example."))
	assertAddressSet(t, got, "192.0.2.54", "2001:db8::53")
	assertNotQueried(t, fake, "ns1.example.", miekgdns.TypeAAAA)
}

// 验证 IPv4-only 模式只查询并产出 A 记录，不发送 AAAA 查询
func TestAddressIteratorIPv4OnlySkipsAAAA(t *testing.T) {
	resolver := netip.MustParseAddrPort("192.0.2.53:53")
	fake := useFakeDNS(t, map[dnsQueryKey]fakeDNSResult{
		{server: resolver.String(), domain: "endpoint.example.", queryType: miekgdns.TypeA}: {
			msg: dnsResponse("endpoint.example.", miekgdns.TypeA, aRecord("endpoint.example.", "198.51.100.10")),
		},
	})
	conf.EnhancedDNS.DirectResolver.IPv4Only = true

	got := collectAddresses(queryAAndAAAAAddrIter("endpoint.example.", []netip.AddrPort{resolver}))
	assertAddresses(t, got, "198.51.100.10")
	assertNotQueried(t, fake, "endpoint.example.", miekgdns.TypeAAAA)
}

// 验证权威 DNS 查询 endpoint 域名失败时，会回退到公共 DNS 并返回其 A 记录
func TestDirectDNSFallsBackToPublicResolver(t *testing.T) {
	publicResolver := netip.MustParseAddrPort("192.0.2.53:53")
	authoritativeResolver := netip.MustParseAddrPort("192.0.2.54:53")
	nsResponse := dnsResponse("endpoint.example.", miekgdns.TypeNS, nsRecord("endpoint.example.", "ns1.example."))
	nsResponse.Extra = []miekgdns.RR{aRecord("ns1.example.", authoritativeResolver.Addr().String())}
	fake := useFakeDNS(t, map[dnsQueryKey]fakeDNSResult{
		{server: publicResolver.String(), domain: "endpoint.example.", queryType: miekgdns.TypeA}: {
			msg: dnsResponse("endpoint.example.", miekgdns.TypeA, aRecord("endpoint.example.", "198.51.100.9")),
		},
		{server: publicResolver.String(), domain: "endpoint.example.", queryType: miekgdns.TypeAAAA}: {
			msg: dnsResponse("endpoint.example.", miekgdns.TypeAAAA),
		},
		{server: publicResolver.String(), domain: "endpoint.example.", queryType: miekgdns.TypeNS}: {
			msg: nsResponse,
		},
		{server: authoritativeResolver.String(), domain: "endpoint.example.", queryType: miekgdns.TypeA}: {
			err: errors.New("authoritative resolver unavailable"),
		},
		{server: authoritativeResolver.String(), domain: "endpoint.example.", queryType: miekgdns.TypeAAAA}: {
			err: errors.New("authoritative resolver unavailable"),
		},
	})

	got := resolveTestEndpoint(t, "endpoint.example")
	if got.String() != "198.51.100.9" {
		t.Fatalf("ResolveUDPAddrDirect returned %s, want 198.51.100.9", got)
	}
	assertQueriedServer(t, fake, authoritativeResolver.String())
	assertQueriedServer(t, fake, publicResolver.String())
}

// 验证 endpoint 域名的 A 查询返回 NXDOMAIN 后立即报错，不再查询 AAAA 或发现权威 NS
func TestDirectDNSEndpointNXDOMAINIsTerminal(t *testing.T) {
	publicResolver := netip.MustParseAddrPort("192.0.2.53:53")
	fake := useFakeDNS(t, map[dnsQueryKey]fakeDNSResult{
		{server: publicResolver.String(), domain: "missing.example.", queryType: miekgdns.TypeA}: {
			msg: dnsErrorResponse("missing.example.", miekgdns.TypeA, miekgdns.RcodeNameError),
		},
	})

	_, err := ResolveUDPAddrDirect("", "missing.example:51820")
	if err == nil || !strings.Contains(err.Error(), "NXDOMAIN") {
		t.Fatalf("got error %v, want NXDOMAIN", err)
	}
	assertNotQueried(t, fake, "missing.example.", miekgdns.TypeNS)
	assertNotQueried(t, fake, "missing.example.", miekgdns.TypeAAAA)
}

// 验证 endpoint 域名的 A 和 AAAA 查询都返回 NODATA 时，最终返回 no address found
func TestDirectDNSReturnsNoAddressForNODATA(t *testing.T) {
	publicResolver := netip.MustParseAddrPort("192.0.2.53:53")
	fake := useFakeDNS(t, map[dnsQueryKey]fakeDNSResult{
		{server: publicResolver.String(), domain: "nodata.example.", queryType: miekgdns.TypeA}: {
			msg: dnsResponse("nodata.example.", miekgdns.TypeA),
		},
		{server: publicResolver.String(), domain: "nodata.example.", queryType: miekgdns.TypeAAAA}: {
			msg: dnsResponse("nodata.example.", miekgdns.TypeAAAA),
		},
		{server: publicResolver.String(), domain: "nodata.example.", queryType: miekgdns.TypeNS}: {
			err: errors.New("NS lookup unavailable"),
		},
	})

	_, err := ResolveUDPAddrDirect("", "nodata.example:51820")
	if err == nil || !strings.Contains(err.Error(), "no address found") {
		t.Fatalf("got error %v, want no address found", err)
	}
	assertQueried(t, fake, "nodata.example.", miekgdns.TypeA)
	assertQueried(t, fake, "nodata.example.", miekgdns.TypeAAAA)
}

// 验证权威 NS 主机名返回 NXDOMAIN 时，会放弃权威路径并回退到公共 DNS 解析 endpoint 域名
func TestDirectDNSFallsBackWhenNameserverHostnameIsNXDOMAIN(t *testing.T) {
	publicResolver := netip.MustParseAddrPort("192.0.2.53:53")
	nsResponse := dnsResponse("endpoint.example.", miekgdns.TypeNS, nsRecord("endpoint.example.", "missing-ns.example."))
	useFakeDNS(t, map[dnsQueryKey]fakeDNSResult{
		{server: publicResolver.String(), domain: "endpoint.example.", queryType: miekgdns.TypeA}: {
			msg: dnsResponse("endpoint.example.", miekgdns.TypeA, aRecord("endpoint.example.", "198.51.100.12")),
		},
		{server: publicResolver.String(), domain: "endpoint.example.", queryType: miekgdns.TypeAAAA}: {
			msg: dnsResponse("endpoint.example.", miekgdns.TypeAAAA),
		},
		{server: publicResolver.String(), domain: "endpoint.example.", queryType: miekgdns.TypeNS}: {
			msg: nsResponse,
		},
		{server: publicResolver.String(), domain: "missing-ns.example.", queryType: miekgdns.TypeA}: {
			msg: dnsErrorResponse("missing-ns.example.", miekgdns.TypeA, miekgdns.RcodeNameError),
		},
		{server: publicResolver.String(), domain: "missing-ns.example.", queryType: miekgdns.TypeAAAA}: {
			msg: dnsErrorResponse("missing-ns.example.", miekgdns.TypeAAAA, miekgdns.RcodeNameError),
		},
	})

	got := resolveTestEndpoint(t, "endpoint.example")
	if got.String() != "198.51.100.12" {
		t.Fatalf("ResolveUDPAddrDirect returned %s, want 198.51.100.12", got)
	}
}

// 验证一个 DNS 服务器返回 SERVFAIL 后，会继续尝试列表中的下一个服务器
func TestDNSQueryTriesNextResolverAfterSERVFAIL(t *testing.T) {
	firstResolver := netip.MustParseAddrPort("192.0.2.53:53")
	secondResolver := netip.MustParseAddrPort("192.0.2.54:53")
	fake := useFakeDNS(t, map[dnsQueryKey]fakeDNSResult{
		{server: firstResolver.String(), domain: "endpoint.example.", queryType: miekgdns.TypeA}: {
			msg: dnsErrorResponse("endpoint.example.", miekgdns.TypeA, miekgdns.RcodeServerFailure),
		},
		{server: secondResolver.String(), domain: "endpoint.example.", queryType: miekgdns.TypeA}: {
			msg: dnsResponse("endpoint.example.", miekgdns.TypeA, aRecord("endpoint.example.", "198.51.100.13")),
		},
	})

	response, err := queryWithRetryWithList(context.Background(), "endpoint.example.", miekgdns.TypeA, []netip.AddrPort{firstResolver, secondResolver})
	if err != nil {
		t.Fatalf("queryWithRetryWithList returned an error: %v", err)
	}
	if len(response.Answer) != 1 || response.Answer[0].(*miekgdns.A).A.String() != "198.51.100.13" {
		t.Fatalf("got answers %v, want 198.51.100.13", response.Answer)
	}
	assertQueriedServer(t, fake, firstResolver.String())
	assertQueriedServer(t, fake, secondResolver.String())
}
