package filter

import (
	"strings"
	"testing"
)

// --- gitleaks 豁免条目（allowlist）---
//
// 期望值均与上游 gitleaks（同一份 rules/gitleaks.toml）逐条对齐核对过。

// TestAttributionTrailerNotRedactedAsSecret 回归：Co-Authored-By 这类署名行曾被整段
// 抹成 [密钥]。成因是 generic-api-key 的关键词含 "auth"，而本库原先丢掉了该规则
// 自带的 allowlist（match 目标，其中含 "author"），上游正是靠它挡下这类误报。
func TestAttributionTrailerNotRedactedAsSecret(t *testing.T) {
	f := newFilter(t)
	for _, in := range []string{
		"Co-Authored-By: deepseek-flash <noreply@deepseek.com>",
		"Co-Authored-By: deepseek-qwq <noreply@deepseek.com>",
	} {
		got := redact(t, f, in)
		if strings.Contains(got, "[密钥]") {
			t.Errorf("署名行被当成密钥脱敏: %q -> %q", in, got)
		}
	}
}

// TestAllowlistsDoNotMaskRealSecrets 豁免生效后，同一形状的真密钥仍须脱敏。
func TestAllowlistsDoNotMaskRealSecrets(t *testing.T) {
	f := newFilter(t)
	for _, in := range []string{
		"X-Api-Key: 9f3a7c2b8e1d4a6f0c5b7d2e8a1f4c6b3d9e",
		"token: ghp_9f3a7c2b8e1d4a6f0c5b7d2e8a1f4c6b3d9e",
		"RUN --build-arg API_KEY=9f3a7c2b8e1d4a6f0c5b7d2e8a1f4c6b3d9e",
	} {
		got := redact(t, f, in)
		if !strings.Contains(got, "[密钥]") {
			t.Errorf("真密钥未被脱敏: %q -> %q", in, got)
		}
	}
}

// TestStopwordTargetsSecretNotWholeMatch generic-api-key 的 stopwords 里含 "password"。
// 停用词必须比对密钥本身（第一个非空捕获分组），而不是整段匹配 —— 否则
// `password": "Hunter2xyzAbCdEf"` 整段里出现的关键词会把真口令一起放过。
func TestStopwordTargetsSecretNotWholeMatch(t *testing.T) {
	f := newFilter(t)
	in := `{"username": "admin", "password": "Hunter2xyzAbCdEf"}`
	got := redact(t, f, in)
	if !strings.Contains(got, "[密钥]") || strings.Contains(got, "Hunter2xyzAbCdEf") {
		t.Errorf("口令被 stopwords 误放: %q -> %q", in, got)
	}
}

// TestGlobalStopwordAllowsPlaceholderAlphabet 顶层 allowlist 的 stopwords 含整条字母表，
// 命中即视为占位符（与上游一致）。
func TestGlobalStopwordAllowsPlaceholderAlphabet(t *testing.T) {
	f := newFilter(t)
	in := "api_key=abcdefghijklmnopqrstuvwxyz"
	if got := redact(t, f, in); strings.Contains(got, "[密钥]") {
		t.Errorf("全局 stopword 未生效: %q -> %q", in, got)
	}
}

// TestRuleAllowlistSampleKeys gcp-api-key 的 allowlist 用 secret 目标列了官方示例 key，
// 差一个字符就不再豁免。
func TestRuleAllowlistSampleKeys(t *testing.T) {
	f := newFilter(t)
	const sample = "AIzaSyAnLA7NfeLquW1tJFpx_eQCxoX-oo6YyIs"
	if got := redact(t, f, sample); strings.Contains(got, "[密钥]") {
		t.Errorf("示例 key 未豁免: %q -> %q", sample, got)
	}
	const variant = "AIzaSyAnLA7NfeLquW1tJFpx_eQCxoX-oo6YyIx"
	if got := redact(t, f, variant); !strings.Contains(got, "[密钥]") {
		t.Errorf("非示例 key 被误放: %q -> %q", variant, got)
	}
}

// TestLineTargetAllowlist generic-api-key 还有一条 regexTarget = "line" 的豁免：
// 行内出现 docker build 的 secret 挂载时整行不脱敏。这里用短值 + auth 关键词，
// 避开本库自己的上下文口令（Route 2）与高熵兜底（Route 3）两条额外检测层。
func TestLineTargetAllowlist(t *testing.T) {
	f := newFilter(t)
	in := "RUN --mount=type=secret,id=k --header X-Auth: 9f3a7c2b8e1d"
	if got := redact(t, f, in); strings.Contains(got, "[密钥]") {
		t.Errorf("line 目标豁免未生效: %q -> %q", in, got)
	}
	// 同样的值换到不含豁免正则的行上 → 仍应脱敏
	in = "RUN --header X-Auth: 9f3a7c2b8e1d"
	if got := redact(t, f, in); !strings.Contains(got, "[密钥]") {
		t.Errorf("非豁免行未脱敏: %q -> %q", in, got)
	}
}

// TestAllowlistSemantics 白盒校验条目语义：AND 合取、空条目丢弃、坏正则计数。
func TestAllowlistSemantics(t *testing.T) {
	// condition = AND 且带 paths：本库没有文件路径上下文，paths 恒为假 → 永不豁免。
	// 复刻上游 fragment 无路径时的取值。
	als, bad := parseAllowlists([]tomlAllowlist{{
		Condition:   "AND",
		Paths:       []string{`\.bb$`},
		RegexTarget: "line",
		Regexes:     []string{`LICENSE`},
	}})
	if bad != 0 || len(als) != 1 {
		t.Fatalf("parse: got %d 条 (bad=%d)", len(als), bad)
	}
	if als[0].allows("m", "s", `LICENSE = "1"`) {
		t.Error("AND + paths 不应豁免（无路径上下文时 paths 恒为假）")
	}

	// AND 无 paths：regexes 与 stopwords 都必须成立。
	als, _ = parseAllowlists([]tomlAllowlist{{
		Condition: "AND",
		Regexes:   []string{`deadbeef`},
		Stopwords: []string{"1234"},
	}})
	if len(als) != 1 {
		t.Fatalf("parse: got %d 条", len(als))
	}
	if !als[0].allows("deadbeef", "deadbeef1234", "") {
		t.Error("AND 条件下两类条件都成立时就应豁免")
	}
	if als[0].allows("deadbeef", "deadbeefxyz", "") {
		t.Error("AND 条件下 stopword 不成立不应豁免")
	}

	// OR：任一成立即豁免。
	als, _ = parseAllowlists([]tomlAllowlist{{
		Regexes:   []string{`deadbeef`},
		Stopwords: []string{"1234"},
	}})
	if !als[0].allows("", "deadbeefxyz", "") {
		t.Error("OR 条件下 regex 命中即应豁免")
	}

	// 空条目直接丢弃；正则编译失败计入 bad。
	if got, _ := parseAllowlists([]tomlAllowlist{{Description: "空"}}); len(got) != 0 {
		t.Errorf("空条目应被丢弃: %d 条", len(got))
	}
	if _, bad := parseAllowlists([]tomlAllowlist{{Regexes: []string{"("}}}); bad != 1 {
		t.Errorf("坏正则应计入 bad: %d", bad)
	}

	// regexTarget = "secret" 与空值等价（上游行为）。
	if normalizeRegexTarget("secret") != "" || normalizeRegexTarget("match") != "match" {
		t.Error("regexTarget 归一化与上游不一致")
	}
}

// TestLineAt 命中跨行时，取从起点所在行首到终点所在行尾。
func TestLineAt(t *testing.T) {
	text := "first line\nsecond token=abc\nthird"
	cases := []struct {
		start, end int
		want       string
	}{
		{0, 5, "first line"},
		{11, 26, "second token=abc"},
		{11, 30, "second token=abc\nthird"},
		{29, 32, "third"},
	}
	for _, c := range cases {
		if got := lineAt(text, c.start, c.end); got != c.want {
			t.Errorf("lineAt(%d,%d) = %q, want %q", c.start, c.end, got, c.want)
		}
	}
}
