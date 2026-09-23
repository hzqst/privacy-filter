package filter

import (
	"math"
	"regexp"
	"strings"

	"github.com/BurntSushi/toml"
)

const (
	entropyMin       = 4.0 // 高熵兜底默认阈值（贴近 gitleaks 经验值）
	entropyMinStrict = 4.8 // 周围无密钥语义关键词时启用，进一步压低误报
	contextLookback  = 30  // hasSecretContext 往前回溯字节数
)

// 上下文型口令：藏在句子里的密码/token，如「我的密码是 hunter2」「api_key: xxx」。
var reContextSecret = regexp.MustCompile(
	`(?i)(密码|口令|密钥|password|passwd|pwd|secret|token|api[_\s-]?key)\s*(?:是|为|:|：|=)\s*['"]?([^\s'"，。；;]{4,})`)

// 高熵兜底：抓不匹配任何已知格式的随机串。
var reEntropyToken = regexp.MustCompile(`[A-Za-z0-9+/=_\-]{20,}`)

// 密钥语义关键词。命中表示候选串身处"明显在谈密钥"的上下文里，
// 保留 entropyMin；不命中则用 entropyMinStrict 收紧阈值。
// 目前覆盖英文 + 中文；日 / 韩 / 俄等其它语种关键词未覆盖（已知限制）。
var reSecretContext = regexp.MustCompile(
	`(?i)(?:password|passwd|pwd|secret|token|api[_\s-]?key|access[_\s-]?key|bearer|authorization|credential|jwt|密码|口令|密钥|凭证|令牌|鉴权)`)

// 路径/URL/哈希边界字符。实际遇到的误伤都是这一类：
//   - 候选串内部含 / \ :   → 整段就是路径
//   - 候选串左右贴上面+ . @ ? = → 路径分段 / sha256: / @host / query 参数
const (
	pathBoundaryChars = `/\:.@?=`
	pathInternalChars = `/\:`
)

// 协议/哈希前缀，候选串左侧短回溯命中即视作路径片段。
var urlPrefixes = []string{
	"http://", "https://", "ftp://", "ssh://",
	"s3://", "gs://", "oss://",
	"git@", "sha256:", "sha1:", "md5:",
}

// 强上下文判定时允许出现在"关键词"和"候选串"之间的字符。
// 例：Authorization: Bearer xxx  之间是 ":" + 空格 + 空格 + 空格 + ...
// 这些字符之外（如 . / 字母数字）出现一个就说明关键词与候选不是赋值关系。
const assignmentChars = " \t\r\n=:'\""

// Post validators —— 命中后再过一遍"明显不是密钥"的形态识别，命中即放过。
var (
	// 模板变量：{{ X }} / ${X} / %{X} / <X>。覆盖 helm/handlebars/sh/Go template/Jinja。
	reTemplateVar = regexp.MustCompile(`^(?:\{\{[^{}]+\}\}|\$\{[^{}]+\}|%\{[^{}]+\}|<[^<>]+>)$`)
	// 标准 UUID（带横线）。
	reUUID = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	// 纯 hex（搭配长度判断 md5/sha1/sha256）。
	reHexOnly = regexp.MustCompile(`^[0-9a-fA-F]+$`)
)

// 业务标识符的常见变量名后缀。`order_id=xxxxx` 这类不应被当密钥。
var benignIDSuffixes = []string{"_id", "_uuid", "_uid", "_oid", "_no", "_seq"}

// HTTP Authorization header 的标准形态：Authorization: <scheme> <value>。
// 把这个结构作为强 context 的特例处理，避免把 "Basic" "Digest" 等加进通用
// 关键词导致普通英文（"basic understanding..."）误报。
var reAuthHeaderPrefix = regexp.MustCompile(
	`(?i)\bauthorization\s*:\s*(?:basic|bearer|digest|ntlm|hmac|token)\s+$`)

// 仅 Route 1（gitleaks）用：判断命中是否落在 URL/域名上下文里。
// 区分于 Route 3 的 isOnPathOrURLBoundary —— 后者把任何含 / \ : 的串都当路径，
// 这对 gitleaks 的具体规则（AWS Secret Access Key 含 base64 `/` 等）会误杀。
// 这里只挡两类：含 :// 的 URL，或者以 host.tld: 开头的命中（generic-api-key 把
// 域名+冒号+路径一起吃掉的情形）。
var reHostPortPrefix = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.-]*\.[A-Za-z0-9-]+:`)

func looksLikeURLMatch(s string) bool {
	if strings.Contains(s, "://") {
		return true
	}
	return reHostPortPrefix.MatchString(s)
}

// 常见占位符词。Route 1 / Route 2 命中的"value"含这些词时跳过 —— 占位符不是真值。
// 子串匹配理论上会误放含同名子串的真密钥（如 "...TODO..."），但概率极低。
var commonPlaceholders = []string{
	"REPLACE_ME", "REPLACE_THIS", "REPLACE_WITH",
	"YOUR_KEY", "YOUR_TOKEN", "YOUR_SECRET", "YOUR_API_KEY", "YOUR_PASSWORD",
	"INSERT_HERE", "INSERT_KEY", "INSERT_TOKEN",
	"PLACEHOLDER", "EXAMPLE_KEY", "EXAMPLE_TOKEN",
	"TODO", "FIXME", "XXXX",
}

// isLikelyPlaceholder 大小写不敏感地匹配常见占位符词。
func isLikelyPlaceholder(s string) bool {
	upper := strings.ToUpper(s)
	for _, p := range commonPlaceholders {
		if strings.Contains(upper, p) {
			return true
		}
	}
	return false
}

// hasJSONNoise 命中含 `,` —— 单 token 的真密钥不会有 `,`，gitleaks 宽规则
// 误吃多 token 时常见。`"` 不能加进来，否则会误杀 key="..." 这种引号包裹的真密钥。
func hasJSONNoise(s string) bool {
	return strings.IndexByte(s, ',') >= 0
}

type secretRule struct {
	id          string
	re          *regexp.Regexp
	keywords    []string // 已小写；空表示该规则总是参与
	entropy     float64
	secretGroup int
	allowlists  []*allowlist // 规则级豁免
}

type secretDetector struct {
	rules   []secretRule
	global  []*allowlist // 顶层豁免，对所有规则生效
	skipped int          // 正则无法编译而被跳过的规则数 + 豁免条目数（Go RE2 下通常为 0）
}

// gitleaks.toml 的最小结构；未涉及的字段（paths 等）会被忽略。
type tomlConfig struct {
	Allowlist  tomlAllowlist   `toml:"allowlist"`
	Allowlists []tomlAllowlist `toml:"allowlists"`
	Rules      []struct {
		ID          string          `toml:"id"`
		Regex       string          `toml:"regex"`
		Keywords    []string        `toml:"keywords"`
		Entropy     float64         `toml:"entropy"`
		SecretGroup int             `toml:"secretGroup"`
		Allowlist   tomlAllowlist   `toml:"allowlist"`
		Allowlists  []tomlAllowlist `toml:"allowlists"`
	} `toml:"rules"`
}

func newSecretDetector(tomlPath string) (*secretDetector, error) {
	sd := &secretDetector{}
	if tomlPath == "" {
		sd.loadBuiltin()
		return sd, nil
	}
	var cfg tomlConfig
	if _, err := toml.DecodeFile(tomlPath, &cfg); err != nil {
		return nil, err
	}
	global, bad := parseAllowlists(append([]tomlAllowlist{cfg.Allowlist}, cfg.Allowlists...))
	sd.global, sd.skipped = global, sd.skipped+bad
	for _, r := range cfg.Rules {
		if r.Regex == "" {
			continue
		}
		re, err := regexp.Compile(r.Regex)
		if err != nil {
			sd.skipped++
			continue
		}
		kws := make([]string, len(r.Keywords))
		for i, k := range r.Keywords {
			kws[i] = strings.ToLower(k)
		}
		als, bad := parseAllowlists(append([]tomlAllowlist{r.Allowlist}, r.Allowlists...))
		sd.skipped += bad
		sd.rules = append(sd.rules, secretRule{
			id:          r.ID,
			re:          re,
			keywords:    kws,
			entropy:     r.Entropy,
			secretGroup: r.SecretGroup,
			allowlists:  als,
		})
	}
	if len(sd.rules) == 0 {
		sd.loadBuiltin()
	}
	return sd, nil
}

// loadBuiltin 在 gitleaks.toml 缺失时提供一组兜底规则。
func (sd *secretDetector) loadBuiltin() {
	builtin := []struct {
		id, pat string
		kws     []string
	}{
		{"openai-key", `sk-(?:proj-)?[A-Za-z0-9_-]{20,}`, []string{"sk-"}},
		{"aws-access-key", `AKIA[0-9A-Z]{16}`, []string{"akia"}},
		{"github-token", `gh[pousr]_[A-Za-z0-9]{36,}`, []string{"ghp_", "gho_", "ghu_", "ghs_", "ghr_"}},
		{"google-api-key", `AIza[0-9A-Za-z_-]{35}`, []string{"aiza"}},
		{"slack-token", `xox[baprs]-[0-9A-Za-z-]{10,}`, []string{"xox"}},
		{"jwt", `eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}`, []string{"eyj"}},
		{"private-key", `-----BEGIN[A-Z ]*PRIVATE KEY-----`, []string{"private key"}},
	}
	for _, b := range builtin {
		sd.rules = append(sd.rules, secretRule{
			id:       b.id,
			re:       regexp.MustCompile(b.pat),
			keywords: b.kws,
		})
	}
}

// detect 返回密钥/凭证的命中区间。
func (sd *secretDetector) detect(text string) []span {
	var spans []span
	low := strings.ToLower(text)

	// gitleaks 规则：关键词预筛 —— 只对命中关键词的规则跑正则
	for i := range sd.rules {
		r := &sd.rules[i]
		if !ruleApplies(r, low) {
			continue
		}
		for _, m := range r.re.FindAllStringSubmatchIndex(text, -1) {
			s, e := m[0], m[1]
			if g := r.secretGroup; g > 0 && 2*g+1 < len(m) && m[2*g] >= 0 {
				s, e = m[2*g], m[2*g+1]
			}
			if s < 0 || s >= e {
				continue
			}
			// 密钥本身（上游 finding.Secret）：指定了 secretGroup 就取该分组，
			// 否则取第一个非空分组；规则没有分组时才是整段匹配。熵、stopwords、
			// regexTarget=secret 的豁免都比对它，而不是比整段匹配 —— 否则像
			// generic-api-key 的 stopwords（含 "password"）会把 `password": "xxx"`
			// 整段匹配里的关键字也算进去，连带放过真正的口令。
			secret := text[s:e]
			if r.secretGroup == 0 {
				if g := firstNonEmptyGroup(m, text); g != "" {
					secret = g
				}
			}
			if r.entropy > 0 && shannonEntropy(secret) <= r.entropy {
				continue // 复刻 gitleaks 的熵阈值与比较方式，压低误报
			}
			// 命中含 URL 或域名前缀（generic-api-key 把 api.x.com:path 一起吃的情形）
			// 或明显是模板/UUID/hash/业务 ID/占位符/JSON 噪声时跳过。
			// 注意：不能用 Route 3 的 isOnPathOrURLBoundary，那会误杀 AWS Secret Access Key
			// （含 base64 的 / 字符）这类合法但带斜杠的密钥。
			cand := text[s:e]
			if looksLikeURLMatch(cand) ||
				isTemplateVar(cand) || isHexHash(cand) || isUUID(cand) ||
				isBusinessIDAssignment(cand) ||
				isLikelyPlaceholder(cand) || hasJSONNoise(cand) {
				continue
			}
			// gitleaks 的豁免条目（规则级 + 顶层）：例如 generic-api-key 的
			// allowlist 用 "author" 挡掉 Co-Authored-By 这类署名行。
			match := text[m[0]:m[1]]
			line := lineAt(text, m[0], m[1])
			if allowsAny(r.allowlists, match, secret, line) || allowsAny(sd.global, match, secret, line) {
				continue
			}
			spans = append(spans, span{s, e, "[密钥]"})
		}
	}
	// 上下文口令：只脱掉 value（第 2 个分组）
	for _, m := range reContextSecret.FindAllStringSubmatchIndex(text, -1) {
		if len(m) >= 6 && m[4] >= 0 {
			// 关键词必须处于词首：`..._CheckPassword: xxx` 里的 Password 只是标识符
			// 片段，不构成「关键词: 值」赋值结构。
			if !keywordBounded(text, m[2]) {
				continue
			}
			value := text[m[4]:m[5]]
			// 模板变量（${TOKEN} / {{ X }} 等）不是真值，跳过
			if isTemplateVar(value) {
				continue
			}
			// 低熵短串（"REPLACE_ME" / "TODO" / "null" / "abc" 等占位符）跳过
			if len(value) <= 16 && shannonEntropy(value) < 3.0 {
				continue
			}
			if allowsAny(sd.global, value, value, lineAt(text, m[4], m[5])) {
				continue
			}
			spans = append(spans, span{m[4], m[5], "[密钥]"})
		}
	}
	// 高熵兜底
	for _, m := range reEntropyToken.FindAllStringIndex(text, -1) {
		s, e := m[0], m[1]
		cand := text[s:e]

		strong := hasStrongSecretContext(text, s, e)
		// 强上下文（Bearer / token= 等）凌驾于路径检查：避免 Bearer abc/xyz== 被路径规则误放
		if !strong && isOnPathOrURLBoundary(text, s, e) {
			continue
		}
		// 形态识别：模板变量 / 标准 hash / UUID / 业务 ID / 代码符号名都不是密钥
		if isTemplateVar(cand) || isHexHash(cand) || isUUID(cand) ||
			isBusinessIDAssignment(cand) || isSymbolName(cand) {
			continue
		}
		threshold := entropyMin
		if !hasSecretContext(text, s, e) {
			threshold = entropyMinStrict
		}
		if shannonEntropy(cand) >= threshold {
			if allowsAny(sd.global, cand, cand, lineAt(text, s, e)) {
				continue
			}
			spans = append(spans, span{s, e, "[密钥]"})
		}
	}
	return spans
}

// isOnPathOrURLBoundary 判断 [start,end) 是否处于路径 / URL / 哈希等"非密钥"上下文。
// 命中即跳过，避开 ls /a/AbCd...、s3://bucket/key、@sha256:hash 这类实际遇到的误伤。
func isOnPathOrURLBoundary(text string, start, end int) bool {
	if strings.ContainsAny(text[start:end], pathInternalChars) {
		return true
	}
	if start > 0 && strings.IndexByte(pathBoundaryChars, text[start-1]) >= 0 {
		return true
	}
	if end < len(text) && strings.IndexByte(pathBoundaryChars, text[end]) >= 0 {
		return true
	}
	lo := start - 8
	if lo < 0 {
		lo = 0
	}
	look := text[lo:start]
	for _, p := range urlPrefixes {
		if strings.Contains(look, p) {
			return true
		}
	}
	return false
}

// hasSecretContext 检查候选串之前是否出现密钥语义关键词（后端 30 字节），
// 命中保留 entropyMin，否则改用更严的 entropyMinStrict。
// 关键词落在候选串内部时只有真实的赋值结构（api_key=xxx）才算数：否则
// CNetworkGameServerBase_CheckPassword 这类「关键词只是标识符尾巴」的符号名
// 会自带伪上下文，把普通代码标识符拖进密钥判定。
func hasSecretContext(text string, start, end int) bool {
	lo := start - contextLookback
	if lo < 0 {
		lo = 0
	}
	before := text[lo:start]
	for _, loc := range reSecretContext.FindAllStringIndex(before, -1) {
		if keywordBounded(before, loc[0]) {
			return true
		}
	}
	return keywordInsideAssignment(text[start:end])
}

// keywordBounded 判断关键词是否位于「词首」：紧贴在字母 / 数字之后的所谓关键词
// 只是更长标识符的片段（Check**Password**、x**auth**），不构成密钥语义上下文。
// 下划线不算粘连 —— DB_PASSWORD / api_key 这类命名里关键词本就是独立词段。
func keywordBounded(text string, start int) bool {
	if start <= 0 {
		return true
	}
	switch text[start-1] {
	case '_':
		return true
	}
	return !isWordCharByte(text[start-1])
}

// isWordCharByte 判断字节是否为标识符字符（ASCII 字母 / 数字）。
func isWordCharByte(b byte) bool {
	return b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9'
}

// keywordInsideAssignment 判断候选串内部是否出现「关键词紧接赋值分隔符」的结构
// （api_key=xxx / token:xxx）。关键词只是标识符尾巴（..._CheckPassword）时返回 false。
func keywordInsideAssignment(cand string) bool {
	low := strings.ToLower(cand)
	for _, loc := range reSecretContext.FindAllStringIndex(low, -1) {
		if !keywordBounded(low, loc[0]) {
			continue
		}
		i := loc[1]
		for i < len(low) && (low[i] == ' ' || low[i] == '\t') {
			i++
		}
		if i < len(low) && (low[i] == '=' || low[i] == ':') {
			return true
		}
	}
	return false
}

// hasStrongSecretContext 比 hasSecretContext 更严：要求"关键词紧贴候选串"，
// 中间只能是空白 / = / : / 引号 这种"赋值分隔"字符。这是真正的赋值结构，能与
// 路径里碰巧含 api_key 的情况区分开（api_key.example.com/AbCd... 不是赋值）。
// 命中时高熵兜底会绕过 Step 1 路径检查，避免漏 Bearer xxx==/yyy 这类带 / 的真密钥。
func hasStrongSecretContext(text string, start, end int) bool {
	lo := start - contextLookback
	if lo < 0 {
		lo = 0
	}
	// HTTP Authorization 头标准形态特别处理：Authorization: <scheme> <candidate>
	if reAuthHeaderPrefix.MatchString(text[lo:start]) {
		return true
	}
	region := text[lo:end]
	var last []int
	for _, loc := range reSecretContext.FindAllStringIndex(region, -1) {
		if keywordBounded(region, loc[0]) {
			last = loc
		}
	}
	if last == nil {
		return false
	}
	candStartInRegion := start - lo
	// 关键词起点落在候选串内 → 只有「关键词 + 赋值分隔符」才算强上下文
	if last[0] >= candStartInRegion {
		return keywordInsideAssignment(text[start:end])
	}
	// 关键词在 lookback 里：检查关键词结束 → 候选起点 之间是否只剩赋值字符
	between := region[last[1]:candStartInRegion]
	for i := 0; i < len(between); i++ {
		if strings.IndexByte(assignmentChars, between[i]) < 0 {
			return false
		}
	}
	return true
}

// isTemplateVar 识别模板占位符：{{...}} / ${...} / %{...} / <...>。
func isTemplateVar(s string) bool { return reTemplateVar.MatchString(s) }

// isHexHash 识别 md5(32) / sha1(40) / sha256(64) 长度的纯 hex 串。
func isHexHash(s string) bool {
	n := len(s)
	return (n == 32 || n == 40 || n == 64) && reHexOnly.MatchString(s)
}

// isUUID 识别标准 8-4-4-4-12 UUID。
func isUUID(s string) bool { return reUUID.MatchString(s) }

// isBusinessIDAssignment 看 = 左边的变量名是否以业务 ID 后缀结尾（_id / _uuid / _no ...）。
// 这类是业务标识符，不是凭证。但若变量名同时含凭证语义词（key/secret/token/auth/password
// /credential），仍按密钥处理 —— 应对 AWS_ACCESS_KEY_ID 这种官方约定的环境变量名。
func isBusinessIDAssignment(s string) bool {
	eq := strings.IndexByte(s, '=')
	if eq <= 0 {
		return false
	}
	name := strings.ToLower(s[:eq])
	for _, k := range []string{"key", "secret", "token", "auth", "password", "credential"} {
		if strings.Contains(name, k) {
			return false
		}
	}
	for _, suf := range benignIDSuffixes {
		if strings.HasSuffix(name, suf) {
			return true
		}
	}
	return false
}

// isSymbolName 识别「代码符号名 / 标识符」形态：整串只由 ASCII 字母、下划线、
// 连字符、冒号组成（不含数字与 base64 的 + / =），且呈驼峰或分段的分词结构。
// 形如 CNetworkGameServerBase_CheckPassword 的符号名会被高熵兜底误当随机串，
// 而真密钥几乎总含数字或 +/= 符号，故跳过这一形态不会漏掉它们。
func isSymbolName(s string) bool {
	var separators, humps int
	prevLower := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z':
			prevLower = true
		case c >= 'A' && c <= 'Z':
			if prevLower {
				humps++
			}
			prevLower = false
		case c == '_' || c == '-' || c == ':':
			separators++
			prevLower = false
		default:
			return false // 数字或其它字符 → 不是标识符形态
		}
	}
	return separators >= 1 || humps >= 2
}

// firstNonEmptyGroup 返回第一个非空捕获分组，复刻上游 detect.go 在未配置
// secretGroup 时对 finding.Secret 的取值。规则没有分组时返回空串。
func firstNonEmptyGroup(m []int, text string) string {
	for g := 1; 2*g+1 < len(m); g++ {
		start, end := m[2*g], m[2*g+1]
		if start >= 0 && end > start {
			return text[start:end]
		}
	}
	return ""
}

// ruleApplies 做关键词预筛：无关键词的规则总是参与，
// 否则文本里出现任一关键词才参与。
func ruleApplies(r *secretRule, lowText string) bool {
	if len(r.keywords) == 0 {
		return true
	}
	for _, kw := range r.keywords {
		if strings.Contains(lowText, kw) {
			return true
		}
	}
	return false
}

// shannonEntropy 按字节计算香农熵（bits/byte）。
func shannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	var freq [256]float64
	for i := 0; i < len(s); i++ {
		freq[s[i]]++
	}
	n := float64(len(s))
	ent := 0.0
	for _, c := range freq {
		if c > 0 {
			p := c / n
			ent -= p * math.Log2(p)
		}
	}
	return ent
}
