package filter

import (
	"regexp"
	"strings"
)

// allowlist 是 gitleaks 豁免条目（allowlist）在纯文本过滤场景下的等价实现。
//
// 语义对齐 gitleaks v8.25 的 detect.checkFindingAllowed：
//
//   - regexTarget 决定 regexes 的比对对象："" / "secret" 比对密钥本身，
//     "match" 比对规则正则的整段匹配，"line" 比对命中所在整行；
//   - stopwords 恒定比对密钥本身，大小写不敏感；
//   - condition 为 "AND" 时，本条目中出现的每一类条件都必须成立，否则任一成立即豁免。
//
// paths / commits 依赖文件名与 commit SHA，本库没有这两个上下文：OR 条件下上游本就
// 不把二者算进判定结果，AND 条件下按"永不匹配"处理 —— 与上游 fragment 无路径、无
// commit SHA 时的取值一致。
type allowlist struct {
	and         bool
	regexTarget string
	regexes     []*regexp.Regexp
	stopwords   []string // 已小写、已去重
	hasPaths    bool
	hasCommits  bool
}

// tomlAllowlist 是 gitleaks.toml 中 [allowlist] / [[allowlists]] / [[rules.allowlists]]
// 块的结构。只取纯文本场景用得上的字段。
type tomlAllowlist struct {
	Description string   `toml:"description"`
	Condition   string   `toml:"condition"`
	Commits     []string `toml:"commits"`
	Paths       []string `toml:"paths"`
	RegexTarget string   `toml:"regexTarget"`
	Regexes     []string `toml:"regexes"`
	Stopwords   []string `toml:"stopwords"`
}

// parseAllowlists 编译豁免条目，返回条目列表与正则无法编译的条数。
// 空条目（没有任何可判定条件）直接丢弃；上游遇到空条目会直接报错。
func parseAllowlists(list []tomlAllowlist) ([]*allowlist, int) {
	var out []*allowlist
	bad := 0
	for _, t := range list {
		a := &allowlist{
			and:         isAndCondition(t.Condition),
			regexTarget: normalizeRegexTarget(t.RegexTarget),
			hasPaths:    len(t.Paths) > 0,
			hasCommits:  len(t.Commits) > 0,
		}
		for _, p := range t.Regexes {
			re, err := regexp.Compile(p)
			if err != nil {
				bad++
				continue
			}
			a.regexes = append(a.regexes, re)
		}
		a.stopwords = normalizeStopwords(t.Stopwords)
		if len(a.regexes) == 0 && len(a.stopwords) == 0 && !a.hasPaths && !a.hasCommits {
			continue
		}
		out = append(out, a)
	}
	return out, bad
}

// isAndCondition 复刻上游对 condition 的取值：AND / && 为合取，其余（含空值）为析取。
// 上游对未知取值会报错，本库无法中断整份规则，按析取处理并计入 skipped。
func isAndCondition(c string) bool {
	switch strings.ToUpper(strings.TrimSpace(c)) {
	case "AND", "&&":
		return true
	default:
		return false
	}
}

// normalizeRegexTarget 复刻上游：secret 与空值等价，只认 match / line。
func normalizeRegexTarget(t string) string {
	switch t {
	case "match", "line":
		return t
	default:
		return ""
	}
}

// normalizeStopwords 小写化并去重，与上游 Validate 的预处理一致。
func normalizeStopwords(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, w := range in {
		w = strings.ToLower(w)
		if _, ok := seen[w]; ok {
			continue
		}
		seen[w] = struct{}{}
		out = append(out, w)
	}
	return out
}

// allows 判断一次命中是否落入本豁免条目。match 为规则正则的整段匹配，
// secret 为密钥本身，line 为命中所在整行。
func (a *allowlist) allows(match, secret, line string) bool {
	target := secret
	switch a.regexTarget {
	case "match":
		target = match
	case "line":
		target = line
	}
	regexAllowed := a.anyRegexMatch(target)
	stopwordAllowed := a.containsStopword(secret)

	if !a.and {
		return regexAllowed || stopwordAllowed
	}
	// AND：本条目里出现的每一类条件都必须成立；本库没有路径与 commit
	// 上下文，这两类条件恒为假。
	checks := make([]bool, 0, 4)
	if a.hasCommits {
		checks = append(checks, false)
	}
	if a.hasPaths {
		checks = append(checks, false)
	}
	if len(a.regexes) > 0 {
		checks = append(checks, regexAllowed)
	}
	if len(a.stopwords) > 0 {
		checks = append(checks, stopwordAllowed)
	}
	for _, ok := range checks {
		if !ok {
			return false
		}
	}
	return true
}

// anyRegexMatch 复刻上游 anyRegexMatch：正则匹配到空串不算命中。
func (a *allowlist) anyRegexMatch(s string) bool {
	if s == "" {
		return false
	}
	for _, re := range a.regexes {
		if re.FindString(s) != "" {
			return true
		}
	}
	return false
}

// containsStopword 复刻上游 ContainsStopWord：只在密钥本身里找，大小写不敏感。
func (a *allowlist) containsStopword(secret string) bool {
	if secret == "" {
		return false
	}
	low := strings.ToLower(secret)
	for _, w := range a.stopwords {
		if strings.Contains(low, w) {
			return true
		}
	}
	return false
}

// allowsAny 逐个检查豁免条目，任一豁免即放过。
func allowsAny(list []*allowlist, match, secret, line string) bool {
	for _, a := range list {
		if a.allows(match, secret, line) {
			return true
		}
	}
	return false
}

// lineAt 返回命中所在整行，等价于上游 finding.Line：从匹配起点所在行首到匹配
// 终点所在行尾。
func lineAt(text string, start, end int) string {
	if start < 0 {
		start = 0
	}
	if end > len(text) {
		end = len(text)
	}
	if start > end {
		return ""
	}
	lineStart := strings.LastIndexByte(text[:start], '\n') + 1
	nl := strings.IndexByte(text[end:], '\n')
	lineEnd := len(text)
	if nl >= 0 {
		lineEnd = end + nl
	}
	return text[lineStart:lineEnd]
}
