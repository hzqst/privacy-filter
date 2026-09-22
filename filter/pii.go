package filter

import (
	"regexp"
	"strings"
)

// 结构化 PII 正则。Go 的 regexp 是 RE2，不支持前后向断言，
// 因此数字边界用 digitBounded / ipBounded 在匹配后手工校验。
var (
	reEmail    = regexp.MustCompile(`[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}`)
	rePhoneCN  = regexp.MustCompile(`(?:\+?86[-\s]?)?1[3-9][0-9]{9}`)
	reIDCard   = regexp.MustCompile(`[1-9][0-9]{16}[0-9Xx]`)
	reBankCard = regexp.MustCompile(`[0-9]{13,19}`)
	reIPv4     = regexp.MustCompile(`(?:(?:25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9])`)
)

// 结构化 PII 检测器的标识。Options.DisabledPII 用这些值选择性关闭。
const (
	PIIEmail    = "email"
	PIIPhone    = "phone"
	PIIIDCard   = "id_card"
	PIIIP       = "ip"
	PIIBankCard = "bank_card"
)

// PIITypes 列出全部结构化 PII 检测器标识，供调用方校验配置。
var PIITypes = []string{PIIEmail, PIIPhone, PIIIDCard, PIIIP, PIIBankCard}

// NormalizePIIType 归一化 PII 类型标识：去掉首尾空白并转小写。
func NormalizePIIType(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}

// IsKnownPIIType 判断标识是否为已支持的结构化 PII 检测器。
func IsKnownPIIType(s string) bool {
	t := NormalizePIIType(s)
	for _, known := range PIITypes {
		if t == known {
			return true
		}
	}
	return false
}

// 远程命令前缀。user@host 出现在这些命令上下文里通常是 SSH 目标，不是邮箱。
var sshCommands = []string{"ssh ", "scp ", "rsync ", "sftp ", "ssh-copy-id ", "ssh-keygen "}

// isInSSHCommandContext 检查 email 命中是否处于 ssh/scp/rsync 命令行里。
// 找到 email 所在行，看行内是否出现 ssh/scp/rsync 命令前缀（不限行首，
// 容忍 "打开 ssh user@host" 这种自然语言包裹）。
func isInSSHCommandContext(text string, emailStart int) bool {
	lineStart := strings.LastIndexByte(text[:emailStart], '\n') + 1
	line := text[lineStart:emailStart]
	for _, cmd := range sshCommands {
		if strings.Contains(line, cmd) {
			return true
		}
	}
	return false
}

func isDigit(b byte) bool { return b >= '0' && b <= '9' }

// digitBounded 校验匹配两侧不是数字（替代 RE2 没有的前后向断言）。
func digitBounded(text string, start, end int) bool {
	if start > 0 && isDigit(text[start-1]) {
		return false
	}
	if end < len(text) && isDigit(text[end]) {
		return false
	}
	return true
}

// ipBounded 校验匹配两侧不是数字或点。
func ipBounded(text string, start, end int) bool {
	if start > 0 && (isDigit(text[start-1]) || text[start-1] == '.') {
		return false
	}
	if end < len(text) && (isDigit(text[end]) || text[end] == '.') {
		return false
	}
	return true
}

// luhnValid 做 Luhn 校验，过滤掉「长得像卡号的普通数字串」。
func luhnValid(num string) bool {
	sum := 0
	double := false
	for i := len(num) - 1; i >= 0; i-- {
		d := int(num[i] - '0')
		if double {
			if d *= 2; d > 9 {
				d -= 9
			}
		}
		sum += d
		double = !double
	}
	return sum%10 == 0
}

// detectPII 返回结构化 PII 的命中区间。disabled 里的检测器会被跳过，nil 表示全部启用。
func detectPII(text string, disabled map[string]bool) []span {
	var spans []span
	if !disabled[PIIEmail] {
		for _, m := range reEmail.FindAllStringIndex(text, -1) {
			// SSH-style URL: user@host:path —— 邮箱后紧接 ":" + 非空白字符 → 视作 git@ URL，不脱
			if m[1] < len(text) && text[m[1]] == ':' &&
				m[1]+1 < len(text) && text[m[1]+1] != ' ' && text[m[1]+1] != '\t' {
				continue
			}
			// SSH 命令上下文：ssh / scp / rsync user@host 这种调用，host 不是邮箱
			if isInSSHCommandContext(text, m[0]) {
				continue
			}
			spans = append(spans, span{m[0], m[1], "[邮箱]"})
		}
	}
	if !disabled[PIIPhone] {
		for _, m := range rePhoneCN.FindAllStringIndex(text, -1) {
			if digitBounded(text, m[0], m[1]) {
				spans = append(spans, span{m[0], m[1], "[电话]"})
			}
		}
	}
	if !disabled[PIIIDCard] {
		for _, m := range reIDCard.FindAllStringIndex(text, -1) {
			if digitBounded(text, m[0], m[1]) {
				spans = append(spans, span{m[0], m[1], "[身份证]"})
			}
		}
	}
	if !disabled[PIIIP] {
		for _, m := range reIPv4.FindAllStringIndex(text, -1) {
			if ipBounded(text, m[0], m[1]) {
				spans = append(spans, span{m[0], m[1], "[IP]"})
			}
		}
	}
	if !disabled[PIIBankCard] {
		for _, m := range reBankCard.FindAllStringIndex(text, -1) {
			if digitBounded(text, m[0], m[1]) && luhnValid(text[m[0]:m[1]]) {
				spans = append(spans, span{m[0], m[1], "[银行卡]"})
			}
		}
	}
	return spans
}
