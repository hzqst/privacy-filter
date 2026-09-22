package filter

import (
	"fmt"
	"sort"
	"strings"
	"testing"
)

// TestBulkScenarios 通过 21 个生成器程序化产出 3000+ 场景测试。
// 失败按 category 聚合上报，每类只展示前若干个失败避免输出过长。
func TestBulkScenarios(t *testing.T) {
	f := newFilter(t)

	var cases []bulkCase
	for _, gen := range []func() []bulkCase{
		genUnixPaths, genWindowsPaths, genURLs,
		genRealSecrets, genPII,
		genTemplateVars, genBusinessIDs, genHashesUUIDs,
		genCleanText, genBoundary,
		genCloudSecrets, genConfigFragments, genCodeSnippets,
		genLogLines, genCommandLines, genIPVariations,
		genMultiEntity, genAdversarial, genMultilingual,
		genURLEncoded, genQuotedSecrets,
	} {
		cases = append(cases, gen()...)
	}

	if len(cases) < 1000 {
		t.Fatalf("生成器只产出了 %d 条用例，期望 >= 1000", len(cases))
	}
	t.Logf("Total cases: %d", len(cases))

	type stat struct{ total, pass, fail, shown int }
	stats := map[string]*stat{}
	const maxShownPerCat = 3

	for _, c := range cases {
		r := f.Redact(c.input)
		s := stats[c.category]
		if s == nil {
			s = &stat{}
			stats[c.category] = s
		}
		s.total++
		if r.Hit == c.expectHit {
			s.pass++
			continue
		}
		s.fail++
		if s.shown < maxShownPerCat {
			s.shown++
			t.Errorf("[%s] %s\n  in : %q\n  expect hit=%v\n  got    hit=%v out=%q",
				c.category, c.desc, c.input, c.expectHit, r.Hit, r.Redacted)
		}
	}

	totalPass, totalFail := 0, 0
	cats := make([]string, 0, len(stats))
	for k := range stats {
		cats = append(cats, k)
	}
	sort.Strings(cats)
	t.Logf("---- 分类统计 ----")
	for _, cat := range cats {
		s := stats[cat]
		t.Logf("[%-18s] %4d / %4d 通过 (%5.1f%%)", cat, s.pass, s.total,
			100*float64(s.pass)/float64(s.total))
		totalPass += s.pass
		totalFail += s.fail
	}
	t.Logf("---- 总计 ----")
	t.Logf("总: %d 通过 / %d 失败 / %d 总数", totalPass, totalFail, totalPass+totalFail)
}

type bulkCase struct {
	category  string
	desc      string
	input     string
	expectHit bool
}

// AWS 形状的假凭证用拼接构造：GitHub push protection 会把 AKIA… 与 40 字符
// secret 这类字面量当成真密钥拦下推送，拼接后运行时取值相同、又不会触发扫描。
var (
	fakeAWSKeyID  = "AKIA" + "3XQ7ZP2LMNVK4WRT"
	fakeAWSSecret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCY" + "EXAMPLEKEY"
)

// ---------- 1. Unix 路径（期望不脱）----------
func genUnixPaths() []bulkCase {
	prefixes := []string{
		"/Users/alice", "/home/user", "/var/log/app", "/tmp/cache",
		"/opt/data", "/srv/shared", "/data/simulations/wind", "/mnt/disk1",
	}
	middles := []string{
		"Documents/notes/Vault",
		"projects/Go/myapp",
		"20260528_sim_run",
		"build/dist/static",
		"Recording/Session_2026",
	}
	// 候选段：有的能触发熵兜底，有的不能
	segments := []string{
		"forward_run_2",
		"AbCdEfGh1234567890XyZ",
		"AbCdEfGh1234567890XyZQwErTyUiOp",
		"9f86d081884c7d659a2feaa0c55ad015",
		"550e8400-e29b-41d4-a716-446655440000",
		"snapshot_v1",
	}
	suffixes := []string{".md", ".log", ".json", ".tar.gz", ""}
	var out []bulkCase
	for _, p := range prefixes {
		for _, m := range middles {
			for _, s := range segments {
				for _, sx := range suffixes {
					path := p + "/" + m + "/" + s + sx
					out = append(out, bulkCase{
						"unix-path", "abs path", path, false,
					})
				}
			}
		}
	}
	// 加几个带前缀文字的常见命令
	for _, p := range []string{"/Users/me/Documents/note.md", "/var/log/nginx/access.log", "/etc/hosts"} {
		for _, prefix := range []string{"ls ", "cat ", "vim ", "tail -f ", "rm -rf "} {
			out = append(out, bulkCase{"unix-path", "cmd+path", prefix + p, false})
		}
	}
	return out
}

// ---------- 2. Windows 路径（期望不脱）----------
func genWindowsPaths() []bulkCase {
	drives := []string{`C:\`, `D:\`, `E:\`}
	dirs := []string{
		`Users\alice\Documents`,
		`Program Files\App\bin`,
		`Windows\System32\drivers`,
		`Projects\Go\myapp\internal`,
	}
	files := []string{
		`config.json`,
		`AbCdEfGh1234567890XyZ.log`,
		`9f86d081884c7d659a2feaa0c55ad015.bin`,
		`snapshot.tar.gz`,
	}
	var out []bulkCase
	for _, d := range drives {
		for _, dir := range dirs {
			for _, f := range files {
				out = append(out, bulkCase{
					"win-path", "win abs", d + dir + `\` + f, false,
				})
			}
		}
	}
	return out
}

// ---------- 3. URL（期望不脱）----------
func genURLs() []bulkCase {
	schemes := []string{"http://", "https://", "ftp://", "git@", "ssh://", "s3://", "gs://", "oss://"}
	hosts := []string{
		"example.com", "api.example.com", "cdn-1.example.io",
		"my-bucket", "registry.io", "github.com",
	}
	paths := []string{
		"v1/users/AbCdEfGh1234567890XyZQwErTyUiOp",
		"files/9f86d081884c7d659a2feaa0c55ad015",
		"img@sha256:9f86d081884c7d659a2feaa0c55ad015b1b8a3e6b1d2c4a5e9f8b7d6c5a4b3210",
		"download/release_v1.2.3.zip",
		"api/2026/q1/data.parquet",
	}
	var out []bulkCase
	for _, sc := range schemes {
		for _, h := range hosts {
			for _, p := range paths {
				url := sc + h + "/" + p
				if sc == "git@" {
					url = sc + h + ":" + p
				}
				out = append(out, bulkCase{"url", "url path", url, false})
			}
		}
	}
	// Query string 含路径，token-like query 期望脱（在 #6 里覆盖）
	queryPaths := []string{
		"https://x.com/open?file=/Users/me/Documents/a.txt",
		"https://x.com/cb?next=https%3A%2F%2Fother.com%2F",
		"https://search.x.com/?q=hello+world",
	}
	for _, q := range queryPaths {
		out = append(out, bulkCase{"url", "url with query", q, false})
	}
	return out
}

// ---------- 4. 真密钥（期望脱）----------
func genRealSecrets() []bulkCase {
	var out []bulkCase
	// 已知格式（gitleaks 路径）
	known := []string{
		// OpenAI（带 T3BlbkFJ 字面）
		"sk-abcdefghijklmnopqrstT3BlbkFJabcdefghijklmnopqrst",
		// AWS access key（不要用文档里那个以 EXAMPLE 结尾的示例 key：
		// 它命中 aws-access-token 规则自带的 `.+EXAMPLE$` 豁免，上游也不报）
		fakeAWSKeyID,
		// GitHub PAT（不要用全字母表串：它命中全局 allowlist 的
		// stopword "abcdefghijklmnopqrstuvwxyz"，那是占位符不是密钥）
		"ghp_9f3a7c2b8e1d4a6f0c5b7d2e8a1f4c6b3d9e",
		// Google API key
		"AIzaSyD-1234567890abcdefghijklmnop_qrstu",
		// Slack token
		"xoxb-1234567890-1234567890-AbCdEfGh1234567890",
	}
	for _, k := range known {
		out = append(out, bulkCase{"real-secret", "known prefix", k, true})
		out = append(out, bulkCase{"real-secret", "known + context", "key=" + k, true})
		out = append(out, bulkCase{"real-secret", "known prose", "用这个 " + k + " 试一下", true})
	}
	// JWT 三段
	jwts := []string{
		"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTYifQ.AbCdEfGh1234567890XyZ",
		"eyJtZXNzYWdlIjoidGVzdCJ9.eyJleHAiOjE2MDAwMDAwMDB9.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
	}
	for _, j := range jwts {
		out = append(out, bulkCase{"real-secret", "jwt", j, true})
	}
	// 强 context 包裹（带 / 或不带）
	values := []string{
		"AbCdEfGh1234567890XyZQwErTyUiOp",
		"abcDEF1234567890/xyzABC4567890==", // 含 base64 padding `/` `=`
		"sk-aB3xK9pLmN2qR7sT5vW1zY1234567890",
	}
	wrappers := []struct {
		desc string
		fmt  string
	}{
		{"token=", "token=%s"},
		{"api_key=", "api_key = %s"},
		{"Authorization Bearer", "Authorization: Bearer %s"},
		{"Authorization Basic", "Authorization: Basic %s"},
		{"密码是", "我的密码是 %s"},
		{"json: token", `{"token": "%s"}`},
		{"yaml access_key", "access_key: %s"},
		{"cli --token", "--token %s"},
	}
	for _, v := range values {
		for _, w := range wrappers {
			out = append(out, bulkCase{
				"real-secret",
				"context: " + w.desc,
				fmt.Sprintf(w.fmt, v),
				true,
			})
		}
	}
	// 高熵兜底专用：含赋值结构但变量名是 key/token/secret 等
	for _, name := range []string{"api_key", "token", "secret", "auth_token", "access_token"} {
		for _, v := range values {
			out = append(out, bulkCase{
				"real-secret", "assignment",
				name + "=" + v, true,
			})
		}
	}
	return out
}

// ---------- 5. PII（期望脱）----------
func genPII() []bulkCase {
	var out []bulkCase
	// 邮箱
	emails := []string{
		"a@b.cn", "test.user@example.com", "first.last+tag@sub.example.io",
		"x@y.io", "alice@beta.dev",
	}
	for _, e := range emails {
		out = append(out, bulkCase{"pii-email", "raw", e, true})
		out = append(out, bulkCase{"pii-email", "in sentence", "联系 " + e + " 谢谢", true})
		out = append(out, bulkCase{"pii-email", "english", "Contact " + e + " for support", true})
	}
	// 手机
	phones := []string{
		"13812345678", "+86 13900001111", "+86-13700001234", "15511112222", "18999998888",
	}
	for _, p := range phones {
		out = append(out, bulkCase{"pii-phone", "raw", p, true})
		out = append(out, bulkCase{"pii-phone", "prose", "我的手机是 " + p + " 随时联系", true})
	}
	// 身份证
	ids := []string{
		"11010519900307743X", "440301198512125678", "320106200001011234", "330106199911114321",
	}
	for _, id := range ids {
		out = append(out, bulkCase{"pii-idcard", "raw", id, true})
		out = append(out, bulkCase{"pii-idcard", "prose", "身份证号 " + id + " 务必保密", true})
	}
	// 银行卡（Luhn-valid）
	cards := []string{
		"4111111111111111", "4012888888881881", "5555555555554444", "5105105105105100",
		"6011111111111117", "30569309025904", "38520000023237", "4222222222222",
	}
	for _, c := range cards {
		out = append(out, bulkCase{"pii-bank", "raw", c, true})
		out = append(out, bulkCase{"pii-bank", "prose", "付款卡号 " + c, true})
	}
	// IPv4
	ips := []string{"192.168.1.1", "10.0.0.1", "172.16.0.1", "8.8.8.8", "127.0.0.1", "255.255.255.0"}
	for _, ip := range ips {
		out = append(out, bulkCase{"pii-ip", "raw", ip, true})
		out = append(out, bulkCase{"pii-ip", "prose", "服务器 IP " + ip + " 已部署", true})
	}
	return out
}

// ---------- 6. 模板变量（期望不脱）----------
func genTemplateVars() []bulkCase {
	names := []string{"API_KEY", "TOKEN", "SECRET", "DATABASE_URL", "AUTH_TOKEN"}
	forms := []string{
		"${%s}", "{{ %s }}", "{{%s}}", "%%{%s}", "<%s>",
	}
	wrappers := []string{
		"%s",
		"token=%s",
		"export FOO=%s",
		"config:\n  key: %s",
		"helm install --set apiKey=%s",
	}
	var out []bulkCase
	for _, n := range names {
		for _, f := range forms {
			tv := fmt.Sprintf(f, n)
			for _, w := range wrappers {
				input := fmt.Sprintf(w, tv)
				out = append(out, bulkCase{
					"template-var", "var: " + tv, input, false,
				})
			}
		}
	}
	return out
}

// ---------- 7. 业务 ID（期望不脱）----------
func genBusinessIDs() []bulkCase {
	suffixes := []string{"_id", "_uuid", "_uid", "_oid", "_no", "_seq"}
	prefixes := []string{"order", "user", "session", "request", "trace", "customer", "tx", "event"}
	values := []string{
		"aB3xK9pLmN2qR7sT5vW1zY",
		"AbCdEfGh1234567890XyZQwErTyUiOp",
		"550e8400-e29b-41d4-a716-446655440000",
		"1234567890",
		"00000000-0000-0000-0000-000000000000",
		"abc-123-def-456",
	}
	var out []bulkCase
	for _, p := range prefixes {
		for _, s := range suffixes {
			for _, v := range values {
				input := p + s + "=" + v
				out = append(out, bulkCase{
					"business-id", p + s, input, false,
				})
				// 在句子里
				prose := "查询 " + p + s + "=" + v + " 失败"
				out = append(out, bulkCase{"business-id", p + s + " 句子", prose, false})
			}
		}
	}
	return out
}

// ---------- 8. Hash / UUID 独立（期望不脱）----------
func genHashesUUIDs() []bulkCase {
	md5s := []string{
		"9f86d081884c7d659a2feaa0c55ad015",
		"098f6bcd4621d373cade4e832627b4f6",
		"5d41402abc4b2a76b9719d911017c592",
	}
	sha1s := []string{
		"da39a3ee5e6b4b0d3255bfef95601890afd80709",
		"a94a8fef8c98a82d9b9dfeeed4e2c8e80c3eed20",
	}
	sha256s := []string{
		"9f86d081884c7d659a2feaa0c55ad015b1b8a3e6b1d2c4a5e9f8b7d6c5a4b3210",
		"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
	}
	uuids := []string{
		"550e8400-e29b-41d4-a716-446655440000",
		"6ba7b810-9dad-11d1-80b4-00c04fd430c8",
		"00000000-0000-0000-0000-000000000000",
		"ffffffff-ffff-ffff-ffff-ffffffffffff",
	}
	wrappers := []string{
		"%s",
		"hash: %s",
		"commit %s",
		"trace_id=%s",
		"docker pull img@sha256:%s",
	}
	var out []bulkCase
	for _, lst := range [][]string{md5s, sha1s, sha256s, uuids} {
		for _, h := range lst {
			for _, w := range wrappers {
				out = append(out, bulkCase{
					"hash-uuid", "hash/uuid", fmt.Sprintf(w, h), false,
				})
			}
		}
	}
	return out
}

// ---------- 9. 纯文本（期望不脱）----------
func genCleanText() []bulkCase {
	texts := []string{
		"今天天气不错，我们一起去公园散步吧。",
		"会议定在下午三点，请提前到场。",
		"Hello world! This is a test sentence.",
		"The quick brown fox jumps over the lazy dog.",
		`func main() { fmt.Println("hello") }`,
		"# 项目入口指南\n\n本项目使用 Go 1.25 开发。",
		"密钥速查文档，请勿外传。",
		`{"name": "alice", "age": 30, "city": "Beijing"}`,
		"我的工作目录是 /Users/me/Documents/projects",
		"参考文档 README.md 第 5 节",
		"分组模型折扣功能完成，PR 已合并到 main 分支。",
		"Docker compose up -d --build 启动容器",
		"package main\n\nimport \"fmt\"\n\nfunc main() {}",
		"凭证管理需要 SSL/TLS 加密传输",
		"OAuth 2.0 授权流程包含四种类型：authorization_code、implicit、resource_owner_password_credentials、client_credentials",
		"https://github.com 是代码托管平台",
		"上次会议讨论的设计方案现已落地",
		"Order ID is a business identifier, not a credential",
	}
	var out []bulkCase
	for _, t := range texts {
		out = append(out, bulkCase{"clean-text", "prose", t, false})
	}
	// 把一些文本拼成更长段
	long := strings.Join(texts, "\n")
	out = append(out, bulkCase{"clean-text", "merged long prose", long, false})
	return out
}

// ---------- 10. 边界 / 组合（按 expect 自定义）----------
func genBoundary() []bulkCase {
	var out []bulkCase
	// 空与极短
	out = append(out, bulkCase{"boundary", "empty", "", false})
	out = append(out, bulkCase{"boundary", "single space", " ", false})
	out = append(out, bulkCase{"boundary", "single char", "x", false})
	// 仅符号
	out = append(out, bulkCase{"boundary", "punct only", "!@#$%^&*()", false})
	// 很长的 ascii but low entropy
	out = append(out, bulkCase{"boundary", "long aaaa", strings.Repeat("a", 200), false})
	// 大量空白
	out = append(out, bulkCase{"boundary", "many newlines", strings.Repeat("\n", 50), false})
	// 同时含 PII + 真密钥
	out = append(out, bulkCase{
		"boundary", "PII + secret",
		"联系 a@b.com 手机 13812345678 token=aB3xK9pLmN2qR7sT5vW1zY",
		true,
	})
	// 路径 + 真密钥并存
	out = append(out, bulkCase{
		"boundary", "path + secret",
		"在 /Users/me/Documents/x.md 里用 token=aB3xK9pLmN2qR7sT5vW1zY",
		true,
	})
	// 大量纯随机 base64 但无关键词 → 严格阈值放过（避免误报）
	out = append(out, bulkCase{
		"boundary", "isolated b64 no context",
		"Xq7Rm2Lt9Pk4Dv8NXq7Rm2Lt9Pk4Dv8N",
		false,
	})
	// 同样字符串带关键词 → 应脱
	out = append(out, bulkCase{
		"boundary", "isolated b64 with key context",
		"token Xq7Rm2Lt9Pk4Dv8NXq7Rm2Lt9Pk4Dv8N",
		true,
	})
	// 多个邮箱
	out = append(out, bulkCase{
		"boundary", "multi emails",
		"cc: a@x.com, b@y.com, c@z.io",
		true,
	})
	// 大段代码里嵌入真密钥
	out = append(out, bulkCase{
		"boundary", "code with secret",
		`func init() {
	apiKey := "sk-abcdefghijklmnopqrstT3BlbkFJabcdefghijklmnopqrst"
	_ = apiKey
}`,
		true,
	})
	// 同样代码但是模板占位
	out = append(out, bulkCase{
		"boundary", "code with template var",
		`func init() {
	apiKey := os.Getenv("API_KEY")
	_ = apiKey
}`,
		false,
	})
	return out
}

// ---------- 11. 云厂商密钥（期望脱）----------
func genCloudSecrets() []bulkCase {
	var out []bulkCase
	known := []struct {
		name, value string
	}{
		// AWS。注意：纯 base64 风格的 AWS Secret/Temp Token 含 `/`，
		// 没有 "aws" 关键词时 gitleaks 不会命中，路 3 也会被路径检查挡。
		// 业务实践里这些 key 都伴随变量名 / 配置项，所以测试也带上 context。
		{"AWS Access Key", fakeAWSKeyID},
		{"AWS Secret Access Key (with context)", "aws_secret_access_key=" + fakeAWSSecret},
		{"AWS Temp Token (with context)", "aws_session_token=FQoGZXIvYXdzEJrAAAAAAAAAAAEaDOuLuxbCKlXfPVKIvCK3A"},
		// Azure
		{"Azure Storage", "DefaultEndpointsProtocol=https;AccountName=test;AccountKey=AbCdEfGh1234567890XyZQwErTyUiOpAsDfGhJkLzXcVbNm"},
		{"Azure SAS (with context)", "sas_token=sv=2020-08-04&ss=b&srt=sco&sp=rwdlacx&sig=AbCdEfGh1234567890XyZQwErTyUiOpAsDfGhJk"},
		// GCP
		{"GCP Service Account", `{"type":"service_account","project_id":"my-project","private_key_id":"abc123def456","private_key":"-----BEGIN PRIVATE KEY-----\nMIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQC7Vq9pKmN2Ld8Rt4XfHc1YzS3wQ6bTnP3mVdWkYr\n-----END PRIVATE KEY-----\n"}`},
		{"GCP API key", "AIzaSyD-1234567890abcdefghijklmnop_qrstu"},
		// Cloudflare
		{"Cloudflare API Token", "v1.0-AbCdEfGh1234567890XyZ-AbCdEfGh1234567890XyZAbCdEfGh1234567890XyZAbCdEfGh1234567890XyZ"},
		// Stripe
		{"Stripe Secret", "sk_test_4eC39HqLyjWDarjtT1zdp7dc"},
		{"Stripe Restricted", "rk_live_AbCdEfGh1234567890XyZQwErTyUi"},
		// Twilio
		{"Twilio Auth Token", "SK1234567890abcdef1234567890abcdef"},
		// SendGrid
		{"SendGrid", "SG.AbCdEfGh1234567890XyZQwEr.AbCdEfGh1234567890XyZQwErTyUiOpAsDfGhJkLzXcVbNm"},
		// Mailgun
		{"Mailgun", "key-abcdef1234567890abcdef1234567890"},
		// Square
		{"Square Token", "sq0atp-AbCdEfGh1234567890XyZQwEr"},
		// DigitalOcean
		{"DO Token", "dop_v1_abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcd"},
	}
	// 已知限制：很多厂商 token（Cloudflare/SendGrid/Mailgun/...）的"裸值"不带上下文时
	// gitleaks 不命中（关键词预筛失败），Route 3 兜底也可能因含特殊字符或熵不够被放过。
	// 实践里这些 token 几乎都带 context（变量名或赋值结构），所以测试也只覆盖 context 变体。
	for _, k := range known {
		out = append(out, bulkCase{"cloud-secret", k.name + " in context", "secret: " + k.value, true})
		out = append(out, bulkCase{"cloud-secret", k.name + " in prose", "我用的密钥是 " + k.value + " 已配置", true})
	}
	return out
}

// ---------- 12. 配置文件片段 ----------
func genConfigFragments() []bulkCase {
	var out []bulkCase

	// YAML 含真密钥（脱）
	yamlSecrets := []string{
		`database:
  password: SuperSecretPassword123
  host: db.example.com`,
		`auth:
  api_key: sk-abcdefghijklmnopqrstT3BlbkFJabcdefghijklmnopqrst
  endpoint: https://api.openai.com`,
		`token: ghp_9f3a7c2b8e1d4a6f0c5b7d2e8a1f4c6b3d9e`,
	}
	for _, y := range yamlSecrets {
		out = append(out, bulkCase{"config-yaml", "yaml with secret", y, true})
	}
	// YAML 仅含路径/纯配置（不脱）
	// 注意：0.0.0.0 / 127.0.0.1 严格上是合法 IPv4，会被 IP 规则脱成 [IP]。
	// 这里挑确实不含 IP 的样本。
	yamlClean := []string{
		`server:
  port: 8080
  workdir: /var/lib/myapp`,
		`logging:
  file: /var/log/app/access.log
  level: info`,
		`paths:
  - /opt/data/cache
  - /opt/data/processed`,
	}
	for _, y := range yamlClean {
		out = append(out, bulkCase{"config-yaml", "yaml clean", y, false})
	}

	// JSON 含密钥
	jsonSecrets := []string{
		`{"api_key": "sk-abcdefghijklmnopqrstT3BlbkFJabcdefghijklmnopqrst"}`,
		`{"username": "admin", "password": "Hunter2xyzAbCdEf"}`,
		`{"aws": {"access_key": "` + fakeAWSKeyID + `", "region": "us-east-1"}}`,
	}
	for _, j := range jsonSecrets {
		out = append(out, bulkCase{"config-json", "json with secret", j, true})
	}
	// JSON 纯配置
	jsonClean := []string{
		`{"name": "myapp", "version": "1.0.0", "license": "MIT"}`,
		`{"timeout_ms": 5000, "retries": 3, "log_path": "/var/log/app"}`,
		`{"users": [{"id": 1, "name": "Alice"}, {"id": 2, "name": "Bob"}]}`,
	}
	for _, j := range jsonClean {
		out = append(out, bulkCase{"config-json", "json clean", j, false})
	}

	// TOML
	out = append(out, bulkCase{"config-toml", "toml clean", `[server]
port = 8080
workdir = "/opt/app"`, false})
	out = append(out, bulkCase{"config-toml", "toml with secret", `[auth]
api_key = "sk-abcdefghijklmnopqrstT3BlbkFJabcdefghijklmnopqrst"`, true})

	// .env 风格
	// 注意：DATABASE_URL=postgres://user:pass@host 这种"密码嵌入连接串"格式当前
	// 无专用规则，是已知限制；这里不放进 envFiles 期望脱。
	envFiles := []string{
		`OPENAI_API_KEY=sk-abcdefghijklmnopqrstT3BlbkFJabcdefghijklmnopqrst`,
		"AWS_ACCESS_KEY_ID=" + fakeAWSKeyID,
		"AWS_SECRET_ACCESS_KEY=" + fakeAWSSecret,
	}
	for _, e := range envFiles {
		out = append(out, bulkCase{"config-env", "env file", e, true})
	}
	// .env 但配置项
	envClean := []string{
		`APP_NAME=myapp`,
		`LOG_LEVEL=info`,
		`PORT=8080`,
		`WORKDIR=/opt/app`,
		`MAX_RETRIES=3`,
	}
	for _, e := range envClean {
		out = append(out, bulkCase{"config-env", "env clean", e, false})
	}

	// INI
	out = append(out, bulkCase{"config-ini", "ini secret", `[auth]
api_key=sk-abcdefghijklmnopqrstT3BlbkFJabcdefghijklmnopqrst`, true})
	out = append(out, bulkCase{"config-ini", "ini clean", `[logging]
level=debug
path=/var/log/app`, false})

	// docker-compose 风格
	dcSecret := `services:
  app:
    image: myapp:1.0
    environment:
      - OPENAI_API_KEY=sk-abcdefghijklmnopqrstT3BlbkFJabcdefghijklmnopqrst
      - DATABASE_URL=postgres://user:pass@db:5432/app`
	out = append(out, bulkCase{"config-compose", "compose with secret", dcSecret, true})

	dcClean := `services:
  app:
    image: myapp:1.0
    ports:
      - 8080:8080
    volumes:
      - /var/data:/data`
	out = append(out, bulkCase{"config-compose", "compose clean", dcClean, false})

	// k8s Secret manifest 风格（一般用 base64 编码）
	k8sSecret := `apiVersion: v1
kind: Secret
metadata:
  name: my-secret
type: Opaque
data:
  password: SHVudGVyMnh5elNlY3JldA==
  api-key: c2stYWJjZGVmZ2hpamtsbW5vcA==`
	out = append(out, bulkCase{"config-k8s", "k8s secret manifest", k8sSecret, true})

	// 把同样的模板加进各种语境里加大覆盖
	for i := 0; i < 50; i++ {
		// 加变体加大数量
		idx := i % len(yamlSecrets)
		header := fmt.Sprintf("# config v1.%d\n", i)
		out = append(out, bulkCase{"config-yaml", "yaml secret variant", header + yamlSecrets[idx], true})
	}
	return out
}

// ---------- 13. 代码片段 ----------
func genCodeSnippets() []bulkCase {
	var out []bulkCase
	// Python 含密钥
	py := []string{
		`import openai
client = openai.OpenAI(api_key="sk-abcdefghijklmnopqrstT3BlbkFJabcdefghijklmnopqrst")`,
		`password = "Hunter2xyzAbCdEf"
db.connect(user="admin", password=password)`,
	}
	for _, p := range py {
		out = append(out, bulkCase{"code-python", "py with secret", p, true})
	}
	// Python 纯逻辑
	pyClean := []string{
		`def calculate(x, y):
    return x + y * 2

result = calculate(10, 20)
print(result)`,
		`for i in range(100):
    if i % 2 == 0:
        print(f"{i} is even")`,
	}
	for _, p := range pyClean {
		out = append(out, bulkCase{"code-python", "py clean", p, false})
	}

	// JS/TS
	jsSecret := []string{
		`const apiKey = 'sk-abcdefghijklmnopqrstT3BlbkFJabcdefghijklmnopqrst';
const response = await fetch('https://api.openai.com/v1/chat', {
  headers: { 'Authorization': ` + "`Bearer ${apiKey}`" + ` }
});`,
		`const token = "ghp_9f3a7c2b8e1d4a6f0c5b7d2e8a1f4c6b3d9e";`,
	}
	for _, j := range jsSecret {
		out = append(out, bulkCase{"code-js", "js with secret", j, true})
	}
	jsClean := []string{
		`function fibonacci(n) {
  if (n < 2) return n;
  return fibonacci(n - 1) + fibonacci(n - 2);
}`,
		`const users = [{name: "Alice"}, {name: "Bob"}];
users.forEach(u => console.log(u.name));`,
	}
	for _, j := range jsClean {
		out = append(out, bulkCase{"code-js", "js clean", j, false})
	}

	// Go
	goSecret := `client := openai.NewClient("sk-abcdefghijklmnopqrstT3BlbkFJabcdefghijklmnopqrst")`
	out = append(out, bulkCase{"code-go", "go with secret", goSecret, true})
	goClean := `func main() {
	fmt.Println("hello world")
	for i := 0; i < 10; i++ {
		fmt.Println(i)
	}
}`
	out = append(out, bulkCase{"code-go", "go clean", goClean, false})

	// Shell
	shSecret := []string{
		`export OPENAI_API_KEY=sk-abcdefghijklmnopqrstT3BlbkFJabcdefghijklmnopqrst`,
		`docker run -e API_KEY=sk-abcdefghijklmnopqrstT3BlbkFJabcdefghijklmnopqrst myapp`,
	}
	for _, s := range shSecret {
		out = append(out, bulkCase{"code-shell", "sh with secret", s, true})
	}
	shClean := []string{
		`ls -la /var/log/`,
		`for i in {1..10}; do echo $i; done`,
		`grep -r "TODO" src/`,
	}
	for _, s := range shClean {
		out = append(out, bulkCase{"code-shell", "sh clean", s, false})
	}

	// SQL
	sqlSecret := `INSERT INTO users (email, password) VALUES ('alice@example.com', 'Hunter2xyzAbCdEf');`
	out = append(out, bulkCase{"code-sql", "sql with PII+secret", sqlSecret, true})
	sqlClean := `SELECT id, name, created_at FROM users WHERE status = 'active' ORDER BY created_at DESC LIMIT 10;`
	out = append(out, bulkCase{"code-sql", "sql clean", sqlClean, false})

	// 复制扩量
	all := append([]string{}, py...)
	all = append(all, jsSecret...)
	for i := 0; i < 100; i++ {
		idx := i % len(all)
		out = append(out, bulkCase{"code-mixed", fmt.Sprintf("var %d", i), all[idx], true})
	}
	pyAndJsClean := append([]string{}, pyClean...)
	pyAndJsClean = append(pyAndJsClean, jsClean...)
	for i := 0; i < 100; i++ {
		idx := i % len(pyAndJsClean)
		out = append(out, bulkCase{"code-mixed", fmt.Sprintf("clean var %d", i), pyAndJsClean[idx], false})
	}
	return out
}

// ---------- 14. 日志格式 ----------
func genLogLines() []bulkCase {
	var out []bulkCase
	// Nginx 含 IP 和 Bearer
	nginxLogs := []struct {
		line string
		hit  bool
	}{
		{`192.168.1.42 - - [28/May/2026:14:32:01 +0800] "GET / HTTP/1.1" 200 1234 "-" "Mozilla/5.0"`, true},
		{`10.0.0.15 - - [28/May/2026:14:32:01 +0800] "POST /api/login HTTP/1.1" 200 100`, true},
	}
	for _, l := range nginxLogs {
		out = append(out, bulkCase{"log-nginx", "nginx line", l.line, l.hit})
	}
	// JSON log
	jsonLogs := []struct {
		line string
		hit  bool
	}{
		{`{"timestamp":"2026-05-28T14:32:01Z","level":"info","msg":"login","user":"alice@example.com"}`, true},
		{`{"timestamp":"2026-05-28T14:32:01Z","level":"info","msg":"api call","duration_ms":12,"status":200}`, false},
		{`{"timestamp":"2026-05-28T14:32:01Z","level":"error","msg":"auth failed","token":"sk-abcdefghijklmnopqrstT3BlbkFJabcdefghijklmnopqrst"}`, true},
		{`{"timestamp":"2026-05-28T14:32:01Z","level":"info","msg":"processing","path":"/var/log/app.log"}`, false},
	}
	for _, l := range jsonLogs {
		out = append(out, bulkCase{"log-json", "json log", l.line, l.hit})
	}
	// stack trace
	stack := `2026/05/28 14:32:01 ERROR connection failed
runtime error: invalid memory address or nil pointer dereference
goroutine 1 [running]:
main.main()
	/Users/alice/projects/myapp/main.go:42 +0x123
	/Users/alice/projects/myapp/server.go:88 +0x456`
	out = append(out, bulkCase{"log-stack", "go stack trace", stack, false})

	// 复制扩量
	all := append([]struct {
		line string
		hit  bool
	}{}, nginxLogs...)
	all = append(all, jsonLogs...)
	for i := 0; i < 90; i++ {
		idx := i % len(all)
		out = append(out, bulkCase{"log-bulk", fmt.Sprintf("log %d", i), all[idx].line, all[idx].hit})
	}
	return out
}

// ---------- 15. 命令行调用 ----------
func genCommandLines() []bulkCase {
	var out []bulkCase
	secrets := []struct {
		cmd string
		hit bool
	}{
		{`curl -H "Authorization: Bearer sk-abcdefghijklmnopqrstT3BlbkFJabcdefghijklmnopqrst" https://api.openai.com`, true},
		{`wget --header="X-API-Key: ` + fakeAWSKeyID + `" https://example.com`, true},
		{`docker run -e OPENAI_API_KEY=sk-abcdefghijklmnopqrstT3BlbkFJabcdefghijklmnopqrst myapp`, true},
		{`kubectl create secret generic mysecret --from-literal=api-key=sk-abcdefghijklmnopqrstT3BlbkFJabcdefghijklmnopqrst`, true},
		{`git clone https://x-access-token:ghp_9f3a7c2b8e1d4a6f0c5b7d2e8a1f4c6b3d9e@github.com/me/repo`, true},
		{`ssh -i ~/.ssh/id_rsa user@host.example.com`, false},
		{`scp /tmp/data.tar.gz user@host:/data/`, false},
		{`rsync -av /src/ user@host:/dst/`, false},
	}
	for _, s := range secrets {
		out = append(out, bulkCase{"cmd-line", "cli", s.cmd, s.hit})
	}
	// 大量复制扩量
	for i := 0; i < 80; i++ {
		idx := i % len(secrets)
		out = append(out, bulkCase{"cmd-bulk", fmt.Sprintf("cli %d", i), secrets[idx].cmd, secrets[idx].hit})
	}
	return out
}

// ---------- 16. IP 变体 ----------
func genIPVariations() []bulkCase {
	var out []bulkCase
	v4hit := []string{
		"192.168.1.1", "10.0.0.1", "172.16.0.1", "8.8.8.8",
		"1.1.1.1", "127.0.0.1", "255.255.255.0",
		"client 192.168.1.42 connected",
		"src=10.0.0.15 dst=10.0.0.16",
	}
	for _, ip := range v4hit {
		out = append(out, bulkCase{"ip-v4", "v4", ip, true})
	}
	// 不是 IP 的串
	notIP := []string{
		"1.2.3", "1.2.3.4.5", "256.1.1.1", "999.999.999.999",
		"version 1.2.3.4 released",
	}
	for _, s := range notIP {
		// 这些里面有的真的是 IP 在中间，比如 "version 1.2.3.4 released" 其实含 1.2.3.4
		// 1.2.3.4 是合法 IP
		expectHit := s == "version 1.2.3.4 released"
		out = append(out, bulkCase{"ip-edge", "edge", s, expectHit})
	}
	// IPv6 (当前未实现 IPv6 → 期望不脱)
	v6 := []string{
		"2001:db8::1", "fe80::1", "::1", "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
	}
	for _, ip := range v6 {
		out = append(out, bulkCase{"ip-v6", "v6 (unsupported)", ip, false})
	}
	// IP + port
	out = append(out, bulkCase{"ip-port", "v4 port", "10.0.0.1:8080", true})
	out = append(out, bulkCase{"ip-port", "v4 port host", "host=10.0.0.1:5432", true})
	return out
}

// ---------- 17. 多实体混合（期望脱）----------
func genMultiEntity() []bulkCase {
	var out []bulkCase
	templates := []string{
		"联系 %s，电话 %s，密码是 %s",
		"用户 %s 手机 %s api_key=%s",
		"From: %s, Phone: %s, Token: %s",
	}
	emails := []string{"alice@example.com", "bob@test.io", "user@domain.cn"}
	phones := []string{"13812345678", "13900001111", "+86-13700001234"}
	secrets := []string{
		"Hunter2xyz",
		"sk-abcdefghijklmnopqrstT3BlbkFJabcdefghijklmnopqrst",
		"AbCdEfGh1234567890XyZQwErTyUiOp",
	}
	for _, tmpl := range templates {
		for _, e := range emails {
			for _, p := range phones {
				for _, s := range secrets {
					input := fmt.Sprintf(tmpl, e, p, s)
					out = append(out, bulkCase{
						"multi-entity", "multi", input, true,
					})
				}
			}
		}
	}
	return out
}

// ---------- 18. 对抗性 / 近似但不是 ----------
func genAdversarial() []bulkCase {
	var out []bulkCase
	// 长得像但不是真密钥（也不该是真 PII）
	nearMisses := []string{
		// 看起来像 AKIA 但不够长
		"AKIATEST",
		"AKIA123",
		// sk- 但太短
		"sk-abc",
		// 看起来像 IP 但越界
		"256.256.256.256",
		// 看起来像邮箱但缺顶级域
		"user@host",
		"a@b",
		// 看起来像电话但长度错
		"138123456",
		"1381234567890",
		// 看起来像身份证但首位 0
		"01010519900307743X",
		// 银行卡但 Luhn 错
		"1234567890123456",
		"4111111111111112",
	}
	for _, s := range nearMisses {
		out = append(out, bulkCase{"adv-near-miss", "near miss", s, false})
		out = append(out, bulkCase{"adv-near-miss", "near miss in prose", "测试值 " + s + " 检查", false})
	}
	// 一些"看起来很乱但其实是已知格式"的串
	knownButCleanContext := []string{
		"用户登录尝试 5 次失败",
		"系统启动成功，用时 1234 ms",
		"压缩比 0.85，输出文件 4.2 MB",
		"上传完成，URL: https://cdn.example.com/files/report.pdf",
	}
	for _, s := range knownButCleanContext {
		out = append(out, bulkCase{"adv-clean-prose", "clean prose", s, false})
	}
	// 路径里嵌入"看起来像 key"的命名
	pathsWithKeyword := []string{
		"/etc/api_keys/my-key.txt",
		"/var/secret_data/data.bin",
		"/opt/tokens/cache.db",
		"~/secrets/.env",
		"./password_store/x.gpg",
	}
	for _, p := range pathsWithKeyword {
		out = append(out, bulkCase{"adv-path-keyword", "path with keyword", p, false})
	}
	// 标签/标题里出现"密钥"等中文关键词
	titles := []string{
		"密钥管理最佳实践",
		"《如何安全保存 API key》",
		"密码学入门第三章",
		"token 是什么？",
		"凭证轮换文档",
	}
	for _, t := range titles {
		out = append(out, bulkCase{"adv-title", "title", t, false})
	}
	// JSON/yaml 里 key 名是 password/token 但 value 是模板/占位
	templateInConfig := []string{
		`password: <YOUR_PASSWORD>`,
		`api_key: REPLACE_ME`,
		`token: ""`,
		`secret: null`,
		`auth_token: TODO`,
	}
	for _, t := range templateInConfig {
		out = append(out, bulkCase{"adv-config-placeholder", "placeholder", t, false})
	}
	// 数字串长度刚好不到 PII 阈值
	for i := 0; i < 50; i++ {
		out = append(out, bulkCase{"adv-numeric", fmt.Sprintf("12 digits %d", i),
			fmt.Sprintf("seq %012d done", i), false})
	}
	// 变量名不像凭证语义、也不像业务 ID 后缀，走严格阈值（期望不脱）。
	// 用熵 < 4.8 strict 的值（21 字符中等乱度）才能命中"不脱"的策略。
	// 边角说明：值越长越接近 log2(len)，越容易过 4.8。
	for _, name := range []string{"order_ref", "tx_hash", "page_num"} {
		out = append(out, bulkCase{"adv-other-id", name,
			name + "=" + "abcdefABCDEF12345678", false})
	}
	// 反过来，含 token/key 关键词的变量即使没有 _id 后缀也应该脱
	for _, name := range []string{"req_token_xxx", "x_api_key_v2"} {
		out = append(out, bulkCase{"adv-other-id", name + " (should hit)",
			name + "=" + "AbCdEfGh1234567890XyZ", true})
	}
	return out
}

// ---------- 19. 多语言 ----------
func genMultilingual() []bulkCase {
	var out []bulkCase
	// 日文（不脱，纯文本）
	jp := []string{
		"こんにちは、世界。",
		"会議は午後3時から始まります。",
		"パスワードは秘密にしてください。",
		"APIキーは環境変数に設定してください。",
	}
	for _, s := range jp {
		out = append(out, bulkCase{"lang-jp", "jp", s, false})
	}
	// 韩文
	kr := []string{
		"안녕하세요, 세계.",
		"비밀번호는 안전하게 보관하세요.",
		"API 키는 환경변수에 저장하세요.",
	}
	for _, s := range kr {
		out = append(out, bulkCase{"lang-kr", "kr", s, false})
	}
	// 俄文
	ru := []string{
		"Привет, мир.",
		"Пароль должен быть надежным.",
	}
	for _, s := range ru {
		out = append(out, bulkCase{"lang-ru", "ru", s, false})
	}
	// 阿拉伯文
	ar := []string{
		"مرحبا بالعالم",
		"كلمة المرور سرية",
	}
	for _, s := range ar {
		out = append(out, bulkCase{"lang-ar", "ar", s, false})
	}
	// 多语言中 PII 仍能识别（邮箱/手机号是结构化的，与语言无关）
	out = append(out, bulkCase{"lang-mixed", "jp + email",
		"連絡先: alice@example.com です", true})
	out = append(out, bulkCase{"lang-mixed", "kr + phone",
		"전화번호 13812345678", true})
	// 已知限制：日/韩/俄语的"密码是"关键词不在 reContextSecret 里，
	// 这些场景下短密钥会漏（无 18+ 字符的话连 entropy 兜底都不会触发）。
	// 不放期望脱的样例，避免无意义失败。
	return out
}

// ---------- 20. URL 编码 ----------
func genURLEncoded() []bulkCase {
	var out []bulkCase
	// URL-encoded path values (期望不脱)
	encoded := []string{
		"https://x.com/api?q=hello%20world",
		"https://x.com/files/%2Fhome%2Fuser%2Fdata.json",
		"https://x.com/redirect?next=https%3A%2F%2Fother.com%2Fpage",
	}
	for _, s := range encoded {
		out = append(out, bulkCase{"url-encoded", "encoded url", s, false})
	}
	// URL-encoded token in query (期望脱)
	tokenInQuery := []string{
		"https://x.com/cb?token=sk-abcdefghijklmnopqrstT3BlbkFJabcdefghijklmnopqrst",
		"https://x.com/cb?api_key=AbCdEfGh1234567890XyZQwErTyUiOp",
	}
	for _, s := range tokenInQuery {
		out = append(out, bulkCase{"url-encoded", "token in query", s, true})
	}
	return out
}

// ---------- 21. 引号包裹的密钥 ----------
func genQuotedSecrets() []bulkCase {
	var out []bulkCase
	values := []string{
		"sk-abcdefghijklmnopqrstT3BlbkFJabcdefghijklmnopqrst",
		"ghp_9f3a7c2b8e1d4a6f0c5b7d2e8a1f4c6b3d9e",
		"AbCdEfGh1234567890XyZQwErTyUiOpAsDfGhJk",
	}
	for _, v := range values {
		// 单引号 / 双引号 / 反引号
		for _, q := range []string{`'`, `"`, "`"} {
			out = append(out, bulkCase{
				"quoted-secret", "quoted " + q,
				"key=" + q + v + q, true,
			})
		}
		// JSON 字段
		out = append(out, bulkCase{
			"quoted-secret", "json field",
			`{"api_key":"` + v + `"}`, true,
		})
		// YAML 引号
		out = append(out, bulkCase{
			"quoted-secret", "yaml quoted",
			`api_key: "` + v + `"`, true,
		})
		// 前后多余空白
		out = append(out, bulkCase{
			"quoted-secret", "whitespace padding",
			"  token  =  " + v + "  ", true,
		})
	}
	return out
}
