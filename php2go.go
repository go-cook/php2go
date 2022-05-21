package php2go

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"golang.org/x/crypto/bcrypt"
	"hash"
	"hash/crc32"
	"io"
	"io/ioutil"
	"math"
	"math/rand"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode"
	"unicode/utf8"
)

func GetEnv(varName string) string {
	return os.Getenv(varName)
}

func GoVersion() string {
	return runtime.Version()
}

func HMAC256(ciphertext, key []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(ciphertext))
	return mac.Sum(nil)
}

func HashHmac(h func() hash.Hash, ciphertext, key []byte) []byte {
	mac := hmac.New(h, key)
	mac.Write([]byte(ciphertext))
	return mac.Sum(nil)
}

func Shuffle(source any) {
	valueOf := reflect.ValueOf(source)
	if valueOf.Type().Kind() != reflect.Slice {
		return
	}
	length := valueOf.Len()
	if length < 2 {
		return
	}
	rand.Seed(time.Now().Unix())
	swapper := reflect.Swapper(source)
	for i := 0; i < length; i++ {
		j := rand.Intn(length)
		swapper(i, j)
	}
}

func MethodExists(obj any, method string) bool {
	valueOf := reflect.ValueOf(obj)
	methodVal := valueOf.MethodByName(method)
	return methodVal.IsValid()
}

func GetClass(obj any) string {
	valueOf := reflect.ValueOf(obj)
	return reflect.Indirect(valueOf).Type().Name()
}

func ParseUrl(str string) (*url.URL, error) {
	return url.Parse(str)
}

func StrrRchr(str, chr string) string {
	if len(str) == 0 || len(chr) == 0 {
		return ""
	}
	if index := strings.LastIndex(str, chr); index != -1 {
		return str[index:]
	}
	return ""
}

// Strtr eg:
//	replace := make(map[string]string)
//	replace["Golang"] = "PHP"
//	fmt.Println(Strtr("Golang is the best language in the world", replace))
func Strtr(str string, replace map[string]string) string {
	if len(replace) == 0 || len(str) == 0 {
		return str
	}
	for old, n := range replace {
		str = strings.ReplaceAll(str, old, n)
	}
	return str
}

func ArrayDiffAssoc(s1, s2 map[string]any) map[string]any {
	r := make(map[string]any)
	for k, v := range s1 {
		if c, ok := s2[k]; !ok || c != v {
			r[k] = v
		}
	}
	return r
}

func Stripos(haystack string, needle string, offset ...int) int {
	off := 0
	if len(offset) > 0 {
		off = offset[0]
	}
	if off > len(haystack) || off < 0 {
		return -1
	}
	haystack = strings.ToLower(haystack[off:])
	needle = strings.ToLower(needle)
	index := strings.Index(haystack, needle)
	if index != -1 {
		return off + index
	}
	return index
}

func StrSplit(str string, sep string) []string {
	return strings.Split(str, sep)
}

func ArrayCountValues(s []any) map[any]uint {
	r := make(map[any]uint)
	for _, v := range s {
		if c, ok := r[v]; ok {
			r[v] = c + 1
		} else {
			r[v] = 1
		}
	}
	return r
}

func Ip2Long(ipAddress string) uint32 {
	ip := net.ParseIP(ipAddress)
	if ip == nil {
		return 0
	}
	return binary.BigEndian.Uint32(ip.To4())
}

func ParseStr(str string, key string) ([]string, error) {
	parseStr, err := url.ParseQuery(str)
	if err != nil {
		return []string{}, err
	}
	return parseStr[key], nil
}

func Pow(a, b int64) int64 {
	var p int64
	p = 1
	for b > 0 {
		if b&1 != 0 {
			p *= a
		}
		b >>= 1
		a *= a
	}
	return p
}
func ArrayUnique(arr []string) []string {
	size := len(arr)
	result := make([]string, 0, size)
	temp := map[string]struct{}{}
	for i := 0; i < size; i++ {
		if _, ok := temp[arr[i]]; ok != true {
			temp[arr[i]] = struct{}{}
			result = append(result, arr[i])
		}
	}
	return result
}

func Fopen(filePath string) (*os.File, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	return file, nil
}

func ScanDir(dir string) ([]string, error) {
	items, err := ioutil.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var list []string
	for _, item := range items {
		list = append(list, item.Name())
	}
	return list, nil
}

func ArrayDiff(array1 []string, arrayOthers ...[]string) []string {
	c := make(map[string]bool)
	for i := 0; i < len(array1); i++ {
		if _, hasKey := c[array1[i]]; hasKey {
			c[array1[i]] = true
		} else {
			c[array1[i]] = false
		}
	}
	for i := 0; i < len(arrayOthers); i++ {
		for j := 0; j < len(arrayOthers[i]); j++ {
			if _, hasKey := c[arrayOthers[i][j]]; hasKey {
				c[arrayOthers[i][j]] = true
			} else {
				c[arrayOthers[i][j]] = false
			}
		}
	}
	result := make([]string, 0)
	for k, v := range c {
		if !v {
			result = append(result, k)
		}
	}
	return result
}

func ArrayIntersect(array1 []string, arrayOthers ...[]string) []string {
	c := make(map[string]bool)
	for i := 0; i < len(array1); i++ {
		if _, hasKey := c[array1[i]]; hasKey {
			c[array1[i]] = true
		} else {
			c[array1[i]] = false
		}
	}
	for i := 0; i < len(arrayOthers); i++ {
		for j := 0; j < len(arrayOthers[i]); j++ {
			if _, hasKey := c[arrayOthers[i][j]]; hasKey {
				c[arrayOthers[i][j]] = true
			} else {
				c[arrayOthers[i][j]] = false
			}
		}
	}
	result := make([]string, 0)
	for k, v := range c {
		if v {
			result = append(result, k)
		}
	}
	return result
}

func ArraySearch(needle any, hystack any) (index int) {
	index = -1
	switch reflect.TypeOf(hystack).Kind() {
	case reflect.Slice:
		s := reflect.ValueOf(hystack)
		for i := 0; i < s.Len(); i++ {
			if reflect.DeepEqual(needle, s.Index(i).Interface()) == true {
				index = i
				return
			}
		}
	}
	return
}

func MbSubStr(str string, star int, len int) string {
	return string([]rune(str)[star:len])
}

func HtmlSpecialChars(html string) string {
	reg, err := regexp.Compile(`<([\w]+)(\s*[\w]+=([\w]+|"[^"]+"))*>([\S\s]*)<[/]?([\w]+)>`)
	if err != nil {
		return html
	}
	ret := html
	for reg.MatchString(ret) {
		ret = reg.ReplaceAllString(ret, "$4")
	}
	return ret
}

func Sprintf(str string) string {
	return fmt.Sprintf("%s", str)
}

func String2Int(str string) int {
	intNum, _ := strconv.Atoi(str)
	return intNum
}

func String2Int64(str string) int64 {
	intNum, _ := strconv.Atoi(str)
	return int64(intNum)
}

func String2Uint64(str string) uint64 {
	intNum, _ := strconv.Atoi(str)
	return uint64(intNum)
}

func MbStrPos(haystack, needle string) int {
	index := strings.Index(haystack, needle)
	if index == -1 || index == 1 {
		return index
	}
	pos := 0
	total := 0
	reader := strings.NewReader(haystack)
	for {
		_, size, err := reader.ReadRune()
		if err != nil {
			return -1
		}
		total += size
		pos++
		if total == index {
			return pos
		}
	}
}

func DirName(dir string) string {
	return filepath.Dir(dir)
}

func PasswordHash(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes), err
}

func PasswordVerify(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func Addcslashes(s string, c string) string {
	var tmpRune []rune
	strRune := []rune(s)
	list := []rune(c)
	for _, ch := range strRune {
		for _, v := range list {
			if ch == v {
				tmpRune = append(tmpRune, '\\')
			}
		}
		tmpRune = append(tmpRune, ch)
	}
	return string(tmpRune)
}

func StrPadLeft(input string, padLength int, padString string) string {
	output := padString

	for padLength > len(output) {
		output += output
	}

	if len(input) >= padLength {
		return input
	}

	return output[:padLength-len(input)] + input
}

func Die(status int) {
	os.Exit(status)
}

func Exit(status int) {
	os.Exit(status)
}

func Min(nums ...float64) float64 {
	if len(nums) < 2 {
		panic("nums: the nums length is less than 2")
	}
	min := nums[0]
	for i := 1; i < len(nums); i++ {
		min = math.Min(min, nums[i])
	}
	return min
}

func JsonDecode(data string) (map[string]any, error) {
	var dat map[string]any
	err := json.Unmarshal([]byte(data), &dat)
	return dat, err
}

func JsonEncode(data any) (string, error) {
	jsons, err := json.Marshal(data)
	return string(jsons), err
}

func Exec(command string) error {
	return exec.Command(command).Run()
}

func PregReplaceCallback(pattern string, callback func(string) string, subject string) string {
	re := regexp.MustCompile(pattern)
	return re.ReplaceAllStringFunc(subject, callback)
}

func NumberFormat(number float64, decimals uint, decPoint, thousandsSep string) string {
	neg := false
	if number < 0 {
		number -= number
		neg = true
	}
	dec := int(decimals)
	// Will round off
	str := fmt.Sprintf("%."+strconv.Itoa(dec)+"F", number)
	prefix, suffix := "", ""
	if dec > 0 {
		prefix = str[:len(str)-(dec+1)]
		suffix = str[len(str)-dec:]
	} else {
		prefix = str
	}
	sep := []byte(thousandsSep)
	n, l1, l2 := 0, len(prefix), len(sep)
	// thousands sep num
	c := (l1 - 1) / 3
	tmp := make([]byte, l2*c+l1)
	pos := len(tmp) - 1
	for i := l1 - 1; i >= 0; i, n, pos = i-1, n+1, pos-1 {
		if l2 > 0 && n > 0 && n%3 == 0 {
			for j := range sep {
				tmp[pos] = sep[l2-j-1]
				pos--
			}
		}
		tmp[pos] = prefix[i]
	}
	s := string(tmp)
	if dec > 0 {
		s += decPoint + suffix
	}
	if neg {
		s = "-" + s
	}
	return s
}

func StripTags(content string) string {
	re := regexp.MustCompile(`<(.|\n)*?>`)
	return re.ReplaceAllString(content, "")
}

func MicroTime() float64 {
	loc, _ := time.LoadLocation("UTC")
	now := time.Now().In(loc)
	micSeconds := float64(now.Nanosecond())
	return float64(now.Unix()) + micSeconds
}

func PregQuote(str string) string {
	return regexp.QuoteMeta(str)
}

func Stripslashes(str string) string {
	var dstRune []rune
	strRune := []rune(str)
	strLenth := len(strRune)
	for i := 0; i < strLenth; i++ {
		if strRune[i] == []rune{'\\'}[0] {
			i++
		}
		dstRune = append(dstRune, strRune[i])
	}
	return string(dstRune)
}

func Addslashes(str string) string {
	var tmpRune []rune
	strRune := []rune(str)
	for _, ch := range strRune {
		switch ch {
		case []rune{'\\'}[0], []rune{'"'}[0], []rune{'\''}[0]:
			tmpRune = append(tmpRune, []rune{'\\'}[0])
			tmpRune = append(tmpRune, ch)
		default:
			tmpRune = append(tmpRune, ch)
		}
	}
	return string(tmpRune)
}

func Chdir(dir string) (string, error) {
	err := os.Chdir(dir)
	if err != nil {
		return "", err
	}
	return "", nil
}

func System(params ...any) string {
	var cmd *exec.Cmd
	cmdstring := params[0].(string)
	windows := false
	if len(params) > 1 {
		windows = params[1].(bool)
	}
	if !windows {
		cmd = exec.Command("/bin/sh", "-c", cmdstring)
	} else {
		cmd = exec.Command("cmd.exe", "/C", cmdstring)
	}
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	err := cmd.Run()
	if err != nil {
		return ""
	}
	return err.Error()
}

func Uniqid(prefix string) string {
	now := time.Now()
	sec := now.Unix()
	usec := now.UnixNano() % 0x100000
	return fmt.Sprintf("%s%08x%05x", prefix, sec, usec)
}

func IsNumeric(val any) bool {
	switch val.(type) {
	case int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64:
	case float32, float64, complex64, complex128:
		return true
	case string:
		str := val.(string)
		if str == "" {
			return false
		}
		// Trim any whitespace
		str = strings.TrimSpace(str)
		if str[0] == '-' || str[0] == '+' {
			if len(str) == 1 {
				return false
			}
			str = str[1:]
		}
		// hex
		if len(str) > 2 && str[0] == '0' && (str[1] == 'x' || str[1] == 'X') {
			for _, h := range str[2:] {
				if !((h >= '0' && h <= '9') || (h >= 'a' && h <= 'f') || (h >= 'A' && h <= 'F')) {
					return false
				}
			}
			return true
		}
		// 0-9,Point,Scientific
		p, s, l := 0, 0, len(str)
		for i, v := range str {
			if v == '.' { // Point
				if p > 0 || s > 0 || i+1 == l {
					return false
				}
				p = i
			} else if v == 'e' || v == 'E' { // Scientific
				if i == 0 || s > 0 || i+1 == l {
					return false
				}
				s = i
			} else if v < '0' || v > '9' {
				return false
			}
		}
		return true
	}

	return false
}

func Glob(pattern string) ([]string, error) {
	return filepath.Glob(pattern)
}

func Mkdir(filename string, mode os.FileMode) error {
	return os.Mkdir(filename, mode)
}

func FileGetContents(filename string) (string, error) {
	data, err := ioutil.ReadFile(filename)
	return string(data), err
}

func FilePutContents(filename string, data string, mode os.FileMode) error {
	return ioutil.WriteFile(filename, []byte(data), mode)
}

func Empty(val any) bool {
	v := reflect.ValueOf(val)
	switch v.Kind() {
	case reflect.String, reflect.Array:
		return v.Len() == 0
	case reflect.Map, reflect.Slice:
		return v.Len() == 0 || v.IsNil()
	case reflect.Bool:
		return !v.Bool()
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return v.Int() == 0
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		return v.Uint() == 0
	case reflect.Float32, reflect.Float64:
		return v.Float() == 0
	case reflect.Interface, reflect.Ptr:
		return v.IsNil()
	}

	return reflect.DeepEqual(val, reflect.Zero(v.Type()).Interface())
}

func Fgetcsv(handle *os.File, length int, delimiter rune) ([][]string, error) {
	reader := csv.NewReader(handle)
	reader.Comma = delimiter
	// TODO length limit
	return reader.ReadAll()
}

func Filemtime(filename string) (int64, error) {
	fd, err := os.Open(filename)
	if err != nil {
		return 0, err
	}
	defer fd.Close()
	fileinfo, err := fd.Stat()
	if err != nil {
		return 0, err
	}
	return fileinfo.ModTime().Unix(), nil
}

func Fclose(handle *os.File) error {
	return handle.Close()
}

func Chown(filename string, uid, gid int) bool {
	return os.Chown(filename, uid, gid) == nil
}

func Chmod(filename string, mode os.FileMode) bool {
	return os.Chmod(filename, mode) == nil
}

func Realpath(path string) (string, error) {
	return filepath.Abs(path)
}

func Getcwd() (string, error) {
	dir, err := os.Getwd()
	return dir, err
}

func Touch(filename string) (bool, error) {
	fd, err := os.OpenFile(filename, os.O_RDONLY|os.O_CREATE, 0666)
	if err != nil {
		return false, err
	}
	fd.Close()
	return true, nil
}

func Rename(oldname, newname string) error {
	return os.Rename(oldname, newname)
}

func IsWriteable(filename string) bool {
	_, err := syscall.Open(filename, syscall.O_WRONLY, 0)
	if err != nil {
		return false
	}
	return true
}

func IsReadable(filename string) bool {
	_, err := syscall.Open(filename, syscall.O_RDONLY, 0)
	if err != nil {
		return false
	}
	return true
}

func Copy(source, dest string) (bool, error) {
	fd1, err := os.Open(source)
	if err != nil {
		return false, err
	}
	defer fd1.Close()
	fd2, err := os.OpenFile(dest, os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		return false, err
	}
	defer fd2.Close()
	_, e := io.Copy(fd2, fd1)
	if e != nil {
		return false, e
	}
	return true, nil
}

func Delete(filename string) error {
	return os.Remove(filename)
}

func Unlink(filename string) error {
	return os.Remove(filename)
}

func FileSize(filename string) (int64, error) {
	info, err := os.Stat(filename)
	if err != nil && os.IsNotExist(err) {
		return 0, err
	}
	return info.Size(), nil
}

func IsDir(filename string) (bool, error) {
	fd, err := os.Stat(filename)
	if err != nil {
		return false, err
	}
	fm := fd.Mode()
	return fm.IsDir(), nil
}

func IsFile(filename string) bool {
	_, err := os.Stat(filename)
	if err != nil && os.IsNotExist(err) {
		return false
	}
	return true
}

func Stat(filename string) (os.FileInfo, error) {
	return os.Stat(filename)
}

func Octdec(str string) (int64, error) {
	return strconv.ParseInt(str, 8, 0)
}

func Decoct(number int64) string {
	return strconv.FormatInt(number, 8)
}

func Sha1File(path string) (string, error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return "", err
	}
	has := sha1.New()
	has.Write([]byte(data))
	return hex.EncodeToString(has.Sum(nil)), nil
}

func Sha1(str string) string {
	has := sha1.New()
	has.Write([]byte(str))
	return hex.EncodeToString(has.Sum(nil))
}

func Strstr(haystack string, needle string) string {
	if needle == "" {
		return ""
	}
	idx := strings.Index(haystack, needle)
	if idx == -1 {
		return ""
	}
	return haystack[idx+len([]byte(needle))-1:]
}

func StrRepeat(input string, multiplier int) string {
	return strings.Repeat(input, multiplier)
}

func MbStrlen(str string) int {
	return utf8.RuneCountInString(str)
}

func Wordwrap(str string, width uint, br string) string {
	if br == "" {
		br = "\n"
	}
	init := make([]byte, 0, len(str))
	buf := bytes.NewBuffer(init)
	var current uint
	var wordbuf, spacebuf bytes.Buffer
	for _, char := range str {
		if char == '\n' {
			if wordbuf.Len() == 0 {
				if current+uint(spacebuf.Len()) > width {
					current = 0
				} else {
					current += uint(spacebuf.Len())
					spacebuf.WriteTo(buf)
				}
				spacebuf.Reset()
			} else {
				current += uint(spacebuf.Len() + wordbuf.Len())
				spacebuf.WriteTo(buf)
				spacebuf.Reset()
				wordbuf.WriteTo(buf)
				wordbuf.Reset()
			}
			buf.WriteRune(char)
			current = 0
		} else if unicode.IsSpace(char) {
			if spacebuf.Len() == 0 || wordbuf.Len() > 0 {
				current += uint(spacebuf.Len() + wordbuf.Len())
				spacebuf.WriteTo(buf)
				spacebuf.Reset()
				wordbuf.WriteTo(buf)
				wordbuf.Reset()
			}
			spacebuf.WriteRune(char)
		} else {
			wordbuf.WriteRune(char)
			if current+uint(spacebuf.Len()+wordbuf.Len()) > width && uint(wordbuf.Len()) < width {
				buf.WriteString(br)
				current = 0
				spacebuf.Reset()
			}
		}
	}

	if wordbuf.Len() == 0 {
		if current+uint(spacebuf.Len()) <= width {
			spacebuf.WriteTo(buf)
		}
	} else {
		spacebuf.WriteTo(buf)
		wordbuf.WriteTo(buf)
	}
	return buf.String()
}

func ChunkSplit(body string, chunklen uint, end string) string {
	if end == "" {
		end = "\r\n"
	}
	runes, erunes := []rune(body), []rune(end)
	l := uint(len(runes))
	if l <= 1 || l < chunklen {
		return body + end
	}
	ns := make([]rune, 0, len(runes)+len(erunes))
	var i uint
	for i = 0; i < l; i += chunklen {
		if i+chunklen > l {
			ns = append(ns, runes[i:]...)
		} else {
			ns = append(ns, runes[i:i+chunklen]...)
		}
		ns = append(ns, erunes...)
	}
	return string(ns)
}

func Ucwords(str string) string {
	return strings.Title(str)
}

func Dechex(number int64) string {
	return strconv.FormatInt(number, 16)
}

func Hexdec(str string) (int64, error) {
	return strconv.ParseInt(str, 16, 0)
}

func Bin2hex(str string) (string, error) {
	i, err := strconv.ParseInt(str, 2, 0)
	if err != nil {
		return "", err
	}
	return strconv.FormatInt(i, 16), nil
}

func Bindec(str string) (string, error) {
	i, err := strconv.ParseInt(str, 2, 0)
	if err != nil {
		return "", err
	}
	return strconv.FormatInt(i, 10), nil
}

func Decbin(number int64) string {
	return strconv.FormatInt(number, 2)
}

func Max(nums ...float64) float64 {
	if len(nums) < 2 {
		panic("nums: the nums length is less than 2")
	}
	max := nums[0]
	for i := 1; i < len(nums); i++ {
		max = math.Max(max, nums[i])
	}
	return max
}

func Ceil(value float64) float64 {
	return math.Ceil(value)
}

func Floor(value float64) float64 {
	return math.Floor(value)
}

func Round(value float64) float64 {
	return math.Floor(value + 0.5)
}

func Abs(number float64) float64 {
	return math.Abs(number)
}

func ArrayReverse(s []any) []any {
	for i, j := 0, len(s)-1; i < j; i, j = i+1, j-1 {
		s[i], s[j] = s[j], s[i]
	}
	return s
}

func ArrayCombine(s1, s2 []any) map[any]any {
	if len(s1) != len(s2) {
		panic("the number of elements for each slice isn't equal")
	}
	m := make(map[any]any, len(s1))
	for i, v := range s1 {
		m[v] = s2[i]
	}
	return m
}

func ArrayKeyExists(key any, m map[any]any) bool {
	_, ok := m[key]
	return ok
}

func ArrayShift(s *[]any) any {
	if len(*s) == 0 {
		return nil
	}
	f := (*s)[0]
	*s = (*s)[1:]
	return f
}

func ArrayUnshift(s *[]any, elements ...any) int {
	*s = append(elements, *s...)
	return len(*s)
}

func ArrayPop(s *[]any) any {
	if len(*s) == 0 {
		return nil
	}
	ep := len(*s) - 1
	e := (*s)[ep]
	*s = (*s)[:ep]
	return e
}

func ArrayPush(s *[]any, elements ...any) int {
	*s = append(*s, elements...)
	return len(*s)
}

func ArrayColumn(input map[string]map[string]any, columnKey string) []any {
	columns := make([]any, 0, len(input))
	for _, val := range input {
		if v, ok := val[columnKey]; ok {
			columns = append(columns, v)
		}
	}
	return columns
}

func ArrayRand(elements []any) []any {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	n := make([]any, len(elements))
	for i, v := range r.Perm(len(elements)) {
		n[i] = elements[v]
	}
	return n
}

func ArraySlice(s []any, offset, length uint) []any {
	if offset > uint(len(s)) {
		panic("offset: the offset is less than the length of s")
	}
	end := offset + length
	if end < uint(len(s)) {
		return s[offset:end]
	}
	return s[offset:]
}

func ArrayPad(s []any, size int, val any) []any {
	if size == 0 || (size > 0 && size < len(s)) || (size < 0 && size > -len(s)) {
		return s
	}
	n := size
	if size < 0 {
		n = -size
	}
	n -= len(s)
	tmp := make([]any, n)
	for i := 0; i < n; i++ {
		tmp[i] = val
	}
	if size > 0 {
		return append(s, tmp...)
	} else {
		return append(tmp, s...)
	}
}

func ArrayChunk(s []any, size int) [][]any {
	if size < 1 {
		panic("size: cannot be less than 1")
	}
	length := len(s)
	chunks := int(math.Ceil(float64(length) / float64(size)))
	var n [][]any
	for i, end := 0, 0; chunks > 0; chunks-- {
		end = (i + 1) * size
		if end > length {
			end = length
		}
		n = append(n, s[i*size:end])
		i++
	}
	return n
}

func ArrayMerge(ss ...[]any) []any {
	n := 0
	for _, v := range ss {
		n += len(v)
	}
	s := make([]any, 0, n)
	for _, v := range ss {
		s = append(s, v...)
	}
	return s
}

func ArrayValues(elements map[any]any) []any {
	i, vals := 0, make([]any, len(elements))
	for _, val := range elements {
		vals[i] = val
		i++
	}
	return vals
}

func ArrayKeys(elements map[any]any) []any {
	i, keys := 0, make([]any, len(elements))
	for key, _ := range elements {
		keys[i] = key
		i++
	}
	return keys
}

func ArrayFlip(m map[any]any) map[any]any {
	n := make(map[any]any)
	for i, v := range m {
		n[v] = i
	}
	return n
}

func ArrayFill(startIndex int, num uint, value any) map[int]any {
	m := make(map[int]any)
	var i uint
	for i = 0; i < num; i++ {
		m[startIndex] = value
		startIndex++
	}
	return m
}

func HttpBuildQuery(queryData url.Values) string {
	return queryData.Encode()
}

func Ucfirst(str string) string {
	for _, v := range str {
		u := string(unicode.ToUpper(v))
		return u + str[len(u):]
	}
	return ""
}

func UrlDecode(str string) (string, error) {
	return url.QueryUnescape(str)
}

func UrlEncode(str string) string {
	return url.QueryEscape(str)
}

func Rawurldecode(str string) (string, error) {
	return url.QueryUnescape(strings.Replace(str, "%20", "+", -1))
}

func Rawurlencode(str string) string {
	return strings.Replace(url.QueryEscape(str), "+", "%20", -1)
}

func MtRand(min, max int64) int64 {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	return r.Int63n(max-min+1) + min
}

func FileExists(file string) bool {
	if _, err := os.Stat(file); os.IsNotExist(err) {
		return false
	} else {
		return true
	}
}

func Base64Encode(data string) string {
	return base64.StdEncoding.EncodeToString([]byte(data))
}

func Base64Decode(data string) (string, error) {
	dec, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return "", err
	}
	return string(dec), nil
}

func Rand(min int, max int) int {
	for {
		x := rand.Intn(max)
		if x > min {
			return x
		}
	}
}

func Md5File(filename string) (string, error) {
	f, err := os.Open(filename)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := md5.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", h.Sum(nil)), nil
}

func TimeNanoSleep(seconds time.Duration) {
	time.Sleep(time.Nanosecond * seconds)
}

func Sleep(seconds time.Duration) {
	time.Sleep(time.Millisecond * seconds)
}

func Nl2br(str string) string {
	return strings.Replace(str, "\n", "<br />", -1)
}

func PRegSplit(pattern string, subject string) []string {
	a := regexp.MustCompile(pattern)
	return a.Split(subject, -1)
}

func PRegReplace(pattern, replacement, subject string) {
	// TODO
	// re := regexp.MustCompile("a(x*)b")
	// fmt.Println(re.ReplaceAllString("-ab-axxb-", "T"))
	// fmt.Println(re.ReplaceAllString("-ab-axxb-", "$1"))
	// fmt.Println(re.ReplaceAllString("-ab-axxb-", "$1W"))
	// fmt.Println(re.ReplaceAllString("-ab-axxb-", "${1}W"))
}

func PRegMatchAll(pattern string, subject string, matches []string) {
	// TODO
	// re = regexp.MustCompile("a(x*)b")
	// fmt.Printf("%q\n", re.FindAllStringSubmatch("-ab-", -1))
	// fmt.Printf("%q\n", re.FindAllStringSubmatch("-axxb-", -1))
	// fmt.Printf("%q\n", re.FindAllStringSubmatch("-ab-axb-", -1))
	// fmt.Printf("%q\n", re.FindAllStringSubmatch("-axxb-ab-", -1))
}

func PRegMatch(pattern string, subject string, matches []string) {
	// TODO
	// re := regexp.MustCompile("a(x*)b(y|z)c")
	// fmt.Printf("%q\n", re.FindStringSubmatch("-axxxbyc-"))
	// fmt.Printf("%q\n", re.FindStringSubmatch("-abzc-"))
}

func StrReplace(search string, replace string, subject string) string {
	return strings.Replace(subject, search, replace, -1)
}

func StrTouPPer(str string) string {
	return strings.ToUpper(str)
}

func StrToLower(str string) string {
	return strings.ToLower(str)
}

func StrRev(str string) string {
	n := len(str)
	runes := make([]rune, n)
	for _, r := range str {
		n--
		runes[n] = r
	}
	return string(runes[n:])
}

func StrPos(haystack string, needle string) int {
	return strings.Index(haystack, needle)
}

func StrLen(str string) int {
	return len(str)
}

func Hex2Bin(hex string) (string, error) {
	ui, err := strconv.ParseUint(hex, 16, 64)
	if err != nil {
		return "", nil
	}
	return fmt.Sprintf("%016b", ui), nil
}

func Crc32(str string) uint32 {
	data := []byte(str)
	return crc32.ChecksumIEEE(data)
}

func Rtrim(s, cutset string) string {
	return strings.TrimRight(s, cutset)
}

func Ltrim(s, cutset string) string {
	return strings.TrimLeft(s, cutset)
}

func SubStr(str string, start int, length int) string {
	if length == 0 {
		return str[start:]
	}
	if start == 0 {
		return str[:length]
	}
	return str[start:length]
}

func Date(layout string) string {
	t := time.Now()
	if layout == "" {
		return t.Format("2006-01-02 15:04:05")
	}
	return t.Format(layout)
}

func Time() int64 {
	return time.Now().Unix()
}

func StrToTime(str string) (int64, error) {
	layout := "2006-01-02 15:04:05"
	t, err := time.Parse(layout, str)
	if err != nil {
		return 0, err
	}
	return t.Unix(), nil
}

func BaseName(path string) string {
	return filepath.Base(path)
}

func inArray(needle any, hystack any) bool {
	switch key := needle.(type) {
	case string:
		for _, item := range hystack.([]string) {
			if key == item {
				return true
			}
		}
	case int:
		for _, item := range hystack.([]int) {
			if key == item {
				return true
			}
		}
	case int64:
		for _, item := range hystack.([]int64) {
			if key == item {
				return true
			}
		}
	default:
		return false
	}
	return false
}

func Explode(delimiter string, text string) []string {
	if len(delimiter) > len(text) {
		return strings.Split(delimiter, text)
	} else {
		return strings.Split(text, delimiter)
	}
}

func Implode(glue string, pieces []string) string {
	return strings.Join(pieces, glue)
}

func VarDump(expression ...any) {
	fmt.Println(fmt.Sprintf("%#v", expression))
}

func Echo(args string) {
	fmt.Println(fmt.Sprintf("%s", args))
}

func Md5(str string) string {
	h := md5.New()
	_, err := io.WriteString(h, str)
	if err != nil {
		return ""
	}
	return fmt.Sprintf("%x", h.Sum(nil))
}
