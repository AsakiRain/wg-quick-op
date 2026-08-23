package daemon

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// 验证 PATH 检测能识别安装目录，并允许目录末尾带斜杠
func TestPathContainsDir(t *testing.T) {
	pathValue := strings.Join([]string{"/usr/bin", "/usr/sbin/", "/bin"}, string(os.PathListSeparator))

	assert.True(t, pathContainsDir(pathValue, "/usr/sbin"))
	assert.False(t, pathContainsDir(pathValue, "/usr/local/sbin"))
}
