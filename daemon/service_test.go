package daemon

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// 验证嵌入的服务模板只使用 Unix 换行符，避免 init.d 的解释器路径带入回车符
func TestEmbeddedServiceFilesUseUnixLineEndings(t *testing.T) {
	assert.NotContains(t, string(InitdServiceFile), "\r")
	assert.NotContains(t, string(SystemdServiceFile), "\r")
}
