package cmd

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// 验证 Bash 补全脚本会安装到第一个存在的补全目录，并在卸载时删除
func TestBashCompletionLifecycle(t *testing.T) {
	oldDirs := bashCompletionDirs
	bashCompletionDirs = []string{
		filepath.Join(t.TempDir(), "not-exist"),
		t.TempDir(),
	}
	t.Cleanup(func() { bashCompletionDirs = oldDirs })

	completionFile := filepath.Join(bashCompletionDirs[1], "wg-quick-op")
	installBashCompletion()
	contents, err := os.ReadFile(completionFile)
	require.NoError(t, err)
	assert.Contains(t, string(contents), "wg-quick-op")

	uninstallBashCompletion()
	_, err = os.Stat(completionFile)
	assert.True(t, os.IsNotExist(err))
}
