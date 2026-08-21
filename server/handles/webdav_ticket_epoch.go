package handles

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/OpenListTeam/OpenList/v4/internal/driver"
	"github.com/OpenListTeam/OpenList/v4/internal/fs"
	"github.com/OpenListTeam/OpenList/v4/internal/model"
	"github.com/OpenListTeam/OpenList/v4/internal/op"
	"github.com/OpenListTeam/OpenList/v4/server/common"
	"github.com/gin-gonic/gin"
)

type RevokeTicketReq struct {
	Path string `json:"path" binding:"required"`
}

var (
	epochMu         sync.RWMutex
	userFileEpoch   = make(map[string]int)
	globalFileEpoch = make(map[string]int)
)

func GetGlobalFileEpoch(canonicalPath string) int {
	epochMu.RLock()
	defer epochMu.RUnlock()
	if v, ok := globalFileEpoch[canonicalPath]; ok && v > 0 {
		return v
	}
	return 1
}

func GetUserFileEpoch(uid uint, canonicalPath string) int {
	epochMu.RLock()
	defer epochMu.RUnlock()
	key := fmt.Sprintf("%d:%s", uid, canonicalPath)
	if v, ok := userFileEpoch[key]; ok && v > 0 {
		return v
	}
	return 1
}

func SyncEpochToWebDAV(d driver.Driver, filename string, epoch int) error {
	type Syncer interface {
		WriteRevocationFile(name string, data []byte) error
	}
	if s, ok := d.(Syncer); ok {
		payload, _ := json.Marshal(map[string]interface{}{
			"epoch":      epoch,
			"revoked_at": time.Now().Unix(),
		})
		return s.WriteRevocationFile(filename, payload)
	}
	return nil
}

func RevokeUserFileTicket(c *gin.Context) {
	user := c.MustGet("user").(*model.User)
	var req RevokeTicketReq
	if err := c.ShouldBindJSON(&req); err != nil {
		common.ErrorResp(c, err, 400)
		return
	}
	reqPath := req.Path
	obj, err := fs.Get(c.Request.Context(), reqPath, &fs.GetArgs{})
	if err != nil {
		common.ErrorResp(c, err, 404)
		return
	}

	epochMu.Lock()
	key := fmt.Sprintf("%d:%s", user.ID, reqPath)
	cur := userFileEpoch[key]
	if cur <= 0 {
		cur = 1
	}
	newEpoch := cur + 1
	userFileEpoch[key] = newEpoch
	epochMu.Unlock()

	storageDriver, _, err := op.GetStorageAndActualPath(reqPath)
	if err == nil && storageDriver != nil {
		hashKey := fmt.Sprintf("%d:%s", user.ID, reqPath)
		hashHex := hex.EncodeToString(sha256Hash([]byte(hashKey)))
		_ = SyncEpochToWebDAV(storageDriver, fmt.Sprintf("userfile-%s.json", hashHex), newEpoch)
	}

	freshLink, _, _ := fs.Link(c.Request.Context(), reqPath, model.LinkArgs{Redirect: true})
	rawURL := ""
	if freshLink != nil {
		rawURL = freshLink.URL
	}
	common.SuccessResp(c, gin.H{
		"message": "User file ticket revoked successfully",
		"epoch":   newEpoch,
		"raw_url": rawURL,
		"obj":     obj,
	})
}

func RevokeGlobalFileTicket(c *gin.Context) {
	user := c.MustGet("user").(*model.User)
	if user.Role != model.ADMIN {
		common.ErrorStrResp(c, "Admin permission required", 403)
		return
	}
	var req RevokeTicketReq
	if err := c.ShouldBindJSON(&req); err != nil {
		common.ErrorResp(c, err, 400)
		return
	}
	reqPath := req.Path
	obj, err := fs.Get(c.Request.Context(), reqPath, &fs.GetArgs{})
	if err != nil {
		common.ErrorResp(c, err, 404)
		return
	}

	epochMu.Lock()
	cur := globalFileEpoch[reqPath]
	if cur <= 0 {
		cur = 1
	}
	newEpoch := cur + 1
	globalFileEpoch[reqPath] = newEpoch
	epochMu.Unlock()

	storageDriver, _, err := op.GetStorageAndActualPath(reqPath)
	if err == nil && storageDriver != nil {
		hashHex := hex.EncodeToString(sha256Hash([]byte(reqPath)))
		_ = SyncEpochToWebDAV(storageDriver, fmt.Sprintf("file-%s.json", hashHex), newEpoch)
	}

	freshLink, _, _ := fs.Link(c.Request.Context(), reqPath, model.LinkArgs{Redirect: true})
	rawURL := ""
	if freshLink != nil {
		rawURL = freshLink.URL
	}
	common.SuccessResp(c, gin.H{
		"message": "Global file ticket revoked successfully",
		"epoch":   newEpoch,
		"raw_url": rawURL,
		"obj":     obj,
	})
}

func sha256Hash(b []byte) []byte {
	h := sha256.Sum256(b)
	return h[:]
}
