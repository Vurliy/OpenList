package handles

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	stdpath "path"
	"strings"
	"time"

	"github.com/OpenListTeam/OpenList/v4/internal/conf"
	"github.com/OpenListTeam/OpenList/v4/internal/driver"
	"github.com/OpenListTeam/OpenList/v4/internal/fs"
	"github.com/OpenListTeam/OpenList/v4/internal/model"
	"github.com/OpenListTeam/OpenList/v4/internal/op"
	"github.com/OpenListTeam/OpenList/v4/pkg/webdavauth"
	"github.com/OpenListTeam/OpenList/v4/server/common"
	"github.com/gin-gonic/gin"
)

type RevokeTicketReq struct {
	Path string `json:"path" binding:"required"`
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

func getUserFromCtx(c *gin.Context) *model.User {
	u, ok := c.Request.Context().Value(conf.UserKey).(*model.User)
	if ok && u != nil {
		return u
	}
	return nil
}

func RevokeUserFileTicket(c *gin.Context) {
	user := getUserFromCtx(c)
	if user == nil || user.IsGuest() {
		common.ErrorStrResp(c, "Login required", 401)
		return
	}
	var req RevokeTicketReq
	if err := c.ShouldBindJSON(&req); err != nil {
		common.ErrorResp(c, err, 400)
		return
	}
	reqPath, err := user.JoinPath(req.Path)
	if err != nil {
		common.ErrorResp(c, err, 403)
		return
	}
	obj, err := fs.Get(c.Request.Context(), reqPath, &fs.GetArgs{})
	if err != nil {
		common.ErrorResp(c, err, 404)
		return
	}

	storageDriver, _, err := op.GetStorageAndActualPath(reqPath)
	if err != nil || storageDriver == nil {
		common.ErrorStrResp(c, "Storage driver not found", 404)
		return
	}

	storage := storageDriver.GetStorage()
	scopePath := "/" + strings.Trim(stdpath.Join("/download", strings.TrimPrefix(reqPath, storage.MountPath)), "/")
	newEpoch := webdavauth.IncrementUserFileEpoch(user.ID, scopePath)

	hashKey := fmt.Sprintf("%d:%s", user.ID, scopePath)
	hashHex := hex.EncodeToString(sha256Hash([]byte(hashKey)))
	_ = SyncEpochToWebDAV(storageDriver, fmt.Sprintf("userfile-%s.json", hashHex), newEpoch)

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
	user := getUserFromCtx(c)
	if user == nil || user.Role != model.ADMIN {
		common.ErrorStrResp(c, "Admin permission required", 403)
		return
	}
	var req RevokeTicketReq
	if err := c.ShouldBindJSON(&req); err != nil {
		common.ErrorResp(c, err, 400)
		return
	}
	reqPath, err := user.JoinPath(req.Path)
	if err != nil {
		common.ErrorResp(c, err, 403)
		return
	}
	obj, err := fs.Get(c.Request.Context(), reqPath, &fs.GetArgs{})
	if err != nil {
		common.ErrorResp(c, err, 404)
		return
	}

	storageDriver, _, err := op.GetStorageAndActualPath(reqPath)
	if err != nil || storageDriver == nil {
		common.ErrorStrResp(c, "Storage driver not found", 404)
		return
	}

	storage := storageDriver.GetStorage()
	scopePath := "/" + strings.Trim(stdpath.Join("/download", strings.TrimPrefix(reqPath, storage.MountPath)), "/")
	newEpoch := webdavauth.IncrementGlobalFileEpoch(scopePath)

	hashHex := hex.EncodeToString(sha256Hash([]byte(scopePath)))
	_ = SyncEpochToWebDAV(storageDriver, fmt.Sprintf("file-%s.json", hashHex), newEpoch)

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
