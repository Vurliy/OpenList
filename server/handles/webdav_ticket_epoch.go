package handles

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	stdpath "path"
	"strings"
	"time"

	"github.com/OpenListTeam/OpenList/v4/internal/conf"
	"github.com/OpenListTeam/OpenList/v4/internal/db"
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

type RolloverStorageReq struct {
	ID        uint `json:"id"`
	StorageID uint `json:"storage_id"`
}

func RolloverStorageGeneration(c *gin.Context) {
	user := getUserFromCtx(c)
	if user == nil || user.Role != model.ADMIN {
		common.ErrorStrResp(c, "Admin permission required", 403)
		return
	}
	var req RolloverStorageReq
	_ = c.ShouldBindJSON(&req)
	storageID := req.ID
	if storageID == 0 {
		storageID = req.StorageID
	}
	if storageID == 0 {
		common.ErrorStrResp(c, "storage_id is required", 400)
		return
	}

	storage, err := db.GetStorageById(storageID)
	if err != nil || storage == nil {
		common.ErrorStrResp(c, "Storage not found", 404)
		return
	}

	type GenerationRolloverDriver interface {
		RolloverGeneration(ctx context.Context) (int, error)
	}

	driverInstance, err := op.GetStorageByMountPath(storage.MountPath)
	if err != nil || driverInstance == nil {
		common.ErrorStrResp(c, "Storage driver instance not found", 404)
		return
	}

	roller, ok := driverInstance.(GenerationRolloverDriver)
	if !ok {
		common.ErrorStrResp(c, "Storage driver does not support generation rollover", 400)
		return
	}

	newGen, err := roller.RolloverGeneration(c.Request.Context())
	if err != nil {
		common.ErrorStrResp(c, fmt.Sprintf("Failed to sync rollover to WebDAV: %v", err), 500)
		return
	}

	// Persist to DB
	additionStr := storage.Addition
	var additionMap map[string]interface{}
	_ = json.Unmarshal([]byte(additionStr), &additionMap)
	if additionMap == nil {
		additionMap = make(map[string]interface{})
	}
	additionMap["storage_generation"] = newGen
	updatedBytes, _ := json.Marshal(additionMap)
	storage.Addition = string(updatedBytes)
	_ = op.UpdateStorage(c.Request.Context(), *storage)

	common.SuccessResp(c, gin.H{
		"message":            "Storage generation rolled over successfully",
		"storage_id":         storage.ID,
		"storage_generation": newGen,
	})
}

func RolloverAllStorageGeneration(c *gin.Context) {
	user := getUserFromCtx(c)
	if user == nil || user.Role != model.ADMIN {
		common.ErrorStrResp(c, "Admin permission required", 403)
		return
	}

	storages, _, err := db.GetStorages(1, 1000)
	if err != nil {
		common.ErrorResp(c, err, 500)
		return
	}

	type GenerationRolloverDriver interface {
		RolloverGeneration(ctx context.Context) (int, error)
	}

	var affected []gin.H
	for _, storage := range storages {
		if storage.Disabled {
			continue
		}
		driverInstance, err := op.GetStorageByMountPath(storage.MountPath)
		if err != nil || driverInstance == nil {
			continue
		}
		roller, ok := driverInstance.(GenerationRolloverDriver)
		if !ok {
			continue
		}

		newGen, _ := roller.RolloverGeneration(c.Request.Context())
		additionStr := storage.Addition
		var additionMap map[string]interface{}
		_ = json.Unmarshal([]byte(additionStr), &additionMap)
		if additionMap == nil {
			additionMap = make(map[string]interface{})
		}
		additionMap["storage_generation"] = newGen
		updatedBytes, _ := json.Marshal(additionMap)
		storage.Addition = string(updatedBytes)
		_ = op.UpdateStorage(c.Request.Context(), storage)

		affected = append(affected, gin.H{
			"storage_id":         storage.ID,
			"mount_path":         storage.MountPath,
			"storage_generation": newGen,
		})
	}

	common.SuccessResp(c, gin.H{
		"message":  "All WebDAV storage generations rolled over successfully",
		"affected": affected,
		"count":    len(affected),
	})
}
