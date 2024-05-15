package web

import (
	"context"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/wetor/PPPwn_go/internal/logger"
	"net/http"
)

type Option struct {
	Debug bool
	Host  string
	Port  int
	WS    *WebSocket
}

func Run(ctx context.Context, opts *Option) {
	if opts.Debug {
		gin.SetMode(gin.DebugMode)
	} else {
		gin.SetMode(gin.ReleaseMode)
	}
	r := gin.New()
	r.Use(Cors())                        // 跨域中间件
	r.Use(GinLogger(logger.GetLogger())) // 日志中间件
	r.Use(GinRecovery(logger.GetLogger(), true, func(c *gin.Context, recovered any) {
		if err, ok := recovered.(error); ok {
			logger.Error(err)
			c.JSON(ErrSvr("InternalServerError"))
		} else {
			logger.Error(recovered.(string))
			c.JSON(ErrSvr(recovered.(string)))
		}
	})) // 错误处理中间件

	wsRoot := r.Group("/websocket")
	wsRoot.GET("/log", opts.WS.Log)

	InitStatic(r)
	s := &http.Server{
		Addr:    fmt.Sprintf("%s:%d", opts.Host, opts.Port),
		Handler: r,
	}

	if err := s.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		logger.Error(err)
	}
}
